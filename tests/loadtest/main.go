// Command loadtest drives Barktrace's real ingestion handler and durable
// SQLite queue for a fixed period, then enforces latency, error, and memory
// budgets. It is intentionally self-contained so it is useful in CI without
// provisioning an external identity provider.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/barktrace/bark/internal/ingest"
	"github.com/barktrace/bark/internal/store"
)

type measurements struct {
	mu        sync.Mutex
	latencies []time.Duration
	sent      atomic.Int64
	accepted  atomic.Int64
	failed    atomic.Int64
	peakHeap  atomic.Uint64
	peakRSS   atomic.Uint64
}

func main() {
	duration := flag.Duration("duration", time.Minute, "sustained request duration")
	concurrency := flag.Int("concurrency", 8, "concurrent ingestion clients")
	minRPS := flag.Float64("min-rps", 25, "minimum accepted requests per second")
	maxP95 := flag.Duration("max-p95", 2*time.Second, "maximum p95 request latency")
	maxErrorRate := flag.Float64("max-error-rate", 0.001, "maximum failed request ratio")
	maxRSSMiB := flag.Uint64("max-rss-mib", 128, "maximum resident memory in MiB (0 disables)")
	flag.Parse()
	if *duration < time.Second || *concurrency < 1 || *maxErrorRate < 0 || *maxErrorRate > 1 {
		log.Fatal("duration must be >= 1s, concurrency >= 1, and max-error-rate between 0 and 1")
	}

	debug.SetMemoryLimit(96 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dataDir, err := os.MkdirTemp("", "barktrace-load-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dataDir)
	st, err := store.Open(ctx, dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	seed(ctx, st)

	service := ingest.New(st, 20<<20, 10_000_000)
	go service.Run(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/1/envelope/", func(w http.ResponseWriter, r *http.Request) {
		service.Envelope(w, r, "1")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := &measurements{latencies: make([]time.Duration, 0, 64_000)}
	stopSampling := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			sampleMemory(result)
			select {
			case <-stopSampling:
				return
			case <-ticker.C:
			}
		}
	}()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		MaxIdleConns: *concurrency * 2, MaxIdleConnsPerHost: *concurrency, MaxConnsPerHost: *concurrency,
	}}
	started := time.Now()
	deadline := started.Add(*duration)
	var sequence atomic.Uint64
	var workers sync.WaitGroup
	workers.Add(*concurrency)
	for worker := 0; worker < *concurrency; worker++ {
		go func() {
			defer workers.Done()
			local := make([]time.Duration, 0, 8192)
			for time.Now().Before(deadline) {
				id := fmt.Sprintf("%032x", sequence.Add(1))
				payload, itemType := telemetryPayload(id)
				envelope := makeEnvelope(id, itemType, payload)
				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/1/envelope/?sentry_key=e2e-public-key&sentry_version=7", bytes.NewReader(envelope))
				request.Header.Set("Content-Type", "application/x-sentry-envelope")
				before := time.Now()
				response, requestErr := client.Do(request)
				local = append(local, time.Since(before))
				result.sent.Add(1)
				if requestErr != nil {
					result.failed.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					result.accepted.Add(1)
				} else {
					result.failed.Add(1)
				}
			}
			result.mu.Lock()
			result.latencies = append(result.latencies, local...)
			result.mu.Unlock()
		}()
	}
	workers.Wait()
	elapsed := time.Since(started)
	close(stopSampling)
	sampler.Wait()
	sampleMemory(result)

	var pending, stored int64
	if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingestion_jobs WHERE status IN ('pending', 'processing')`).Scan(&pending); err != nil {
		log.Fatal(err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM events) + (SELECT COUNT(*) FROM transactions) + (SELECT COUNT(*) FROM logs)
	`).Scan(&stored); err != nil {
		log.Fatal(err)
	}

	sort.Slice(result.latencies, func(i, j int) bool { return result.latencies[i] < result.latencies[j] })
	sent, accepted, failed := result.sent.Load(), result.accepted.Load(), result.failed.Load()
	rps := float64(accepted) / elapsed.Seconds()
	errorRate := float64(failed) / float64(max(int64(1), sent))
	p50, p95, p99 := percentile(result.latencies, .50), percentile(result.latencies, .95), percentile(result.latencies, .99)
	report := map[string]any{
		"duration": elapsed.Round(time.Millisecond).String(), "concurrency": *concurrency,
		"sent": sent, "accepted": accepted, "failed": failed, "stored": stored, "queue_pending": pending,
		"requests_per_second": round(rps), "error_rate": round(errorRate),
		"latency_p50": p50.String(), "latency_p95": p95.String(), "latency_p99": p99.String(),
		"peak_heap_mib": round(float64(result.peakHeap.Load()) / (1 << 20)),
		"peak_rss_mib":  round(float64(result.peakRSS.Load()) / (1 << 20)),
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(encoded))

	var failures []string
	if rps < *minRPS {
		failures = append(failures, fmt.Sprintf("throughput %.2f req/s is below %.2f", rps, *minRPS))
	}
	if errorRate > *maxErrorRate {
		failures = append(failures, fmt.Sprintf("error rate %.4f exceeds %.4f", errorRate, *maxErrorRate))
	}
	if p95 > *maxP95 {
		failures = append(failures, fmt.Sprintf("p95 %s exceeds %s", p95, *maxP95))
	}
	if pending != 0 || stored != accepted {
		failures = append(failures, fmt.Sprintf("durability mismatch: accepted=%d stored=%d pending=%d", accepted, stored, pending))
	}
	if *maxRSSMiB > 0 && result.peakRSS.Load() > *maxRSSMiB*(1<<20) {
		failures = append(failures, fmt.Sprintf("peak RSS %.2f MiB exceeds %d MiB", float64(result.peakRSS.Load())/(1<<20), *maxRSSMiB))
	}
	if len(failures) > 0 {
		log.Fatalf("load gate failed: %s", strings.Join(failures, "; "))
	}
}

func seed(ctx context.Context, st *store.Store) {
	if _, err := st.DB.ExecContext(ctx, `INSERT INTO organizations(id, slug, name) VALUES ('e2e-org', 'e2e', 'Load Test')`); err != nil {
		log.Fatal(err)
	}
	if _, err := st.DB.ExecContext(ctx, `INSERT INTO projects(id, organization_id, sentry_id, slug, name, platform, public_key) VALUES ('e2e-project', 'e2e-org', '1', 'load', 'Load Test', 'javascript', 'e2e-public-key')`); err != nil {
		log.Fatal(err)
	}
}

func telemetryPayload(id string) ([]byte, string) {
	sequence, _ := strconv.ParseUint(strings.TrimLeft(id, "0"), 16, 64)
	now := float64(time.Now().UnixNano()) / float64(time.Second)
	switch sequence % 5 {
	case 0:
		body, _ := json.Marshal(map[string]any{
			"event_id": id, "type": "transaction", "transaction": "POST /checkout", "op": "http.server",
			"start_timestamp": now - .025, "timestamp": now, "environment": "load", "release": "load@1.0.0",
			"contexts": map[string]any{"trace": map[string]any{"trace_id": id, "span_id": id[:16], "op": "http.server", "status": "ok"}},
		})
		return body, "transaction"
	case 1:
		body, _ := json.Marshal(map[string]any{"items": []map[string]any{{
			"timestamp": now, "severity_text": "info", "body": "load-test log", "environment": "load", "release": "load@1.0.0", "trace_id": id, "span_id": id[:16],
		}}})
		return body, "log"
	default:
		body, _ := json.Marshal(map[string]any{
			"event_id": id, "timestamp": now, "platform": "javascript", "environment": "load", "release": "load@1.0.0", "level": "error",
			"exception": map[string]any{"values": []map[string]any{{"type": "LoadError", "value": "controlled load event"}}},
		})
		return body, "event"
	}
}

func makeEnvelope(id, itemType string, payload []byte) []byte {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "{\"event_id\":%q}\n{\"type\":%q,\"length\":%d}\n", id, itemType, len(payload))
	buffer.Write(payload)
	return buffer.Bytes()
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * quantile)
	return values[index].Round(time.Microsecond)
}

func sampleMemory(result *measurements) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	updateMaximum(&result.peakHeap, memory.HeapAlloc)
	if rss := residentMemory(); rss > 0 {
		updateMaximum(&result.peakRSS, rss)
	}
}

func residentMemory() uint64 {
	body, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(body))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func updateMaximum(value *atomic.Uint64, candidate uint64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func round(value float64) float64 {
	result, _ := strconv.ParseFloat(fmt.Sprintf("%.4f", value), 64)
	return result
}
