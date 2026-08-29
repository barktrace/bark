package uptime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store        *store.Store
	allowPrivate bool
}

type Monitor struct {
	ID                string
	ProjectID         string
	URL               string
	Method            string
	IntervalSeconds   int
	TimeoutSeconds    int
	ExpectedStatusMin int
	ExpectedStatusMax int
}

type Result struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	CheckedAt  string `json:"checked_at"`
}

func New(st *store.Store, allowPrivate bool) *Service {
	return &Service{store: st, allowPrivate: allowPrivate}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	s.runDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDue(ctx)
		}
	}
}

func (s *Service) RunDue(ctx context.Context) { s.runDue(ctx) }

func (s *Service) ValidateURL(ctx context.Context, raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("URL must use http or https and include a host")
	}
	if parsed.User != nil {
		return errors.New("URL credentials are not allowed")
	}
	if _, err := validatedIPs(ctx, parsed.Hostname(), s.allowPrivate); err != nil {
		return err
	}
	return nil
}

func (s *Service) CheckNow(ctx context.Context, monitorID string) (Result, error) {
	var monitor Monitor
	err := s.store.DB.QueryRowContext(ctx, `
		SELECT id, project_id, url, method, interval_seconds, timeout_seconds, expected_status_min, expected_status_max
		FROM uptime_monitors WHERE id = ?
	`, monitorID).Scan(&monitor.ID, &monitor.ProjectID, &monitor.URL, &monitor.Method, &monitor.IntervalSeconds, &monitor.TimeoutSeconds, &monitor.ExpectedStatusMin, &monitor.ExpectedStatusMax)
	if err != nil {
		return Result{}, err
	}
	result := s.check(ctx, monitor)
	if _, err := s.record(ctx, monitor, result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (s *Service) runDue(ctx context.Context) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT id, project_id, url, method, interval_seconds, timeout_seconds, expected_status_min, expected_status_max
		FROM uptime_monitors WHERE enabled = 1 AND next_check_at <= ? ORDER BY next_check_at LIMIT 20
	`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		slog.Error("load due uptime monitors", "error", err)
		return
	}
	monitors := make([]Monitor, 0)
	for rows.Next() {
		var monitor Monitor
		if err := rows.Scan(&monitor.ID, &monitor.ProjectID, &monitor.URL, &monitor.Method, &monitor.IntervalSeconds, &monitor.TimeoutSeconds, &monitor.ExpectedStatusMin, &monitor.ExpectedStatusMax); err == nil {
			monitors = append(monitors, monitor)
		}
	}
	_ = rows.Close()
	for _, monitor := range monitors {
		next := time.Now().UTC().Add(time.Duration(monitor.IntervalSeconds) * time.Second).Format(time.RFC3339Nano)
		if _, err := s.store.DB.ExecContext(ctx, `UPDATE uptime_monitors SET next_check_at = ? WHERE id = ?`, next, monitor.ID); err != nil {
			continue
		}
		result := s.check(ctx, monitor)
		if _, err := s.record(ctx, monitor, result); err != nil {
			slog.Error("record uptime check", "monitor_id", monitor.ID, "error", err)
		}
	}
}

func (s *Service) check(parent context.Context, monitor Monitor) Result {
	started := time.Now()
	result := Result{Status: "down", CheckedAt: started.UTC().Format(time.RFC3339Nano)}
	ctx, cancel := context.WithTimeout(parent, time.Duration(monitor.TimeoutSeconds)*time.Second)
	defer cancel()
	if err := s.ValidateURL(ctx, monitor.URL); err != nil {
		result.Error = err.Error()
		return result
	}
	transport := &http.Transport{
		DialContext:           s.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(monitor.TimeoutSeconds) * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(monitor.TimeoutSeconds) * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return s.ValidateURL(request.Context(), request.URL.String())
		},
	}
	request, err := http.NewRequestWithContext(ctx, monitor.Method, monitor.URL, nil)
	if err != nil {
		result.Error = "invalid request"
		return result
	}
	request.Header.Set("User-Agent", "Barktrace-Uptime/1.0")
	response, err := client.Do(request)
	result.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	result.StatusCode = response.StatusCode
	if response.StatusCode >= monitor.ExpectedStatusMin && response.StatusCode <= monitor.ExpectedStatusMax {
		result.Status = "up"
	} else {
		result.Error = fmt.Sprintf("unexpected HTTP status %d", response.StatusCode)
	}
	return result
}

func (s *Service) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := validatedIPs(ctx, host, s.allowPrivate)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *Service) record(ctx context.Context, monitor Monitor, result Result) (bool, error) {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var statusCode any
	if result.StatusCode > 0 {
		statusCode = result.StatusCode
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uptime_checks(monitor_id, status, status_code, duration_ms, error, checked_at) VALUES (?, ?, ?, ?, ?, ?)`, monitor.ID, result.Status, statusCode, result.DurationMS, result.Error, result.CheckedAt); err != nil {
		return false, err
	}
	next := time.Now().UTC().Add(time.Duration(monitor.IntervalSeconds) * time.Second).Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE uptime_monitors SET last_checked_at = ?, last_status = ?, next_check_at = ? WHERE id = ?`, result.CheckedAt, result.Status, next, monitor.ID); err != nil {
		return false, err
	}
	openedIncident := false
	if result.Status == "down" {
		var execution sql.Result
		execution, err = tx.ExecContext(ctx, `INSERT INTO uptime_incidents(id, monitor_id, started_at, cause) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM uptime_incidents WHERE monitor_id = ? AND resolved_at IS NULL)`, uuid.NewString(), monitor.ID, result.CheckedAt, result.Error, monitor.ID)
		if err == nil {
			count, _ := execution.RowsAffected()
			openedIncident = count > 0
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE uptime_incidents SET resolved_at = ? WHERE monitor_id = ? AND resolved_at IS NULL`, result.CheckedAt, monitor.ID)
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if openedIncident {
		_ = alerts.Queue(ctx, s.store.DB, monitor.ProjectID, "uptime_down", map[string]any{"title": "Uptime monitor is down", "monitor_id": monitor.ID, "url": monitor.URL, "error": result.Error, "status_code": result.StatusCode, "checked_at": result.CheckedAt})
	}
	return openedIncident, nil
}

func validatedIPs(ctx context.Context, host string, allowPrivate bool) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("host could not be resolved")
	}
	if !allowPrivate {
		for _, ip := range ips {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, errors.New("private and local network targets are disabled")
			}
		}
	}
	return ips, nil
}

func cleanError(err error) string {
	message := err.Error()
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func ParsePositive(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}

func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
