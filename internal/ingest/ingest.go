package ingest

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

const maxEventBytes = 5 << 20

type Service struct {
	store            *store.Store
	maxEnvelopeBytes int64
}

type envelopeHeader struct {
	EventID string `json:"event_id"`
}

type itemHeader struct {
	Type   string `json:"type"`
	Length int64  `json:"length"`
}

type eventPayload struct {
	EventID     string          `json:"event_id"`
	Message     json.RawMessage `json:"message"`
	Level       string          `json:"level"`
	Platform    string          `json:"platform"`
	Release     string          `json:"release"`
	Environment string          `json:"environment"`
	Transaction string          `json:"transaction"`
	Timestamp   json.RawMessage `json:"timestamp"`
	Fingerprint json.RawMessage `json:"fingerprint"`
	Exception   json.RawMessage `json:"exception"`
}

type transactionPayload struct {
	EventID        string            `json:"event_id"`
	Transaction    string            `json:"transaction"`
	Operation      string            `json:"op"`
	Release        string            `json:"release"`
	Environment    string            `json:"environment"`
	Timestamp      json.RawMessage   `json:"timestamp"`
	StartTimestamp json.RawMessage   `json:"start_timestamp"`
	Spans          []json.RawMessage `json:"spans"`
	Contexts       struct {
		Trace struct {
			TraceID string `json:"trace_id"`
			SpanID  string `json:"span_id"`
			Op      string `json:"op"`
			Status  string `json:"status"`
		} `json:"trace"`
	} `json:"contexts"`
}

type logEnvelope struct {
	Items []logPayload `json:"items"`
}

type logPayload struct {
	Timestamp   json.RawMessage `json:"timestamp"`
	Level       string          `json:"level"`
	Severity    string          `json:"severity_text"`
	Body        json.RawMessage `json:"body"`
	Message     json.RawMessage `json:"message"`
	Environment string          `json:"environment"`
	Release     string          `json:"release"`
	TraceID     string          `json:"trace_id"`
	SpanID      string          `json:"span_id"`
	Attributes  map[string]any  `json:"attributes"`
}

type exceptionValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Result struct {
	ID string `json:"id"`
}

func New(st *store.Store, maxEnvelopeBytes int64) *Service {
	return &Service{store: st, maxEnvelopeBytes: maxEnvelopeBytes}
}

func (s *Service) Envelope(w http.ResponseWriter, r *http.Request, projectID string) {
	project, err := s.authenticateProject(r.Context(), r, projectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	reader, closeReader, err := decodedBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unsupported content encoding")
		return
	}
	defer closeReader()
	buffered := bufio.NewReader(io.LimitReader(reader, s.maxEnvelopeBytes+1))
	headerLine, err := readLine(buffered, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope header")
		return
	}
	var envelope envelopeHeader
	if err := json.Unmarshal(headerLine, &envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope header")
		return
	}
	acceptedID := envelope.EventID
	for {
		line, err := readLine(buffered, 64<<10)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid envelope item header")
			return
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var item itemHeader
		if err := json.Unmarshal(line, &item); err != nil || item.Length < 0 || item.Length > maxEventBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid envelope item")
			return
		}
		payload := make([]byte, item.Length)
		if _, err := io.ReadFull(buffered, payload); err != nil {
			writeError(w, http.StatusBadRequest, "truncated envelope item")
			return
		}
		if next, _ := buffered.Peek(1); len(next) == 1 && next[0] == '\n' {
			_, _ = buffered.ReadByte()
		}
		switch item.Type {
		case "event", "security":
			id, err := s.StoreEvent(r.Context(), project, payload, envelope.EventID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "event was rejected")
				return
			}
			acceptedID = id
		case "transaction":
			id, err := s.StoreTransaction(r.Context(), project, payload, envelope.EventID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "transaction was rejected")
				return
			}
			acceptedID = id
		case "log", "logs":
			if _, err := s.StoreLogs(r.Context(), project, payload); err != nil {
				writeError(w, http.StatusBadRequest, "logs were rejected")
				return
			}
		default:
			_, _ = s.store.DB.ExecContext(r.Context(), `INSERT INTO ingestion_outcomes(project_id, category, outcome, reason) VALUES (?, ?, 'accepted', 'processor pending')`, project.ID, item.Type)
		}
	}
	writeJSON(w, http.StatusOK, Result{ID: acceptedID})
}

// Logs accepts a small, documented JSON endpoint in addition to Sentry log
// envelope items. A payload can be one log object, an array, or {"items":[]}.
func (s *Service) Logs(w http.ResponseWriter, r *http.Request, projectID string) {
	project, err := s.authenticateProject(r.Context(), r, projectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxEventBytes)
	payload, err := io.ReadAll(body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "logs payload is too large")
		return
	}
	count, err := s.StoreLogs(r.Context(), project, payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "logs were rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": count})
}

func (s *Service) Store(w http.ResponseWriter, r *http.Request, projectID string) {
	project, err := s.authenticateProject(r.Context(), r, projectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxEventBytes)
	payload, err := io.ReadAll(body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "event is too large")
		return
	}
	id, err := s.StoreEvent(r.Context(), project, payload, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, "event was rejected")
		return
	}
	writeJSON(w, http.StatusOK, Result{ID: id})
}

type Project struct {
	ID             string
	OrganizationID string
	PublicKey      string
}

func (s *Service) authenticateProject(ctx context.Context, r *http.Request, projectID string) (Project, error) {
	key := r.URL.Query().Get("sentry_key")
	if key == "" {
		key = sentryAuthValue(r.Header.Get("X-Sentry-Auth"), "sentry_key")
	}
	var project Project
	err := s.store.DB.QueryRowContext(ctx, `SELECT id, organization_id, public_key FROM projects WHERE sentry_id = ? AND public_key = ?`, projectID, key).Scan(&project.ID, &project.OrganizationID, &project.PublicKey)
	return project, err
}

func (s *Service) StoreEvent(ctx context.Context, project Project, raw []byte, envelopeEventID string) (string, error) {
	var event eventPayload
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", fmt.Errorf("decode event: %w", err)
	}
	eventID := normalizeEventID(event.EventID)
	if eventID == "" {
		eventID = normalizeEventID(envelopeEventID)
	}
	if eventID == "" {
		eventID = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	timestamp := eventTime(event.Timestamp)
	title, fingerprint := eventIdentity(event)
	level := strings.ToLower(strings.TrimSpace(event.Level))
	if level == "" {
		level = "error"
	}

	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE project_id = ? AND event_id = ?`, project.ID, eventID).Scan(&existing); err != nil {
		return "", err
	}
	if existing != 0 {
		return eventID, tx.Commit()
	}
	releaseID, err := linkRelease(ctx, tx, project, strings.TrimSpace(event.Release), timestamp)
	if err != nil {
		return "", err
	}
	issueID := uuid.NewString()
	err = tx.QueryRowContext(ctx, `
		INSERT INTO issues(id, project_id, fingerprint, title, level, first_seen_at, last_seen_at, first_release_id, last_release_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, fingerprint) DO UPDATE SET
			title = excluded.title,
			level = excluded.level,
			last_seen_at = excluded.last_seen_at,
			last_release_id = COALESCE(excluded.last_release_id, issues.last_release_id),
			event_count = issues.event_count + 1,
			status = CASE WHEN issues.status = 'resolved' THEN 'unresolved' ELSE issues.status END
		RETURNING id
	`, issueID, project.ID, fingerprint, title, level, timestamp, timestamp, nullable(releaseID), nullable(releaseID)).Scan(&issueID)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO events(id, event_id, project_id, issue_id, release_id, environment, platform, level, timestamp, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, uuid.NewString(), eventID, project.ID, issueID, nullable(releaseID), event.Environment, event.Platform, level, timestamp, raw)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return eventID, nil
}

func (s *Service) StoreTransaction(ctx context.Context, project Project, raw []byte, envelopeEventID string) (string, error) {
	var event transactionPayload
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", fmt.Errorf("decode transaction: %w", err)
	}
	eventID := normalizeEventID(firstNonEmpty(event.EventID, envelopeEventID))
	if eventID == "" {
		eventID = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	finished := parseEventTime(event.Timestamp, time.Now().UTC())
	started := parseEventTime(event.StartTimestamp, finished)
	if started.After(finished) || finished.Sub(started) > 24*time.Hour {
		return "", errors.New("invalid transaction duration")
	}
	name := strings.TrimSpace(event.Transaction)
	if name == "" {
		name = "Unknown transaction"
	}
	operation := strings.TrimSpace(firstNonEmpty(event.Contexts.Trace.Op, event.Operation))

	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	releaseID, err := linkRelease(ctx, tx, project, strings.TrimSpace(event.Release), finished.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO transactions(id, event_id, project_id, release_id, trace_id, span_id, name, operation, status, environment, started_at, finished_at, duration_ms, span_count, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, event_id) DO NOTHING
	`, uuid.NewString(), eventID, project.ID, nullable(releaseID), strings.TrimSpace(event.Contexts.Trace.TraceID), strings.TrimSpace(event.Contexts.Trace.SpanID), name, operation, strings.TrimSpace(event.Contexts.Trace.Status), strings.TrimSpace(event.Environment), started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), float64(finished.Sub(started))/float64(time.Millisecond), len(event.Spans), raw)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return eventID, nil
}

func (s *Service) StoreLogs(ctx context.Context, project Project, raw []byte) (int, error) {
	items, err := decodeLogs(raw)
	if err != nil || len(items) == 0 {
		return 0, errors.New("log payload has no items")
	}
	if len(items) > 1000 {
		return 0, errors.New("too many log items")
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, item := range items {
		message := firstNonEmpty(rawText(item.Body), rawText(item.Message), attributeString(item.Attributes, "message"))
		if strings.TrimSpace(message) == "" {
			return 0, errors.New("log message is required")
		}
		seenAt := parseEventTime(item.Timestamp, time.Now().UTC()).Format(time.RFC3339Nano)
		release := firstNonEmpty(item.Release, attributeString(item.Attributes, "sentry.release"), attributeString(item.Attributes, "release"))
		releaseID, err := linkRelease(ctx, tx, project, strings.TrimSpace(release), seenAt)
		if err != nil {
			return 0, err
		}
		attributes, _ := json.Marshal(item.Attributes)
		level := strings.ToLower(strings.TrimSpace(firstNonEmpty(item.Level, item.Severity, attributeString(item.Attributes, "sentry.severity_text"), "info")))
		environment := firstNonEmpty(item.Environment, attributeString(item.Attributes, "sentry.environment"), attributeString(item.Attributes, "environment"))
		traceID := firstNonEmpty(item.TraceID, attributeString(item.Attributes, "sentry.trace_id"), attributeString(item.Attributes, "trace_id"))
		spanID := firstNonEmpty(item.SpanID, attributeString(item.Attributes, "sentry.span_id"), attributeString(item.Attributes, "span_id"))
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs(id, project_id, release_id, timestamp, level, message, environment, trace_id, span_id, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, uuid.NewString(), project.ID, nullable(releaseID), seenAt, level, message, strings.TrimSpace(environment), strings.TrimSpace(traceID), strings.TrimSpace(spanID), attributes); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

func decodeLogs(raw []byte) ([]logPayload, error) {
	var envelope logEnvelope
	if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Items) > 0 {
		return envelope.Items, nil
	}
	var items []logPayload
	if err := json.Unmarshal(raw, &items); err == nil && len(items) > 0 {
		return items, nil
	}
	var item logPayload
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, err
	}
	return []logPayload{item}, nil
}

func rawText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var object struct {
		Formatted   string `json:"formatted"`
		Message     string `json:"message"`
		StringValue string `json:"string_value"`
		Value       string `json:"value"`
	}
	if json.Unmarshal(raw, &object) == nil {
		return strings.TrimSpace(firstNonEmpty(object.Formatted, object.Message, object.StringValue, object.Value))
	}
	return ""
}

func attributeString(attributes map[string]any, key string) string {
	value, ok := attributes[key]
	if !ok {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	if object, ok := value.(map[string]any); ok {
		for _, field := range []string{"value", "string_value"} {
			if text, ok := object[field].(string); ok {
				return text
			}
		}
	}
	return ""
}

func linkRelease(ctx context.Context, tx *sql.Tx, project Project, version, seenAt string) (string, error) {
	if version == "" {
		return "", nil
	}
	releaseID := uuid.NewString()
	err := tx.QueryRowContext(ctx, `
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(organization_id, version) DO UPDATE SET last_seen_at = excluded.last_seen_at
		RETURNING id
	`, releaseID, project.OrganizationID, version, seenAt, seenAt).Scan(&releaseID)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(project_id, release_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
	`, project.ID, releaseID, seenAt, seenAt)
	return releaseID, err
}

func eventIdentity(event eventPayload) (string, string) {
	title := messageText(event.Message)
	typeName := ""
	value := ""
	values := exceptionValues(event.Exception)
	if len(values) > 0 {
		last := values[len(values)-1]
		typeName, value = strings.TrimSpace(last.Type), strings.TrimSpace(last.Value)
		if typeName != "" && value != "" {
			title = typeName + ": " + value
		} else if value != "" {
			title = value
		}
	}
	if title == "" {
		title = firstNonEmpty(event.Transaction, "Unknown error")
	}
	components := explicitFingerprint(event.Fingerprint)
	if len(components) == 0 {
		components = []string{typeName, firstLine(firstNonEmpty(value, title)), event.Transaction}
	}
	sum := sha256.Sum256([]byte(strings.Join(components, "\x00")))
	return title, hex.EncodeToString(sum[:])
}

func exceptionValues(raw json.RawMessage) []exceptionValue {
	var container struct {
		Values []exceptionValue `json:"values"`
	}
	if json.Unmarshal(raw, &container) == nil && len(container.Values) > 0 {
		return container.Values
	}
	var values []exceptionValue
	if json.Unmarshal(raw, &values) == nil {
		return values
	}
	return nil
}

func explicitFingerprint(raw json.RawMessage) []string {
	var values []string
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil {
		return nil
	}
	result := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "{{ default }}" {
			result = append(result, value)
		}
	}
	return result
}

func messageText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var object struct {
		Formatted string `json:"formatted"`
		Message   string `json:"message"`
	}
	if json.Unmarshal(raw, &object) == nil {
		return strings.TrimSpace(firstNonEmpty(object.Formatted, object.Message))
	}
	return ""
}

func eventTime(raw json.RawMessage) string {
	return parseEventTime(raw, time.Now().UTC()).Format(time.RFC3339Nano)
}

func parseEventTime(raw json.RawMessage, fallback time.Time) time.Time {
	if len(raw) != 0 {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
				return parsed.UTC()
			}
		}
		var epoch float64
		if json.Unmarshal(raw, &epoch) == nil && epoch > 0 {
			if epoch > 1e15 {
				return time.Unix(0, int64(epoch)).UTC()
			}
			if epoch > 1e12 {
				return time.UnixMilli(int64(epoch)).UTC()
			}
			seconds, fraction := mathModf(epoch)
			return time.Unix(seconds, int64(fraction*1e9)).UTC()
		}
	}
	return fallback.UTC()
}

func mathModf(value float64) (int64, float64) {
	seconds := int64(value)
	return seconds, value - float64(seconds)
}

func normalizeEventID(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	if len(value) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}

func sentryAuthValue(header, key string) string {
	header = strings.TrimSpace(strings.TrimPrefix(header, "Sentry"))
	for _, part := range strings.Split(header, ",") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) == 2 && pair[0] == key {
			return pair[1]
		}
	}
	return ""
}

func decodedBody(r *http.Request) (io.Reader, func(), error) {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return r.Body, func() {}, nil
	case "gzip":
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, func() {}, err
		}
		return reader, func() { _ = reader.Close() }, nil
	case "deflate":
		reader := flate.NewReader(r.Body)
		return reader, func() { _ = reader.Close() }, nil
	case "br":
		return brotli.NewReader(r.Body), func() {}, nil
	case "zstd":
		reader, err := zstd.NewReader(r.Body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, func() {}, err
		}
		return reader, reader.Close, nil
	default:
		return nil, func() {}, errors.New("unsupported encoding")
	}
}

func readLine(reader *bufio.Reader, limit int) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > limit {
		return nil, errors.New("line too long")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = []byte(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
	if len(line) == 0 && errors.Is(err, io.EOF) {
		return nil, io.EOF
	}
	return line, nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index]
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"type": http.StatusText(status), "message": message}})
}

func ParseProjectID(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "api" {
		return "", false
	}
	if parts[2] != "envelope" && parts[2] != "store" {
		return "", false
	}
	return parts[1], true
}

func ParseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}
