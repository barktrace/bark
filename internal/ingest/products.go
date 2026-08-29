package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/blobstore"
	"github.com/barktrace/bark/internal/cronmon"
	"github.com/barktrace/bark/internal/quota"
	"github.com/google/uuid"
)

func (s *Service) storeBlob(ctx context.Context, project Project, kind, contentType string, payload []byte) (string, error) {
	result, err := s.store.Blobs.Put(bytes.NewReader(payload), blobstore.MaxBlobBytes)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}
	id := uuid.NewString()
	_, err = s.store.DB.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, project.OrganizationID, project.ID, kind, result.Key, result.Checksum, result.Size, contentType)
	return id, err
}

func (s *Service) StoreAttachment(ctx context.Context, project Project, externalEventID, filename, contentType, attachmentType string, payload []byte) error {
	externalEventID = normalizeEventID(externalEventID)
	filename = strings.TrimSpace(filename)
	if externalEventID == "" || filename == "" || len(payload) == 0 {
		return errors.New("event id, filename, and attachment content are required")
	}
	var eventID string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT id FROM events WHERE project_id = ? AND event_id = ?`, project.ID, externalEventID).Scan(&eventID); err != nil {
		return fmt.Errorf("attachment event: %w", err)
	}
	blobID, err := s.storeBlob(ctx, project, "attachment", contentType, payload)
	if err != nil {
		return err
	}
	if attachmentType = strings.TrimSpace(attachmentType); attachmentType == "" {
		attachmentType = "event.attachment"
	}
	_, err = s.store.DB.ExecContext(ctx, `INSERT INTO event_attachments(id, event_id, blob_id, filename, attachment_type) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), eventID, blobID, filename, attachmentType)
	return err
}

func (s *Service) Feedback(w http.ResponseWriter, r *http.Request, sentryProjectID string) {
	project, err := s.authenticateProject(r.Context(), r, sentryProjectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	if !s.allow(project.ID) {
		writeRateLimited(w)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "feedback payload is too large")
		return
	}
	if decision, err := quota.Check(r.Context(), s.store.DB, project.ID, "feedback", int64(len(raw)), time.Now().UTC()); err != nil || !decision.Allowed {
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check project quota")
		} else if decision.Reason == "item_size" {
			writeError(w, http.StatusRequestEntityTooLarge, "feedback exceeds category size quota")
		} else {
			writeCategoryRateLimited(w, "feedback", decision.RetryAfter)
		}
		return
	}
	result, err := s.enqueueAndProcess(r.Context(), project, itemHeader{Type: "user_report", Length: int64(len(raw)), ContentType: "application/json"}, "", "", "", raw)
	if err != nil && !result.Queued {
		writeError(w, http.StatusServiceUnavailable, "could not persist feedback")
		return
	}
	if result.JobID != "" {
		w.Header().Set("X-Barktrace-Ingestion-Job", result.JobID)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "created", "queued": err != nil})
}

func (s *Service) CheckIn(w http.ResponseWriter, r *http.Request, sentryProjectID, monitorSlug, checkinID string) {
	project, err := s.authenticateProject(r.Context(), r, sentryProjectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	if !s.allow(project.ID) {
		writeRateLimited(w)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "check-in payload is too large")
		return
	}
	if decision, err := quota.Check(r.Context(), s.store.DB, project.ID, "check_in", int64(len(raw)), time.Now().UTC()); err != nil || !decision.Allowed {
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check project quota")
		} else if decision.Reason == "item_size" {
			writeError(w, http.StatusRequestEntityTooLarge, "check-in exceeds category size quota")
		} else {
			writeCategoryRateLimited(w, "check_in", decision.RetryAfter)
		}
		return
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		writeError(w, http.StatusBadRequest, "invalid check-in payload")
		return
	}
	payload["monitor_slug"] = monitorSlug
	if strings.TrimSpace(checkinID) == "" {
		checkinID = uuid.NewString()
	}
	payload["check_in_id"] = checkinID
	raw, _ = json.Marshal(payload)
	result, err := s.enqueueAndProcess(r.Context(), project, itemHeader{Type: "check_in", Length: int64(len(raw)), ContentType: "application/json"}, "", "", "", raw)
	if err != nil && !result.Queued {
		writeError(w, http.StatusServiceUnavailable, "could not persist check-in")
		return
	}
	if result.JobID != "" {
		w.Header().Set("X-Barktrace-Ingestion-Job", result.JobID)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": payload["check_in_id"], "monitor_slug": monitorSlug})
}

func (s *Service) StoreFeedback(ctx context.Context, project Project, raw []byte) error {
	var feedback struct {
		EventID  string `json:"event_id"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Comments string `json:"comments"`
		Message  string `json:"message"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal(raw, &feedback); err != nil {
		return err
	}
	feedback.Comments = strings.TrimSpace(firstNonEmpty(feedback.Comments, feedback.Message))
	if feedback.Comments == "" || len(feedback.Comments) > 20000 {
		return errors.New("feedback comments are required and limited to 20000 characters")
	}
	id := uuid.NewString()
	_, err := s.store.DB.ExecContext(ctx, `INSERT INTO user_feedback(id, project_id, event_id, name, email, comments, url, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, project.ID, normalizeEventID(feedback.EventID), strings.TrimSpace(feedback.Name), strings.TrimSpace(feedback.Email), feedback.Comments, strings.TrimSpace(feedback.URL), raw)
	if err == nil {
		_ = alerts.Queue(ctx, s.store.DB, project.ID, "user_feedback", map[string]any{"title": "New user feedback", "feedback_id": id, "event_id": normalizeEventID(feedback.EventID), "name": feedback.Name, "email": feedback.Email, "comments": feedback.Comments})
	}
	return err
}

type replayPayload struct {
	ReplayID    string          `json:"replay_id"`
	SegmentID   int             `json:"segment_id"`
	Timestamp   json.RawMessage `json:"timestamp"`
	StartedAt   json.RawMessage `json:"replay_start_timestamp"`
	Environment string          `json:"environment"`
	Release     string          `json:"release"`
	URLs        []string        `json:"urls"`
	ErrorIDs    []string        `json:"error_ids"`
	User        struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func (s *Service) StoreReplayEvent(ctx context.Context, project Project, raw []byte) error {
	var replay replayPayload
	if err := json.Unmarshal(raw, &replay); err != nil {
		return err
	}
	replay.ReplayID = normalizeReplayID(replay.ReplayID)
	if replay.ReplayID == "" {
		return errors.New("replay_id is required")
	}
	blobID, err := s.storeBlob(ctx, project, "replay_event", "application/json", raw)
	if err != nil {
		return err
	}
	finished := parseEventTime(replay.Timestamp, time.Now().UTC())
	started := parseEventTime(replay.StartedAt, finished)
	urlValue := ""
	if len(replay.URLs) > 0 {
		urlValue = replay.URLs[0]
	}
	userID := firstNonEmpty(replay.User.ID, replay.User.Email)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO replays(id, replay_id, project_id, event_blob_id, segment_id, environment, release, user_id, started_at, finished_at, error_count, url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, replay_id, segment_id) DO UPDATE SET event_blob_id = excluded.event_blob_id, environment = excluded.environment, release = excluded.release, user_id = excluded.user_id, started_at = excluded.started_at, finished_at = excluded.finished_at, error_count = excluded.error_count, url = excluded.url
	`, uuid.NewString(), replay.ReplayID, project.ID, blobID, replay.SegmentID, replay.Environment, replay.Release, userID, started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), len(replay.ErrorIDs), urlValue)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM replay_error_links WHERE project_id = ? AND replay_id = ? AND segment_id = ?`, project.ID, replay.ReplayID, replay.SegmentID); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(replay.ErrorIDs))
	for _, rawEventID := range replay.ErrorIDs {
		eventID := normalizeEventID(rawEventID)
		if eventID == "" {
			continue
		}
		if _, exists := seen[eventID]; exists {
			continue
		}
		seen[eventID] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO replay_error_links(project_id, replay_id, segment_id, event_id) VALUES (?, ?, ?, ?)`, project.ID, replay.ReplayID, replay.SegmentID, eventID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) StoreReplayRecording(ctx context.Context, project Project, envelopeReplayID string, raw []byte) error {
	replayID := normalizeReplayID(envelopeReplayID)
	var header struct {
		ReplayID  string `json:"replay_id"`
		SegmentID int    `json:"segment_id"`
	}
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	_ = json.Unmarshal(line, &header)
	if replayID == "" {
		replayID = normalizeReplayID(header.ReplayID)
	}
	if replayID == "" {
		return errors.New("replay id is required")
	}
	blobID, err := s.storeBlob(ctx, project, "replay_recording", "application/octet-stream", raw)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.store.DB.ExecContext(ctx, `UPDATE replays SET recording_blob_id = ? WHERE id = (SELECT id FROM replays WHERE project_id = ? AND replay_id = ? AND segment_id = ? ORDER BY created_at DESC LIMIT 1)`, blobID, project.ID, replayID, header.SegmentID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		_, err = s.store.DB.ExecContext(ctx, `INSERT INTO replays(id, replay_id, project_id, recording_blob_id, segment_id, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, uuid.NewString(), replayID, project.ID, blobID, header.SegmentID, now, now)
	}
	return err
}

func (s *Service) StoreProfile(ctx context.Context, project Project, raw []byte) error {
	var profile struct {
		ProfileID   string          `json:"profile_id"`
		ProfilerID  string          `json:"profiler_id"`
		ChunkID     string          `json:"chunk_id"`
		EventID     string          `json:"event_id"`
		Platform    string          `json:"platform"`
		Environment string          `json:"environment"`
		Release     string          `json:"release"`
		Timestamp   json.RawMessage `json:"timestamp"`
		DurationNS  float64         `json:"duration_ns"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		return err
	}
	profile.ProfileID = strings.TrimSpace(firstNonEmpty(profile.ProfileID, profile.EventID))
	profile.ProfilerID = strings.TrimSpace(profile.ProfilerID)
	profile.ChunkID = strings.TrimSpace(profile.ChunkID)
	if profile.ProfileID == "" && profile.ProfilerID != "" {
		profile.ProfileID = profile.ProfilerID
		if profile.ChunkID != "" {
			profile.ProfileID += ":" + profile.ChunkID
		}
	}
	if profile.ProfileID == "" {
		return errors.New("profile id is required")
	}
	blobID, err := s.storeBlob(ctx, project, "profile", "application/json", raw)
	if err != nil {
		return err
	}
	started := parseEventTime(profile.Timestamp, time.Now().UTC()).Format(time.RFC3339Nano)
	_, err = s.store.DB.ExecContext(ctx, `INSERT INTO profiles(id, profile_id, project_id, transaction_id, blob_id, platform, environment, release, started_at, duration_ms, profiler_id, chunk_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, profile_id) DO UPDATE SET blob_id = excluded.blob_id, platform = excluded.platform, environment = excluded.environment, release = excluded.release, started_at = excluded.started_at, duration_ms = excluded.duration_ms, profiler_id = excluded.profiler_id, chunk_id = excluded.chunk_id`, uuid.NewString(), profile.ProfileID, project.ID, normalizeEventID(profile.EventID), blobID, profile.Platform, profile.Environment, profile.Release, started, profile.DurationNS/1e6, profile.ProfilerID, profile.ChunkID)
	return err
}

type metricPoint struct {
	Name      string
	Type      string
	Value     float64
	Unit      string
	Tags      map[string]any
	Timestamp time.Time
}

func (s *Service) StoreMetrics(ctx context.Context, project Project, raw []byte) (int, error) {
	points := decodeMetricPoints(raw)
	if len(points) == 0 || len(points) > 10000 {
		return 0, errors.New("metric payload has no supported points or is too large")
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, point := range points {
		tags, _ := json.Marshal(point.Tags)
		if _, err := tx.ExecContext(ctx, `INSERT INTO metric_points(project_id, name, metric_type, value, unit, tags, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`, project.ID, point.Name, point.Type, point.Value, point.Unit, tags, point.Timestamp.UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, point := range points {
		_ = alerts.Queue(ctx, s.store.DB, project.ID, "metric_threshold", map[string]any{"title": "Metric threshold reached", "metric_name": point.Name, "value": point.Value, "unit": point.Unit, "timestamp": point.Timestamp.UTC().Format(time.RFC3339Nano)})
	}
	return len(points), nil
}

func decodeMetricPoints(raw []byte) []metricPoint {
	var envelope struct {
		Buckets []struct {
			Name      string          `json:"name"`
			Type      string          `json:"type"`
			Value     json.RawMessage `json:"value"`
			Unit      string          `json:"unit"`
			Tags      map[string]any  `json:"tags"`
			Timestamp json.RawMessage `json:"timestamp"`
		} `json:"buckets"`
	}
	if json.Unmarshal(raw, &envelope) == nil && len(envelope.Buckets) > 0 {
		points := make([]metricPoint, 0, len(envelope.Buckets))
		for _, bucket := range envelope.Buckets {
			var value float64
			if json.Unmarshal(bucket.Value, &value) != nil {
				var values []float64
				if json.Unmarshal(bucket.Value, &values) != nil || len(values) == 0 {
					continue
				}
				for _, item := range values {
					value += item
				}
				value /= float64(len(values))
			}
			points = append(points, metricPoint{Name: bucket.Name, Type: firstNonEmpty(bucket.Type, "gauge"), Value: value, Unit: bucket.Unit, Tags: bucket.Tags, Timestamp: parseEventTime(bucket.Timestamp, time.Now().UTC())})
		}
		return points
	}
	points := make([]metricPoint, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		valueAndType := strings.Split(parts[1], "|")
		if len(valueAndType) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(valueAndType[0], 64)
		if err != nil {
			continue
		}
		points = append(points, metricPoint{Name: parts[0], Type: valueAndType[1], Value: value, Timestamp: time.Now().UTC(), Tags: map[string]any{}})
	}
	return points
}

func (s *Service) StoreClientReport(ctx context.Context, project Project, raw []byte) error {
	var report struct {
		Timestamp json.RawMessage `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	timestamp := parseEventTime(report.Timestamp, time.Now().UTC()).Format(time.RFC3339Nano)
	_, err := s.store.DB.ExecContext(ctx, `INSERT INTO client_reports(id, project_id, timestamp, payload) VALUES (?, ?, ?, ?)`, uuid.NewString(), project.ID, timestamp, raw)
	return err
}

func (s *Service) StoreCheckIn(ctx context.Context, project Project, raw []byte) error {
	var checkin struct {
		CheckInID   string          `json:"check_in_id"`
		MonitorSlug string          `json:"monitor_slug"`
		Status      string          `json:"status"`
		Duration    *float64        `json:"duration"`
		Release     string          `json:"release"`
		Environment string          `json:"environment"`
		Timestamp   json.RawMessage `json:"date_created"`
		Contexts    struct {
			MonitorConfig struct {
				Schedule struct {
					Type  string          `json:"type"`
					Value json.RawMessage `json:"value"`
				} `json:"schedule"`
				CheckinMargin int    `json:"checkin_margin"`
				MaxRuntime    int    `json:"max_runtime"`
				Timezone      string `json:"timezone"`
			} `json:"monitor_config"`
		} `json:"contexts"`
	}
	if err := json.Unmarshal(raw, &checkin); err != nil {
		return err
	}
	checkin.MonitorSlug = strings.TrimSpace(checkin.MonitorSlug)
	checkin.Status = strings.ToLower(strings.TrimSpace(checkin.Status))
	if checkin.MonitorSlug == "" || (checkin.Status != "in_progress" && checkin.Status != "ok" && checkin.Status != "error") {
		return errors.New("monitor_slug and a valid status are required")
	}
	if checkin.CheckInID = strings.TrimSpace(checkin.CheckInID); checkin.CheckInID == "" {
		checkin.CheckInID = uuid.NewString()
	}
	config := checkin.Contexts.MonitorConfig
	scheduleType, scheduleValue, err := cronmon.NormalizeSchedule(config.Schedule.Type, config.Schedule.Value)
	if err != nil {
		return err
	}
	if config.CheckinMargin <= 0 {
		config.CheckinMargin = 5
	}
	if config.MaxRuntime <= 0 {
		config.MaxRuntime = 30
	}
	if config.Timezone == "" {
		config.Timezone = "UTC"
	}
	now := parseEventTime(checkin.Timestamp, time.Now().UTC())
	next := cronmon.Next(now, scheduleType, scheduleValue, config.Timezone)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	monitorID := uuid.NewString()
	err = tx.QueryRowContext(ctx, `
		INSERT INTO cron_monitors(id, project_id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, status, last_checkin_at, next_checkin_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, slug) DO UPDATE SET schedule_type = excluded.schedule_type, schedule_value = excluded.schedule_value, timezone = excluded.timezone, checkin_margin = excluded.checkin_margin, max_runtime = excluded.max_runtime, status = excluded.status, last_checkin_at = excluded.last_checkin_at, next_checkin_at = excluded.next_checkin_at
		RETURNING id
	`, monitorID, project.ID, checkin.MonitorSlug, checkin.MonitorSlug, scheduleType, scheduleValue, config.Timezone, config.CheckinMargin, config.MaxRuntime, checkin.Status, now.Format(time.RFC3339Nano), next.Format(time.RFC3339Nano)).Scan(&monitorID)
	if err != nil {
		return err
	}
	started := now
	var finished any
	if checkin.Status == "in_progress" {
		finished = nil
	} else {
		finished = now.Format(time.RFC3339Nano)
		if checkin.Duration != nil {
			started = now.Add(-time.Duration(*checkin.Duration * float64(time.Second)))
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO cron_checkins(id, checkin_id, monitor_id, status, duration, release, environment, started_at, finished_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(monitor_id, checkin_id) DO UPDATE SET status = excluded.status, duration = excluded.duration, release = excluded.release, environment = excluded.environment, finished_at = excluded.finished_at, payload = excluded.payload`, uuid.NewString(), checkin.CheckInID, monitorID, checkin.Status, checkin.Duration, checkin.Release, checkin.Environment, started.Format(time.RFC3339Nano), finished, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func normalizeReplayID(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	if len(value) != 32 {
		return ""
	}
	return value
}
