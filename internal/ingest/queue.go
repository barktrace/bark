package ingest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/blobstore"
	"github.com/google/uuid"
)

const (
	ingestionLease = 2 * time.Minute
	maxJobAttempts = 5
)

type queuedItemHeaders struct {
	Item             itemHeader `json:"item"`
	EnvelopeReplayID string     `json:"envelope_replay_id,omitempty"`
	AcceptedEventID  string     `json:"accepted_event_id,omitempty"`
}

type durableResult struct {
	ID     string
	JobID  string
	Count  int
	Queued bool
}

type claimedJob struct {
	ID              string
	Project         Project
	BlobID          string
	StorageKey      string
	Category        string
	EnvelopeEventID string
	Headers         queuedItemHeaders
}

// Run processes queued ingestion payloads serially. The single worker keeps
// memory usage bounded; leases make jobs recoverable when the process exits
// after claiming an item but before marking it complete.
func (s *Service) Run(ctx context.Context) {
	workerID := uuid.NewString()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for processed := 0; processed < 25; processed++ {
			didWork, err := s.runQueuedJob(ctx, workerID, time.Now().UTC())
			if err != nil {
				slog.Error("process ingestion queue", "error", err)
				break
			}
			if !didWork {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) enqueueAndProcess(ctx context.Context, project Project, item itemHeader, envelopeEventID, envelopeReplayID, acceptedEventID string, payload []byte) (durableResult, error) {
	headers, err := json.Marshal(queuedItemHeaders{Item: item, EnvelopeReplayID: envelopeReplayID, AcceptedEventID: acceptedEventID})
	if err != nil {
		return durableResult{}, err
	}
	stored, err := s.store.Blobs.Put(bytes.NewReader(payload), blobstore.MaxBlobBytes)
	if err != nil {
		return durableResult{}, fmt.Errorf("persist ingestion payload: %w", err)
	}
	jobID, blobID := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.removePhysicalBlobIfUnreferenced(context.Background(), stored.Key)
		return durableResult{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, 'ingestion', ?, ?, ?, ?)`, blobID, project.OrganizationID, project.ID, stored.Key, stored.Checksum, stored.Size, firstNonEmpty(item.ContentType, "application/octet-stream")); err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO ingestion_jobs(id, project_id, blob_id, category, envelope_event_id, item_headers, status, attempts, lease_expires_at, worker_id) VALUES (?, ?, ?, ?, ?, ?, 'processing', 1, ?, ?)`, jobID, project.ID, blobID, item.Type, envelopeEventID, headers, now.Add(ingestionLease).Format(time.RFC3339Nano), "request-"+uuid.NewString())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.removePhysicalBlobIfUnreferenced(context.Background(), stored.Key)
		return durableResult{}, fmt.Errorf("enqueue ingestion item: %w", err)
	}

	result := durableResult{JobID: jobID, Queued: true}
	result.ID, result.Count, err = s.processItem(ctx, project, item, envelopeEventID, envelopeReplayID, acceptedEventID, payload)
	if err != nil {
		if updateErr := s.failJob(ctx, jobID, err, now); updateErr != nil {
			return result, errors.Join(err, updateErr)
		}
		return result, err
	}
	if err := s.completeJob(ctx, jobID, now); err != nil {
		return result, fmt.Errorf("complete ingestion job: %w", err)
	}
	return result, nil
}

func (s *Service) processItem(ctx context.Context, project Project, item itemHeader, envelopeEventID, envelopeReplayID, acceptedEventID string, payload []byte) (string, int, error) {
	switch item.Type {
	case "event", "security":
		id, err := s.StoreEvent(ctx, project, payload, envelopeEventID)
		return id, 1, err
	case "transaction":
		id, err := s.StoreTransaction(ctx, project, payload, envelopeEventID)
		return id, 1, err
	case "log", "logs":
		count, err := s.StoreLogs(ctx, project, payload)
		return "", count, err
	case "session":
		return "", 1, s.StoreSession(ctx, project, payload)
	case "span", "spans":
		count, err := s.StoreSpans(ctx, project, payload)
		return "", count, err
	case "check_in":
		return "", 1, s.StoreCheckIn(ctx, project, payload)
	case "attachment":
		return "", 1, s.StoreAttachment(ctx, project, firstNonEmpty(envelopeEventID, acceptedEventID), item.Filename, item.ContentType, item.AttachmentType, payload)
	case "user_report", "feedback":
		return "", 1, s.StoreFeedback(ctx, project, payload)
	case "replay_event":
		return "", 1, s.StoreReplayEvent(ctx, project, payload)
	case "replay_recording":
		return "", 1, s.StoreReplayRecording(ctx, project, firstNonEmpty(envelopeReplayID, envelopeEventID), payload)
	case "profile", "profile_chunk":
		return "", 1, s.StoreProfile(ctx, project, payload)
	case "metric_buckets", "metrics", "statsd":
		count, err := s.StoreMetrics(ctx, project, payload)
		return "", count, err
	case "client_report":
		return "", 1, s.StoreClientReport(ctx, project, payload)
	default:
		_, err := s.store.DB.ExecContext(ctx, `INSERT INTO ingestion_outcomes(project_id, category, outcome, reason) VALUES (?, ?, 'accepted', 'processor pending')`, project.ID, item.Type)
		return "", 0, err
	}
}

func (s *Service) runQueuedJob(ctx context.Context, workerID string, now time.Time) (bool, error) {
	job, err := s.claimJob(ctx, workerID, now)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file, err := s.store.Blobs.Open(job.StorageKey)
	if err == nil {
		defer file.Close()
		var payload []byte
		payload, err = io.ReadAll(io.LimitReader(file, blobstore.MaxBlobBytes+1))
		if err == nil && int64(len(payload)) > blobstore.MaxBlobBytes {
			err = errors.New("queued payload exceeds blob limit")
		}
		if err == nil {
			_, _, err = s.processItem(ctx, job.Project, job.Headers.Item, job.EnvelopeEventID, job.Headers.EnvelopeReplayID, job.Headers.AcceptedEventID, payload)
		}
	}
	if err != nil {
		if failErr := s.failJob(ctx, job.ID, err, now); failErr != nil {
			return true, errors.Join(err, failErr)
		}
		return true, nil
	}
	return true, s.completeJob(ctx, job.ID, now)
}

func (s *Service) claimJob(ctx context.Context, workerID string, now time.Time) (claimedJob, error) {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return claimedJob{}, err
	}
	defer tx.Rollback()
	var job claimedJob
	var rawHeaders []byte
	err = tx.QueryRowContext(ctx, `
		SELECT j.id, j.project_id, p.organization_id, p.public_key, j.blob_id, b.storage_key, j.category, j.envelope_event_id, j.item_headers
		FROM ingestion_jobs j
		JOIN projects p ON p.id = j.project_id
		JOIN blobs b ON b.id = j.blob_id
		WHERE (j.status = 'pending' AND j.available_at <= ?)
		   OR (j.status = 'processing' AND j.lease_expires_at <= ?)
		ORDER BY j.created_at, j.id
		LIMIT 1
	`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Scan(&job.ID, &job.Project.ID, &job.Project.OrganizationID, &job.Project.PublicKey, &job.BlobID, &job.StorageKey, &job.Category, &job.EnvelopeEventID, &rawHeaders)
	if err != nil {
		return claimedJob{}, err
	}
	if err := json.Unmarshal(rawHeaders, &job.Headers); err != nil {
		return claimedJob{}, fmt.Errorf("decode queued headers: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'processing', attempts = attempts + 1, worker_id = ?, lease_expires_at = ?, last_error = ''
		WHERE id = ? AND ((status = 'pending' AND available_at <= ?) OR (status = 'processing' AND lease_expires_at <= ?))
	`, workerID, now.Add(ingestionLease).Format(time.RFC3339Nano), job.ID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return claimedJob{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return claimedJob{}, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return claimedJob{}, err
	}
	return job, nil
}

func (s *Service) failJob(ctx context.Context, jobID string, processingErr error, now time.Time) error {
	message := strings.TrimSpace(processingErr.Error())
	if len(message) > 2000 {
		message = message[:2000]
	}
	var attempts int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT attempts FROM ingestion_jobs WHERE id = ?`, jobID).Scan(&attempts); err != nil {
		return err
	}
	if attempts >= maxJobAttempts {
		_, err := s.store.DB.ExecContext(ctx, `UPDATE ingestion_jobs SET status = 'dead', lease_expires_at = NULL, worker_id = '', last_error = ?, processed_at = ? WHERE id = ?`, message, now.Format(time.RFC3339Nano), jobID)
		if err == nil {
			slog.Warn("ingestion job exhausted retries", "job_id", jobID, "attempts", attempts, "error", message)
		}
		return err
	}
	delay := retryDelay(attempts)
	_, err := s.store.DB.ExecContext(ctx, `UPDATE ingestion_jobs SET status = 'pending', available_at = ?, lease_expires_at = NULL, worker_id = '', last_error = ? WHERE id = ?`, now.Add(delay).Format(time.RFC3339Nano), message, jobID)
	return err
}

func retryDelay(attempts int) time.Duration {
	switch attempts {
	case 0, 1:
		return time.Second
	case 2:
		return 5 * time.Second
	case 3:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func (s *Service) completeJob(ctx context.Context, jobID string, now time.Time) error {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var blobID, storageKey string
	if err := tx.QueryRowContext(ctx, `SELECT j.blob_id, b.storage_key FROM ingestion_jobs j JOIN blobs b ON b.id = j.blob_id WHERE j.id = ?`, jobID).Scan(&blobID, &storageKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ingestion_jobs SET status = 'done', blob_id = NULL, lease_expires_at = NULL, worker_id = '', last_error = '', processed_at = ? WHERE id = ?`, now.Format(time.RFC3339Nano), jobID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removePhysicalBlobIfUnreferenced(context.Background(), storageKey)
	return nil
}

func (s *Service) removePhysicalBlobIfUnreferenced(ctx context.Context, storageKey string) {
	var references int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, storageKey).Scan(&references); err == nil && references == 0 {
		if err := s.store.Blobs.Remove(storageKey); err != nil {
			slog.Warn("remove unreferenced ingestion blob", "key", storageKey, "error", err)
		}
	}
}

// RetryJob makes a dead-letter item immediately available to the worker.
func (s *Service) RetryJob(ctx context.Context, jobID string) error {
	result, err := s.store.DB.ExecContext(ctx, `UPDATE ingestion_jobs SET status = 'pending', attempts = 0, available_at = ?, lease_expires_at = NULL, worker_id = '', last_error = '', processed_at = NULL WHERE id = ? AND status = 'dead'`, time.Now().UTC().Format(time.RFC3339Nano), jobID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteJob removes a completed or dead-letter job and its unreferenced payload.
func (s *Service) DeleteJob(ctx context.Context, jobID string) error {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var blobID sql.NullString
	var storageKey sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT j.blob_id, b.storage_key FROM ingestion_jobs j LEFT JOIN blobs b ON b.id = j.blob_id WHERE j.id = ? AND j.status IN ('done', 'dead')`, jobID).Scan(&blobID, &storageKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ingestion_jobs WHERE id = ?`, jobID); err != nil {
		return err
	}
	if blobID.Valid {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID.String); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if storageKey.Valid {
		s.removePhysicalBlobIfUnreferenced(context.Background(), storageKey.String)
	}
	return nil
}
