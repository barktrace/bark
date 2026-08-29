package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/quota"
	"github.com/barktrace/bark/internal/symbolicate"
)

const (
	maxMinidumpMetadataBytes = 1 << 20
	maxMinidumpParts         = 32
)

type minidumpAttachment struct {
	filename, contentType, attachmentType string
	payload                               []byte
}

func (s *Service) Minidump(w http.ResponseWriter, r *http.Request, sentryProjectID string) {
	project, err := s.authenticateProject(r.Context(), r, sentryProjectID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid DSN key")
		return
	}
	if !s.allow(project.ID) {
		writeRateLimited(w)
		return
	}
	limit := s.maxEnvelopeBytes
	if limit <= 0 {
		limit = maxEventBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dump, metadata, attachments, err := readMinidumpRequest(r, limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	decision, err := quota.Check(r.Context(), s.store.DB, project.ID, "error", int64(len(dump)), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check project quota")
		return
	}
	if !decision.Allowed {
		if decision.Reason == "item_size" {
			writeError(w, http.StatusRequestEntityTooLarge, "minidump exceeds category size quota")
		} else {
			writeCategoryRateLimited(w, "error", decision.RetryAfter)
		}
		return
	}
	dumpDecision, err := quota.Check(r.Context(), s.store.DB, project.ID, "attachment", int64(len(dump)), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check minidump attachment quota")
		return
	}
	if !dumpDecision.Allowed {
		if dumpDecision.Reason == "item_size" {
			writeError(w, http.StatusRequestEntityTooLarge, "minidump exceeds attachment size quota")
		} else {
			writeCategoryRateLimited(w, "attachment", dumpDecision.RetryAfter)
		}
		return
	}
	event, err := symbolicate.MinidumpEvent(r.Context(), s.store, project.ID, dump, metadata)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var eventHeader struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(event, &eventHeader)
	result, processingErr := s.enqueueAndProcess(r.Context(), project, itemHeader{Type: "event", Length: int64(len(event)), ContentType: "application/json"}, eventHeader.EventID, "", "", event)
	if processingErr != nil && !result.Queued {
		writeError(w, http.StatusServiceUnavailable, "could not persist minidump event")
		return
	}
	eventID := firstNonEmpty(result.ID, eventHeader.EventID)
	attachments = append([]minidumpAttachment{{filename: "upload_file_minidump", contentType: "application/octet-stream", attachmentType: "event.minidump", payload: dump}}, attachments...)
	for index, attachment := range attachments {
		if index > 0 {
			attachmentDecision, quotaErr := quota.Check(r.Context(), s.store.DB, project.ID, "attachment", int64(len(attachment.payload)), time.Now().UTC())
			if quotaErr != nil || !attachmentDecision.Allowed {
				continue
			}
		}
		attachmentResult, attachmentErr := s.enqueueAndProcess(r.Context(), project, itemHeader{
			Type: "attachment", Length: int64(len(attachment.payload)), Filename: attachment.filename,
			ContentType: attachment.contentType, AttachmentType: attachment.attachmentType,
		}, eventID, "", eventID, attachment.payload)
		if index == 0 && attachmentErr != nil && !attachmentResult.Queued {
			writeError(w, http.StatusServiceUnavailable, "could not persist minidump attachment")
			return
		}
	}
	if result.JobID != "" {
		w.Header().Set("X-Barktrace-Ingestion-Job", result.JobID)
	}
	writeJSON(w, http.StatusOK, Result{ID: eventID})
}

func readMinidumpRequest(r *http.Request, limit int64) ([]byte, []byte, []minidumpAttachment, error) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(mediaType, "multipart/") {
		dump, err := io.ReadAll(r.Body)
		if err != nil || len(dump) == 0 {
			return nil, nil, nil, errors.New("minidump body is missing or too large")
		}
		return dump, nil, nil, nil
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, nil, nil, errors.New("invalid minidump multipart request")
	}
	var dump, metadata []byte
	attachments := make([]minidumpAttachment, 0)
	for parts := 0; parts < maxMinidumpParts; parts++ {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nil, nil, errors.New("invalid minidump multipart body")
		}
		name := part.FormName()
		partLimit := limit
		if name == "sentry" || name == "event" || name == "event_payload" {
			partLimit = maxMinidumpMetadataBytes
		}
		payload, readErr := io.ReadAll(io.LimitReader(part, partLimit+1))
		_ = part.Close()
		if readErr != nil || int64(len(payload)) > partLimit {
			return nil, nil, nil, errors.New("minidump multipart field is too large")
		}
		switch name {
		case "upload_file_minidump", "minidump":
			dump = payload
		case "sentry", "event", "event_payload":
			metadata = payload
		default:
			if filename := strings.TrimSpace(part.FileName()); filename != "" && len(payload) > 0 {
				attachments = append(attachments, minidumpAttachment{filename: filename, contentType: part.Header.Get("Content-Type"), attachmentType: "event.attachment", payload: payload})
			}
		}
	}
	if len(dump) == 0 {
		return nil, nil, nil, errors.New("minidump multipart field is missing")
	}
	return dump, metadata, attachments, nil
}
