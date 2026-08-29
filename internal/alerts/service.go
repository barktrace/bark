package alerts

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store  *store.Store
	client *http.Client
}

type delivery struct {
	id, ruleID, destinationType, destinationURL, eventType string
	payload                                                []byte
	attempts                                               int
}

func New(st *store.Store) *Service {
	return &Service{store: st, client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deliverPending(ctx)
		}
	}
}

func Queue(ctx context.Context, db *sql.DB, projectID, eventType string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM alert_rules WHERE project_id = ? AND trigger = ? AND enabled = 1`, projectID, eventType)
	if err != nil {
		return err
	}
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ruleIDs = append(ruleIDs, id)
		}
	}
	_ = rows.Close()
	for _, ruleID := range ruleIDs {
		if _, err := db.ExecContext(ctx, `INSERT INTO alert_deliveries(id, rule_id, event_type, payload, status) VALUES (?, ?, ?, ?, 'pending')`, uuid.NewString(), ruleID, eventType, encoded); err != nil {
			return err
		}
	}
	return nil
}

func ValidateDestination(kind, raw string) error {
	if kind != "webhook" && kind != "slack" {
		return errors.New("destination type must be webhook or slack")
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("destination must be an HTTPS URL without credentials")
	}
	return nil
}

func (s *Service) deliverPending(ctx context.Context) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT d.id, d.rule_id, r.destination_type, r.destination_url, d.event_type, d.payload, d.attempts
		FROM alert_deliveries d JOIN alert_rules r ON r.id = d.rule_id
		WHERE d.status = 'pending' ORDER BY d.created_at LIMIT 10
	`)
	if err != nil {
		slog.Error("load pending alerts", "error", err)
		return
	}
	items := make([]delivery, 0)
	for rows.Next() {
		var item delivery
		if err := rows.Scan(&item.id, &item.ruleID, &item.destinationType, &item.destinationURL, &item.eventType, &item.payload, &item.attempts); err == nil {
			items = append(items, item)
		}
	}
	_ = rows.Close()
	for _, item := range items {
		if err := s.deliver(ctx, item); err != nil {
			status := "pending"
			if item.attempts >= 2 {
				status = "failed"
			}
			_, _ = s.store.DB.ExecContext(ctx, `UPDATE alert_deliveries SET attempts = attempts + 1, status = ?, last_error = ? WHERE id = ?`, status, truncate(err.Error(), 500), item.id)
			continue
		}
		_, _ = s.store.DB.ExecContext(ctx, `UPDATE alert_deliveries SET attempts = attempts + 1, status = 'sent', last_error = '', delivered_at = CURRENT_TIMESTAMP WHERE id = ?`, item.id)
	}
}

func (s *Service) deliver(ctx context.Context, item delivery) error {
	if err := ValidateDestination(item.destinationType, item.destinationURL); err != nil {
		return err
	}
	body := item.payload
	if item.destinationType == "slack" {
		var payload map[string]any
		_ = json.Unmarshal(item.payload, &payload)
		title, _ := payload["title"].(string)
		if title == "" {
			title = "Barktrace alert: " + item.eventType
		}
		body, _ = json.Marshal(map[string]any{"text": title, "attachments": []any{map[string]any{"color": "#b7e34b", "text": string(item.payload)}}})
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, item.destinationURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Barktrace-Alerts/1.0")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("destination returned HTTP %d", response.StatusCode)
	}
	return nil
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
