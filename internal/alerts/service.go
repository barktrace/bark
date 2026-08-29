package alerts

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/config"
	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store  *store.Store
	client *http.Client
	smtp   config.SMTP
}

type delivery struct {
	id, ruleID, destinationType, destinationURL, destinationEmail, eventType string
	payload                                                                  []byte
	attempts                                                                 int
}

func New(st *store.Store, smtpConfig ...config.SMTP) *Service {
	var smtpSettings config.SMTP
	if len(smtpConfig) > 0 {
		smtpSettings = smtpConfig[0]
	}
	return &Service{store: st, client: &http.Client{Timeout: 10 * time.Second}, smtp: smtpSettings}
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

func (s *Service) DeliverPending(ctx context.Context) { s.deliverPending(ctx) }

func Queue(ctx context.Context, db *sql.DB, projectID, eventType string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var values map[string]any
	_ = json.Unmarshal(encoded, &values)
	rows, err := db.QueryContext(ctx, `SELECT id, conditions, frequency_minutes FROM alert_rules WHERE project_id = ? AND trigger = ? AND enabled = 1`, projectID, eventType)
	if err != nil {
		return err
	}
	type rule struct {
		id, conditions string
		frequency      int
	}
	rules := make([]rule, 0)
	for rows.Next() {
		var item rule
		if err := rows.Scan(&item.id, &item.conditions, &item.frequency); err == nil && matchesConditions(item.conditions, values) {
			rules = append(rules, item)
		}
	}
	_ = rows.Close()
	for _, item := range rules {
		if item.frequency > 0 {
			var recent int
			cutoff := time.Now().UTC().Add(-time.Duration(item.frequency) * time.Minute).Format(time.RFC3339Nano)
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_deliveries WHERE rule_id = ? AND status IN ('pending', 'sent') AND datetime(created_at) >= datetime(?)`, item.id, cutoff).Scan(&recent); err != nil {
				return err
			}
			if recent > 0 {
				continue
			}
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO alert_deliveries(id, rule_id, event_type, payload, status) VALUES (?, ?, ?, ?, 'pending')`, uuid.NewString(), item.id, eventType, encoded); err != nil {
			return err
		}
	}
	return nil
}

func ValidateDestination(kind, raw string) error {
	if kind == "email" {
		address, err := mail.ParseAddress(strings.TrimSpace(raw))
		if err != nil || address.Address != strings.TrimSpace(raw) {
			return errors.New("destination must be a valid email address")
		}
		return nil
	}
	if kind != "webhook" && kind != "slack" {
		return errors.New("destination type must be webhook, slack, or email")
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("destination must be an HTTPS URL without credentials")
	}
	return nil
}

func (s *Service) deliverPending(ctx context.Context) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT d.id, d.rule_id, r.destination_type, r.destination_url, r.destination_email, d.event_type, d.payload, d.attempts
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
		if err := rows.Scan(&item.id, &item.ruleID, &item.destinationType, &item.destinationURL, &item.destinationEmail, &item.eventType, &item.payload, &item.attempts); err == nil {
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
	destination := item.destinationURL
	if item.destinationType == "email" {
		destination = item.destinationEmail
	}
	if err := ValidateDestination(item.destinationType, destination); err != nil {
		return err
	}
	if item.destinationType == "email" {
		return s.deliverEmail(item)
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

func matchesConditions(raw string, payload map[string]any) bool {
	var conditions struct {
		Environment string   `json:"environment"`
		Levels      []string `json:"levels"`
		MetricName  string   `json:"metric_name"`
		MinValue    *float64 `json:"min_value"`
		MaxValue    *float64 `json:"max_value"`
	}
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &conditions) != nil {
		return true
	}
	if conditions.Environment != "" && !strings.EqualFold(stringField(payload, "environment"), conditions.Environment) {
		return false
	}
	if len(conditions.Levels) > 0 {
		level := strings.ToLower(stringField(payload, "level"))
		matched := false
		for _, allowed := range conditions.Levels {
			matched = matched || strings.EqualFold(level, allowed)
		}
		if !matched {
			return false
		}
	}
	if conditions.MetricName != "" && stringField(payload, "metric_name") != conditions.MetricName {
		return false
	}
	value, hasValue := numberField(payload, "value")
	if conditions.MinValue != nil && (!hasValue || value < *conditions.MinValue) {
		return false
	}
	if conditions.MaxValue != nil && (!hasValue || value > *conditions.MaxValue) {
		return false
	}
	return true
}

func (s *Service) deliverEmail(item delivery) error {
	if s.smtp.Host == "" || s.smtp.From == "" {
		return errors.New("SMTP is not configured")
	}
	subject := "Barktrace alert: " + item.eventType
	var payload map[string]any
	if json.Unmarshal(item.payload, &payload) == nil {
		if title := stringField(payload, "title"); title != "" {
			subject = title
		}
	}
	subject = strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	message := []byte("From: " + s.smtp.From + "\r\nTo: " + item.destinationEmail + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" + string(item.payload))
	address := net.JoinHostPort(s.smtp.Host, strconv.Itoa(s.smtp.Port))
	tlsConfig := &tls.Config{ServerName: s.smtp.Host, MinVersion: tls.VersionTLS12}
	var client *smtp.Client
	var err error
	if s.smtp.TLSMode == "tls" {
		connection, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, tlsConfig)
		if dialErr != nil {
			return dialErr
		}
		client, err = smtp.NewClient(connection, s.smtp.Host)
	} else {
		connection, dialErr := net.DialTimeout("tcp", address, 10*time.Second)
		if dialErr != nil {
			return dialErr
		}
		client, err = smtp.NewClient(connection, s.smtp.Host)
	}
	if err != nil {
		return err
	}
	defer client.Close()
	if s.smtp.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if s.smtp.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.smtp.Username, s.smtp.Password, s.smtp.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(s.smtp.From); err != nil {
		return err
	}
	if err := client.Rcpt(item.destinationEmail); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func stringField(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func numberField(values map[string]any, key string) (float64, bool) {
	value, ok := values[key].(float64)
	return value, ok
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
