package replayissues

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/telemetry"
	"github.com/google/uuid"
)

type Project struct {
	ID             string
	OrganizationID string
}

type Segment struct {
	ReplayID    string
	SegmentID   int
	Environment string
	Release     string
	UserID      string
	URL         string
}

type Notification struct {
	Trigger string
	Payload map[string]any
}

type occurrence struct {
	IssueType string
	Selector  string
	Element   telemetry.ReplayElement
	Count     int
	Timestamp time.Time
}

type storedOccurrence struct {
	EventID string
	IssueID string
}

// SyncSegment turns classified Replay interactions into ordinary issue events.
// One event is kept for each issue type and selector in a Replay segment, so
// resending the same recording is idempotent while the issue groups aggregate
// occurrences across sessions.
func SyncSegment(ctx context.Context, tx *sql.Tx, project Project, segment Segment, clicks []telemetry.ReplayClick) ([]Notification, error) {
	desired := aggregate(clicks)
	existing, err := loadOccurrences(ctx, tx, project.ID, segment.ReplayID, segment.SegmentID)
	if err != nil {
		return nil, err
	}
	affectedIssues := make(map[string]struct{})
	for key, stored := range existing {
		if _, keep := desired[key]; keep {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE id = ?`, stored.EventID); err != nil {
			return nil, err
		}
		affectedIssues[stored.IssueID] = struct{}{}
		delete(existing, key)
	}
	if err := recalculateIssues(ctx, tx, affectedIssues); err != nil {
		return nil, err
	}
	if len(desired) == 0 {
		return nil, nil
	}

	releaseID, err := linkRelease(ctx, tx, project, segment.Release, earliestTimestamp(desired))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	notifications := make([]Notification, 0)
	for _, key := range keys {
		item := desired[key]
		timestamp := item.Timestamp.UTC().Format(time.RFC3339Nano)
		fingerprint := digest("replay-issue", item.IssueType, item.Selector)
		title := issueTitle(item.IssueType, item.Selector)
		eventExternalID := digest(project.ID, segment.ReplayID, fmt.Sprint(segment.SegmentID), item.IssueType, item.Selector)[:32]
		payload, err := eventPayload(eventExternalID, fingerprint, title, project.ID, segment, item)
		if err != nil {
			return nil, err
		}
		if stored, ok := existing[key]; ok {
			element, _ := json.Marshal(item.Element)
			if _, err := tx.ExecContext(ctx, `UPDATE replay_issue_occurrences SET element = ?, click_count = ?, timestamp = ? WHERE project_id = ? AND replay_id = ? AND segment_id = ? AND issue_type = ? AND dom_element = ?`, element, item.Count, timestamp, project.ID, segment.ReplayID, segment.SegmentID, item.IssueType, item.Selector); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE events SET release_id = ?, environment = ?, platform = 'javascript', level = 'warning', timestamp = ?, payload = ? WHERE id = ?`, nullable(releaseID), segment.Environment, timestamp, payload, stored.EventID); err != nil {
				return nil, err
			}
			affectedIssues[stored.IssueID] = struct{}{}
			continue
		}

		var discarded int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM discarded_issue_fingerprints WHERE project_id = ? AND fingerprint = ?`, project.ID, fingerprint).Scan(&discarded); err != nil {
			return nil, err
		}
		if discarded != 0 {
			continue
		}
		issueID, previousStatus, issueExists, err := upsertIssue(ctx, tx, project.ID, fingerprint, title, item.IssueType, releaseID, timestamp)
		if err != nil {
			return nil, err
		}
		eventInternalID := uuid.NewString()
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(id, event_id, project_id, issue_id, release_id, environment, platform, level, timestamp, payload) VALUES (?, ?, ?, ?, ?, ?, 'javascript', 'warning', ?, ?)`, eventInternalID, eventExternalID, project.ID, issueID, nullable(releaseID), segment.Environment, timestamp, payload); err != nil {
			return nil, err
		}
		element, _ := json.Marshal(item.Element)
		if _, err := tx.ExecContext(ctx, `INSERT INTO replay_issue_occurrences(project_id, replay_id, segment_id, issue_type, dom_element, element, click_count, timestamp, issue_id, event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, project.ID, segment.ReplayID, segment.SegmentID, item.IssueType, item.Selector, element, item.Count, timestamp, issueID, eventInternalID); err != nil {
			return nil, err
		}
		trigger := ""
		if !issueExists {
			trigger = "new_issue"
		} else if previousStatus == "resolved" {
			trigger = "regression"
		}
		if trigger != "" {
			notifications = append(notifications, Notification{Trigger: trigger, Payload: map[string]any{
				"title": title, "issue_id": issueID, "event_id": eventExternalID, "level": "warning", "trigger": trigger,
				"timestamp": timestamp, "environment": segment.Environment, "issue_type": item.IssueType,
				"replay_id": segment.ReplayID, "selector": item.Selector,
			}})
		}
	}
	if err := recalculateIssues(ctx, tx, affectedIssues); err != nil {
		return nil, err
	}
	return notifications, nil
}

// DeleteSessions removes synthetic Replay issue events before their Replay
// sessions are deleted, then repairs or removes the affected issue groups.
func DeleteSessions(ctx context.Context, tx *sql.Tx, projectID string, replayIDs []string) error {
	if len(replayIDs) == 0 {
		return nil
	}
	issues := make(map[string]struct{})
	for start := 0; start < len(replayIDs); start += 500 {
		end := min(start+500, len(replayIDs))
		batch := replayIDs[start:end]
		marks := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		arguments := make([]any, 0, len(batch)+1)
		arguments = append(arguments, projectID)
		for _, replayID := range batch {
			arguments = append(arguments, replayID)
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT issue_id, event_id FROM replay_issue_occurrences WHERE project_id = ? AND replay_id IN (`+marks+`)`, arguments...)
		if err != nil {
			return err
		}
		events := make([]string, 0)
		for rows.Next() {
			var issueID, eventID string
			if err := rows.Scan(&issueID, &eventID); err != nil {
				_ = rows.Close()
				return err
			}
			issues[issueID] = struct{}{}
			events = append(events, eventID)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, eventID := range events {
			if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE id = ?`, eventID); err != nil {
				return err
			}
		}
	}
	return recalculateIssues(ctx, tx, issues)
}

// RefreshSegmentMetadata handles envelopes where the recording reached the
// durable queue before its Replay event. It enriches already-created synthetic
// issue events without creating another occurrence.
func RefreshSegmentMetadata(ctx context.Context, tx *sql.Tx, project Project, segment Segment, seenAt string) error {
	releaseID, err := linkRelease(ctx, tx, project, segment.Release, seenAt)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT rio.event_id, rio.issue_id, e.payload FROM replay_issue_occurrences rio JOIN events e ON e.id = rio.event_id WHERE rio.project_id = ? AND rio.replay_id = ? AND rio.segment_id = ?`, project.ID, segment.ReplayID, segment.SegmentID)
	if err != nil {
		return err
	}
	type replayEvent struct {
		eventID, issueID string
		payload          []byte
	}
	events := make([]replayEvent, 0)
	for rows.Next() {
		var item replayEvent
		if err := rows.Scan(&item.eventID, &item.issueID, &item.payload); err != nil {
			_ = rows.Close()
			return err
		}
		events = append(events, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range events {
		payload := make(map[string]any)
		if err := json.Unmarshal(item.payload, &payload); err != nil {
			return err
		}
		payload["environment"], payload["release"] = segment.Environment, segment.Release
		contexts, _ := payload["contexts"].(map[string]any)
		if contexts == nil {
			contexts = make(map[string]any)
			payload["contexts"] = contexts
		}
		replay, _ := contexts["replay"].(map[string]any)
		if replay == nil {
			replay = make(map[string]any)
			contexts["replay"] = replay
		}
		replay["url"], replay["user_id"] = segment.URL, segment.UserID
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE events SET release_id = ?, environment = ?, payload = ? WHERE id = ?`, nullable(releaseID), segment.Environment, encoded, item.eventID); err != nil {
			return err
		}
		if releaseID != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE issues SET first_release_id = COALESCE(first_release_id, ?), last_release_id = ? WHERE id = ?`, releaseID, releaseID, item.issueID); err != nil {
				return err
			}
		}
	}
	return nil
}

func aggregate(clicks []telemetry.ReplayClick) map[string]occurrence {
	items := make(map[string]occurrence)
	for _, click := range clicks {
		for _, issueType := range []string{"dead_click", "rage_click"} {
			if issueType == "dead_click" && !click.Dead || issueType == "rage_click" && !click.Rage {
				continue
			}
			selector := strings.TrimSpace(click.DOMElement)
			if selector == "" {
				selector = "unknown"
			}
			key := issueType + "\x00" + selector
			item := items[key]
			item.IssueType, item.Selector, item.Element = issueType, selector, click.Element
			item.Count++
			clickedAt := time.UnixMilli(click.Timestamp).UTC()
			if item.Timestamp.IsZero() || clickedAt.Before(item.Timestamp) {
				item.Timestamp = clickedAt
			}
			items[key] = item
		}
	}
	return items
}

func loadOccurrences(ctx context.Context, tx *sql.Tx, projectID, replayID string, segmentID int) (map[string]storedOccurrence, error) {
	rows, err := tx.QueryContext(ctx, `SELECT issue_type, dom_element, event_id, issue_id FROM replay_issue_occurrences WHERE project_id = ? AND replay_id = ? AND segment_id = ?`, projectID, replayID, segmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make(map[string]storedOccurrence)
	for rows.Next() {
		var issueType, selector, eventID, issueID string
		if err := rows.Scan(&issueType, &selector, &eventID, &issueID); err != nil {
			return nil, err
		}
		items[issueType+"\x00"+selector] = storedOccurrence{EventID: eventID, IssueID: issueID}
	}
	return items, rows.Err()
}

func upsertIssue(ctx context.Context, tx *sql.Tx, projectID, fingerprint, title, issueType, releaseID, timestamp string) (string, string, bool, error) {
	issueID := uuid.NewString()
	previousStatus := ""
	exists := true
	err := tx.QueryRowContext(ctx, `SELECT id, status FROM issues WHERE project_id = ? AND fingerprint = ?`, projectID, fingerprint).Scan(&issueID, &previousStatus)
	if errors.Is(err, sql.ErrNoRows) {
		exists = false
		issueID = uuid.NewString()
	} else if err != nil {
		return "", "", false, err
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO issues(id, project_id, fingerprint, title, level, first_seen_at, last_seen_at, first_release_id, last_release_id, issue_type, issue_category)
		VALUES (?, ?, ?, ?, 'warning', ?, ?, ?, ?, ?, 'replay')
		ON CONFLICT(project_id, fingerprint) DO UPDATE SET
			title = excluded.title, level = excluded.level, last_seen_at = excluded.last_seen_at,
			last_release_id = COALESCE(excluded.last_release_id, issues.last_release_id),
			issue_type = excluded.issue_type, issue_category = excluded.issue_category,
			event_count = issues.event_count + 1,
			status = CASE WHEN issues.status = 'resolved' THEN 'unresolved' ELSE issues.status END
		RETURNING id
	`, issueID, projectID, fingerprint, title, timestamp, timestamp, nullable(releaseID), nullable(releaseID), issueType).Scan(&issueID)
	return issueID, previousStatus, exists, err
}

func recalculateIssues(ctx context.Context, tx *sql.Tx, issues map[string]struct{}) error {
	for issueID := range issues {
		if _, err := tx.ExecContext(ctx, `DELETE FROM issues WHERE id = ? AND NOT EXISTS (SELECT 1 FROM events e WHERE e.issue_id = issues.id)`, issueID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issues SET event_count = (SELECT COUNT(*) FROM events e WHERE e.issue_id = issues.id), first_seen_at = (SELECT MIN(timestamp) FROM events e WHERE e.issue_id = issues.id), last_seen_at = (SELECT MAX(timestamp) FROM events e WHERE e.issue_id = issues.id) WHERE id = ?`, issueID); err != nil {
			return err
		}
	}
	return nil
}

func linkRelease(ctx context.Context, tx *sql.Tx, project Project, version, seenAt string) (string, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return "", nil
	}
	releaseID := uuid.NewString()
	err := tx.QueryRowContext(ctx, `INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(organization_id, version) DO UPDATE SET last_seen_at = excluded.last_seen_at RETURNING id`, releaseID, project.OrganizationID, version, seenAt, seenAt).Scan(&releaseID)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, release_id) DO UPDATE SET last_seen_at = excluded.last_seen_at`, project.ID, releaseID, seenAt, seenAt)
	return releaseID, err
}

func eventPayload(eventID, fingerprint, title, projectID string, segment Segment, item occurrence) ([]byte, error) {
	return json.Marshal(map[string]any{
		"event_id": eventID, "message": title, "level": "warning", "platform": "javascript",
		"timestamp": item.Timestamp.UTC().Format(time.RFC3339Nano), "environment": segment.Environment,
		"release": segment.Release, "fingerprint": []string{fingerprint},
		"tags": map[string]string{"replay.issue_type": item.IssueType, "replay.id": segment.ReplayID, "replay.selector": item.Selector},
		"contexts": map[string]any{"replay": map[string]any{
			"type": "replay", "replay_id": segment.ReplayID, "segment_id": segment.SegmentID,
			"selector": item.Selector, "element": item.Element, "click_count": item.Count,
			"url": segment.URL, "user_id": segment.UserID, "project_id": projectID,
		}},
	})
}

func issueTitle(issueType, selector string) string {
	label := "Dead click"
	if issueType == "rage_click" {
		label = "Rage click"
	}
	return label + " on " + selector
}

func earliestTimestamp(items map[string]occurrence) string {
	earliest := time.Time{}
	for _, item := range items {
		if earliest.IsZero() || item.Timestamp.Before(earliest) {
			earliest = item.Timestamp
		}
	}
	return earliest.UTC().Format(time.RFC3339Nano)
}

func digest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
