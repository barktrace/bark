package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/ingest"
	"github.com/barktrace/bark/internal/maintenance"
)

func TestSentryReplaySearchCorrelationSegmentsAndDelete(t *testing.T) {
	server, principal := managementFixture(t)
	const eventID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const replayID = "12121212121212121212121212121212"
	if _, err := server.store.DB.Exec(`INSERT INTO events(id, event_id, project_id, issue_id, timestamp, received_at, payload) VALUES ('event', ?, 'project', 'issue', '2026-08-29T10:04:00Z', '2026-08-29T10:04:00Z', '{}')`, eventID); err != nil {
		t.Fatal(err)
	}
	service := ingest.New(server.store, 20<<20)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}
	if err := service.StoreReplayEvent(context.Background(), project, []byte(`{"replay_id":"`+replayID+`","segment_id":0,"timestamp":"2026-08-29T10:05:00Z","replay_start_timestamp":"2026-08-29T10:00:00Z","environment":"production","release":"app@1.0","urls":["https://example.com/checkout"],"user":{"id":"customer-1"},"error_ids":["`+eventID+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if err := service.StoreReplayRecording(context.Background(), project, replayID, []byte(`{"replay_id":"`+replayID+`","segment_id":0}`+"\n"+`[{"type":2,"timestamp":1787997600000,"data":{"node":{"type":0,"id":1,"childNodes":[{"type":2,"id":42,"tagName":"button","attributes":{"id":"checkout","class":"primary"},"childNodes":[]}]}}},{"type":3,"timestamp":1787997600200,"data":{"source":2,"type":2,"id":42}},{"type":3,"timestamp":1787997600500,"data":{"source":2,"type":2,"id":42}},{"type":3,"timestamp":1787997600900,"data":{"source":2,"type":2,"id":42}},{"type":3,"timestamp":1787997601000,"data":{"source":0,"adds":[],"removes":[],"texts":[],"attributes":[]}}]`)); err != nil {
		t.Fatal(err)
	}
	var replayIssueID, replayIssueType, replayIssueCategory string
	var replayIssueEvents int
	if err := server.store.DB.QueryRow(`SELECT id, issue_type, issue_category, event_count FROM issues WHERE issue_type = 'rage_click'`).Scan(&replayIssueID, &replayIssueType, &replayIssueCategory, &replayIssueEvents); err != nil {
		t.Fatal(err)
	}
	if replayIssueType != "rage_click" || replayIssueCategory != "replay" || replayIssueEvents != 1 {
		t.Fatalf("Replay issue type=%s category=%s events=%d", replayIssueType, replayIssueCategory, replayIssueEvents)
	}
	nativeIssue := principalRequest(t, principal, http.MethodGet, "/issues/"+replayIssueID, "")
	nativeIssue.SetPathValue("issue_id", replayIssueID)
	response := httptest.NewRecorder()
	server.issueDetail(response, nativeIssue)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"issue_type":"rage_click"`, `"issue_category":"replay"`, `"replay_id":"`+replayID+`"`) {
		t.Fatalf("native Replay issue status=%d body=%s", response.Code, response.Body.String())
	}
	var replayLegacyIssueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = ?`, replayIssueID).Scan(&replayLegacyIssueID); err != nil {
		t.Fatal(err)
	}
	sentryIssue := principalRequest(t, principal, http.MethodGet, "/api/0/issues/"+strconv.FormatInt(replayLegacyIssueID, 10)+"/", "")
	sentryIssue.SetPathValue("issue_id", strconv.FormatInt(replayLegacyIssueID, 10))
	response = httptest.NewRecorder()
	server.sentryIssueDetail(response, sentryIssue)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"issueType":"rage_click"`, `"issueCategory":"replay"`) {
		t.Fatalf("Sentry Replay issue status=%d body=%s", response.Code, response.Body.String())
	}
	var legacyIssueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&legacyIssueID); err != nil {
		t.Fatal(err)
	}
	native := principalRequest(t, principal, http.MethodGet, "/replays?project_id=project&environment=production&q=checkout&has_error=true&issue_id="+strconv.FormatInt(legacyIssueID, 10), "")
	response = httptest.NewRecorder()
	server.replays(response, native)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"replay_id":"`+replayID+`"`, `"environment":"production"`, `"error_count":1`) {
		t.Fatalf("native replay search status=%d body=%s", response.Code, response.Body.String())
	}

	request := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replays/?project=1&query=environment:production+issue:"+strconv.FormatInt(legacyIssueID, 10), "")
	request.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryOrganizationReplays(response, request)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"replayId":"`+replayID+`"`, `"title":"Boom"`, `"title":"Rage click on button#checkout.primary"`, `"error_ids":["`+eventID+`"]`, `"count_segments":1`, `"hasRecording":true`) {
		t.Fatalf("replay search status=%d body=%s", response.Code, response.Body.String())
	}

	detail := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replays/"+replayID+"/", "")
	detail.SetPathValue("org_slug", "org")
	detail.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplayDetail(response, detail)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"data":{`, `"duration":300`, `"count_errors":1`, `"count_rage_clicks":3`, `"count_dead_clicks":0`, `"releases":["app@1.0"]`) {
		t.Fatalf("replay detail status=%d body=%s", response.Code, response.Body.String())
	}
	viewers := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/"+replayID+"/viewed-by/", "")
	viewers.SetPathValue("org_slug", "org")
	viewers.SetPathValue("project_slug", "app")
	viewers.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplayViewedBy(response, viewers)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"viewed_by":[`, `"email":"user@example.com"`) {
		t.Fatalf("replay viewers status=%d body=%s", response.Code, response.Body.String())
	}

	segments := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/"+replayID+"/recording-segments/", "")
	segments.SetPathValue("org_slug", "org")
	segments.SetPathValue("project_slug", "app")
	segments.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplaySegments(response, segments)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `[[{"type":2,`, `"id":42`) {
		t.Fatalf("replay segments status=%d body=%s", response.Code, response.Body.String())
	}
	segment := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/"+replayID+"/recording-segments/0/", "")
	segment.SetPathValue("org_slug", "org")
	segment.SetPathValue("project_slug", "app")
	segment.SetPathValue("replay_id", replayID)
	segment.SetPathValue("segment_id", "0")
	response = httptest.NewRecorder()
	server.sentryReplaySegments(response, segment)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"replayId":"`+replayID+`"`, `"segmentId":0`, `"projectId":"1"`) {
		t.Fatalf("replay segment status=%d body=%s", response.Code, response.Body.String())
	}
	clicks := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/"+replayID+"/clicks/", "")
	clicks.SetPathValue("org_slug", "org")
	clicks.SetPathValue("project_slug", "app")
	clicks.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplayClicks(response, clicks)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"node_id":42`, `"timestamp":"2026-08-29T10:00:00.2Z"`) {
		t.Fatalf("replay clicks status=%d body=%s", response.Code, response.Body.String())
	}
	selectors := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replay-selectors/?project=1&environment=production", "")
	selectors.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryReplaySelectors(response, selectors)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"dom_element":"button#checkout.primary"`, `"count_rage_clicks":3`, `"project_id":"1"`) {
		t.Fatalf("replay selectors status=%d body=%s", response.Code, response.Body.String())
	}
	count := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replay-count/?data_source=events", "")
	count.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryReplayCount(response, count)
	if response.Code != http.StatusOK || response.Body.String() != "{\"1\":1}\n" {
		t.Fatalf("replay count status=%d body=%s", response.Code, response.Body.String())
	}

	var beforeBlobs int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM blobs`).Scan(&beforeBlobs)
	if beforeBlobs != 2 {
		t.Fatalf("blob count before delete=%d", beforeBlobs)
	}
	remove := principalRequest(t, principal, http.MethodDelete, "/api/0/projects/org/app/replays/"+replayID+"/", "")
	remove.SetPathValue("org_slug", "org")
	remove.SetPathValue("project_slug", "app")
	remove.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplayDetail(response, remove)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete replay status=%d body=%s", response.Code, response.Body.String())
	}
	for table, want := range map[string]int{"replays": 0, "replay_error_links": 0, "replay_views": 0, "replay_clicks": 0, "blobs": 0, "blob_deletion_queue": 0} {
		var got int
		if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}
	var remainingEvents, remainingIssues, occurrences int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&remainingEvents)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&remainingIssues)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM replay_issue_occurrences`).Scan(&occurrences)
	if remainingEvents != 1 || remainingIssues != 1 || occurrences != 0 {
		t.Fatalf("after Replay delete events=%d issues=%d occurrences=%d", remainingEvents, remainingIssues, occurrences)
	}
	var audits int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'delete_replay' AND target_id = ?`, replayID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("delete replay audits=%d err=%v", audits, err)
	}
}

func TestSentryReplayDeletionJobIsDurableAndFiltered(t *testing.T) {
	server, principal := managementFixture(t)
	service := ingest.New(server.store, 20<<20)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}
	for _, replay := range []struct {
		id, environment string
	}{
		{"11111111111111111111111111111111", "production"},
		{"22222222222222222222222222222222", "staging"},
	} {
		payload := `{"replay_id":"` + replay.id + `","segment_id":0,"timestamp":"2026-08-29T10:05:00Z","replay_start_timestamp":"2026-08-29T10:00:00Z","environment":"` + replay.environment + `","urls":["https://example.com/checkout"]}`
		if err := service.StoreReplayEvent(context.Background(), project, []byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.store.DB.Exec(`
		INSERT INTO replay_views(project_id, replay_id, user_id) VALUES ('project', '11111111111111111111111111111111', ?), ('project', '22222222222222222222222222222222', ?);
		INSERT INTO replay_clicks(project_id, replay_id, segment_id, sequence, node_id, timestamp, dom_element, element, is_dead) VALUES
			('project', '11111111111111111111111111111111', 0, 0, 1, '2026-08-29T10:01:00Z', 'button.production', '{}', 1),
			('project', '22222222222222222222222222222222', 0, 0, 2, '2026-08-29T10:01:00Z', 'button.staging', '{}', 1);
		INSERT INTO issues(id, project_id, fingerprint, title, level, first_seen_at, last_seen_at, issue_type, issue_category) VALUES
			('production-replay-issue', 'project', 'production-replay-fingerprint', 'Dead click production', 'warning', '2026-08-29T10:01:00Z', '2026-08-29T10:01:00Z', 'dead_click', 'replay'),
			('staging-replay-issue', 'project', 'staging-replay-fingerprint', 'Dead click staging', 'warning', '2026-08-29T10:01:00Z', '2026-08-29T10:01:00Z', 'dead_click', 'replay');
		INSERT INTO events(id, event_id, project_id, issue_id, environment, level, timestamp, payload) VALUES
			('production-replay-event', '33333333333333333333333333333333', 'project', 'production-replay-issue', 'production', 'warning', '2026-08-29T10:01:00Z', '{}'),
			('staging-replay-event', '44444444444444444444444444444444', 'project', 'staging-replay-issue', 'staging', 'warning', '2026-08-29T10:01:00Z', '{}');
		INSERT INTO replay_issue_occurrences(project_id, replay_id, segment_id, issue_type, dom_element, timestamp, issue_id, event_id) VALUES
			('project', '11111111111111111111111111111111', 0, 'dead_click', 'button.production', '2026-08-29T10:01:00Z', 'production-replay-issue', 'production-replay-event'),
			('project', '22222222222222222222222222222222', 0, 'dead_click', 'button.staging', '2026-08-29T10:01:00Z', 'staging-replay-issue', 'staging-replay-event');
	`, principal.UserID, principal.UserID); err != nil {
		t.Fatal(err)
	}
	create := principalRequest(t, principal, http.MethodPost, "/api/0/projects/org/app/replays/jobs/delete/", `{"data":{"rangeStart":"2026-08-29T00:00:00Z","rangeEnd":"2026-08-30T00:00:00Z","environments":["production"],"query":"checkout"}}`)
	create.SetPathValue("org_slug", "org")
	create.SetPathValue("project_slug", "app")
	response := httptest.NewRecorder()
	server.sentryReplayDeletionJob(response, create)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"status":"pending"`) {
		t.Fatalf("create deletion job status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Data.ID <= 0 {
		t.Fatalf("decode deletion job: %#v err=%v", created, err)
	}
	maintenance.New(server.store).RunReplayDeletionJobs(context.Background())
	status := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/jobs/delete/"+strconv.FormatInt(created.Data.ID, 10)+"/", "")
	status.SetPathValue("org_slug", "org")
	status.SetPathValue("project_slug", "app")
	status.SetPathValue("job_id", strconv.FormatInt(created.Data.ID, 10))
	response = httptest.NewRecorder()
	server.sentryReplayDeletionJob(response, status)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"status":"completed"`, `"countDeleted":1`) {
		t.Fatalf("deletion job status=%d body=%s", response.Code, response.Body.String())
	}
	var production, staging int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM replays WHERE environment = 'production'`).Scan(&production)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM replays WHERE environment = 'staging'`).Scan(&staging)
	if production != 0 || staging != 1 {
		t.Fatalf("filtered replay counts production=%d staging=%d", production, staging)
	}
	for _, table := range []string{"replay_views", "replay_clicks", "replay_issue_occurrences"} {
		var removed, retained int
		_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE replay_id = '11111111111111111111111111111111'`).Scan(&removed)
		_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE replay_id = '22222222222222222222222222222222'`).Scan(&retained)
		if removed != 0 || retained != 1 {
			t.Fatalf("%s filtered rows removed=%d retained=%d", table, removed, retained)
		}
	}
	var removedIssue, retainedIssue int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues WHERE id = 'production-replay-issue'`).Scan(&removedIssue)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues WHERE id = 'staging-replay-issue'`).Scan(&retainedIssue)
	if removedIssue != 0 || retainedIssue != 1 {
		t.Fatalf("filtered Replay issues removed=%d retained=%d", removedIssue, retainedIssue)
	}
	var audits int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'create_replay_deletion_job'`).Scan(&audits)
	if audits != 1 {
		t.Fatalf("deletion job audits=%d", audits)
	}
}

func TestSentryReplaySearchRejectsInvalidTime(t *testing.T) {
	server, principal := managementFixture(t)
	request := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replays/?start=yesterday", "")
	request.SetPathValue("org_slug", "org")
	response := httptest.NewRecorder()
	server.sentryOrganizationReplays(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid time status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid time response=%#v err=%v", payload, err)
	}
	errorBody, _ := payload["error"].(map[string]any)
	if errorBody["message"] != "start must be RFC3339" {
		t.Fatalf("invalid time response=%#v", payload)
	}
}
