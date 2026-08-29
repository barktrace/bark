package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/barktrace/bark/internal/ingest"
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
	if err := service.StoreReplayRecording(context.Background(), project, replayID, []byte(`{"replay_id":"`+replayID+`","segment_id":0}`+"\n"+`[{"type":2},{"type":3,"timestamp":1787997600200,"data":{"source":2,"type":2,"id":42}}]`)); err != nil {
		t.Fatal(err)
	}
	var legacyIssueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&legacyIssueID); err != nil {
		t.Fatal(err)
	}
	native := principalRequest(t, principal, http.MethodGet, "/replays?project_id=project&environment=production&q=checkout&has_error=true&issue_id="+strconv.FormatInt(legacyIssueID, 10), "")
	response := httptest.NewRecorder()
	server.replays(response, native)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"replay_id":"`+replayID+`"`, `"environment":"production"`, `"error_count":1`) {
		t.Fatalf("native replay search status=%d body=%s", response.Code, response.Body.String())
	}

	request := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replays/?project=1&query=environment:production+issue:"+strconv.FormatInt(legacyIssueID, 10), "")
	request.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryOrganizationReplays(response, request)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"replayId":"`+replayID+`"`, `"title":"Boom"`, `"error_ids":["`+eventID+`"]`, `"count_segments":1`, `"hasRecording":true`) {
		t.Fatalf("replay search status=%d body=%s", response.Code, response.Body.String())
	}

	detail := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/replays/"+replayID+"/", "")
	detail.SetPathValue("org_slug", "org")
	detail.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplayDetail(response, detail)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"data":{`, `"duration":300`, `"count_errors":1`, `"releases":["app@1.0"]`) {
		t.Fatalf("replay detail status=%d body=%s", response.Code, response.Body.String())
	}

	segments := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/replays/"+replayID+"/recording-segments/", "")
	segments.SetPathValue("org_slug", "org")
	segments.SetPathValue("project_slug", "app")
	segments.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.sentryReplaySegments(response, segments)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `[[{"type":2}`, `"id":42`) {
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
	for table, want := range map[string]int{"replays": 0, "replay_error_links": 0, "blobs": 0, "blob_deletion_queue": 0} {
		var got int
		if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}
	var audits int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'delete_replay' AND target_id = ?`, replayID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("delete replay audits=%d err=%v", audits, err)
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
