package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/ingest"
)

func TestReplayAndProfileAnalysisEndpoints(t *testing.T) {
	server, principal, replayID, profileID := telemetryAnalysisFixture(t)

	replayRequest := principalRequest(t, principal, http.MethodGet, "/replays/"+replayID+"/analysis", "")
	replayRequest.SetPathValue("replay_id", replayID)
	response := httptest.NewRecorder()
	server.replayAnalysis(response, replayRequest)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"interaction":1`, `"type":"click"`, `"duration_ms":200`) {
		t.Fatalf("replay analysis status=%d body=%s", response.Code, response.Body.String())
	}

	playbackRequest := principalRequest(t, principal, http.MethodGet, "/replays/"+replayID+"/playback", "")
	playbackRequest.SetPathValue("replay_id", replayID)
	response = httptest.NewRecorder()
	server.replayPlayback(response, playbackRequest)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"event_count":3`, `"has_snapshot":true`, `"segment_count":1`) {
		t.Fatalf("replay playback status=%d body=%s", response.Code, response.Body.String())
	}

	profileRequest := principalRequest(t, principal, http.MethodGet, "/profiles/"+profileID+"/analysis", "")
	profileRequest.SetPathValue("profile_id", profileID)
	response = httptest.NewRecorder()
	server.profileAnalysis(response, profileRequest)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"sample_count":2`, `"name":"query"`, `"self_samples":2`) {
		t.Fatalf("profile analysis status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReplayRecordingLinksOnlyMatchingSegment(t *testing.T) {
	server, _, _, _ := telemetryAnalysisFixture(t)
	var segmentZero, segmentOne bool
	if err := server.store.DB.QueryRow(`SELECT recording_blob_id IS NOT NULL FROM replays WHERE replay_id = '12121212121212121212121212121212' AND segment_id = 0`).Scan(&segmentZero); err != nil {
		t.Fatal(err)
	}
	if err := server.store.DB.QueryRow(`SELECT recording_blob_id IS NOT NULL FROM replays WHERE replay_id = '12121212121212121212121212121212' AND segment_id = 1`).Scan(&segmentOne); err != nil {
		t.Fatal(err)
	}
	if segmentZero || !segmentOne {
		t.Fatalf("recording linkage segment0=%v segment1=%v", segmentZero, segmentOne)
	}
}

func telemetryAnalysisFixture(t *testing.T) (*Server, *auth.Principal, string, string) {
	t.Helper()
	st := openTestStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'acme', 'Acme');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'api', 'API', 'key');
	`)
	if err != nil {
		t.Fatal(err)
	}
	service := ingest.New(st, 20<<20, 1000)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}
	for segment := 0; segment < 2; segment++ {
		payload, _ := json.Marshal(map[string]any{"replay_id": "12121212121212121212121212121212", "segment_id": segment, "timestamp": "2026-08-29T10:00:01Z", "replay_start_timestamp": "2026-08-29T10:00:00Z", "urls": []string{"https://example.com"}})
		if err := service.StoreReplayEvent(context.Background(), project, payload); err != nil {
			t.Fatal(err)
		}
	}
	recording := []byte("{\"replay_id\":\"12121212121212121212121212121212\",\"segment_id\":1}\n[{\"type\":4,\"timestamp\":1787997600000,\"data\":{\"href\":\"https://example.com\",\"width\":800,\"height\":600}},{\"type\":2,\"timestamp\":1787997600100,\"data\":{\"node\":{\"type\":0,\"id\":1,\"childNodes\":[]},\"initialOffset\":{\"top\":0,\"left\":0}}},{\"type\":3,\"timestamp\":1787997600200,\"data\":{\"source\":2,\"type\":2}}]")
	if err := service.StoreReplayRecording(context.Background(), project, "12121212121212121212121212121212", recording); err != nil {
		t.Fatal(err)
	}
	profile := []byte(`{"profile_id":"profile-one","platform":"go","duration_ns":200000000,"profile":{"frames":[{"function":"main"},{"function":"query"}],"stacks":[[0,1]],"samples":[{"stack_id":0,"thread_id":"1"},{"stack_id":0,"thread_id":"1"}]}}`)
	if err := service.StoreProfile(context.Background(), project, profile); err != nil {
		t.Fatal(err)
	}
	var replayRowID, profileRowID string
	if err := st.DB.QueryRow(`SELECT id FROM replays WHERE replay_id = '12121212121212121212121212121212' AND segment_id = 1`).Scan(&replayRowID); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT id FROM profiles WHERE profile_id = 'profile-one'`).Scan(&profileRowID); err != nil {
		t.Fatal(err)
	}
	server := New(configForTest(), st, &auth.Service{})
	principal := &auth.Principal{UserID: "user", Memberships: []auth.Membership{{OrganizationID: "org", Role: "owner"}}}
	return server, principal, replayRowID, profileRowID
}
