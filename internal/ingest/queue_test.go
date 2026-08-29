package ingest

import (
	"context"
	"testing"
	"time"
)

func TestDurableQueueCompletesAndRemovesPayload(t *testing.T) {
	st, project := testProject(t)
	service := New(st, 20<<20)
	result, err := service.enqueueAndProcess(context.Background(), project, itemHeader{Type: "event", ContentType: "application/json"}, "", "", "", []byte(`{"event_id":"10101010101010101010101010101010","message":"durable"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Queued || result.JobID == "" || result.ID == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	var status string
	var hasPayload int
	if err := st.DB.QueryRow(`SELECT status, blob_id IS NOT NULL FROM ingestion_jobs WHERE id = ?`, result.JobID).Scan(&status, &hasPayload); err != nil {
		t.Fatal(err)
	}
	if status != "done" || hasPayload != 0 {
		t.Fatalf("job status=%q has_payload=%d, want done/0", status, hasPayload)
	}
	var ingestionBlobs int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM blobs WHERE kind = 'ingestion'`).Scan(&ingestionBlobs)
	if ingestionBlobs != 0 {
		t.Fatalf("ingestion blobs=%d, want 0", ingestionBlobs)
	}
}

func TestDurableQueueRetriesTransientlyUnprocessableItem(t *testing.T) {
	st, project := testProject(t)
	service := New(st, 20<<20)
	externalEventID := "20202020202020202020202020202020"
	result, err := service.enqueueAndProcess(context.Background(), project, itemHeader{Type: "attachment", Filename: "trace.txt", ContentType: "text/plain"}, externalEventID, "", "", []byte("queued attachment"))
	if err == nil || !result.Queued {
		t.Fatalf("initial processing error=%v result=%+v, want a durable retry", err, result)
	}
	if _, err := service.StoreEvent(context.Background(), project, []byte(`{"event_id":"`+externalEventID+`","message":"arrived later"}`), ""); err != nil {
		t.Fatal(err)
	}
	didWork, err := service.runQueuedJob(context.Background(), "test-worker", time.Now().UTC().Add(10*time.Second))
	if err != nil || !didWork {
		t.Fatalf("run queued job: worked=%t error=%v", didWork, err)
	}
	var attachments int
	var status string
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM event_attachments`).Scan(&attachments)
	_ = st.DB.QueryRow(`SELECT status FROM ingestion_jobs WHERE id = ?`, result.JobID).Scan(&status)
	if attachments != 1 || status != "done" {
		t.Fatalf("attachments=%d status=%q, want 1/done", attachments, status)
	}
}

func TestDurableQueueMarksPoisonPayloadDead(t *testing.T) {
	st, project := testProject(t)
	service := New(st, 20<<20)
	result, err := service.enqueueAndProcess(context.Background(), project, itemHeader{Type: "event", ContentType: "application/json"}, "", "", "", []byte(`not-json`))
	if err == nil || !result.Queued {
		t.Fatalf("initial processing error=%v result=%+v, want queued failure", err, result)
	}
	now := time.Now().UTC().Add(time.Hour)
	for attempt := 2; attempt <= maxJobAttempts; attempt++ {
		didWork, runErr := service.runQueuedJob(context.Background(), "test-worker", now)
		if runErr != nil || !didWork {
			t.Fatalf("attempt %d: worked=%t error=%v", attempt, didWork, runErr)
		}
		now = now.Add(time.Hour)
	}
	var status string
	var attempts int
	var hasPayload int
	if err := st.DB.QueryRow(`SELECT status, attempts, blob_id IS NOT NULL FROM ingestion_jobs WHERE id = ?`, result.JobID).Scan(&status, &attempts, &hasPayload); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || attempts != maxJobAttempts || hasPayload != 1 {
		t.Fatalf("status=%q attempts=%d has_payload=%d", status, attempts, hasPayload)
	}
}
