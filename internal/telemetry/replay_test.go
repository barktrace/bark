package telemetry

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
)

func TestAnalyzeReplayBuildsBoundedTimeline(t *testing.T) {
	event := []byte(`{"urls":["https://example.com/checkout"],"error_ids":["error-one"],"trace_ids":["trace-one"],"breadcrumbs":[{"timestamp":1787997600,"category":"http","type":"http","message":"POST /orders"}]}`)
	recording := []byte(`[
		{"type":4,"timestamp":1787997600000,"data":{"href":"https://example.com/checkout","width":1440,"height":900}},
		{"type":2,"timestamp":1787997600100,"data":{}},
		{"type":3,"timestamp":1787997600200,"data":{"source":2,"type":2,"id":12}},
		{"type":3,"timestamp":1787997600300,"data":{"source":5,"id":13,"text":"secret"}},
		{"type":3,"timestamp":1787997600400,"data":{"source":0,"adds":[{}],"removes":[{}],"texts":[],"attributes":[{}]}}
	]`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(recording); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeReplay(event, compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result.DurationMS != 400 || result.Stats["events"] != 5 || result.Stats["interaction"] != 1 || result.Stats["input"] != 1 || result.Stats["mutation"] != 1 {
		t.Fatalf("unexpected replay stats: %#v", result)
	}
	if len(result.URLs) != 1 || len(result.ErrorIDs) != 1 || len(result.TraceIDs) != 1 || len(result.Timeline) != 6 {
		t.Fatalf("unexpected replay metadata: %#v", result)
	}
	for _, item := range result.Timeline {
		if item.Summary == "secret" {
			t.Fatal("input contents leaked into timeline")
		}
	}
}

func TestAnalyzeReplaySupportsEnvelopeHeader(t *testing.T) {
	recording := []byte("{\"replay_id\":\"abc\",\"segment_id\":0}\n[{\"type\":1,\"timestamp\":1787997600000,\"data\":{}}]")
	result, err := AnalyzeReplay(nil, recording)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats["lifecycle"] != 1 || len(result.Timeline) != 1 {
		t.Fatalf("unexpected header recording: %#v", result)
	}
}

func TestReplayPlaybackCombinesSegments(t *testing.T) {
	playback := NewReplayPlayback()
	first := []byte(`{"events":[{"type":4,"timestamp":1787997600000,"data":{"href":"https://example.com","width":800,"height":600}},{"type":2,"timestamp":1787997600010,"data":{"node":{"type":0,"id":1,"childNodes":[]},"initialOffset":{"top":0,"left":0}}}]}`)
	second := []byte(`[{"type":3,"timestamp":1787997600250,"data":{"source":2,"type":2,"id":4}}]`)
	if err := playback.AddRecording(first); err != nil {
		t.Fatal(err)
	}
	if err := playback.AddRecording(second); err != nil {
		t.Fatal(err)
	}
	if playback.EventCount != 3 || len(playback.Events) != 3 || !playback.HasSnapshot || playback.DurationMS != 250 || playback.Truncated {
		t.Fatalf("unexpected playback: %#v", playback)
	}
	var event replayEvent
	if err := json.Unmarshal(playback.Events[2], &event); err != nil || event.Type != 3 {
		t.Fatalf("unexpected retained event: type=%d err=%v", event.Type, err)
	}
}

func TestReplayPlaybackRejectsMalformedEvent(t *testing.T) {
	playback := NewReplayPlayback()
	if err := playback.AddRecording([]byte(`[{"type":"snapshot","timestamp":1000}]`)); err == nil {
		t.Fatal("expected malformed rrweb event to fail")
	}
}
