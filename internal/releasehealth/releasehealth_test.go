package releasehealth

import (
	"context"
	"testing"
	"time"
)

func TestParseRange(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	start, end, err := ParseRange(now, "", "", " 7D ")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, time.August, 23, 10, 0, 0, 0, time.UTC); !start.Equal(want) {
		t.Fatalf("start = %s, want %s", start, want)
	}
	if want := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC); !end.Equal(want) {
		t.Fatalf("end = %s, want %s", end, want)
	}

	start, end, err = ParseRange(now, "2026-08-29T08:00:00+02:00", "2026-08-29T12:00:00+02:00", "")
	if err != nil {
		t.Fatal(err)
	}
	if start.Location() != time.UTC || end.Location() != time.UTC || end.Sub(start) != 4*time.Hour {
		t.Fatalf("explicit range = %s..%s", start, end)
	}

	for _, test := range []struct {
		name, start, end, period string
	}{
		{name: "invalid start", start: "yesterday", end: "2026-08-30T12:00:00Z"},
		{name: "reversed", start: "2026-08-30T12:00:00Z", end: "2026-08-30T08:00:00Z"},
		{name: "range too large", start: "2026-01-01T00:00:00Z", end: "2026-08-30T00:00:00Z"},
		{name: "period too small", period: "30m"},
		{name: "period too large", period: "999999999999999999h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := ParseRange(now, test.start, test.end, test.period); err == nil {
				t.Fatal("expected range error")
			}
		})
	}
}

func TestParseInterval(t *testing.T) {
	for _, test := range []struct {
		raw    string
		period time.Duration
		want   time.Duration
	}{
		{period: 24 * time.Hour, want: time.Hour},
		{period: 7 * 24 * time.Hour, want: 24 * time.Hour},
		{raw: " 30M ", period: 24 * time.Hour, want: 30 * time.Minute},
		{raw: "2h", period: 24 * time.Hour, want: 2 * time.Hour},
		{raw: "1d", period: 7 * 24 * time.Hour, want: 24 * time.Hour},
	} {
		got, err := ParseInterval(test.raw, test.period)
		if err != nil {
			t.Fatalf("ParseInterval(%q): %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("ParseInterval(%q) = %s, want %s", test.raw, got, test.want)
		}
	}

	for _, raw := range []string{"0h", "1w", "1s", "999999999999999999h"} {
		if _, err := ParseInterval(raw, 24*time.Hour); err == nil {
			t.Fatalf("ParseInterval(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestQueryWithNoProjectsReturnsAlignedEmptyResult(t *testing.T) {
	start := time.Date(2026, time.August, 30, 8, 0, 0, 0, time.UTC)
	result, err := Query(context.Background(), nil, Request{
		Start: start, End: start.Add(3 * time.Hour), Interval: time.Hour,
		Fields: []string{"sum(session)", "crash_free_rate(session)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Intervals) != 3 || len(result.Groups) != 0 {
		t.Fatalf("empty result = %#v", result)
	}
	if _, err := Query(context.Background(), nil, Request{
		Start: start, End: start.Add(time.Hour), Interval: time.Hour, GroupBy: []string{"unknown"},
	}); err == nil {
		t.Fatal("unsupported grouping unexpectedly succeeded without projects")
	}
}

func TestAggregateStatusAndEmptyMetrics(t *testing.T) {
	value := newAggregate()
	if metric("sum(session)", value) != int64(0) || metric("count_unique(user)", value) != 0 {
		t.Fatalf("empty count metrics are not zero: %#v", value)
	}
	if metric("avg(session.duration)", value) != nil || metric("crash_free_rate(session)", value) != nil || metric("crash_free_rate(user)", value) != nil {
		t.Fatalf("empty rate metrics must be null: %#v", value)
	}

	updateAggregate(&value, normalizedStatus("ok", 0), "healthy-user", 10, true)
	updateAggregate(&value, normalizedStatus("ok", 1), "error-user", 0, false)
	updateAggregate(&value, normalizedStatus("crashed", 1), "crashed-user", 20, true)
	updateAggregate(&value, normalizedStatus("abnormal", 0), "abnormal-user", 0, false)
	if value.sessions != 4 || value.crashed != 1 || value.durations != 2 || value.duration != 30 {
		t.Fatalf("aggregate = %#v", value)
	}
	if got := metric("crash_free_rate(session)", value); got != float64(75) {
		t.Fatalf("crash-free session rate = %#v", got)
	}
	if normalizedStatus("ok", 1) != "errored" || normalizedStatus("abnormal", 2) != "abnormal" {
		t.Fatal("status normalization changed")
	}
}
