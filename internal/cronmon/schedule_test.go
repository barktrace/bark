package cronmon

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeIntervalAndNextCrontab(t *testing.T) {
	kind, value, err := NormalizeSchedule("interval", json.RawMessage(`[2,"hours"]`))
	if err != nil || kind != "interval" || value != "120" {
		t.Fatalf("schedule = %q %q, %v", kind, value, err)
	}
	start := time.Date(2026, 8, 29, 10, 7, 0, 0, time.UTC)
	next := Next(start, "crontab", "*/15 * * * *", "UTC")
	if !next.Equal(time.Date(2026, 8, 29, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("next = %v", next)
	}
}
