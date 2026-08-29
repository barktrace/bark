package coordination

import (
	"context"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/store"
)

func TestLeaseHasSingleOwnerAndCanFailOver(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first, second := New(st.DB), New(st.DB)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if acquired, err := first.Acquire(context.Background(), "alerts", now); err != nil || !acquired {
		t.Fatalf("first acquire = %v, %v", acquired, err)
	}
	if acquired, err := second.Acquire(context.Background(), "alerts", now.Add(time.Second)); err != nil || acquired {
		t.Fatalf("second early acquire = %v, %v", acquired, err)
	}
	if acquired, err := second.Acquire(context.Background(), "alerts", now.Add(leaseTTL+time.Second)); err != nil || !acquired {
		t.Fatalf("second failover acquire = %v, %v", acquired, err)
	}
	if err := first.Release(context.Background(), "alerts"); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := st.DB.QueryRow(`SELECT owner_id FROM service_leases WHERE name = 'alerts'`).Scan(&owner); err != nil || owner != second.ownerID {
		t.Fatalf("first owner released second owner's lease: %q, %v", owner, err)
	}
}
