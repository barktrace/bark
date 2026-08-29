package quota

import (
	"context"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/store"
)

func TestCategoryQuota(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`INSERT INTO organizations(id, slug, name) VALUES ('org','org','Org'); INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project','1','org','app','App','key'); INSERT INTO project_quotas(project_id, category, per_minute, per_day, max_item_bytes) VALUES ('project','error',1,10,100)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first, err := Check(context.Background(), st.DB, "project", "error", 20, now)
	if err != nil || !first.Allowed {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := Check(context.Background(), st.DB, "project", "error", 20, now)
	if err != nil || second.Allowed || second.Reason != "minute_quota" {
		t.Fatalf("second = %#v, %v", second, err)
	}
	oversized, err := Check(context.Background(), st.DB, "project", "error", 101, now.Add(time.Minute))
	if err != nil || oversized.Allowed || oversized.Reason != "item_size" {
		t.Fatalf("oversized = %#v, %v", oversized, err)
	}
}
