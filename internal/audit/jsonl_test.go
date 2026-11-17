package audit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testCfg(dir string) config.AuditConfig {
	return config.AuditConfig{
		Enabled:          true,
		Store:            "jsonl",
		Dir:              dir,
		MaxSizeMB:        100,
		MaxFiles:         30,
		FlushIntervalSec: 3600, // effectively never flush mid-test; Close flushes
	}
}

// countSegments counts audit segment files in dir.
func countSegments(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, filePrefix+"*"+fileExt))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

func TestJSONLRoundTripAndFilters(t *testing.T) {
	dir := t.TempDir()
	s, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC().Add(-time.Hour)
	seed := []struct {
		id   string
		user string
		sev  events.Severity
		typ  events.EventType
		eng  string
	}{
		{"e1", "alice", events.SevInfo, events.EvQueryAudit, "postgres"},
		{"e2", "bob", events.SevHigh, events.EvSQLi, "postgres"},
		{"e3", "carol", events.SevCritical, events.EvExfil, "mysql"},
	}
	for i, rec := range seed {
		ev := &events.Event{
			ID: rec.id, Type: rec.typ, Severity: rec.sev,
			Time: base.Add(time.Duration(i) * time.Second),
			User: rec.user, Engine: rec.eng,
		}
		if err := s.Append(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// reopen over the same directory: the store must replay the segments
	s2, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	ctx := context.Background()
	got, err := s2.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	for i, ev := range got {
		if ev.ID != fmt.Sprintf("e%d", i+1) {
			t.Fatalf("out of order: index %d has id %s", i, ev.ID)
		}
		if !ev.Time.Equal(base.Add(time.Duration(i) * time.Second)) {
			t.Fatalf("event %s time drifted: %v", ev.ID, ev.Time)
		}
	}

	// filter: by user (only e1 was seeded as alice)
	if got, _ = s2.Query(ctx, Filter{User: "alice"}); len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("user filter: got %d, want 1 (e1)", len(got))
	}
	// filter: by minimum severity
	if got, _ = s2.Query(ctx, Filter{MinSeverity: events.SevHigh}); len(got) != 2 {
		t.Fatalf("severity filter: got %d, want 2", len(got))
	}
	// filter: by type
	if got, _ = s2.Query(ctx, Filter{Types: []events.EventType{events.EvSQLi}}); len(got) != 1 || got[0].ID != "e2" {
		t.Fatalf("type filter wrong: %+v", got)
	}
	// filter: by engine
	if got, _ = s2.Query(ctx, Filter{Engine: "mysql"}); len(got) != 1 || got[0].ID != "e3" {
		t.Fatalf("engine filter wrong: %+v", got)
	}
	// limit is respected
	if got, _ = s2.Query(ctx, Filter{Limit: 2}); len(got) != 2 {
		t.Fatalf("limit filter: got %d, want 2", len(got))
	}
}

func TestJSONLRotationAndPrune(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir)
	cfg.MaxSizeMB = 1 // rotate at 1 MiB
	cfg.MaxFiles = 2  // keep at most 2 segments

	s, err := NewJSONLStore(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// ~2.1 KB per record => 1200 records ≈ 2.5 MB => at least 3 segments,
	// after pruning exactly MaxFiles remain.
	big := strings.Repeat("x", 2048)
	for i := 0; i < 1200; i++ {
		ev := &events.Event{
			ID:       fmt.Sprintf("rot-%04d", i),
			Type:     events.EvQueryAudit,
			Time:     time.Now().UTC(),
			Severity: events.SevInfo,
			Message:  big,
		}
		if err := s.Append(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if got := countSegments(t, dir); got != 2 {
		t.Fatalf("segments after rotation+prune = %d, want 2", got)
	}

	// the surviving segments must still be queryable
	s2, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Query(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) >= 1200 {
		t.Fatalf("query after prune returned %d events, want pruned subset", len(got))
	}
}

func TestJSONLRotateNow(t *testing.T) {
	dir := t.TempDir()
	s, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Append(context.Background(), &events.Event{
		ID: "pre-rotate", Type: events.EvQueryAudit, Time: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateNow(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), &events.Event{
		ID: "post-rotate", Type: events.EvQueryAudit, Time: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if got := countSegments(t, dir); got != 2 {
		t.Fatalf("segments after explicit rotation = %d, want 2", got)
	}
	s2, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _ := s2.Query(context.Background(), Filter{})
	if len(got) != 2 {
		t.Fatalf("query across rotation returned %d events, want 2", len(got))
	}
}

func TestJSONLAppendAfterClose(t *testing.T) {
	dir := t.TempDir()
	s, err := NewJSONLStore(testCfg(dir), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
	err = s.Append(context.Background(), &events.Event{ID: "late"})
	if err == nil {
		t.Fatal("Append after Close must fail")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONLDirRequired(t *testing.T) {
	if _, err := NewJSONLStore(config.AuditConfig{}, testLogger()); err == nil {
		t.Fatal("expected error for empty dir")
	}
}
