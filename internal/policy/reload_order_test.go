package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

// A hot-added lower-numbered policy file must evaluate BEFORE a higher-numbered
// one (filename order), and a deleted file's rules must be dropped on reload.
func TestReloadOrderingAndDeletion(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 90: broad deny on any SELECT (stands in for a catch-all rate/firewall rule)
	write("90-broad.yaml", `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: broad}
spec:
  default_action: allow
  rules:
    - id: broad.deny_select
      query: {pattern: '(?i)^select'}
      actions: [deny, alert]
`)
	eng := New(nil)
	if err := eng.SetDirs([]string{dir}, false); err != nil {
		t.Fatal(err)
	}
	ctx := &Context{Engine: "postgres", SQL: "SELECT 1", Now: time.Now()}
	if d := eng.Evaluate(ctx); d.Allowed || firstRule(d) != "broad.deny_select" {
		t.Fatalf("expected broad.deny_select, got %+v", d)
	}

	// Hot-add a LOWER-numbered file that allows the same query; it must win
	// (evaluated first by filename order), not be appended after 90.
	write("70-mine.yaml", `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: mine}
spec:
  default_action: allow
  rules:
    - id: my.allow_select
      query: {pattern: '(?i)^select'}
      actions: [allow]
`)
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	if d := eng.Evaluate(ctx); !d.Allowed {
		t.Fatalf("hot-added 70-file must evaluate before 90-file: got %+v", d)
	}

	// Delete the 70 file; its rule must be unloaded and 90 denies again.
	os.Remove(filepath.Join(dir, "70-mine.yaml"))
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	if d := eng.Evaluate(ctx); d.Allowed {
		t.Fatalf("deleted file's rule must be dropped on reload: got %+v", d)
	}
}

func firstRule(d Decision) string {
	if len(d.RuleIDs) > 0 {
		return d.RuleIDs[0]
	}
	return ""
}

var _ = events.SevInfo
