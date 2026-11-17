package rids

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// testRIDSConfig returns a policy suitable for deterministic tests.
func testRIDSConfig(alertOnly bool) config.RIDSConfig {
	return config.RIDSConfig{
		Enabled:         true,
		AlertOnly:       alertOnly,
		BlockedBinaries: []string{"/bin/sh", "wget"},
		ProtectedPaths:  []string{"/var/lib/postgresql"},
		MaxPathLen:      256,
		FIM:             config.FIMConfig{Enabled: false, IntervalSec: 300},
	}
}

func newExecEvent(path, argv string) *events.Event {
	ev := &events.Event{ID: events.NewID(), Type: events.EvExecve, Time: time.Now(), PID: 4242, Binary: "postgres"}
	ev.MetaSet("path", path)
	ev.MetaSet("argv", argv)
	return ev
}

func newFileEvent(path string) *events.Event {
	ev := &events.Event{ID: events.NewID(), Type: events.EvFileAccess, Time: time.Now(), PID: 4242, Binary: "postgres"}
	ev.MetaSet("path", path)
	return ev
}

func TestMonitorBlockedExec(t *testing.T) {
	m, err := New(testRIDSConfig(false), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Name() != "rids" {
		t.Fatalf("Name() = %q, want rids", m.Name())
	}

	// Exact full-path rule.
	ev := newExecEvent("/bin/sh", "sh -c id")
	fs := m.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindBlockedExec {
		t.Fatalf("expected one %s finding, got %+v", KindBlockedExec, fs)
	}
	if fs[0].Severity == "" || ev.Severity != events.SevCritical {
		t.Errorf("blocked exec must escalate severity to critical, got %q", ev.Severity)
	}
	if !strings.Contains(fs[0].Detail, "sh -c id") {
		t.Errorf("argv must appear in the finding detail, got %q", fs[0].Detail)
	}
	if !ev.HasAction(events.ActKill) || !ev.HasAction(events.ActQuarantine) {
		t.Errorf("enforcement mode must attach kill+quarantine, got %v", ev.Actions)
	}

	// Base-name rule ("wget" matches /usr/bin/wget).
	ev2 := newExecEvent("/usr/bin/wget", "wget http://evil")
	if fs := m.Evaluate(ev2); len(fs) != 1 {
		t.Fatalf("basename rule must match /usr/bin/wget, got %+v", fs)
	}

	// Benign binary stays silent.
	ev3 := newExecEvent("/usr/bin/psql", "psql -c 'select 1'")
	if fs := m.Evaluate(ev3); len(fs) != 0 || len(ev3.Actions) != 0 {
		t.Fatalf("benign exec must produce no findings/actions, got %+v / %v", fs, ev3.Actions)
	}
}

func TestMonitorBlockedExecAlertOnly(t *testing.T) {
	m, err := New(testRIDSConfig(true), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := newExecEvent("/bin/sh", "sh -c whoami")
	fs := m.Evaluate(ev)
	if len(fs) != 1 {
		t.Fatalf("expected finding in alert-only mode, got %+v", fs)
	}
	if ev.HasAction(events.ActKill) || ev.HasAction(events.ActQuarantine) {
		t.Errorf("alert_only must not attach enforcement actions, got %v", ev.Actions)
	}
	if !ev.HasAction(events.ActAlert) {
		t.Errorf("alert_only must attach ActAlert, got %v", ev.Actions)
	}
}

func TestMonitorProtectedPath(t *testing.T) {
	m, err := New(testRIDSConfig(false), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := newFileEvent("/var/lib/postgresql/16/base/16384")
	fs := m.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindProtectedFile {
		t.Fatalf("expected one %s finding, got %+v", KindProtectedFile, fs)
	}
	if ev.Severity != events.SevHigh {
		t.Errorf("protected file access must be high severity, got %q", ev.Severity)
	}
	if !ev.HasAction(events.ActDeny) || !ev.HasAction(events.ActFreeze) {
		t.Errorf("expected deny+freeze actions, got %v", ev.Actions)
	}

	// Boundary-aware prefix: sibling directory must not match.
	ev2 := newFileEvent("/var/lib/postgresql-backup/PG_VERSION")
	if fs := m.Evaluate(ev2); len(fs) != 0 || len(ev2.Actions) != 0 {
		t.Fatalf("sibling path must not match protected prefix, got %+v / %v", fs, ev2.Actions)
	}
}

func TestResponderQuarantineLifecycle(t *testing.T) {
	r := NewResponder()
	const pid uint32 = 4711
	if r.IsQuarantined(pid) {
		t.Fatal("fresh responder must not report an active quarantine")
	}
	if err := r.Quarantine(pid, time.Minute); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !r.IsQuarantined(pid) {
		t.Fatal("pid must be quarantined before expiry")
	}
	if r.IsQuarantined(pid + 1) {
		t.Fatal("unrelated pid must not be quarantined")
	}
	// Deterministic expiry via Sweep with an injected clock (no sleeps).
	r.Sweep(time.Now().Add(2 * time.Minute))
	if r.IsQuarantined(pid) {
		t.Fatal("entry must be gone after sweeping past expiry")
	}
	// Explicit release via non-positive TTL.
	if err := r.Quarantine(pid, time.Minute); err != nil {
		t.Fatalf("re-quarantine: %v", err)
	}
	if err := r.Quarantine(pid, 0); err != nil {
		t.Fatalf("release: %v", err)
	}
	if r.IsQuarantined(pid) {
		t.Fatal("pid must be released after zero-TTL quarantine")
	}
}

func TestResponderKillProcessGone(t *testing.T) {
	r := NewResponder()
	// PID far above pid_max on any realistic host: ESRCH → mapped error.
	if err := r.Kill(4_000_000); !errors.Is(err, ErrProcessGone) {
		t.Fatalf("expected ErrProcessGone, got %v", err)
	}
}

func TestMonitorIntegrityEventSynthesis(t *testing.T) {
	var got []*events.Event
	m, err := New(testRIDSConfig(false), nil, func(ev *events.Event) { got = append(got, ev) })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.reportIntegrity("/var/lib/postgresql/16/global/pg_control", "aaa", "bbb")
	if len(got) != 1 {
		t.Fatalf("expected one published event, got %d", len(got))
	}
	ev := got[0]
	if ev.ID == "" || ev.Type != events.EvIntegrity || ev.Source != "rids" {
		t.Fatalf("synthesized event incomplete: %+v", ev)
	}
	if ev.Severity != events.SevCritical {
		t.Errorf("integrity events must be critical, got %q", ev.Severity)
	}
	if ev.MetaGet("path") == "" || ev.MetaGet("old_hash") != "aaa" || ev.MetaGet("new_hash") != "bbb" {
		t.Errorf("integrity meta missing: %v", ev.Meta)
	}
	// The synthesized event re-enters Evaluate and gains the finding+alert.
	fs := m.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindFIMChange {
		t.Fatalf("expected %s finding on re-evaluation, got %+v", KindFIMChange, fs)
	}
	if !ev.HasAction(events.ActAlert) {
		t.Errorf("integrity finding must attach ActAlert, got %v", ev.Actions)
	}

	// nil publisher must not panic (log-only path).
	m2, _ := New(testRIDSConfig(false), nil, nil)
	m2.reportIntegrity("/tmp/x", "1", "2")
}

func TestMonitorRunFIMDisabled(t *testing.T) {
	m, err := New(testRIDSConfig(false), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run must exit promptly on ctx cancel")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFIMDiffDetectsAddAndModify(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.txt")
	fileB := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(fileA, []byte("one"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	s := NewScanner([]string{dir}, 1<<20)
	base, err := s.Baseline()
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if len(base) != 1 || base[fileA] == "" {
		t.Fatalf("unexpected baseline: %v", base)
	}
	if err := os.WriteFile(fileA, []byte("one-two"), 0o600); err != nil {
		t.Fatalf("modify a: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("fresh"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}
	added, removed, changed, next, err := s.Diff(base)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(added) != 1 || added[0] != fileB {
		t.Errorf("added = %v, want [%s]", added, fileB)
	}
	if len(changed) != 1 || changed[0] != fileA {
		t.Errorf("changed = %v, want [%s]", changed, fileA)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v, want empty", removed)
	}
	if next[fileA] == base[fileA] {
		t.Errorf("next baseline must carry the new hash for %s", fileA)
	}
}

func TestBaselineSaveLoadRoundtrip(t *testing.T) {
	b := Baseline{"/var/lib/db/a": "aa11", "/var/lib/db/b": "bb22"}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(got) != 2 || got["/var/lib/db/a"] != "aa11" || got["/var/lib/db/b"] != "bb22" {
		t.Fatalf("roundtrip mismatch: %v", got)
	}
}
