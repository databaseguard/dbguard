package exfil

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func hasKind(fs []events.Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestKernelExfilQuarantine: a kernel byte-window report quarantines the
// session for QuarantineSec and the quarantine expires afterwards.
func TestKernelExfilQuarantine(t *testing.T) {
	b, err := New(config.ExfilConfig{
		QuarantineSec:     1,
		ResetEnabled:      true,
		MaxBytesPerWindow: 1 << 30,
		MaxRateKbps:       1000000,
	}, testLogger())
	if err != nil {
		t.Fatalf("exfil.New: %v", err)
	}
	base := time.Unix(1700000000, 0)
	b.nowFn = func() time.Time { return base }

	ev := &events.Event{
		Type: events.EvExfil, Severity: events.SevInfo, SessionID: 42,
		Meta: map[string]string{"bytes_window": "12345678"},
	}
	fs := b.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != "exfil.burst" {
		t.Fatalf("findings = %+v, want one exfil.burst", fs)
	}
	if fs[0].Confidence != 1.0 {
		t.Fatalf("confidence = %.2f, want 1.0", fs[0].Confidence)
	}
	if !ev.HasAction(events.ActQuarantine) || !ev.HasAction(events.ActReset) {
		t.Fatalf("actions wrong (ResetEnabled=true): %v", ev.Actions)
	}
	if ev.Severity.Order() < events.SevCritical.Order() {
		t.Fatalf("severity not critical: %s", ev.Severity)
	}
	if ev.MetaGet("exfil_granted") != "12345678" {
		t.Fatalf("bucket under-granted inside burst budget: %q", ev.MetaGet("exfil_granted"))
	}
	if !b.Quarantined(42) {
		t.Fatal("session 42 must be quarantined")
	}
	if b.Quarantined(43) {
		t.Fatal("unknown session must not be quarantined")
	}

	// after 2s (> QuarantineSec=1) the quarantine expired
	b.nowFn = func() time.Time { return base.Add(2 * time.Second) }
	if b.Quarantined(42) {
		t.Fatal("quarantine did not expire")
	}
}

func TestBulkSelectQuery(t *testing.T) {
	b, _ := New(config.ExfilConfig{}, testLogger())
	base := time.Unix(1700000000, 0)
	b.nowFn = func() time.Time { return base }

	ev := &events.Event{
		Type: events.EvQueryAudit, Severity: events.SevInfo, SessionID: 7,
		SQL: "SELECT * FROM customers",
	}
	fs := b.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != "exfil.bulk_query" {
		t.Fatalf("findings = %+v, want exfil.bulk_query", fs)
	}
	if !ev.HasAction(events.ActAlert) || ev.Severity.Order() < events.SevHigh.Order() {
		t.Fatalf("alert/severity missing: %v %s", ev.Actions, ev.Severity)
	}

	// repeat is annotated in the detail
	ev2 := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo, SessionID: 7,
		SQL: "select * from customers"}
	fs2 := b.Evaluate(ev2)
	if len(fs2) != 1 || !hasKind(fs2, "exfil.bulk_query") {
		t.Fatalf("repeat not flagged: %+v", fs2)
	}

	// clean query: nothing
	clean := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo, SessionID: 7,
		SQL: "SELECT id FROM t WHERE id = 1"}
	if fs := b.Evaluate(clean); fs != nil {
		t.Fatalf("clean query flagged: %+v", fs)
	}

	// kernel pre-filter flag wins over the user-space regex
	flagged := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo, SessionID: 7,
		SQL: "SELECT id FROM t", Meta: map[string]string{"kflag_bulk_select": "1"}}
	if fs := b.Evaluate(flagged); !hasKind(fs, "exfil.bulk_query") {
		t.Fatalf("kernel bulk flag ignored: %+v", fs)
	}
}

func TestConnCloseDropsSession(t *testing.T) {
	b, _ := New(config.ExfilConfig{QuarantineSec: 60}, testLogger())
	base := time.Unix(1700000000, 0)
	b.nowFn = func() time.Time { return base }

	ev := &events.Event{Type: events.EvExfil, Severity: events.SevInfo, SessionID: 99,
		Meta: map[string]string{"bytes_window": "1024"}}
	b.Evaluate(ev)
	if !b.Quarantined(99) {
		t.Fatal("session must be quarantined")
	}
	closeEv := &events.Event{Type: events.EvConnClose, Severity: events.SevInfo, SessionID: 99}
	if fs := b.Evaluate(closeEv); fs != nil {
		t.Fatalf("close must yield no findings: %+v", fs)
	}
	if b.Quarantined(99) {
		t.Fatal("closed session state was not dropped")
	}
}

// TestTokenBucketMath: rate 100/s, burst 1000 - spend, short-fall grant,
// then refill permits another take.
func TestTokenBucketMath(t *testing.T) {
	b := newTokenBucket(100, 1000)
	start := time.Unix(1700000000, 0)

	granted, ok := b.Take(600, start)
	if !ok || granted != 600 {
		t.Fatalf("first take = %d,%v; want 600,true", granted, ok)
	}
	granted, ok = b.Take(600, start)
	if ok || granted != 400 {
		t.Fatalf("second take = %d,%v; want 400,false (short-fall grant)", granted, ok)
	}
	granted, ok = b.Take(100, start.Add(time.Second))
	if !ok || granted != 100 {
		t.Fatalf("third take after 1s = %d,%v; want 100,true (100 refilled)", granted, ok)
	}
	if bal := b.Balance(start.Add(time.Second)); bal != 0 {
		t.Fatalf("balance = %.0f, want 0", bal)
	}
}

func TestRunnerLifecycle(t *testing.T) {
	b, _ := New(config.ExfilConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

// TestImplausibleWindowIgnored verifies a 4 GiB+ byte window (the kernel
// underflow signature) does NOT trip the breaker - defense in depth so a stale
// BPF object can't falsely quarantine (incl. loopback).
func TestImplausibleWindowIgnored(t *testing.T) {
	b, _ := New(config.ExfilConfig{}, nil)
	ev := &events.Event{
		Type: events.EvExfil, SessionID: 1,
		Meta: map[string]string{"bytes_window": "4294969639"},
	}
	findings := b.Evaluate(ev)
	if len(findings) != 0 {
		t.Fatalf("implausible window should yield no findings, got %d", len(findings))
	}
	if ev.HasAction(events.ActQuarantine) {
		t.Fatal("implausible window must NOT request quarantine")
	}
}
