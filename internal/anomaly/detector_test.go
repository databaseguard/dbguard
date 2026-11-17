package anomaly

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

func queryEvent(ip, user string) *events.Event {
	return &events.Event{
		Type: events.EvQueryAudit, Severity: events.SevInfo,
		Time: time.Now(), ClientIP: ip, User: user,
	}
}

func connEvent(t events.EventType, ip, user string) *events.Event {
	return &events.Event{
		Type: t, Severity: events.SevInfo,
		Time: time.Now(), ClientIP: ip, User: user,
	}
}

// TestQueryRateTrigger fires once for a burst of 100 quick queries and then
// stays quiet for the 30s alert gap.
func TestQueryRateTrigger(t *testing.T) {
	d, err := New(config.AnomalyConfig{WindowSec: 1, QueryRateThreshold: 50}, testLogger())
	if err != nil {
		t.Fatalf("anomaly.New: %v", err)
	}
	var triggered *events.Event
	for i := 0; i < 120; i++ {
		ev := queryEvent("10.0.0.1", "app")
		fs := d.Evaluate(ev)
		if hasKind(fs, "anomaly.query_rate") {
			if triggered != nil {
				t.Fatal("rate alert repeated inside the 30s gap")
			}
			triggered = ev
		}
	}
	if triggered == nil {
		t.Fatal("query burst did not trigger anomaly.query_rate")
	}
	if triggered.Type != events.EvConnAnomaly {
		t.Fatalf("event type = %q, want %q", triggered.Type, events.EvConnAnomaly)
	}
	if !triggered.HasAction(events.ActRateLimit) || !triggered.HasAction(events.ActAlert) {
		t.Fatalf("actions wrong: %v", triggered.Actions)
	}
	if triggered.Severity.Order() < events.SevHigh.Order() {
		t.Fatalf("severity not high: %s", triggered.Severity)
	}
}

// TestConnSpike escalates medium -> high as the burst doubles the threshold.
func TestConnSpike(t *testing.T) {
	d, _ := New(config.AnomalyConfig{WindowSec: 60, ConnSpikeThreshold: 5}, testLogger())
	var last *events.Event
	for i := 0; i < 12; i++ {
		ev := connEvent(events.EvConnOpen, "10.0.0.2", "app")
		fs := d.Evaluate(ev)
		if hasKind(fs, "anomaly.conn_spike") {
			last = ev
		}
	}
	if last == nil {
		t.Fatal("connection burst did not trigger anomaly.conn_spike")
	}
	if last.Severity != events.SevHigh {
		t.Fatalf("escalated severity = %s, want high", last.Severity)
	}
	if last.Type != events.EvConnAnomaly || !last.HasAction(events.ActAlert) {
		t.Fatalf("event not reclassified/alerted: %+v", last)
	}
}

// TestAuthBruteforce alerts once per threshold worth of failures (the
// counter resets after each alert).
func TestAuthBruteforce(t *testing.T) {
	d, _ := New(config.AnomalyConfig{FailedAuthThreshold: 3}, testLogger())
	alerts := 0
	for i := 0; i < 6; i++ {
		ev := connEvent(events.EvAuthAnomaly, "10.0.0.3", "svc")
		fs := d.Evaluate(ev)
		if hasKind(fs, "anomaly.auth_bruteforce") {
			alerts++
			if !ev.HasAction(events.ActDeny) || !ev.HasAction(events.ActAlert) {
				t.Fatalf("deny/alert actions missing: %v", ev.Actions)
			}
			if ev.Severity.Order() < events.SevHigh.Order() {
				t.Fatalf("severity not high: %s", ev.Severity)
			}
		}
	}
	if alerts != 2 {
		t.Fatalf("alerts = %d, want exactly 2 (one per 3 failures)", alerts)
	}
}

// TestAdminConcurrent: more than the configured number of concurrent admin
// logins for one client triggers; close decrements release the pressure.
func TestAdminConcurrent(t *testing.T) {
	d, _ := New(config.AnomalyConfig{AdminConcurrentMax: 2, ConnSpikeThreshold: 100}, testLogger())

	var flagged *events.Event
	for i := 0; i < 3; i++ {
		ev := connEvent(events.EvConnOpen, "10.0.0.4", "postgres")
		if fs := d.Evaluate(ev); hasKind(fs, "anomaly.admin_concurrent") {
			flagged = ev
		}
	}
	if flagged == nil {
		t.Fatal("third concurrent admin session did not trigger")
	}
	if !flagged.HasAction(events.ActAlert) || flagged.Severity.Order() < events.SevHigh.Order() {
		t.Fatalf("admin finding not high/alerted: %+v", flagged)
	}

	// close all sessions (plus spurious duplicates: floor at zero)
	for i := 0; i < 5; i++ {
		d.Evaluate(connEvent(events.EvConnClose, "10.0.0.4", "postgres"))
	}
	// pressure rebuilds from a clean slate: two more opens stay quiet
	for i := 0; i < 2; i++ {
		if fs := d.Evaluate(connEvent(events.EvConnOpen, "10.0.0.4", "postgres")); len(fs) != 0 {
			t.Fatalf("unexpected finding after close: %+v", fs)
		}
	}
	if fs := d.Evaluate(connEvent(events.EvConnOpen, "10.0.0.4", "postgres")); !hasKind(fs, "anomaly.admin_concurrent") {
		t.Fatal("third admin session after teardown did not trigger")
	}
}

func TestCleanTrafficNoFindings(t *testing.T) {
	d, _ := New(config.AnomalyConfig{
		WindowSec: 60, QueryRateThreshold: 50, ConnSpikeThreshold: 5,
		AdminConcurrentMax: 3, FailedAuthThreshold: 10,
	}, testLogger())
	for i := 0; i < 10; i++ {
		ev := queryEvent("10.0.0.5", "reporting")
		if fs := d.Evaluate(ev); len(fs) != 0 {
			t.Fatalf("clean query produced %+v", fs)
		}
	}
	for _, ev := range []*events.Event{
		connEvent(events.EvConnOpen, "10.0.0.5", "reporting"),
		connEvent(events.EvConnOpen, "10.0.0.5", "reporting"),
		connEvent(events.EvAuthAnomaly, "10.0.0.5", "reporting"),
		connEvent(events.EvConnClose, "10.0.0.5", "reporting"),
	} {
		if fs := d.Evaluate(ev); len(fs) != 0 {
			t.Fatalf("clean traffic produced %+v", fs)
		}
		if ev.Type != events.EvConnOpen && ev.Type != events.EvAuthAnomaly && ev.Type != events.EvConnClose {
			t.Fatalf("clean event reclassified: %q", ev.Type)
		}
	}
}

// TestRunnerSweep exercises the background sweep once via the Runner
// contract without depending on wall-clock timing.
func TestRunnerSweep(t *testing.T) {
	d, _ := New(config.AnomalyConfig{WindowSec: 1}, testLogger())
	d.profiles.Update("10.0.0.6/app", func(p *clientProfile) {
		p.queryTimes.Add(time.Now().Add(-time.Hour), 5)
	})
	old := time.Now().Add(-30 * time.Minute)
	d.profiles.ForEach(func(p *clientProfile) {
		p.queryTimes.Prune(2*d.window, old)
		p.connOpens.Prune(2*d.window, old)
	})
	if got := d.profiles.Get("10.0.0.6/app").queryTimes.Count(time.Hour, time.Now()); got != 0 {
		t.Fatalf("prune left weight %.0f behind", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
