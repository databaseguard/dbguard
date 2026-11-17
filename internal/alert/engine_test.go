// Package alert - engine_test.go covers the router: webhook delivery of a
// critical event, dedupe collapse inside the window and the severity gate.
package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// quietLogger discards engine diagnostics during tests.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// criticalEvent builds a representative SQLi alert.
func criticalEvent(id string) *events.Event {
	return &events.Event{
		ID:       id,
		Type:     events.EvSQLi,
		Time:     time.Now().UTC(),
		Severity: events.SevCritical,
		RuleID:   "sqli.tautology",
		Message:  "tautology detected",
		SQL:      "SELECT * FROM users WHERE id = '' OR 1=1 --",
		User:     "app",
		Database: "dbguard_test",
		ClientIP: "10.0.0.7",
		Engine:   "postgres",
		Actions:  []events.Action{events.ActAlert},
	}
}

// TestRouterDeliversAndDedupes exercises the happy path plus dedupe:
// the first critical event reaches the webhook, an identical event inside
// the dedupe window does not.
func TestRouterDeliversAndDedupes(t *testing.T) {
	received := make(chan wireEvent, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "dbguard/1.0" {
			t.Errorf("User-Agent = %q, want dbguard/1.0", got)
		}
		var got wireEvent
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
		received <- got
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.AlertsConfig{
		MinSeverity:    "medium",
		DedupWindowSec: 60,
		Sinks:          []config.SinkConfig{{Type: "webhook", URL: srv.URL, Timeout: 2}},
	}
	eng, err := NewEngine(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if got := eng.Name(); got != "router" {
		t.Errorf("Name() = %q, want router", got)
	}
	if got := len(eng.Sinks()); got != 1 {
		t.Fatalf("len(Sinks()) = %d, want 1", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := eng.Dispatch(ctx, criticalEvent("evt-1")); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	select {
	case got := <-received:
		if got.RuleID != "sqli.tautology" || got.Severity != "critical" ||
			got.User != "app" || got.ClientIP != "10.0.0.7" || got.Engine != "postgres" {
			t.Fatalf("unexpected payload: %+v", got)
		}
		if len(got.Actions) != 1 || got.Actions[0] != "alert" {
			t.Errorf("Actions = %v, want [alert]", got.Actions)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook did not receive the critical alert")
	}

	// Identical event inside the window must be collapsed by the router.
	if err := eng.Dispatch(ctx, criticalEvent("evt-1")); err != nil {
		t.Fatalf("Dispatch duplicate: %v", err)
	}
	select {
	case got := <-received:
		t.Fatalf("duplicate alert delivered: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
	if eng.Failures() != 0 {
		t.Errorf("Failures() = %d, want 0", eng.Failures())
	}
	eng.Close()
}

// TestRouterFiltersBelowMinSeverity verifies the severity gate: info events
// are dropped even when alert-worthy by type, medium events pass.
func TestRouterFiltersBelowMinSeverity(t *testing.T) {
	calls := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.AlertsConfig{
		MinSeverity:    "medium",
		DedupWindowSec: 60,
		Sinks:          []config.SinkConfig{{Type: "webhook", URL: srv.URL, Timeout: 2}},
	}
	eng, err := NewEngine(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	info := &events.Event{
		ID: "evt-2", Type: events.EvQueryAudit, Time: time.Now().UTC(),
		Severity: events.SevInfo, Message: "routine query", ClientIP: "10.0.0.9",
	}
	if err := eng.Dispatch(ctx, info); err != nil {
		t.Fatalf("Dispatch info: %v", err)
	}
	select {
	case <-calls:
		t.Fatal("info event was delivered despite min_severity=medium")
	case <-time.After(300 * time.Millisecond):
	}

	// Positive control: a medium event carrying an alert action must pass.
	medium := &events.Event{
		ID: "evt-3", Type: events.EvPIIHit, Time: time.Now().UTC(),
		Severity: events.SevMedium, RuleID: "pii.cc.tables", ClientIP: "10.0.0.9",
		Actions: []events.Action{events.ActAlert},
	}
	if err := eng.Dispatch(ctx, medium); err != nil {
		t.Fatalf("Dispatch medium: %v", err)
	}
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("medium event was filtered unexpectedly")
	}
	eng.Close()
}
