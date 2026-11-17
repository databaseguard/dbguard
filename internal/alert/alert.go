// Package alert defines the sink contract used to deliver notifications
// (webhook, Slack, syslog, file). The concrete routing engine with dedupe
// and severity thresholds lives in internal/alert as well (engine.go).
package alert

import (
	"context"

	"github.com/databaseguard/dbguard/internal/events"
)

// Sink is any component that consumes alert-worthy events.
// Implementations must be safe for concurrent use and should not block the
// pipeline for long (use internal buffering/timeouts).
type Sink interface {
	// Name identifies the sink in logs/metrics.
	Name() string
	// Send delivers one event. Returning an error marks the delivery
	// as failed (counted in metrics, retried according to sink policy).
	Send(ctx context.Context, ev *events.Event) error
}

// DedupKey renders a stable key used to collapse duplicate alerts within a
// time window: same rule + same primary subject.
func DedupKey(ev *events.Event) string {
	subject := ev.ClientIP
	if ev.User != "" {
		subject = subject + "/" + ev.User
	}
	if ev.RuleID == "" {
		return string(ev.Type) + "|" + subject
	}
	return ev.RuleID + "|" + subject + "|" + string(ev.Type)
}

// IsAlertWorthy decides whether an event should be dispatched to sinks:
// it must carry an alert-ish action or be at/above the given severity.
func IsAlertWorthy(ev *events.Event, minSeverity events.Severity) bool {
	if minSeverity.Order() > ev.Severity.Order() {
		return false
	}
	for _, a := range ev.Actions {
		switch a {
		case events.ActAlert, events.ActDeny, events.ActDrop, events.ActReset,
			events.ActKill, events.ActFreeze, events.ActQuarantine:
			return true
		}
	}
	switch ev.Type {
	case events.EvSQLi, events.EvPIIHit, events.EvExfil, events.EvExecve,
		events.EvFileAccess, events.EvIntegrity, events.EvLineage,
		events.EvTenant, events.EvConnAnomaly, events.EvAuthAnomaly:
		return true
	}
	return false
}
