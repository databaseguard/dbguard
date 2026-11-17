// Package alert - engine.go implements the alerting router: it filters
// events by severity and alert-worthiness, collapses duplicates inside a
// configurable window and fans every alert out to the configured sinks
// (webhook, Slack, syslog, file) concurrently with a hard per-sink timeout.
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// deliveryTimeout caps every per-sink delivery regardless of the sink's own
// HTTP/UDP timeouts, so one slow endpoint can never stall the pipeline.
const deliveryTimeout = 5 * time.Second

// maxDedupEntries bounds the dedupe map; once reached, expired entries are
// swept to keep memory flat during alert floods.
const maxDedupEntries = 4096

// routed pairs a sink with the per-sink severity floor derived from
// SinkConfig.MinSev (0 when unset, i.e. accept everything the router passes).
type routed struct {
	sink     Sink
	minOrder int
}

// Engine routes alert-worthy events to all configured sinks. It implements
// alert.Sink itself (Name "router") so the pipeline treats it like any other
// consumer. Construct with NewEngine; the zero value is not usable.
type Engine struct {
	log      *slog.Logger
	minSev   events.Severity
	window   time.Duration
	sinks    []routed
	failures atomic.Uint64

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewEngine builds the router from cfg.Sinks using the sink factory. A
// misconfigured sink is fatal: silently dropping security alerts would be
// worse than refusing to start.
func NewEngine(cfg config.AlertsConfig, log *slog.Logger) (*Engine, error) {
	if log == nil {
		log = slog.Default()
	}
	window := time.Duration(cfg.DedupWindowSec) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}
	e := &Engine{
		log:    log,
		minSev: events.ParseSeverity(cfg.MinSeverity),
		window: window,
		seen:   make(map[string]time.Time, 64),
	}
	for i, sc := range cfg.Sinks {
		s, err := buildSink(sc, log)
		if err != nil {
			return nil, fmt.Errorf("alert: sink[%d] type=%s: %w", i, sc.Type, err)
		}
		e.sinks = append(e.sinks, routed{sink: s, minOrder: events.ParseSeverity(sc.MinSev).Order()})
	}
	return e, nil
}

// buildSink is the sink factory mapping SinkConfig.Type onto a concrete Sink.
func buildSink(cfg config.SinkConfig, log *slog.Logger) (Sink, error) {
	switch cfg.Type {
	case "webhook":
		return NewWebhook(cfg, log)
	case "slack":
		return NewSlack(cfg, log)
	case "syslog":
		return NewSyslog(cfg, log)
	case "file":
		return NewFile(cfg, log)
	default:
		return nil, fmt.Errorf("alert: unknown sink type %q (want webhook|slack|syslog|file)", cfg.Type)
	}
}

// Name implements Sink; the router identifies as "router" in logs/metrics.
func (e *Engine) Name() string { return "router" }

// Send implements Sink. Events below the configured severity floor or not
// alert-worthy are dropped; duplicates inside the dedupe window are collapsed
// (same rule + same primary subject, per alert.DedupKey). Surviving events
// are delivered to every eligible sink concurrently.
func (e *Engine) Send(ctx context.Context, ev *events.Event) error {
	if ev == nil {
		return nil
	}
	if !IsAlertWorthy(ev, e.minSev) {
		return nil
	}

	key := DedupKey(ev)
	e.mu.Lock()
	if t, ok := e.seen[key]; ok && time.Since(t) < e.window {
		e.mu.Unlock()
		return nil // duplicate inside the dedupe window
	}
	e.seen[key] = time.Now()
	if len(e.seen) >= maxDedupEntries {
		e.sweepLocked()
	}
	e.mu.Unlock()

	e.deliver(ctx, ev)
	return nil
}

// sweepLocked drops expired dedupe entries; caller must hold e.mu.
func (e *Engine) sweepLocked() {
	now := time.Now()
	for k, t := range e.seen {
		if now.Sub(t) >= e.window {
			delete(e.seen, k)
		}
	}
}

// deliver fans the event out to every eligible sink concurrently. Each
// delivery runs under a 5s context deadline; failures are counted and logged
// but never abort the fan-out or propagate to the caller.
func (e *Engine) deliver(ctx context.Context, ev *events.Event) {
	var wg sync.WaitGroup
	for _, r := range e.sinks {
		if ev.Severity.Order() < r.minOrder {
			continue // per-sink severity floor
		}
		wg.Add(1)
		go func(r routed) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
			defer cancel()
			if err := r.sink.Send(dctx, ev); err != nil {
				e.failures.Add(1)
				e.log.Warn("alert: delivery failed",
					"sink", r.sink.Name(), "event", ev.ID, "error", err)
			}
		}(r)
	}
	wg.Wait()
}

// Dispatch is an alias for Send kept for pipeline readability at call sites.
func (e *Engine) Dispatch(ctx context.Context, ev *events.Event) error {
	return e.Send(ctx, ev)
}

// Sinks returns the configured sinks (a copy; safe to iterate).
func (e *Engine) Sinks() []Sink {
	out := make([]Sink, 0, len(e.sinks))
	for _, r := range e.sinks {
		out = append(out, r.sink)
	}
	return out
}

// Failures reports how many sink deliveries failed since engine start.
func (e *Engine) Failures() uint64 { return e.failures.Load() }

// Close releases every sink implementing Close (currently the file sink).
func (e *Engine) Close() {
	for _, r := range e.sinks {
		if c, ok := r.sink.(interface{ Close() error }); ok {
			if err := c.Close(); err != nil {
				e.log.Warn("alert: sink close failed", "sink", r.sink.Name(), "error", err)
			}
		}
	}
}

// wireEvent is the canonical JSON alert payload shared by all sinks
// (webhook body, syslog message, Slack attachment fields).
type wireEvent struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	RuleID   string    `json:"rule_id,omitempty"`
	Message  string    `json:"message,omitempty"`
	SQL      string    `json:"sql,omitempty"`
	User     string    `json:"user,omitempty"`
	Database string    `json:"database,omitempty"`
	ClientIP string    `json:"client_ip,omitempty"`
	Engine   string    `json:"engine,omitempty"`
	Actions  []string  `json:"actions,omitempty"`
}

// renderEvent converts a pipeline event into the wire payload.
func renderEvent(ev *events.Event) wireEvent {
	actions := make([]string, 0, len(ev.Actions))
	for _, a := range ev.Actions {
		actions = append(actions, string(a))
	}
	return wireEvent{
		ID:       ev.ID,
		Type:     string(ev.Type),
		Time:     ev.Time,
		Severity: string(ev.Severity),
		RuleID:   ev.RuleID,
		Message:  ev.Message,
		SQL:      ev.SQL,
		User:     ev.User,
		Database: ev.Database,
		ClientIP: ev.ClientIP,
		Engine:   ev.Engine,
		Actions:  actions,
	}
}

// snippet truncates s to at most max runes, appending an ellipsis marker.
func snippet(s string, max int) string {
	if len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}
