// Package audit defines the durable audit-store contract. The pipeline
// appends every decision-worthy event; operators query via CLI/API.
// The shipped implementation is a rotating JSONL store (SIEM-friendly);
// alternative backends can implement Store.
package audit

import (
	"context"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

// Store is a durable, append-oriented event sink with query support.
type Store interface {
	// Append persists one event. Must be safe for concurrent use.
	Append(ctx context.Context, ev *events.Event) error
	// Query returns matching events ordered by time ascending.
	Query(ctx context.Context, f Filter) ([]*events.Event, error)
	// Close flushes and releases resources.
	Close() error
}

// Filter selects events for Query.
type Filter struct {
	After       time.Time          `json:"after"`
	Before      time.Time          `json:"before"`
	Types       []events.EventType `json:"types,omitempty"`
	Severities  []events.Severity  `json:"severities,omitempty"`
	Engine      string             `json:"engine,omitempty"`
	User        string             `json:"user,omitempty"`
	Database    string             `json:"database,omitempty"`
	ClientIP    string             `json:"client_ip,omitempty"`
	MinSeverity events.Severity    `json:"min_severity,omitempty"`
	Limit       int                `json:"limit,omitempty"`
}

// Match reports whether ev satisfies the filter.
func (f Filter) Match(ev *events.Event) bool {
	if !f.After.IsZero() && ev.Time.Before(f.After) {
		return false
	}
	if !f.Before.IsZero() && ev.Time.After(f.Before) {
		return false
	}
	if len(f.Types) > 0 {
		ok := false
		for _, t := range f.Types {
			if t == ev.Type {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.MinSeverity != "" && ev.Severity.Order() < f.MinSeverity.Order() {
		return false
	}
	if f.Engine != "" && ev.Engine != f.Engine {
		return false
	}
	if f.User != "" && ev.User != f.User {
		return false
	}
	if f.Database != "" && ev.Database != f.Database {
		return false
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	return true
}

// NoopStore discards everything; used when auditing is disabled.
type NoopStore struct{}

// NewNoop returns the discard store.
func NewNoop() *NoopStore { return &NoopStore{} }

// Append is a no-op.
func (NoopStore) Append(context.Context, *events.Event) error { return nil }

// Query returns no events.
func (NoopStore) Query(context.Context, Filter) ([]*events.Event, error) {
	return nil, nil
}

// Close is a no-op.
func (NoopStore) Close() error { return nil }
