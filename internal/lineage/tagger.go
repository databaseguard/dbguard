// Package lineage implements the user-space half of feature 8: app-to-DB
// lineage verification ("which application route issued this query?").
//
// Runtime probes (uprobes into Go/node/JVM HTTP routers and OpenSSL, per
// config.LineageConfig.RuntimeProbes) publish route observations as
// pipeline events carrying Meta["route"] and Meta["pid"]; RouteTagger
// keeps the most recent route per application PID within a staleness
// window (CorrelationWindowSec). Correlator then joins those tags with
// kernel query/lineage verdicts per socket-cookie session, flags unmatched
// routes and pool hijacks, and - when configured - tears the offending
// session down via a hook the daemon wires to the eBPF manager.
package lineage

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

// DefaultCorrelationWindowSec mirrors the internal/config default for
// LineageConfig.CorrelationWindowSec; used when the config value is unset.
const DefaultCorrelationWindowSec = 30

// routeEntry is one PID's latest route observation.
type routeEntry struct {
	route string
	seen  time.Time
}

// RouteTagger maps application PID → last observed HTTP route, expiring
// entries after the correlation window so recycled PIDs and stale tags
// cannot poison the join. Safe for concurrent use.
type RouteTagger struct {
	window time.Duration
	mu     sync.RWMutex
	routes map[uint32]routeEntry
}

// NewRouteTagger builds a tagger with the given staleness window in
// seconds; correlationWindowSec <= 0 selects DefaultCorrelationWindowSec.
func NewRouteTagger(correlationWindowSec int) *RouteTagger {
	w := time.Duration(correlationWindowSec) * time.Second
	if w <= 0 {
		w = DefaultCorrelationWindowSec * time.Second
	}
	return &RouteTagger{window: w, routes: make(map[uint32]routeEntry, 256)}
}

// Window returns the staleness window (exposed for daemon introspection).
func (t *RouteTagger) Window() time.Duration { return t.window }

// SetRoute records route as the latest observation for pid. Zero PIDs and
// empty routes are ignored (they carry no joinable information).
func (t *RouteTagger) SetRoute(pid uint32, route string) {
	if pid == 0 || route == "" {
		return
	}
	t.mu.Lock()
	t.routes[pid] = routeEntry{route: route, seen: time.Now()}
	t.mu.Unlock()
}

// Route returns the latest route for pid if it was observed within the
// staleness window (now is injectable for deterministic tests). Expired
// entries are dropped lazily; a fresh SetRoute racing the drop wins.
func (t *RouteTagger) Route(pid uint32, now time.Time) (string, bool) {
	t.mu.RLock()
	e, ok := t.routes[pid]
	t.mu.RUnlock()
	if !ok {
		return "", false
	}
	if now.Sub(e.seen) <= t.window {
		return e.route, true
	}
	t.mu.Lock()
	if cur, ok := t.routes[pid]; ok && cur.seen.Equal(e.seen) {
		delete(t.routes, pid)
	}
	t.mu.Unlock()
	return "", false
}

// GC drops every entry older than the window; the Correlator runner (or
// the daemon's GC loop) calls it periodically. now is injectable.
func (t *RouteTagger) GC(now time.Time) {
	t.mu.Lock()
	for pid, e := range t.routes {
		if now.Sub(e.seen) > t.window {
			delete(t.routes, pid)
		}
	}
	t.mu.Unlock()
}

// Len returns the number of tracked PIDs (metrics and tests).
func (t *RouteTagger) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.routes)
}

// IngestRuntimeEvent feeds one TLS/app-runtime probe event into the
// tagger. Contract with the runtime probes (wired by the daemon):
//
//   - Any event may carry route context; canonical probes emit
//     Type EvTLSSession (OpenSSL/uprobe) or a dedicated app-runtime event.
//   - Meta["route"] holds the HTTP route / operation tag
//     (e.g. "POST /api/orders"); ev.Route is accepted as fallback.
//   - Meta["pid"] holds the observed application PID (decimal);
//     ev.PID is accepted as fallback.
//
// Events without a resolvable (pid, route) pair are ignored silently so
// unrelated traffic (SNI-only TLS handshakes, kernel-only events) can be
// streamed through without filtering upstream.
func (t *RouteTagger) IngestRuntimeEvent(ev *events.Event) {
	if ev == nil {
		return
	}
	route := ev.MetaGet("route")
	if route == "" {
		route = ev.Route
	}
	if route == "" {
		return
	}
	pid := ev.PID
	if raw := ev.MetaGet("pid"); raw != "" {
		if v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32); err == nil {
			pid = uint32(v)
		}
	}
	if pid == 0 {
		return
	}
	t.SetRoute(pid, route)
}
