// Correlator joins application route tags with kernel query/lineage
// verdicts (feature 8, decision half). Sessions are keyed by the kernel
// socket cookie (Event.SessionID):
//
//   - EvLineage carries the kernel matcher's verdict in
//     Meta["lineage_flags"] (1 = pooled connection borrowed under an
//     unexpected route, 2 = no application route context at all); the
//     correlator enriches it into lineage.kernel_flag findings.
//   - EvQueryAudit with SessionID != 0 is joined against the tagger and
//     the per-session state: unmatched sessions surface as
//     lineage.unmatched_route after a grace period, rapid route
//     alternation as lineage.pool_hijack (optionally with teardown).
package lineage

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// Finding kinds emitted by this module.
const (
	KindKernelFlag     = "lineage.kernel_flag"
	KindUnmatchedRoute = "lineage.unmatched_route"
	KindPoolHijack     = "lineage.pool_hijack"
)

// DefaultGCInterval is the runner cadence for stale tag/session cleanup.
const DefaultGCInterval = 30 * time.Second

// snippetMax caps SQL evidence in findings.
const snippetMax = 200

// sessionState is the user-space view of one DB session (socket cookie).
type sessionState struct {
	appPID      uint32
	route       string // route currently bound to the session ("" = none yet)
	mismatches  int    // route flips / route-less queries inside the window
	windowStart time.Time
	firstSeen   time.Time
	lastSeen    time.Time
}

// Correlator implements detect.Detector + detect.Runner for feature 8.
// Safe for concurrent use: all session state is guarded by mu; the
// tagger guards its own state.
type Correlator struct {
	cfg    config.LineageConfig
	log    *slog.Logger
	pub    func(*events.Event)
	tagger *RouteTagger
	window time.Duration

	mu            sync.Mutex
	sessionRoutes map[uint64]sessionState
	teardown      func(session uint64, appPID uint32) error

	nowFn func() time.Time // swappable clock for deterministic tests
}

// New builds a Correlator. pub (may be nil) receives synthesized EvLineage
// events for confirmed pool hijacks so enforcement is visible in the event
// stream, not only as a finding on the triggering query.
func New(cfg config.LineageConfig, log *slog.Logger, pub func(*events.Event)) (*Correlator, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.CorrelationWindowSec < 0 {
		return nil, fmt.Errorf("lineage: correlation_window_sec must not be negative")
	}
	if cfg.AllowedRouteMismatch < 0 {
		return nil, fmt.Errorf("lineage: allowed_route_mismatch must not be negative")
	}
	window := time.Duration(cfg.CorrelationWindowSec) * time.Second
	if window <= 0 {
		window = DefaultCorrelationWindowSec * time.Second
	}
	return &Correlator{
		cfg:           cfg,
		log:           log,
		pub:           pub,
		tagger:        NewRouteTagger(cfg.CorrelationWindowSec),
		window:        window,
		sessionRoutes: make(map[uint64]sessionState, 1024),
		nowFn:         time.Now,
	}, nil
}

// Name implements detect.Detector.
func (c *Correlator) Name() string { return "lineage" }

// Tagger exposes the route tagger; the daemon streams runtime probe events
// through Correlator.Tagger().IngestRuntimeEvent(ev).
func (c *Correlator) Tagger() *RouteTagger { return c.tagger }

// SetTeardownFunc wires the teardown hook invoked when a pool hijack is
// confirmed (and TeardownEnabled is set). The daemon typically connects it
// to the eBPF manager (cgroup_skb quarantine map) - see teardown.go. The
// hook is called synchronously and must be fast and non-blocking.
func (c *Correlator) SetTeardownFunc(f func(session uint64, appPID uint32) error) {
	c.mu.Lock()
	c.teardown = f
	c.mu.Unlock()
}

// Evaluate implements detect.Detector.
func (c *Correlator) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	switch ev.Type {
	case events.EvLineage:
		return c.evalKernelVerdict(ev)
	case events.EvQueryAudit:
		if ev.SessionID == 0 {
			return nil
		}
		return c.evalQuery(ev)
	default:
		return nil
	}
}

// evalKernelVerdict enriches the kernel matcher's verdict. Flag semantics
// mirror decodeLineage: 1 → high (pool hijack signal), 2 → medium (missing
// route context), anything else nonzero → medium with a generic detail.
func (c *Correlator) evalKernelVerdict(ev *events.Event) []events.Finding {
	flags, _ := strconv.ParseUint(strings.TrimSpace(ev.MetaGet("lineage_flags")), 10, 32)
	if flags == 0 {
		// Kernel matched fine; refresh our session view if route context
		// traveled with the verdict.
		c.noteSession(ev)
		return nil
	}
	sev := events.SevMedium
	detail := "kernel lineage matcher: query lacks usable application route context"
	switch flags {
	case 1:
		sev = events.SevHigh
		detail = "kernel lineage matcher: pooled connection used under unexpected application route"
	case 2:
		detail = "kernel lineage matcher: query carries no application route context"
	}
	f := events.Finding{
		Kind:       KindKernelFlag,
		Detail:     detail,
		Confidence: 0.9,
		Snippet:    ev.Route,
	}
	ev.AddFinding(f)
	ev.Severity = maxSeverity(ev.Severity, sev)
	ev.AddAction(events.ActAlert)
	if c.cfg.TeardownEnabled {
		ev.AddAction(events.ActReset)
	}
	c.log.Warn("lineage: kernel flag", "flags", flags, "session", ev.SessionID,
		"app_pid", ev.AppPID, "route", ev.Route)
	c.noteSession(ev)
	return []events.Finding{f}
}

// noteSession adopts route context from a kernel lineage event. Kernel
// verdicts are authoritative for their own flagging decisions, so adopting
// a changed route here does not count as a user-space mismatch.
func (c *Correlator) noteSession(ev *events.Event) {
	if ev.SessionID == 0 {
		return
	}
	route := ev.Route
	if route == "" {
		route = ev.MetaGet("route")
	}
	appPID := ev.AppPID
	if appPID == 0 {
		appPID = ev.PID
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.sessionRoutes[ev.SessionID]
	if !ok {
		if route == "" {
			return
		}
		c.sessionRoutes[ev.SessionID] = sessionState{
			appPID: appPID, route: route,
			windowStart: now, firstSeen: now, lastSeen: now,
		}
		return
	}
	if route != "" {
		st.route = route
	}
	if appPID != 0 {
		st.appPID = appPID
	}
	st.lastSeen = now
	c.sessionRoutes[ev.SessionID] = st
}

// evalQuery joins a query audit event against the session table and the
// route tagger:
//
//   - session bound to a route + fresh tag: consistent → touch; tag
//     differs → count a flip and re-arm/flag on pool-hijack threshold.
//   - unbound session + fresh tag: bind (first join is always silent).
//   - no route anywhere: enforce the grace period (first-seen + more than
//     AllowedRouteMismatch route-less queries) before flagging.
func (c *Correlator) evalQuery(ev *events.Event) []events.Finding {
	now := c.now()
	tagged, tagOK := c.tagger.Route(ev.PID, now)

	c.mu.Lock()
	st, haveState := c.sessionRoutes[ev.SessionID]

	var (
		out        []events.Finding
		hijack     *hijackInfo
		doTeardown bool
	)

	switch {
	case haveState && st.route != "":
		if !tagOK || tagged == st.route {
			st.lastSeen = now
			break
		}
		from := st.route
		if st.windowStart.IsZero() || now.Sub(st.windowStart) > c.window {
			st.windowStart = now
			st.mismatches = 0
		}
		st.mismatches++
		st.lastSeen = now
		if st.mismatches <= c.cfg.AllowedRouteMismatch {
			// Tolerated churn (batch endpoints legitimately share pooled
			// connections); adopt the new route for the next comparison.
			st.route = tagged
			break
		}
		appPID := st.appPID
		if appPID == 0 {
			appPID = ev.PID
		}
		st.route = tagged
		st.mismatches = 0 // re-arm: a continuing hijack re-alerts per burst
		st.windowStart = now
		f := events.Finding{
			Kind: KindPoolHijack,
			Detail: fmt.Sprintf(
				"session %d flipped route %q -> %q more than %d time(s) within %s (app pid %d) - connection-pool hijack suspected",
				ev.SessionID, from, tagged, c.cfg.AllowedRouteMismatch, c.window, appPID),
			Confidence: 0.85,
			Snippet:    snippet(ev.SQL),
		}
		ev.AddFinding(f)
		ev.Severity = maxSeverity(ev.Severity, events.SevHigh)
		if c.cfg.TeardownEnabled {
			ev.AddAction(events.ActReset)
			doTeardown = true
		}
		hijack = &hijackInfo{from: from, to: tagged, appPID: appPID}
		out = append(out, f)
		c.log.Warn("lineage: pool hijack", "session", ev.SessionID,
			"from", from, "to", tagged, "app_pid", appPID)

	case tagOK:
		// First time this session can be bound to an application route -
		// never a finding, it is the happy-path join.
		nb := sessionState{
			appPID: ev.PID, route: tagged,
			windowStart: now, firstSeen: now, lastSeen: now,
		}
		if haveState {
			nb.firstSeen = st.firstSeen
			if st.appPID != 0 {
				nb.appPID = st.appPID
			}
		}
		st = nb

	default:
		// No route available from session state or the tagger.
		if !haveState {
			st = sessionState{appPID: ev.PID, windowStart: now, firstSeen: now, lastSeen: now}
		} else {
			if st.windowStart.IsZero() || now.Sub(st.windowStart) > c.window {
				st.windowStart = now
				st.mismatches = 0
			}
			st.mismatches++
			st.lastSeen = now
		}
		if now.Sub(st.firstSeen) <= c.window || st.mismatches <= c.cfg.AllowedRouteMismatch {
			break // inside grace period
		}
		appPID := st.appPID
		if appPID == 0 {
			appPID = ev.PID
		}
		st.mismatches = 0 // re-arm: alert once per window, not once per query
		st.windowStart = now
		f := events.Finding{
			Kind: KindUnmatchedRoute,
			Detail: fmt.Sprintf(
				"session %d (app pid %d) served queries without any application route context for %s",
				ev.SessionID, appPID, now.Sub(st.firstSeen).Round(time.Second)),
			Confidence: 0.7,
			Snippet:    snippet(ev.SQL),
		}
		ev.AddFinding(f)
		ev.Severity = maxSeverity(ev.Severity, events.SevMedium)
		ev.AddAction(events.ActAlert)
		out = append(out, f)
		c.log.Warn("lineage: unmatched route", "session", ev.SessionID, "app_pid", appPID)
	}

	c.sessionRoutes[ev.SessionID] = st
	c.mu.Unlock()

	if hijack != nil {
		if doTeardown {
			c.runTeardown(ev.SessionID, hijack.appPID)
		}
		c.publishHijack(ev, hijack.from, hijack.to, hijack.appPID)
	}
	return out
}

// Run implements detect.Runner: a 30s GC loop drops stale route tags and
// sessions idle for more than twice the correlation window. Returns nil
// on ctx cancellation.
func (c *Correlator) Run(ctx context.Context) error {
	ticker := time.NewTicker(DefaultGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := c.now()
			c.tagger.GC(now)
			c.gcSessions(now)
		}
	}
}

// gcSessions drops sessions idle beyond twice the correlation window;
// such sessions can no longer join anything meaningful.
func (c *Correlator) gcSessions(now time.Time) {
	ttl := 2 * c.window
	c.mu.Lock()
	for s, st := range c.sessionRoutes {
		if now.Sub(st.lastSeen) > ttl {
			delete(c.sessionRoutes, s)
		}
	}
	c.mu.Unlock()
}

// Close implements detect.Runner; it clears the session table and detaches
// the teardown hook (the daemon re-wires it on restart).
func (c *Correlator) Close() error {
	c.mu.Lock()
	c.sessionRoutes = make(map[uint64]sessionState)
	c.teardown = nil
	c.mu.Unlock()
	return nil
}

// now delegates through the swappable clock.
func (c *Correlator) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

// snippet trims SQL used as finding evidence.
func snippet(sql string) string {
	if len(sql) <= snippetMax {
		return sql
	}
	return sql[:snippetMax] + "..."
}

// maxSeverity returns the more severe of a and b.
func maxSeverity(a, b events.Severity) events.Severity {
	if a.Order() >= b.Order() {
		return a
	}
	return b
}
