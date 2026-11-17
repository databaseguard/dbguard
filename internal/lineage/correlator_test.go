package lineage

import (
	"strings"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// newTestCorrelator builds a correlator with a deterministic clock frozen
// at "base" (tests advance it by reassigning c.nowFn) and captures
// synthesized events through pub.
func newTestCorrelator(t *testing.T, mutate func(*config.LineageConfig)) (*Correlator, *[]*events.Event) {
	t.Helper()
	cfg := config.LineageConfig{
		Enabled:              true,
		CorrelationWindowSec: 60,
		AllowedRouteMismatch: 2,
		TeardownEnabled:      true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	var published []*events.Event
	c, err := New(cfg, nil, func(ev *events.Event) { published = append(published, ev) })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, &published
}

func queryEvent(pid uint32, session uint64, sql string) *events.Event {
	return &events.Event{
		ID:        events.NewID(),
		Type:      events.EvQueryAudit,
		Time:      time.Now(),
		PID:       pid,
		SessionID: session,
		SQL:       sql,
		Engine:    "postgres",
	}
}

func TestCorrelatorRouteJoinNoFinding(t *testing.T) {
	c, published := newTestCorrelator(t, nil)
	base := time.Now()
	c.tagger.SetRoute(111, "GET /api/users")
	c.nowFn = func() time.Time { return base }

	for i := 0; i < 3; i++ {
		ev := queryEvent(111, 42, "SELECT * FROM users")
		if fs := c.Evaluate(ev); len(fs) != 0 {
			t.Fatalf("joined query #%d must be silent, got %+v", i+1, fs)
		}
	}
	if len(*published) != 0 {
		t.Errorf("nothing must be published for clean joins, got %d events", len(*published))
	}
	if c.Name() != "lineage" {
		t.Errorf("Name() = %q, want lineage", c.Name())
	}
}

func TestCorrelatorUnmatchedRouteAfterGrace(t *testing.T) {
	c, published := newTestCorrelator(t, func(lc *config.LineageConfig) {
		lc.AllowedRouteMismatch = 1
	})
	// A route tag exists but will be stale long before the queries run:
	// the tagger stamps real time.Now, the correlator clock jumps ahead.
	base := time.Now()
	c.tagger.SetRoute(9, "GET /stale")
	t0 := base.Add(5 * time.Minute)
	now := t0
	c.nowFn = func() time.Time { return now }

	ev1 := queryEvent(9, 7, "SELECT 1")
	if fs := c.Evaluate(ev1); len(fs) != 0 {
		t.Fatalf("first route-less query (grace period) must be silent, got %+v", fs)
	}
	now = t0.Add(70 * time.Second)
	ev2 := queryEvent(9, 7, "SELECT 2")
	if fs := c.Evaluate(ev2); len(fs) != 0 {
		t.Fatalf("route-less query within AllowedRouteMismatch must be silent, got %+v", fs)
	}
	now = t0.Add(80 * time.Second)
	ev3 := queryEvent(9, 7, "SELECT 3")
	fs := c.Evaluate(ev3)
	if len(fs) != 1 || fs[0].Kind != KindUnmatchedRoute {
		t.Fatalf("expected one %s finding after grace, got %+v", KindUnmatchedRoute, fs)
	}
	if ev3.Severity != events.SevMedium {
		t.Errorf("unmatched route must be medium severity, got %q", ev3.Severity)
	}
	if !ev3.HasAction(events.ActAlert) {
		t.Errorf("unmatched route must attach ActAlert, got %v", ev3.Actions)
	}
	if !strings.Contains(fs[0].Detail, "session 7") {
		t.Errorf("detail should name the session, got %q", fs[0].Detail)
	}
	if len(*published) != 0 {
		t.Errorf("unmatched route is reported on the query event only, got %d published", len(*published))
	}
}

func TestCorrelatorPoolHijackTeardown(t *testing.T) {
	c, published := newTestCorrelator(t, nil) // AllowedRouteMismatch=2, teardown on
	ledger := NewInMemoryLedger(0)
	c.SetTeardownFunc(ledger.Hook(nil))

	base := time.Now()
	c.nowFn = func() time.Time { return base }

	// Bind: first join is always silent.
	c.tagger.SetRoute(200, "POST /api/orders")
	if fs := c.Evaluate(queryEvent(200, 777, "SELECT * FROM orders")); len(fs) != 0 {
		t.Fatalf("binding query must be silent, got %+v", fs)
	}

	// Two tolerated flips (<= AllowedRouteMismatch) stay silent.
	c.tagger.SetRoute(200, "GET /api/health")
	if fs := c.Evaluate(queryEvent(200, 777, "SELECT 1")); len(fs) != 0 {
		t.Fatalf("first flip within allowance must be silent, got %+v", fs)
	}
	c.tagger.SetRoute(200, "GET /api/metrics")
	if fs := c.Evaluate(queryEvent(200, 777, "SELECT 2")); len(fs) != 0 {
		t.Fatalf("second flip within allowance must be silent, got %+v", fs)
	}

	// Third flip exceeds the allowance → pool hijack + teardown.
	c.tagger.SetRoute(200, "GET /admin/secret")
	ev := queryEvent(200, 777, "SELECT * FROM secrets")
	fs := c.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindPoolHijack {
		t.Fatalf("expected one %s finding, got %+v", KindPoolHijack, fs)
	}
	if ev.Severity != events.SevHigh {
		t.Errorf("pool hijack must be high severity, got %q", ev.Severity)
	}
	if !ev.HasAction(events.ActReset) {
		t.Errorf("teardown_enabled must attach ActReset, got %v", ev.Actions)
	}
	if ledger.Len() != 1 {
		t.Fatalf("teardown hook must be called exactly once, got %d", ledger.Len())
	}
	recs := ledger.Records()
	if recs[0].Session != 777 || recs[0].AppPID != 200 || recs[0].Err != "" {
		t.Errorf("bad teardown record: %+v", recs[0])
	}
	if len(*published) != 1 {
		t.Fatalf("hijack must publish one synthesized event, got %d", len(*published))
	}
	pub := (*published)[0]
	if pub.Type != events.EvLineage || pub.Source != "lineage" || pub.Severity != events.SevHigh {
		t.Errorf("bad synthesized event: type=%s source=%s sev=%s", pub.Type, pub.Source, pub.Severity)
	}
	if pub.SessionID != 777 || pub.AppPID != 200 || pub.MetaGet("hijack") != "1" {
		t.Errorf("synthesized event must carry session/app pid/hijack meta: %+v", pub)
	}
	if !strings.Contains(pub.Message, "777") {
		t.Errorf("synthesized message should name the session, got %q", pub.Message)
	}
}

func TestCorrelatorKernelFlagEnrich(t *testing.T) {
	c, published := newTestCorrelator(t, nil) // TeardownEnabled=true

	// Flag 1 (pool hijack signal) → high + alert + reset.
	ev1 := &events.Event{ID: events.NewID(), Type: events.EvLineage, Time: time.Now(),
		SessionID: 5, AppPID: 300, Route: "POST /api/orders", Severity: events.SevInfo}
	ev1.MetaSet("lineage_flags", "1")
	fs := c.Evaluate(ev1)
	if len(fs) != 1 || fs[0].Kind != KindKernelFlag {
		t.Fatalf("expected one %s finding, got %+v", KindKernelFlag, fs)
	}
	if ev1.Severity != events.SevHigh {
		t.Errorf("flag 1 must escalate to high, got %q", ev1.Severity)
	}
	if !ev1.HasAction(events.ActAlert) || !ev1.HasAction(events.ActReset) {
		t.Errorf("flag 1 actions: got %v, want alert+reset (teardown enabled)", ev1.Actions)
	}

	// Flag 2 (no route context) → medium, still alert+reset per config.
	ev2 := &events.Event{ID: events.NewID(), Type: events.EvLineage, Time: time.Now(),
		SessionID: 6, AppPID: 301, Severity: events.SevInfo}
	ev2.MetaSet("lineage_flags", "2")
	if fs := c.Evaluate(ev2); len(fs) != 1 || ev2.Severity != events.SevMedium {
		t.Fatalf("flag 2 must yield one medium finding, got %+v / sev %q", fs, ev2.Severity)
	}

	// Flag 0 (kernel matched fine) → silent.
	ev3 := &events.Event{ID: events.NewID(), Type: events.EvLineage, Time: time.Now(),
		SessionID: 7, AppPID: 302, Route: "GET /ok"}
	ev3.MetaSet("lineage_flags", "0")
	if fs := c.Evaluate(ev3); len(fs) != 0 || len(ev3.Actions) != 0 {
		t.Fatalf("flag 0 must stay silent, got %+v / %v", fs, ev3.Actions)
	}
	if len(*published) != 0 {
		t.Errorf("kernel verdict enrichment must not publish events, got %d", len(*published))
	}
}

func TestCorrelatorTeardownNotWiredIsTolerated(t *testing.T) {
	c, published := newTestCorrelator(t, nil)
	c.SetTeardownFunc(DefaultTeardown(nil)) // passive fallback: records + error

	base := time.Now()
	c.nowFn = func() time.Time { return base }
	c.tagger.SetRoute(500, "GET /a")
	if fs := c.Evaluate(queryEvent(500, 900, "SELECT 1")); len(fs) != 0 {
		t.Fatalf("bind must be silent, got %+v", fs)
	}
	// Three flips with allowance 2 → hijack; the failing hook must not
	// change the finding, only log.
	c.tagger.SetRoute(500, "GET /b")
	c.Evaluate(queryEvent(500, 900, "SELECT 2"))
	c.tagger.SetRoute(500, "GET /c")
	c.Evaluate(queryEvent(500, 900, "SELECT 3"))
	c.tagger.SetRoute(500, "GET /a")
	ev := queryEvent(500, 900, "SELECT 4")
	fs := c.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindPoolHijack {
		t.Fatalf("expected pool hijack finding, got %+v", fs)
	}
	if len(*published) != 1 {
		t.Errorf("expected one synthesized event, got %d", len(*published))
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
