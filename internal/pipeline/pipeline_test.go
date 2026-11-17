package pipeline

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/alert"
	"github.com/databaseguard/dbguard/internal/audit"
	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/enrich"
	"github.com/databaseguard/dbguard/internal/events"
	"github.com/databaseguard/dbguard/internal/policy"
)

// ---- test fakes ----

type fakeResolver struct{}

func (fakeResolver) Resolve(pid uint32, cgroup uint64) enrich.Identity {
	return enrich.Identity{
		PID: pid, CgroupID: cgroup,
		ContainerID: "ctr-abc", PodName: "payments-db-0", Namespace: "prod",
		Labels: map[string]string{"team": "payments"},
	}
}

type fakeRecorder struct {
	mu       sync.Mutex
	events   map[string]int
	findings map[string]int
	actions  map[string]int
	rules    map[string]int
	latencyN int
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{
		events:   map[string]int{},
		findings: map[string]int{},
		actions:  map[string]int{},
		rules:    map[string]int{},
	}
}

func (r *fakeRecorder) IncEvent(t, s string) { r.mu.Lock(); r.events[t+"|"+s]++; r.mu.Unlock() }
func (r *fakeRecorder) IncFinding(m, k string) {
	r.mu.Lock()
	r.findings[m+"|"+k]++
	r.mu.Unlock()
}
func (r *fakeRecorder) IncAction(a string) { r.mu.Lock(); r.actions[a]++; r.mu.Unlock() }
func (r *fakeRecorder) IncRuleMatch(id string) {
	r.mu.Lock()
	r.rules[id]++
	r.mu.Unlock()
}
func (r *fakeRecorder) ObservePipelineLatency(f float64) { r.mu.Lock(); r.latencyN++; r.mu.Unlock() }
func (r *fakeRecorder) SetActiveSessions(int)            {}

type fakeStore struct {
	mu     sync.Mutex
	evs    []*events.Event
	closed bool
}

func (s *fakeStore) Append(_ context.Context, ev *events.Event) error {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

func (s *fakeStore) Query(_ context.Context, f audit.Filter) ([]*events.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*events.Event
	for _, ev := range s.evs {
		if f.Match(ev) {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (s *fakeStore) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

type fakeSink struct {
	mu  sync.Mutex
	evs []*events.Event
}

func (s *fakeSink) Name() string { return "fake" }

func (s *fakeSink) Send(_ context.Context, ev *events.Event) error {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

// piiDetector is a minimal stand-in for the real PII module.
type piiDetector struct{}

func (piiDetector) Name() string { return "pii" }

func (piiDetector) Evaluate(ev *events.Event) []events.Finding {
	if strings.Contains(ev.SQL, "4111111111111111") {
		return []events.Finding{{Kind: "credit_card", Detail: "Luhn-valid PAN in SQL text", Confidence: 0.95}}
	}
	return nil
}

const sqliPolicyYAML = `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: test-sqli
spec:
  default_action: allow
  rules:
    - id: deny-union-select
      name: Union Select Injection
      severity: high
      query:
        pattern: "union.*select"
        case_insensitive: true
      actions:
        - deny
        - alert
`

// newTestPipeline builds a pipeline wired to fakes, backed by a real policy
// engine loaded from a temp dir.
func newTestPipeline(t *testing.T) (*Pipeline, *fakeStore, *fakeSink, *fakeRecorder) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "10-sqli.yaml"), []byte(sqliPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := policy.New(logger)
	if err := eng.SetDirs([]string{dir}, false); err != nil {
		t.Fatalf("policy load: %v", err)
	}
	var cfg config.Config
	cfg.Alerts.MinSeverity = "info"
	cfg.Audit.Enabled = true
	store := &fakeStore{}
	sink := &fakeSink{}
	rec := newFakeRecorder()
	p := NewPipeline(cfg, eng, fakeResolver{}, []detect.Detector{piiDetector{}},
		[]alert.Sink{sink}, store, rec, logger)
	t.Cleanup(func() { _ = p.Close() })
	return p, store, sink, rec
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestPipelineEndToEnd(t *testing.T) {
	p, store, sink, rec := newTestPipeline(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	subCh, unsub := p.Subscribe(16)
	defer unsub()

	sqli := &events.Event{
		ID: "evt-sqli", Type: events.EvQueryAudit, User: "app",
		ClientIP: "10.0.0.9", ClientPort: 55555, ServerPort: 5432,
		Severity: events.SevInfo,
		SQL:      "SELECT id FROM users WHERE name='a' UNION SELECT cc FROM payments",
	}
	pii := &events.Event{
		ID: "evt-pii", Type: events.EvQueryAudit, User: "app",
		ClientIP: "10.0.0.9", ClientPort: 55556, ServerPort: 5432,
		Severity: events.SevInfo,
		SQL:      "SELECT note FROM logs WHERE note='4111111111111111'",
	}
	p.Ingest(sqli)
	p.Ingest(pii)

	var sqliOut, piiOut *events.Event
	waitFor(t, 5*time.Second, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		for _, ev := range store.evs {
			if ev.ID == "evt-sqli" {
				sqliOut = ev
			}
			if ev.ID == "evt-pii" {
				piiOut = ev
			}
		}
		return sqliOut != nil && piiOut != nil
	})

	// stage 2: the injected statement is denied by the union-select rule
	if sqliOut.Allowed {
		t.Fatal("SQLi event must be denied by policy")
	}
	if sqliOut.RuleID != "deny-union-select" || sqliOut.RuleName != "Union Select Injection" {
		t.Fatalf("rule attribution wrong: id=%q name=%q", sqliOut.RuleID, sqliOut.RuleName)
	}
	if !sqliOut.HasAction(events.ActDeny) || !sqliOut.HasAction(events.ActAlert) {
		t.Fatalf("actions wrong: %v", sqliOut.Actions)
	}
	if sqliOut.Severity.Order() < events.SevHigh.Order() {
		t.Fatalf("severity not bumped: %s", sqliOut.Severity)
	}

	// stage 1: engine guessed from port, tables/columns extracted, identity set
	if sqliOut.Engine != "postgres" {
		t.Fatalf("engine not guessed: %q", sqliOut.Engine)
	}
	wantTables := map[string]bool{"users": false, "payments": false}
	for _, tb := range sqliOut.Tables {
		if _, ok := wantTables[tb]; ok {
			wantTables[tb] = true
		}
	}
	for tb, seen := range wantTables {
		if !seen {
			t.Fatalf("table %q missing from %v", tb, sqliOut.Tables)
		}
	}
	if len(sqliOut.Columns) == 0 || sqliOut.Columns[0] != "id" {
		t.Fatalf("columns not extracted: %v", sqliOut.Columns)
	}
	if sqliOut.ContainerID != "ctr-abc" || sqliOut.PodName != "payments-db-0" || sqliOut.Namespace != "prod" {
		t.Fatalf("identity enrichment missing: %+v", sqliOut)
	}
	if want := events.SessionKey("10.0.0.9", 55555, 5432); sqliOut.MetaGet("session_key") != want {
		t.Fatalf("session_key = %q, want %q", sqliOut.MetaGet("session_key"), want)
	}

	// stage 3: PII detector finding on the card-number statement, benign verdict
	found := false
	for _, f := range piiOut.Findings {
		if f.Kind == "credit_card" {
			found = true
		}
	}
	if !found {
		t.Fatalf("credit_card finding missing: %+v", piiOut.Findings)
	}
	if !piiOut.Allowed {
		t.Fatal("benign query must stay allowed")
	}

	// stage 5: only the alert-worthy event reached the sink
	waitFor(t, 5*time.Second, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.evs) == 1
	})
	sink.mu.Lock()
	if sink.evs[0].ID != "evt-sqli" {
		t.Fatalf("sink got wrong event: %s", sink.evs[0].ID)
	}
	sink.mu.Unlock()

	// stage 4: metrics were recorded
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.rules["deny-union-select"] != 1 {
		t.Fatalf("rule match metric missing: %v", rec.rules)
	}
	if rec.actions[string(events.ActDeny)] != 1 {
		t.Fatalf("action metric missing: %v", rec.actions)
	}
	if rec.latencyN == 0 {
		t.Fatal("pipeline latency not observed")
	}

	// subscriber saw both processed events
	seen := 0
	waitFor(t, 5*time.Second, func() bool {
		for {
			select {
			case <-subCh:
				seen++
			default:
				return seen >= 2
			}
		}
	})
	if seen != 2 {
		t.Fatalf("subscriber got %d events, want 2", seen)
	}

	// clean shutdown flushes the store
	cancel()
	_ = p.Close()
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.closed {
		t.Fatal("audit store was not closed")
	}
}

func TestIngestDropsOnOverflow(t *testing.T) {
	p, _, _, rec := newTestPipeline(t) // no Run: nothing drains the queue
	for i := 0; i < ingestBuffer+256; i++ {
		p.Ingest(&events.Event{Type: events.EvQueryAudit})
	}
	rec.mu.Lock()
	dropped := rec.events["dropped|"+string(events.SevInfo)]
	rec.mu.Unlock()
	if dropped == 0 {
		t.Fatalf("expected drops on overflow, got %d", dropped)
	}
}
