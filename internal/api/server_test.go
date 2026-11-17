package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/audit"
	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
	"github.com/databaseguard/dbguard/internal/policy"
)

// ---- fakes ----

type fakeStatus struct{}

func (fakeStatus) Status() map[string]any {
	return map[string]any{"version": "test", "uptime_s": 42}
}

type fakePolicy struct {
	mu       sync.Mutex
	reloaded int
}

func (f *fakePolicy) Policies() []policy.PolicyInfo {
	return []policy.PolicyInfo{{Name: "base", Description: "test", Rules: 2, Default: "allow"}}
}

func (f *fakePolicy) RuleCount() int { return 2 }

func (f *fakePolicy) Reload() error {
	f.mu.Lock()
	f.reloaded++
	f.mu.Unlock()
	return nil
}

func (f *fakePolicy) EvaluateDryRun(ctx *policy.Context) policy.Decision {
	if strings.Contains(strings.ToLower(ctx.SQL), "union select") {
		return policy.Decision{
			Allowed:   false,
			Actions:   []events.Action{events.ActDeny, events.ActAlert},
			RuleIDs:   []string{"deny-union"},
			RuleNames: []string{"No Union Select"},
			Severity:  events.SevHigh,
			Reason:    "matched rule deny-union",
		}
	}
	return policy.Decision{Allowed: true, Severity: events.SevInfo, Reason: "no rule matched"}
}

type fakeStore struct{ evs []*events.Event }

func (s *fakeStore) Append(_ context.Context, ev *events.Event) error {
	s.evs = append(s.evs, ev)
	return nil
}

func (s *fakeStore) Query(_ context.Context, f audit.Filter) ([]*events.Event, error) {
	var out []*events.Event
	for _, ev := range s.evs {
		if f.Match(ev) {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (s *fakeStore) Close() error { return nil }

// newTestServer builds a Server over fakes and serves it via httptest.
func newTestServer(t *testing.T, mutate func(*config.APIConfig), pol PolicyAPI, store audit.Store) (*Server, *httptest.Server) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var cfg config.APIConfig
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg, pol, store, fakeStatus{}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestTokenAuth(t *testing.T) {
	_, ts := newTestServer(t, func(c *config.APIConfig) { c.Token = "s3cret" }, &fakePolicy{}, &fakeStore{})

	// missing token -> 401
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// wrong token -> 401
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", resp.StatusCode)
	}

	// correct token -> 200
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", resp.StatusCode)
	}

	// healthz stays open for probes
	resp, err = http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
	}
}

func TestLoopbackOnlyWithoutToken(t *testing.T) {
	srv, _ := newTestServer(t, nil, &fakePolicy{}, &fakeStore{})
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "203.0.113.9:4444" // external client
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback: got %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback: got %d, want 200", rec.Code)
	}
}

func TestPolicyTestEndpointDenies(t *testing.T) {
	_, ts := newTestServer(t, nil, &fakePolicy{}, &fakeStore{})
	body := strings.NewReader(`{"engine":"postgres","user":"app","sql":"SELECT 1 UNION SELECT 2"}`)
	resp, err := http.Post(ts.URL+"/api/v1/policy/test", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var dec policy.Decision
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		t.Fatal(err)
	}
	if dec.Allowed {
		t.Fatal("malicious SQL must be denied")
	}
	if len(dec.RuleIDs) != 1 || dec.RuleIDs[0] != "deny-union" {
		t.Fatalf("unexpected rule ids: %v", dec.RuleIDs)
	}
}

func TestEventsEndpoint(t *testing.T) {
	store := &fakeStore{evs: []*events.Event{
		{ID: "e1", Type: events.EvQueryAudit, Severity: events.SevInfo, User: "alice"},
		{ID: "e2", Type: events.EvSQLi, Severity: events.SevHigh, User: "bob"},
	}}
	_, ts := newTestServer(t, nil, &fakePolicy{}, store)
	resp, err := http.Get(ts.URL + "/api/v1/events?limit=10&min_severity=info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var out struct {
		Count  int             `json:"count"`
		Events []*events.Event `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Events) != 2 {
		t.Fatalf("count=%d events=%d, want 2/2", out.Count, len(out.Events))
	}
}

func TestSSEStream(t *testing.T) {
	srv, ts := newTestServer(t, nil, &fakePolicy{}, &fakeStore{})

	ch := make(chan *events.Event, 1)
	var mu sync.Mutex
	unsubCalled := false
	ch <- &events.Event{ID: "sse-1", Type: events.EvSQLi, Severity: events.SevHigh}
	srv.SetEventSource(func(buffered int) (<-chan *events.Event, func()) {
		if buffered < 1 {
			t.Errorf("buffered=%d, want >= 1", buffered)
		}
		return ch, func() {
			mu.Lock()
			unsubCalled = true
			mu.Unlock()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	found := ""
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "data: ") {
			found = line
			break
		}
	}
	if !strings.Contains(found, "sse-1") {
		t.Fatalf("SSE frame missing event: %q", found)
	}

	// client disconnect must trigger the unsubscribe hook
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		called := unsubCalled
		mu.Unlock()
		if called {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("unsubscribe hook was not called after disconnect")
}

func TestReloadEndpoint(t *testing.T) {
	pol := &fakePolicy{}
	_, ts := newTestServer(t, nil, pol, &fakeStore{})
	resp, err := http.Post(ts.URL+"/api/v1/policies/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	pol.mu.Lock()
	defer pol.mu.Unlock()
	if pol.reloaded != 1 {
		t.Fatalf("reloaded=%d, want 1", pol.reloaded)
	}
}
