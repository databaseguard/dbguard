// Package api implements DBGuard's admin REST API: health probes, runtime
// status, policy inspection / reload / dry-run testing, audit event queries
// and a Server-Sent-Events stream wired to the pipeline subscriber fan-out.
//
// Auth is handled by withAuth (bearer token or loopback-only default); all
// routes are additionally wrapped with request logging and panic recovery.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/audit"
	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
	"github.com/databaseguard/dbguard/internal/policy"
)

// StatusProvider exposes component status for /readyz and /api/v1/status.
type StatusProvider interface {
	// Status returns a snapshot of component state (JSON-serialisable values).
	Status() map[string]any
}

// PolicyAPI is the policy-management surface consumed by the admin
// endpoints; implemented by PolicyService around *policy.Engine.
type PolicyAPI interface {
	// Policies lists loaded policy documents.
	Policies() []policy.PolicyInfo
	// RuleCount reports the number of compiled rules.
	RuleCount() int
	// Reload re-reads all configured policy directories.
	Reload() error
	// EvaluateDryRun evaluates a context and returns the verdict.
	EvaluateDryRun(ctx *policy.Context) policy.Decision
}

// PolicyService adapts *policy.Engine to the PolicyAPI interface.
//
// NOTE: the engine does not expose a side-effect-free dry-run; EvaluateDryRun
// delegates to Engine.Evaluate, which also advances the sliding-window rate
// limiter for the subject. Repeated dry-runs of rate-limited rules can
// therefore consume real quota - a documented, accepted trade-off.
type PolicyService struct {
	E *policy.Engine
}

// NewPolicyService wraps an engine for use with NewServer.
func NewPolicyService(e *policy.Engine) PolicyService { return PolicyService{E: e} }

// Policies lists loaded policy documents.
func (s PolicyService) Policies() []policy.PolicyInfo { return s.E.Policies() }

// RuleCount reports the number of compiled rules.
func (s PolicyService) RuleCount() int { return s.E.RuleCount() }

// Reload re-reads configured policy directories.
func (s PolicyService) Reload() error { return s.E.Reload() }

// EvaluateDryRun delegates to Engine.Evaluate (see the type doc for the
// rate-limiter side effect).
func (s PolicyService) EvaluateDryRun(ctx *policy.Context) policy.Decision { return s.E.Evaluate(ctx) }

// Server serves the admin REST API. Construct with NewServer; either use
// Handler() in an existing mux/server or Run for a managed http.Server.
type Server struct {
	cfg    config.APIConfig
	pol    PolicyAPI
	store  audit.Store
	status StatusProvider
	log    *slog.Logger

	mu          sync.Mutex
	eventSource func(buffered int) (<-chan *events.Event, func())

	http *http.Server
}

// NewServer validates the API configuration and returns a ready Server.
// A nil status provider or store is replaced with safe defaults.
func NewServer(cfg config.APIConfig, pol PolicyAPI, store audit.Store, status StatusProvider,
	log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9700"
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, fmt.Errorf("api: tls_cert and tls_key must be configured together")
	}
	if store == nil {
		store = audit.NewNoop()
	}
	return &Server{cfg: cfg, pol: pol, store: store, status: status, log: log}, nil
}

// SetEventSource wires GET /api/v1/events/stream to a subscriber factory -
// typically (*pipeline.Pipeline).Subscribe. The factory must return a
// receive-only channel plus an unsubscribe function. Calling it twice
// replaces the previous hook.
func (s *Server) SetEventSource(hook func(buffered int) (<-chan *events.Event, func())) {
	s.mu.Lock()
	s.eventSource = hook
	s.mu.Unlock()
}

// Handler builds the authenticated, logged, panic-recovering route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/policies", s.handlePolicies)
	mux.HandleFunc("POST /api/v1/policies/reload", s.handleReload)
	mux.HandleFunc("POST /api/v1/policy/test", s.handlePolicyTest)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)
	return withRecovery(s.log, withRequestLog(s.log, withAuth(s.cfg.Token, s.log)(mux)))
}

// Run starts the HTTP(S) server and blocks until ctx is cancelled (graceful
// shutdown with a 5s drain window) or the listener fails.
func (s *Server) Run(ctx context.Context) error {
	s.http = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
			err = s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			err = s.http.ListenAndServe()
		}
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("api: server: %w", err)
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(sctx); err != nil {
			s.log.Warn("api: shutdown incomplete", "err", err)
		}
		return nil
	}
}

// handleHealth is an unauthenticated liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReady reports readiness plus the status snapshot as JSON.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.statusSnapshot())
}

// handleStatus returns the full component status map.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.statusSnapshot())
}

func (s *Server) statusSnapshot() map[string]any {
	if s.status != nil {
		if m := s.status.Status(); m != nil {
			return m
		}
	}
	return map[string]any{"status": "ok"}
}

// handlePolicies lists loaded policy documents and the compiled rule count.
func (s *Server) handlePolicies(w http.ResponseWriter, _ *http.Request) {
	var out struct {
		Policies  []policy.PolicyInfo `json:"policies"`
		RuleCount int                 `json:"rule_count"`
	}
	if s.pol != nil {
		out.Policies = s.pol.Policies()
		out.RuleCount = s.pol.RuleCount()
	}
	if out.Policies == nil {
		out.Policies = []policy.PolicyInfo{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleReload triggers a policy hot reload.
func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
	if s.pol == nil {
		errorJSON(w, http.StatusServiceUnavailable, "policy engine not wired")
		return
	}
	if err := s.pol.Reload(); err != nil {
		errorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "rules": s.pol.RuleCount()})
}

// policyTestRequest is the POST /api/v1/policy/test body.
type policyTestRequest struct {
	Engine   string   `json:"engine"`
	User     string   `json:"user"`
	Database string   `json:"database"`
	ClientIP string   `json:"client_ip"`
	SQL      string   `json:"sql"`
	Tables   []string `json:"tables"`
	Columns  []string `json:"columns"`
}

// handlePolicyTest evaluates an ad-hoc request against the policy engine
// and returns the decision JSON (no enforcement happens here).
func (s *Server) handlePolicyTest(w http.ResponseWriter, r *http.Request) {
	if s.pol == nil {
		errorJSON(w, http.StatusServiceUnavailable, "policy engine not wired")
		return
	}
	var req policyTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	dec := s.pol.EvaluateDryRun(&policy.Context{
		Engine:   req.Engine,
		User:     req.User,
		Database: req.Database,
		ClientIP: req.ClientIP,
		SQL:      req.SQL,
		Tables:   req.Tables,
		Columns:  req.Columns,
		Now:      time.Now(),
	})
	writeJSON(w, http.StatusOK, dec)
}

// handleEvents queries the audit store. Query parameters: limit,
// min_severity, type (comma-separated), user, engine, database, client_ip.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f audit.Filter
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errorJSON(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}
	if f.Limit <= 0 {
		f.Limit = 500
	}
	if f.Limit > 10000 {
		f.Limit = 10000
	}
	if v := q.Get("min_severity"); v != "" {
		f.MinSeverity = events.ParseSeverity(v)
	}
	if v := q.Get("type"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				f.Types = append(f.Types, events.EventType(part))
			}
		}
	}
	f.User = q.Get("user")
	f.Engine = q.Get("engine")
	f.Database = q.Get("database")
	f.ClientIP = q.Get("client_ip")

	evs, err := s.store.Query(r.Context(), f)
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	if evs == nil {
		evs = []*events.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(evs), "events": evs})
}

// handleEventStream serves Server-Sent Events: one "data: {json}" frame per
// processed event, a ": ping" heartbeat every 15s, terminated when the
// client disconnects (which also unsubscribes from the pipeline).
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	src := s.eventSource
	s.mu.Unlock()
	if src == nil {
		errorJSON(w, http.StatusServiceUnavailable, "event source not configured")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		errorJSON(w, http.StatusInternalServerError, "streaming unsupported by transport")
		return
	}
	ch, cancel := src(64)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, ": dbguard event stream\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// writeJSON encodes v with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// errorJSON writes a {"error": ...} envelope.
func errorJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
