// Package metrics - prometheus.go implements the metrics.Recorder contract
// on top of github.com/prometheus/client_golang and serves the registry via
// a minimal HTTP endpoint (cfg.Metrics.Listen / cfg.Metrics.Path / /healthz).
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/databaseguard/dbguard/internal/config"
)

// latencyBuckets cover the expected µs..ms range of pipeline processing.
var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
}

// PromRecorder implements metrics.Recorder with Prometheus collectors and
// exposes them over HTTP. It uses a private registry so DBGuard's metrics
// never collide with a host process default registry.
type PromRecorder struct {
	cfg config.MetricsConfig
	log *slog.Logger
	reg *prometheus.Registry

	eventsTotal     *prometheus.CounterVec
	findingsTotal   *prometheus.CounterVec
	actionsTotal    *prometheus.CounterVec
	ruleMatches     *prometheus.CounterVec
	pipelineLatency prometheus.Histogram
	activeSessions  prometheus.Gauge

	mu     sync.Mutex
	srv    *http.Server
	closed bool
}

// NewPromRecorder builds and registers all collectors. It is always
// functional regardless of cfg.Enabled; the caller decides whether to serve.
func NewPromRecorder(cfg config.MetricsConfig, log *slog.Logger) (*PromRecorder, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9701"
	}
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}
	reg := prometheus.NewRegistry()

	p := &PromRecorder{cfg: cfg, log: log, reg: reg}

	p.eventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "events_total",
		Help: "DBGuard events observed, by event type and severity.",
	}, []string{"type", "severity"})
	p.findingsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "findings_total",
		Help: "Detector findings, by module and finding kind.",
	}, []string{"module", "kind"})
	p.actionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "actions_total",
		Help: "Enforcement actions taken, by action name.",
	}, []string{"action"})
	p.ruleMatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rule_matches_total",
		Help: "Policy rule matches, by rule id.",
	}, []string{"rule"})
	p.pipelineLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_latency_seconds",
		Help:    "End-to-end pipeline processing latency per event.",
		Buckets: latencyBuckets,
	})
	p.activeSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_sessions",
		Help: "Currently tracked database connections/flows.",
	})

	for _, c := range []prometheus.Collector{
		p.eventsTotal, p.findingsTotal, p.actionsTotal,
		p.ruleMatches, p.pipelineLatency, p.activeSessions,
	} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("metrics: register %s: %w", collectorName(c), err)
		}
	}
	return p, nil
}

// collectorName extracts a human-readable name from a collector for error
// messages (desc string or Go type).
func collectorName(c prometheus.Collector) string {
	ch := make(chan *prometheus.Desc, 16)
	go func() {
		c.Describe(ch)
		close(ch)
	}()
	first := ""
	for desc := range ch {
		if desc != nil && first == "" {
			first = desc.String()
		}
	}
	if first != "" {
		return first
	}
	return fmt.Sprintf("%T", c)
}

// Serve blocks until ctx is canceled or the listener fails, exposing
// cfg.Path (Prometheus) and /healthz on cfg.Listen.
func (p *PromRecorder) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(p.cfg.Path, promhttp.HandlerFor(p.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              p.cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	p.mu.Lock()
	p.srv = srv
	p.closed = false
	p.mu.Unlock()

	p.log.Info("metrics: serving", "listen", p.cfg.Listen, "path", p.cfg.Path)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics: serve %s: %w", p.cfg.Listen, err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("metrics: shutdown: %w", err)
		}
		return nil
	}
}

// Close force-stops the HTTP server if Serve has not shut it down already.
func (p *PromRecorder) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv == nil || p.closed {
		return nil
	}
	p.closed = true
	return p.srv.Close()
}

// IncEvent counts one event of the given type/severity.
func (p *PromRecorder) IncEvent(eventType, severity string) {
	p.eventsTotal.WithLabelValues(eventType, severity).Inc()
}

// IncFinding counts one detector finding.
func (p *PromRecorder) IncFinding(module, kind string) {
	p.findingsTotal.WithLabelValues(module, kind).Inc()
}

// IncAction counts an enforcement action.
func (p *PromRecorder) IncAction(action string) {
	p.actionsTotal.WithLabelValues(action).Inc()
}

// IncRuleMatch counts a policy rule match.
func (p *PromRecorder) IncRuleMatch(ruleID string) {
	p.ruleMatches.WithLabelValues(ruleID).Inc()
}

// ObservePipelineLatency records pipeline processing latency in seconds.
func (p *PromRecorder) ObservePipelineLatency(seconds float64) {
	p.pipelineLatency.Observe(seconds)
}

// SetActiveSessions reports the current tracked connection count.
func (p *PromRecorder) SetActiveSessions(n int) {
	p.activeSessions.Set(float64(n))
}
