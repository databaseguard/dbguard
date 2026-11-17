// Package detect defines the detector contract implemented by every DBGuard
// analysis module (pii, sqli, anomaly, exfil, rids, lineage, tenant).
//
// A Detector is invoked synchronously by the pipeline for each enriched
// event; it returns findings and may attach decided actions directly on the
// event. Detectors that need background work (window sweeps, responders,
// hash checks) additionally implement Runner so the daemon can start/stop
// them.
package detect

import (
	"context"

	"github.com/databaseguard/dbguard/internal/events"
)

// Detector inspects an event and returns findings. Implementations must be
// safe for concurrent use (the pipeline is multi-goroutine).
type Detector interface {
	// Name returns the module identifier used in logs/metrics ("pii", ...).
	Name() string
	// Evaluate inspects the event. Returning findings is enough for
	// observability-only modules; enforcement modules additionally call
	// ev.AddAction(...) with the enforcement decision.
	Evaluate(ev *events.Event) []events.Finding
}

// Runner is implemented by modules with background loops.
type Runner interface {
	Run(ctx context.Context) error
	Close() error
}

// Registry holds the active detectors in pipeline order.
type Registry struct {
	detectors []Detector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a detector.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// All returns registered detectors in order.
func (r *Registry) All() []Detector { return r.detectors }
