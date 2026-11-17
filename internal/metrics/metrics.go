// Package metrics defines the Recorder contract used across DBGuard plus a
// no-op implementation. The concrete Prometheus-backed recorder lives in
// metrics/prometheus.go.
package metrics

// Recorder is the telemetry interface consumed by the pipeline and modules.
// Implementations must be safe for concurrent use and never panic.
type Recorder interface {
	// IncEvent counts one event of the given type/severity.
	IncEvent(eventType, severity string)
	// IncFinding counts one detector finding.
	IncFinding(module, kind string)
	// IncAction counts an enforcement action.
	IncAction(action string)
	// IncRuleMatch counts a policy rule match.
	IncRuleMatch(ruleID string)
	// ObservePipelineLatency records pipeline processing latency seconds.
	ObservePipelineLatency(seconds float64)
	// SetActiveSessions reports the current tracked connection count.
	SetActiveSessions(n int)
}

// Noop discards all metrics; used when telemetry is disabled.
type Noop struct{}

// NewNoop returns the discard recorder.
func NewNoop() *Noop { return &Noop{} }

func (Noop) IncEvent(string, string)        {}
func (Noop) IncFinding(string, string)      {}
func (Noop) IncAction(string)               {}
func (Noop) IncRuleMatch(string)            {}
func (Noop) ObservePipelineLatency(float64) {}
func (Noop) SetActiveSessions(int)          {}
