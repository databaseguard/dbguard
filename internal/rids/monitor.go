// Package rids implements the user-space half of DBGuard's runtime
// intrusion detection system (feature 3).
//
// Kernel probes (LSM execve / file-open hooks, see internal/ebpf) stream
// EvExecve and EvFileAccess events into the pipeline; Monitor matches them
// against the configured policy - blocked binaries and protected path
// prefixes - and attaches findings plus enforcement actions. The actual
// enforcement primitives (SIGKILL, cgroup v2 freeze, quarantine tracking)
// live in the Responder and are executed either via Monitor.Enforce or by
// the daemon after the pipeline verdict.
//
// The optional file-integrity monitor baselines the database data
// directories and periodically re-hashes them; changes are synthesized as
// EvIntegrity events (Meta: path, old_hash, new_hash) and re-enter the
// pipeline through the pub callback, where Evaluate attaches the final
// finding and ActAlert.
package rids

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// Finding kinds emitted by this module.
const (
	KindBlockedExec   = "rids.blocked_exec"
	KindProtectedFile = "rids.protected_file"
	KindFIMChange     = "rids.fim_change"
)

const (
	// DefaultFIMIntervalSec is applied when cfg.FIM.IntervalSec is unset
	// (mirrors internal/config defaults).
	DefaultFIMIntervalSec = 300
	// DefaultQuarantineTTL is the quarantine window applied by Enforce.
	DefaultQuarantineTTL = 5 * time.Minute
	// snippetMax caps evidence snippets attached to findings.
	snippetMax = 256
)

// Monitor is the RIDS pipeline module: it implements detect.Detector
// (synchronous evaluation of kernel events) and detect.Runner (the
// file-integrity sweep loop). It is safe for concurrent use; all mutable
// state is either immutable-after-construction or guarded inside
// Responder / the Run goroutine.
type Monitor struct {
	cfg  config.RIDSConfig
	log  *slog.Logger
	pub  func(*events.Event)
	resp *Responder
}

// New builds a Monitor from the RIDS config. pub is the callback used to
// inject synthesized events (FIM integrity changes) into the pipeline; it
// may be nil, in which case integrity changes are logged only.
func New(cfg config.RIDSConfig, log *slog.Logger, pub func(*events.Event)) (*Monitor, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxPathLen < 0 {
		return nil, fmt.Errorf("rids: invalid config: max_path_len must not be negative")
	}
	if cfg.FIM.IntervalSec < 0 {
		return nil, fmt.Errorf("rids: invalid config: fim.interval_sec must not be negative")
	}
	if cfg.FIM.IntervalSec == 0 {
		cfg.FIM.IntervalSec = DefaultFIMIntervalSec
	}
	return &Monitor{cfg: cfg, log: log, pub: pub, resp: NewResponder()}, nil
}

// Name implements detect.Detector.
func (m *Monitor) Name() string { return "rids" }

// Responder exposes the enforcement primitives so the daemon can wire them
// to its own control paths (API endpoints, manual quarantine release).
func (m *Monitor) Responder() *Responder { return m.resp }

// Evaluate implements detect.Detector. It inspects execve, file-access and
// integrity events and attaches findings/actions to ev in place.
func (m *Monitor) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	switch ev.Type {
	case events.EvExecve:
		return m.evalExec(ev)
	case events.EvFileAccess:
		return m.evalFile(ev)
	case events.EvIntegrity:
		return m.evalIntegrity(ev)
	default:
		return nil
	}
}

// evalExec flags executions of policy-blocked binaries. A rule matches the
// full path or the base name ("sh" catches "/bin/sh" and "/usr/bin/sh").
func (m *Monitor) evalExec(ev *events.Event) []events.Finding {
	path := ev.MetaGet("path")
	if path == "" || m.truncated(path) {
		return nil
	}
	rule, blocked := m.matchBlocked(path)
	if !blocked {
		return nil
	}
	argv := ev.MetaGet("argv")
	f := events.Finding{
		Kind: KindBlockedExec,
		Detail: fmt.Sprintf("blocked binary %q matches rule %q (pid %d, comm %q): argv=[%s]",
			path, rule, ev.PID, commLabel(ev), argv),
		Confidence: 1.0,
		Severity:   events.SevCritical,
		Snippet:    truncate(argv, snippetMax),
	}
	ev.AddFinding(f)
	ev.Severity = maxSeverity(ev.Severity, events.SevCritical)
	if m.cfg.AlertOnly {
		ev.AddAction(events.ActAlert)
	} else {
		ev.AddAction(events.ActKill)
		ev.AddAction(events.ActQuarantine)
	}
	m.log.Warn("rids: blocked exec",
		"pid", ev.PID, "path", path, "rule", rule, "alert_only", m.cfg.AlertOnly)
	return []events.Finding{f}
}

// evalFile flags accesses under protected path prefixes (the database data
// directories and credentials that must never be touched by stray tooling).
func (m *Monitor) evalFile(ev *events.Event) []events.Finding {
	path := ev.MetaGet("path")
	if path == "" || m.truncated(path) {
		return nil
	}
	prefix := m.matchProtected(path)
	if prefix == "" {
		return nil
	}
	f := events.Finding{
		Kind: KindProtectedFile,
		Detail: fmt.Sprintf("access to protected path %q matches policy prefix %q (pid %d, comm %q)",
			path, prefix, ev.PID, commLabel(ev)),
		Confidence: 1.0,
		Severity:   events.SevHigh,
		Snippet:    truncate(path, snippetMax),
	}
	ev.AddFinding(f)
	ev.Severity = maxSeverity(ev.Severity, events.SevHigh)
	if m.cfg.AlertOnly {
		ev.AddAction(events.ActAlert)
	} else {
		ev.AddAction(events.ActDeny)
		ev.AddAction(events.ActFreeze)
	}
	m.log.Warn("rids: protected file access",
		"pid", ev.PID, "path", path, "prefix", prefix, "alert_only", m.cfg.AlertOnly)
	return []events.Finding{f}
}

// evalIntegrity turns a file-integrity event (synthesized by Run, or
// relayed from a peer instance) into the canonical FIM finding.
func (m *Monitor) evalIntegrity(ev *events.Event) []events.Finding {
	path := ev.MetaGet("path")
	f := events.Finding{
		Kind: KindFIMChange,
		Detail: fmt.Sprintf("file-integrity change on %q (old hash %q, new hash %q)",
			path, ev.MetaGet("old_hash"), ev.MetaGet("new_hash")),
		Confidence: 1.0,
		Severity:   events.SevCritical,
		Snippet:    truncate(path, snippetMax),
	}
	ev.AddFinding(f)
	ev.Severity = events.SevCritical
	ev.AddAction(events.ActAlert)
	m.log.Warn("rids: file integrity change", "path", path,
		"old_hash", ev.MetaGet("old_hash"), "new_hash", ev.MetaGet("new_hash"))
	return []events.Finding{f}
}

// matchBlocked returns the matched rule, if any. Exact full-path equality
// and base-name equality both count ("sh" and "/bin/sh" are equivalent).
func (m *Monitor) matchBlocked(path string) (string, bool) {
	base := filepath.Base(path)
	for _, rule := range m.cfg.BlockedBinaries {
		if rule == "" {
			continue
		}
		if rule == path || filepath.Base(rule) == base {
			return rule, true
		}
	}
	return "", false
}

// matchProtected returns the longest protected prefix covering path.
func (m *Monitor) matchProtected(path string) string {
	best := ""
	for _, p := range m.cfg.ProtectedPaths {
		if len(p) <= len(best) || !pathPrefixMatch(path, p) {
			continue
		}
		best = p
	}
	return best
}

// pathPrefixMatch is boundary-aware: /var/lib/se does not match
// /var/lib/secret, avoiding policy bypasses via sibling directories.
func pathPrefixMatch(path, prefix string) bool {
	if prefix == "" || !strings.HasPrefix(path, prefix) {
		return false
	}
	if strings.HasSuffix(prefix, "/") || len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// truncated reports whether the kernel likely truncated the path (the
// wire format caps paths at cfg.MaxPathLen). Matching on a truncated path
// would produce unreliable verdicts, so such events are ignored.
func (m *Monitor) truncated(path string) bool {
	return m.cfg.MaxPathLen > 0 && len(path) >= m.cfg.MaxPathLen
}

// Enforce executes the enforcement decisions Evaluate attached to ev
// (ActKill, ActQuarantine, ActFreeze). The daemon calls it after the
// pipeline so verdicts and side effects stay decoupled; a frozen cgroup
// stays frozen until an operator (or another control path) calls Thaw.
func (m *Monitor) Enforce(ev *events.Event) error {
	if ev == nil || ev.PID == 0 {
		return nil
	}
	var errs []error
	if ev.HasAction(events.ActKill) {
		if err := m.resp.Kill(ev.PID); err != nil {
			errs = append(errs, fmt.Errorf("rids: kill pid %d: %w", ev.PID, err))
		}
	}
	if ev.HasAction(events.ActQuarantine) {
		if err := m.resp.Quarantine(ev.PID, DefaultQuarantineTTL); err != nil {
			errs = append(errs, fmt.Errorf("rids: quarantine pid %d: %w", ev.PID, err))
		}
	}
	if ev.HasAction(events.ActFreeze) {
		cg, err := FindCgroupPath(ev.PID)
		if err != nil {
			errs = append(errs, fmt.Errorf("rids: freeze pid %d: %w", ev.PID, err))
		} else if err := m.resp.Freeze(cg); err != nil {
			errs = append(errs, fmt.Errorf("rids: freeze cgroup %s: %w", cg, err))
		}
	}
	return errors.Join(errs...)
}

// Run implements detect.Runner. When FIM is enabled it builds the initial
// baseline and then sweeps every FIM.IntervalSec, publishing EvIntegrity
// events for added/removed/changed files. FIM errors are logged and
// non-fatal (the next sweep retries); Run returns nil on ctx cancellation.
func (m *Monitor) Run(ctx context.Context) error {
	if !m.cfg.FIM.Enabled || len(m.cfg.FIM.Dirs) == 0 {
		m.log.Info("rids: file-integrity monitoring disabled")
		<-ctx.Done()
		return nil
	}
	interval := time.Duration(m.cfg.FIM.IntervalSec) * time.Second
	if interval <= 0 {
		interval = DefaultFIMIntervalSec * time.Second
	}
	scanner := NewScanner(m.cfg.FIM.Dirs, 0)
	baseline, err := scanner.Baseline()
	if err != nil {
		// Permission holes are skipped inside the walker; a partial
		// baseline is still better than none. The next sweep heals it.
		m.log.Warn("rids: fim baseline incomplete", "err", err)
	}
	m.log.Info("rids: fim baseline established",
		"files", len(baseline), "dirs", strings.Join(m.cfg.FIM.Dirs, ","))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			prev := baseline
			added, removed, changed, next, err := scanner.Diff(prev)
			if err != nil {
				m.log.Warn("rids: fim sweep failed", "err", err)
				continue
			}
			baseline = next
			for _, p := range added {
				m.reportIntegrity(p, "", next[p])
			}
			for _, p := range removed {
				m.reportIntegrity(p, prev[p], "")
			}
			for _, p := range changed {
				m.reportIntegrity(p, prev[p], next[p])
			}
		}
	}
}

// reportIntegrity synthesizes an EvIntegrity event and pushes it into the
// pipeline via pub. Without a publisher (pub == nil) the change is
// log-only, which keeps RIDS usable in observability-only deployments.
func (m *Monitor) reportIntegrity(path, oldHash, newHash string) {
	if m.pub == nil {
		m.log.Info("rids: fim change (no publisher wired, log-only)",
			"path", path, "old_hash", oldHash, "new_hash", newHash)
		return
	}
	ev := &events.Event{
		ID:       events.NewID(),
		Type:     events.EvIntegrity,
		Time:     time.Now().UTC(),
		Severity: events.SevCritical,
		Source:   "rids",
		Message:  fmt.Sprintf("file-integrity change: %s", path),
	}
	ev.MetaSet("path", path)
	ev.MetaSet("old_hash", oldHash)
	ev.MetaSet("new_hash", newHash)
	m.pub(ev)
}

// Close implements detect.Runner; the FIM loop owns no external handles.
func (m *Monitor) Close() error { return nil }

// commLabel renders the DB-process comm for finding details.
func commLabel(ev *events.Event) string {
	if ev.Binary == "" {
		return "unknown"
	}
	return ev.Binary
}

// maxSeverity returns the more severe of a and b.
func maxSeverity(a, b events.Severity) events.Severity {
	if a.Order() >= b.Order() {
		return a
	}
	return b
}

// truncate shortens s to at most n bytes plus an ellipsis marker.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
