// Teardown plumbing for lineage enforcement.
//
// Kernel-side context (for the daemon wiring): a confirmed hijack is best
// contained inside the kernel. The daemon wires
// Correlator.SetTeardownFunc to the eBPF manager, which inserts the
// session's socket cookie into the quarantine map consulted by the
// cgroup_skb programs (see bpf/include/dbguard/common.h and the DBG_ACT_*
// quarantine action): packets on quarantined sockets are dropped until the
// operator clears the entry or the connection resets. A complementary path
// injects a TCP reset (events.ActReset) via the kernel reset helper.
// Process-level controls (SIGKILL, cgroup freeze) live in internal/rids
// and are only appropriate for clearly compromised processes - resetting
// the DB session is the proportionate response to a pool hijack.
//
// DefaultTeardown is the passive fallback used when the daemon did not
// wire a real hook: it records the request and returns
// ErrTeardownNotWired, so callers (and tests) can distinguish "nothing
// wired" from "attempted but failed". InMemoryLedger is a bounded,
// thread-safe audit trail of teardown attempts; the daemon can wrap any
// real hook with it, and tests use it to count invocations.
package lineage

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

// ErrTeardownNotWired is returned by the DefaultTeardown fallback hook.
var ErrTeardownNotWired = errors.New("lineage: teardown hook not wired")

// hijackInfo carries the facts needed after the session-state lock is
// released (teardown + event synthesis run off the critical path).
type hijackInfo struct {
	from   string
	to     string
	appPID uint32
}

// DefaultTeardown returns a best-effort, passive teardown hook: it logs
// the request and fails with ErrTeardownNotWired instead of pretending the
// session was reset. This keeps deployments without kernel teardown honest
// while still surfacing every hijack in the logs.
func DefaultTeardown(log *slog.Logger) func(session uint64, appPID uint32) error {
	if log == nil {
		log = slog.Default()
	}
	return func(session uint64, appPID uint32) error {
		log.Warn("lineage: teardown requested but no hook wired",
			"session", session, "app_pid", appPID)
		return fmt.Errorf("lineage: session %d app pid %d: %w", session, appPID, ErrTeardownNotWired)
	}
}

// TeardownRecord is one audited teardown attempt.
type TeardownRecord struct {
	Session uint64    `json:"session"`
	AppPID  uint32    `json:"app_pid"`
	At      time.Time `json:"at"`
	Err     string    `json:"err,omitempty"` // empty = success
}

// InMemoryLedger is a bounded, thread-safe audit trail of teardown
// actions, oldest first. Capacity-bounded means a teardown storm cannot
// exhaust memory; the oldest records are dropped.
type InMemoryLedger struct {
	mu   sync.Mutex
	max  int
	recs []TeardownRecord
}

// NewInMemoryLedger keeps at most max records; max <= 0 selects 1024.
func NewInMemoryLedger(max int) *InMemoryLedger {
	if max <= 0 {
		max = 1024
	}
	return &InMemoryLedger{max: max}
}

// Hook returns a teardown function that records every invocation into the
// ledger and then delegates to inner (inner may be nil → record only).
// The delegation result is returned unchanged so callers observe real
// hook outcomes.
func (l *InMemoryLedger) Hook(inner func(session uint64, appPID uint32) error) func(session uint64, appPID uint32) error {
	return func(session uint64, appPID uint32) error {
		var err error
		if inner != nil {
			err = inner(session, appPID)
		}
		l.mu.Lock()
		l.recs = append(l.recs, TeardownRecord{
			Session: session,
			AppPID:  appPID,
			At:      time.Now(),
			Err:     errString(err),
		})
		if drop := len(l.recs) - l.max; drop > 0 {
			l.recs = l.recs[drop:]
		}
		l.mu.Unlock()
		return err
	}
}

// Records returns a copy of the audit trail, oldest first.
func (l *InMemoryLedger) Records() []TeardownRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]TeardownRecord, len(l.recs))
	copy(out, l.recs)
	return out
}

// Len returns the number of recorded teardown attempts.
func (l *InMemoryLedger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recs)
}

// errString renders err for storage ("" for success).
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// runTeardown invokes the wired teardown hook synchronously; the hook runs
// on the pipeline goroutine and must be fast. Errors are logged, never
// fatal - the finding is already attached to the event.
func (c *Correlator) runTeardown(session uint64, appPID uint32) {
	c.mu.Lock()
	td := c.teardown
	c.mu.Unlock()
	if td == nil {
		return
	}
	if err := td(session, appPID); err != nil {
		c.log.Error("lineage: teardown failed", "session", session, "app_pid", appPID, "err", err)
	}
}

// publishHijack synthesizes a dedicated EvLineage event so the alert/audit
// pipeline sees the enforcement decision even though the original finding
// rides on the triggering query event.
func (c *Correlator) publishHijack(ev *events.Event, from, to string, appPID uint32) {
	if c.pub == nil {
		return
	}
	out := &events.Event{
		ID:        events.NewID(),
		Type:      events.EvLineage,
		Time:      c.now().UTC(),
		Severity:  events.SevHigh,
		Source:    "lineage",
		Message:   fmt.Sprintf("connection-pool hijack on session %d (route %q -> %q)", ev.SessionID, from, to),
		SessionID: ev.SessionID,
		AppPID:    appPID,
		PID:       ev.PID,
		Route:     to,
		Engine:    ev.Engine,
		User:      ev.User,
		Database:  ev.Database,
	}
	out.MetaSet("hijack", "1")
	out.MetaSet("from_route", from)
	out.MetaSet("to_route", to)
	out.MetaSet("query_event_id", ev.ID)
	c.pub(out)
}
