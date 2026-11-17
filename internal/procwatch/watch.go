// Package procwatch discovers database server processes on the host and
// inspects their binaries for uprobe symbols. The Watcher feeds the eBPF
// Manager with fresh Target lists as processes appear/disappear (restarts,
// container churn) and supports a pluggable matcher so tests and
// deployments can teach it custom engine names.
//
// Matching contract: the default matcher classifies by process name (comm)
// and executable basename against the well-known DB server names. Callbacks
// receive (Process, added): additions carry a fully populated Process with
// Engine set; removals carry only the PID (Engine empty) because the
// process is already gone.
package procwatch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procRoot is the filesystem root scanned for processes.
const procRoot = "/proc"

// engineByComm maps known DB server process names to engine identifiers.
var engineByComm = map[string]string{
	"postgres":   "postgres",
	"postmaster": "postgres", // pre-fork parent on some builds
	"mysqld":     "mysql",
	"mariadbd":   "mysql",
}

// Process is one discovered database server process.
type Process struct {
	PID     uint32
	Comm    string // comm from /proc/<pid>/comm (max 15 chars)
	ExePath string // resolved /proc/<pid>/exe symlink ("" when unreadable)
	Cmdline string // NUL-joined argv, single-spaced
	Engine  string // postgres|mysql|sqlite ("" on removal callbacks)
}

// Watcher periodically scans /proc and emits add/remove callbacks.
type Watcher struct {
	log      *slog.Logger
	interval time.Duration
	matcher  func(comm string) (string, bool)

	mu      sync.Mutex
	subs    []func(Process, bool)
	prev    map[uint32]Process
	stopped chan struct{}

	closeOnce sync.Once
}

// NewWatcher returns a watcher polling every interval (<=0 uses 5s) with
// the DefaultMatcher installed.
func NewWatcher(log *slog.Logger, interval time.Duration) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		log:      log,
		interval: interval,
		matcher:  DefaultMatcher,
		prev:     make(map[uint32]Process),
		stopped:  make(chan struct{}),
	}
}

// DefaultMatcher classifies a process name against the well-known DB
// server binaries. Matching is case-insensitive.
func DefaultMatcher(comm string) (string, bool) {
	eng, ok := engineByComm[strings.ToLower(strings.TrimSpace(comm))]
	return eng, ok
}

// SetMatcher replaces the engine classifier; call before Run. The matcher
// receives the comm and (as a fallback during discovery) the exe basename.
func (w *Watcher) SetMatcher(fn func(comm string) (string, bool)) {
	w.matcher = fn
}

// Subscribe registers fn for discovery callbacks: (process, true) on
// addition, ({PID: pid}, false) on removal (Engine empty by contract).
func (w *Watcher) Subscribe(fn func(Process, bool)) {
	w.mu.Lock()
	w.subs = append(w.subs, fn)
	w.mu.Unlock()
}

// Run scans /proc immediately and then every interval until ctx is
// cancelled or Close is called. It never returns an error for transient
// scan failures (those are logged and retried on the next tick).
func (w *Watcher) Run(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	w.scan()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.stopped:
			return nil
		case <-t.C:
			w.scan()
		}
	}
}

// Close stops the run loop; safe to call multiple times.
func (w *Watcher) Close() {
	w.closeOnce.Do(func() { close(w.stopped) })
}

// scan performs one discovery pass and diffs it against the previous set.
func (w *Watcher) scan() {
	cur, err := w.discover()
	if err != nil {
		w.log.Warn("procwatch: scan failed", "err", err)
		return
	}

	w.mu.Lock()
	prev := w.prev
	w.prev = cur
	subs := append([]func(Process, bool){}, w.subs...)
	w.mu.Unlock()

	for pid, p := range cur {
		if old, ok := prev[pid]; ok {
			if old == p {
				continue
			}
			// PID reuse or binary replacement: report remove + add so the
			// manager detaches stale uprobes first.
			w.notify(subs, Process{PID: pid}, false)
		}
		w.notify(subs, p, true)
	}
	for pid := range prev {
		if _, ok := cur[pid]; !ok {
			// removals carry only the PID; Engine is empty by contract
			w.notify(subs, Process{PID: pid}, false)
		}
	}
}

// notify invokes the (already copied) subscriber list.
func (w *Watcher) notify(subs []func(Process, bool), p Process, added bool) {
	for _, fn := range subs {
		fn(p, added)
	}
	if added {
		w.log.Debug("procwatch: DB process added",
			"pid", p.PID, "comm", p.Comm, "engine", p.Engine)
	} else {
		w.log.Debug("procwatch: DB process removed", "pid", p.PID)
	}
}

// discover walks /proc and returns all matching DB processes keyed by PID.
func (w *Watcher) discover() (map[uint32]Process, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("procwatch: scan %s: %w", procRoot, err)
	}
	cur := make(map[uint32]Process, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}
		pid := uint32(pid64)
		comm := readComm(pid)
		if comm == "" {
			continue // vanished mid-scan or unreadable
		}
		engine := ""
		if e, ok := w.matcher(comm); ok {
			engine = e
		} else if exe := readExe(pid); exe != "" {
			if base := filepath.Base(exe); base != comm {
				if e, ok := w.matcher(base); ok {
					engine = e
				}
			}
		}
		if engine == "" {
			continue
		}
		cur[pid] = Process{
			PID:     pid,
			Comm:    comm,
			ExePath: readExe(pid),
			Cmdline: readCmdline(pid),
			Engine:  engine,
		}
	}
	return cur, nil
}

// readComm reads the (newline-terminated) comm of a process.
func readComm(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", procRoot, pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readExe resolves the /proc/<pid>/exe symlink ("" when unreadable -
// e.g. the process is not ours or vanished).
func readExe(pid uint32) string {
	p, err := os.Readlink(fmt.Sprintf("%s/%d/exe", procRoot, pid))
	if err != nil {
		return ""
	}
	return p
}

// readCmdline returns the argv joined with single spaces.
func readCmdline(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/cmdline", procRoot, pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}
