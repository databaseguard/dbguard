// Responder executes the enforcement half of the runtime intrusion
// detection system: SIGKILL of offending processes, cgroup v2 freeze /
// thaw, and the in-memory quarantine set with expiry that mirrors the
// kernel-side quarantine map maintained by the eBPF manager.
//
// All primitives are permission-aware: EPERM/EACCES are mapped onto
// ErrPermission so operators see an actionable error instead of a raw
// errno, and vanished targets surface as ErrProcessGone.
package rids

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Sentinel errors returned by Responder primitives.
var (
	// ErrProcessGone means the target pid no longer exists (ESRCH).
	ErrProcessGone = errors.New("rids: target process does not exist")
	// ErrPermission means DBGuard lacks the privileges for the operation.
	ErrPermission = errors.New("rids: operation not permitted (insufficient privileges)")
	// ErrCgroupFreezeUnsupported means the path has no cgroup.freeze file
	// (cgroup v1 host, or the controller is not enabled for that cgroup).
	ErrCgroupFreezeUnsupported = errors.New("rids: cgroup v2 freeze unsupported on this path")
)

// CgroupV2Root is the conventional mount point of the unified hierarchy.
const CgroupV2Root = "/sys/fs/cgroup"

// freezeFile is the cgroup v2 control file implementing the freezer.
const freezeFile = "cgroup.freeze"

// Responder holds the mutable quarantine state. The other primitives are
// stateless wrappers around syscalls/filesystem writes and are safe for
// concurrent use.
type Responder struct {
	mu          sync.Mutex
	quarantined map[uint32]time.Time // pid -> expiry
	log         *slog.Logger
}

// NewResponder returns an empty Responder.
func NewResponder() *Responder {
	return &Responder{
		quarantined: make(map[uint32]time.Time, 16),
		log:         slog.Default(),
	}
}

// Kill sends SIGKILL to pid. A target that exited in the meantime is
// reported as ErrProcessGone (not swallowed) so the caller can audit the
// race between detection and enforcement.
func (r *Responder) Kill(pid uint32) error {
	err := unix.Kill(int(pid), unix.SIGKILL)
	switch {
	case err == nil:
		r.log.Info("rids: killed process", "pid", pid)
		return nil
	case errors.Is(err, unix.ESRCH):
		return fmt.Errorf("rids: kill %d: %w", pid, ErrProcessGone)
	case errors.Is(err, unix.EPERM):
		return fmt.Errorf("rids: kill %d: %w", pid, ErrPermission)
	default:
		return fmt.Errorf("rids: kill %d: %w", pid, err)
	}
}

// Freeze writes "1" to <cgroupPath>/cgroup.freeze, stopping every process
// in the cgroup (cgroup v2 freezer semantics). Thaw must be called
// explicitly (or use FreezeFor for an automatic timer-based thaw).
func (r *Responder) Freeze(cgroupPath string) error {
	return r.writeFreeze(cgroupPath, "1")
}

// Thaw writes "0" to <cgroupPath>/cgroup.freeze, resuming the cgroup.
func (r *Responder) Thaw(cgroupPath string) error {
	return r.writeFreeze(cgroupPath, "0")
}

// FreezeFor freezes the cgroup and schedules an automatic thaw after d,
// completing the write-"1"-then-"0" lifecycle without operator action.
// The freeze itself is synchronous; thaw errors are logged (best effort).
func (r *Responder) FreezeFor(cgroupPath string, d time.Duration) error {
	if err := r.Freeze(cgroupPath); err != nil {
		return err
	}
	time.AfterFunc(d, func() {
		if err := r.Thaw(cgroupPath); err != nil {
			r.log.Warn("rids: scheduled thaw failed", "cgroup", cgroupPath, "err", err)
		} else {
			r.log.Info("rids: scheduled thaw completed", "cgroup", cgroupPath, "after", d.String())
		}
	})
	return nil
}

// writeFreeze performs the actual cgroup.freeze write with permission and
// support mapping.
func (r *Responder) writeFreeze(cgroupPath, state string) error {
	if cgroupPath == "" {
		return fmt.Errorf("rids: freeze: empty cgroup path")
	}
	target := filepath.Join(cgroupPath, freezeFile)
	f, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return fmt.Errorf("rids: freeze %s: %w", cgroupPath, ErrCgroupFreezeUnsupported)
		case os.IsPermission(err):
			return fmt.Errorf("rids: freeze %s: %w", cgroupPath, ErrPermission)
		default:
			return fmt.Errorf("rids: freeze %s: open %s: %w", cgroupPath, target, err)
		}
	}
	defer f.Close()
	if _, err := f.WriteString(state); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("rids: freeze %s: write %s: %w", cgroupPath, target, ErrPermission)
		}
		return fmt.Errorf("rids: freeze %s: write %s: %w", cgroupPath, target, err)
	}
	r.log.Info("rids: cgroup freeze state written", "cgroup", cgroupPath, "state", state)
	return nil
}

// Quarantine marks pid as quarantined until now+d. The in-memory set feeds
// user-space decision points (e.g. rejecting queries from quarantined
// clients) and mirrors the kernel quarantine map; it does not by itself
// stop the process - pair it with Kill/Freeze for hard enforcement.
// A non-positive duration releases the pid.
func (r *Responder) Quarantine(pid uint32, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.quarantined == nil {
		r.quarantined = make(map[uint32]time.Time, 16)
	}
	if d <= 0 {
		delete(r.quarantined, pid)
		return nil
	}
	r.quarantined[pid] = time.Now().Add(d)
	r.log.Debug("rids: pid quarantined", "pid", pid, "ttl", d.String())
	return nil
}

// IsQuarantined reports whether pid is currently quarantined. Expired
// entries are removed lazily on read.
func (r *Responder) IsQuarantined(pid uint32) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.quarantined[pid]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(r.quarantined, pid)
		return false
	}
	return true
}

// Sweep drops expired quarantine entries; the daemon's GC loop calls it
// periodically. now is injectable for deterministic tests.
func (r *Responder) Sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for pid, exp := range r.quarantined {
		if now.After(exp) {
			delete(r.quarantined, pid)
		}
	}
}

// FindCgroupPath resolves the absolute cgroup v2 path for pid by parsing
// /proc/<pid>/cgroup and joining the "0::<rel>" entry onto CgroupV2Root.
// An unreadable procfs entry means the process is gone (or the namespace
// hides it); a missing v2 line (legacy cgroup v1 host) falls back to the
// unified root so callers can still attempt a freeze.
func FindCgroupPath(pid uint32) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup")
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return "", fmt.Errorf("rids: cgroup for pid %d: %w", pid, ErrProcessGone)
		case os.IsPermission(err):
			return "", fmt.Errorf("rids: cgroup for pid %d: %w", pid, ErrPermission)
		default:
			return "", fmt.Errorf("rids: read /proc/%d/cgroup: %w", pid, err)
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 entry: "0::<relative path>" (single unified hierarchy).
		rel, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		rel = strings.TrimSpace(rel)
		if rel == "" || rel == "/" {
			return CgroupV2Root, nil
		}
		return filepath.Join(CgroupV2Root, rel), nil
	}
	// Legacy v1-only host: no v2 line exists; expose the default root.
	return CgroupV2Root, nil
}
