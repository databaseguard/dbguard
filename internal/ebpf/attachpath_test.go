package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestAttachPathSameNamespace: when the recorded binary path exists directly
// (the single-host case where dbguard shares the DB's mount namespace), the
// path is usable as-is (possibly via /proc/<pid>/root, which resolves to the
// same file). Either way the returned path must stat to the real binary.
func TestAttachPathSameNamespace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "postgres")
	if err := os.WriteFile(bin, []byte("\x7fELF stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// pid 0 forces the no-/proc branch: the raw path is returned.
	got := attachPath(0, bin)
	if got != bin {
		t.Fatalf("pid=0: got %q, want raw path %q", got, bin)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("returned path does not stat: %v", err)
	}
}

// TestAttachPathEmptyBinary: with no recorded binary, fall back to the
// /proc/<pid>/exe magic symlink (valid cross-namespace for a privileged
// hostPID process).
func TestAttachPathEmptyBinary(t *testing.T) {
	if got := attachPath(1234, ""); got != "/proc/1234/exe" {
		t.Errorf("empty binary: got %q, want /proc/1234/exe", got)
	}
	if got := attachPath(0, ""); got != "" {
		t.Errorf("empty binary, pid 0: got %q, want \"\"", got)
	}
}

// TestAttachPathPrefersNamespaceRoot: when /proc/<pid>/root/<binary> exists
// (the DaemonSet/cross-container case), it is preferred over the bare path so
// the uprobe attaches to the inode inside the target's root filesystem. We
// simulate the target rootfs by pointing at our own pid, whose /proc/self/root
// is "/", and checking a file that exists under it.
func TestAttachPathPrefersNamespaceRoot(t *testing.T) {
	pid := uint32(os.Getpid())
	// A file that exists at an absolute path on this host; /proc/<pid>/root
	// + that path resolves to the same file for our own process.
	abs := "/bin/sh"
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("%s not present: %v", abs, err)
	}
	got := attachPath(pid, abs)
	want := fmt.Sprintf("/proc/%d/root%s", pid, abs)
	if got != want {
		t.Errorf("got %q, want namespaced %q", got, want)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("namespaced path does not stat: %v", err)
	}
}
