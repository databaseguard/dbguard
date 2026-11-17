package procwatch

import (
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSymbolPresentOnSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procwatch requires /proc (Linux)")
	}
	// the test binary normally keeps its symbol table; guard for stripped runs
	name, ok := SymbolPresent(uint32(os.Getpid()), []string{"main.main", "testing.tRunner"})
	if !ok {
		t.Skip("test binary appears stripped (no main.main / testing.tRunner)")
	}
	if name != "main.main" && name != "testing.tRunner" {
		t.Fatalf("unexpected symbol %q returned", name)
	}

	if _, ok := SymbolPresent(uint32(os.Getpid()), []string{"definitely.not.a.real.symbol"}); ok {
		t.Fatal("absent symbol reported present")
	}
	if _, ok := SymbolPresent(uint32(os.Getpid()), nil); ok {
		t.Fatal("empty name list must report absent")
	}
}

func TestExecMappingsSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procwatch requires /proc (Linux)")
	}
	pid := uint32(os.Getpid())
	maps, err := ExecMappings(pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) == 0 {
		t.Fatal("no mappings parsed")
	}
	exe, err := ExecutablePath(pid)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range maps {
		if m.Path == exe && strings.Contains(m.Perms, "x") {
			found = true
		}
		if m.End <= m.Start {
			t.Fatalf("bad mapping range %d-%d", m.Start, m.End)
		}
	}
	if !found {
		t.Fatalf("executable mapping for %s not found in maps", exe)
	}
}

func TestWatcherSeesCurrentProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procwatch requires /proc (Linux)")
	}
	raw, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Skip("cannot read /proc/self/comm")
	}
	selfComm := strings.TrimSpace(string(raw))
	selfPID := uint32(os.Getpid())

	w := NewWatcher(testLogger(), time.Hour)
	// custom matcher keeps the scan deterministic: only the test binary matches
	w.SetMatcher(func(comm string) (string, bool) {
		if comm == selfComm {
			return "testengine", true
		}
		return "", false
	})

	var mu sync.Mutex
	added := map[uint32]Process{}
	removed := map[uint32]bool{}
	w.Subscribe(func(p Process, isAdd bool) {
		mu.Lock()
		defer mu.Unlock()
		if isAdd {
			added[p.PID] = p
		} else {
			removed[p.PID] = true
		}
	})

	w.scan()

	mu.Lock()
	p, ok := added[selfPID]
	mu.Unlock()
	if !ok {
		t.Fatalf("current process %d not discovered", selfPID)
	}
	if p.Engine != "testengine" || p.Comm != selfComm || p.PID != selfPID {
		t.Fatalf("unexpected process record: %+v", p)
	}
	if p.Cmdline == "" {
		t.Fatal("cmdline not populated")
	}

	// a second scan is idempotent (no repeated add callbacks)
	mu.Lock()
	count := len(added)
	mu.Unlock()
	w.scan()
	mu.Lock()
	grew := len(added) != count
	mu.Unlock()
	if grew {
		t.Fatal("duplicate add callbacks on unchanged scan")
	}

	// a stale entry in prev must fire a removal callback with empty Engine
	stale := Process{PID: 999999, Comm: "gone", Engine: "mysql"}
	w.mu.Lock()
	w.prev[stale.PID] = stale
	w.mu.Unlock()
	w.scan()
	mu.Lock()
	gone := removed[999999]
	_, stillAdded := added[999999]
	mu.Unlock()
	if !gone {
		t.Fatal("missing removal callback for stale process")
	}
	if stillAdded {
		t.Fatal("stale process must not be re-added")
	}
}

func TestDefaultMatcher(t *testing.T) {
	for comm, want := range map[string]string{
		"postgres":   "postgres",
		"mysqld":     "mysql",
		"mariadbd":   "mysql",
		"postmaster": "postgres",
	} {
		got, ok := DefaultMatcher(comm)
		if !ok || got != want {
			t.Fatalf("DefaultMatcher(%q) = %q,%v; want %q,true", comm, got, ok, want)
		}
	}
	if _, ok := DefaultMatcher("nginx"); ok {
		t.Fatal("nginx must not classify as a DB engine")
	}
}
