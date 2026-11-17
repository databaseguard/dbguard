// elf.go resolves uprobe symbols for discovered DB processes.
//
// Design note: cilium/ebpf's link.UprobeOptions{PID, Symbol} performs the
// real address math - it opens the ELF, finds the symbol's file offset and
// translates it into the live process mapping via /proc/<pid>/maps. This
// package therefore only needs to answer *presence*: "does the binary
// running as pid X export one of these symbols?" - which saves attach
// attempts (and noisy kernel errors) for stripped or custom builds.
package procwatch

import (
	"debug/elf"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcMap is one line of /proc/<pid>/maps.
type ProcMap struct {
	Start uint64 // mapping start address
	End   uint64 // mapping end address
	Perms string // rwxp permission string
	Path  string // backing file ("" for anonymous mappings)
}

// ExecMappings parses /proc/<pid>/maps. Useful for diagnostics and for
// verifying that a binary is actually mapped executable before installing
// uprobes; the address translation itself stays with cilium/ebpf.
func ExecMappings(pid uint32) ([]ProcMap, error) {
	raw, err := os.ReadFile(fmt.Sprintf("%s/%d/maps", procRoot, pid))
	if err != nil {
		return nil, fmt.Errorf("procwatch: read maps for pid %d: %w", pid, err)
	}
	var out []ProcMap
	for _, line := range strings.Split(string(raw), "\n") {
		// format: start-end perms offset dev inode [pathname]
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		span := strings.SplitN(fields[0], "-", 2)
		if len(span) != 2 {
			continue
		}
		start, errStart := strconv.ParseUint(span[0], 16, 64)
		end, errEnd := strconv.ParseUint(span[1], 16, 64)
		if errStart != nil || errEnd != nil {
			continue
		}
		m := ProcMap{Start: start, End: end, Perms: fields[1]}
		if len(fields) >= 6 {
			m.Path = fields[5]
		}
		out = append(out, m)
	}
	return out, nil
}

// ExecutablePath resolves /proc/<pid>/exe. It fails for processes the
// caller lacks ptrace privileges against (deferred to link.Uprobe which
// runs under the same constraints).
func ExecutablePath(pid uint32) (string, error) {
	p := fmt.Sprintf("%s/%d/exe", procRoot, pid)
	exe, err := os.Readlink(p)
	if err != nil {
		return "", fmt.Errorf("procwatch: readlink %s: %w", p, err)
	}
	return exe, nil
}

// SymbolPresent reports whether any of names is exported by the ELF symbol
// tables of the binary executing as pid. .symtab is consulted first (full
// symbols), then .dynsym (which usually survives stripping). On a hit it
// returns the matched name so callers can hand it straight to
// link.UprobeOptions{Symbol: ...}; on any error (no such process,
// unreadable binary) it reports absent rather than failing.
func SymbolPresent(pid uint32, names []string) (string, bool) {
	if len(names) == 0 {
		return "", false
	}
	exe, err := ExecutablePath(pid)
	if err != nil {
		return "", false
	}
	f, err := elf.Open(exe)
	if err != nil {
		return "", false
	}
	defer f.Close()

	for _, fetch := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := fetch()
		if err != nil {
			continue // missing or stripped symbol table
		}
		for _, want := range names {
			for _, have := range syms {
				if have.Name == want && have.Value != 0 {
					return have.Name, true
				}
			}
		}
	}
	return "", false
}

// ExecutableIsStripped reports whether the binary lacks a .symtab - a
// common reason for uprobe misses on distro-packaged DB servers.
func ExecutableIsStripped(pid uint32) (bool, error) {
	exe, err := ExecutablePath(pid)
	if err != nil {
		return false, err
	}
	f, err := elf.Open(exe)
	if err != nil {
		return false, fmt.Errorf("procwatch: open %s: %w", exe, err)
	}
	defer f.Close()
	return f.Section(".symtab") == nil, nil
}
