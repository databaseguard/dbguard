// loader.go loads compiled eBPF object files (*.bpf.o) and attaches their
// programs to kernel hooks (tracepoints, kprobes, uprobes, cgroup, XDP).
//
// Attachment failures are logged per program and collected; they are
// non-fatal so a missing hook on an old kernel never takes the whole agent
// down. The link handles created here are tracked and released by
// CloseLinks / the Manager.
package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"debug/elf"
	"encoding/binary"
	"encoding/hex"

	"github.com/databaseguard/dbguard/internal/config"
)

// LoadObjects loads every *.bpf.o object under cfg.ObjectDir into its own
// collection keyed by the file name minus the ".bpf.o" suffix. When
// cfg.PinPath is set, map pinning is honoured so state (config_map and
// friends) survives restarts. Returns a combined error for per-object
// failures; a directory without any object is an error.
func LoadObjects(cfg config.EBPFConfig) (map[string]*ebpf.Collection, error) {
	entries, err := os.ReadDir(cfg.ObjectDir)
	if err != nil {
		return nil, fmt.Errorf("ebpf: read object dir %s: %w", cfg.ObjectDir, err)
	}
	colls := make(map[string]*ebpf.Collection)
	var errs []error
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".bpf.o") {
			continue
		}
		// The *_lsm.bpf.o objects carry BPF-LSM programs (lsm/file_open,
		// lsm/bprm_check_security) that add in-kernel inline BLOCKING of file
		// opens and exec. They require CONFIG_BPF_LSM with "bpf" in the active
		// LSM list AND permission to load BPF_PROG_TYPE_LSM (often blocked in
		// containers). The core RIDS detection is already provided by the
		// tracepoint programs in rids.bpf.o, so the LSM variants are an opt-in
		// enhancement: skip them unless the operator has explicitly enabled
		// lsm_enabled after confirming their kernel supports it.
		if !cfg.LSMEnabled && strings.HasSuffix(ent.Name(), "_lsm.bpf.o") {
			continue
		}
		path := filepath.Join(cfg.ObjectDir, ent.Name())
		name := strings.TrimSuffix(ent.Name(), ".bpf.o")

		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("ebpf: load spec %s: %w", path, err))
			continue
		}
		// Programs in a bare "uprobe" ELF section have no type that cilium/ebpf
		// can infer, so it leaves them UnspecifiedProgram and SILENTLY SKIPS
		// them at load - the collection comes back with zero programs and no
		// error. Uprobes load under the Kprobe program type, so set it
		// explicitly here; without this, SQL query auditing never attaches.
		for _, ps := range spec.Programs {
			if ps.Type == ebpf.UnspecifiedProgram {
				ps.Type = ebpf.Kprobe
			}
		}
		opts := ebpf.CollectionOptions{}
		if cfg.PinPath != "" {
			opts.Maps.PinPath = cfg.PinPath
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("ebpf: load collection %s: %w", path, err))
			continue
		}
		if err := loadPinnedMaps(coll, cfg); err != nil {
			errs = append(errs, err)
		}
		colls[name] = coll
	}
	if len(colls) == 0 && len(errs) == 0 {
		return nil, fmt.Errorf("ebpf: no *.bpf.o objects found in %s", cfg.ObjectDir)
	}
	return colls, errors.Join(errs...)
}

// loadPinnedMaps reuses on-disk pinned maps when a freshly loaded collection
// lacks them - the "config_map" singleton is typically pinned across
// restarts by a previous Manager instance. Missing pins are not an error.
func loadPinnedMaps(coll *ebpf.Collection, cfg config.EBPFConfig) error {
	if cfg.PinPath == "" {
		return nil
	}
	for _, name := range []string{"config_map"} {
		if _, ok := coll.Maps[name]; ok {
			continue
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(cfg.PinPath, name), nil)
		if err != nil {
			continue // not pinned; the in-collection map (if any) stands
		}
		coll.Maps[name] = m // collection Close() will release it
	}
	return nil
}

// linkRegistry tracks links created through the exported AttachCollection
// wrapper so they can be released deterministically with CloseLinks.
var (
	linkRegistryMu sync.Mutex
	linkRegistry   = map[string][]link.Link{}
)

// AttachCollection attaches every program of coll to its kernel hook and
// registers the created links under the collection name. Failures are
// logged per program and combined; attachment continues past errors.
// The Manager uses attachCollectionLinks directly to keep the links itself.
func AttachCollection(name string, coll *ebpf.Collection, cfg config.EBPFConfig,
	targets []Target, log *slog.Logger) error {
	links, err := attachCollectionLinks(name, coll, cfg, targets, log)
	linkRegistryMu.Lock()
	linkRegistry[name] = append(linkRegistry[name], links...)
	linkRegistryMu.Unlock()
	return err
}

// CloseLinks closes and forgets all links registered under name.
func CloseLinks(name string) error {
	linkRegistryMu.Lock()
	links := linkRegistry[name]
	delete(linkRegistry, name)
	linkRegistryMu.Unlock()
	var errs []error
	for _, l := range links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// attachCollectionLinks attaches every program and returns the created
// links for later teardown.
func attachCollectionLinks(name string, coll *ebpf.Collection, cfg config.EBPFConfig,
	targets []Target, log *slog.Logger) ([]link.Link, error) {
	var (
		links []link.Link
		errs  []error
	)
	for progName, prog := range coll.Programs {
		ls, err := attachProgram(progName, prog, cfg, targets, log)
		links = append(links, ls...)
		if err != nil {
			log.Warn("ebpf: attach failed", "collection", name, "program", progName, "err", err)
			errs = append(errs, fmt.Errorf("program %s: %w", progName, err))
		}
	}
	return links, errors.Join(errs...)
}

// attachProgram dispatches one program to its hook by name suffix/prefix.
// Programs whose name carries no known convention are skipped with a debug
// log (they may be freestanding, e.g. sockmap-managed sk_msg progs).
func attachProgram(progName string, prog *ebpf.Program, cfg config.EBPFConfig,
	targets []Target, log *slog.Logger) ([]link.Link, error) {
	switch {
	case strings.HasSuffix(progName, "kretprobe_tcp_sendmsg"):
		l, err := link.Kretprobe("tcp_sendmsg", prog, nil)
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "kprobe_tcp_sendmsg"):
		l, err := link.Kprobe("tcp_sendmsg", prog, nil)
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "kretprobe_inet_csk_accept"),
		strings.HasSuffix(progName, "krp_inet_csk_accept"):
		l, err := link.Kretprobe("inet_csk_accept", prog, nil)
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "kprobe_inet_csk_accept"):
		l, err := link.Kprobe("inet_csk_accept", prog, nil)
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "kprobe_tcp_v4_connect"),
		strings.HasSuffix(progName, "kp_tcp_v4_connect"):
		l, err := link.Kprobe("tcp_v4_connect", prog, nil)
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "kprobe_tcp_close"),
		strings.HasSuffix(progName, "kp_tcp_close"):
		l, err := link.Kprobe("tcp_close", prog, nil)
		return maybeLink(l, err)
	case strings.Contains(progName, "recvmsg"):
		// Correlates a DB backend's client socket tuple to its tgid so the
		// SQL uprobe can stamp the client IP onto query events (audit.bpf.c).
		l, err := link.Kprobe("tcp_recvmsg", prog, nil)
		if err != nil {
			log.Warn("ebpf: client-IP kprobe attach FAILED", "program", progName, "err", err)
		} else {
			log.Info("ebpf: client-IP correlation kprobe attached", "program", progName, "hook", "tcp_recvmsg")
		}
		return maybeLink(l, err)
	case strings.Contains(progName, "bprm_check"),
		strings.HasPrefix(progName, "lsm_"):
		// BPF LSM hooks (bprm_check_security, file_open). Requires
		// CONFIG_BPF_LSM and "lsm=bpf" in the boot parameters; a
		// failure here is non-fatal (logged by the caller).
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		return maybeLink(l, err)
	case strings.HasSuffix(progName, "tp_execve"):
		l, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		return maybeLink(l, err)
	case strings.Contains(progName, "tp_openat"):
		// covers tp_openat and tp_openat_tenant
		l, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
		return maybeLink(l, err)
	case strings.HasPrefix(progName, "uprobe_"):
		return attachUprobes(progName, prog, cfg, targets, log)
	case strings.HasPrefix(progName, "cgroup_egress_"):
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    "/sys/fs/cgroup",
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: prog,
		})
		return maybeLink(l, err)
	case strings.HasPrefix(progName, "cgroup_ingress_"):
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    "/sys/fs/cgroup",
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: prog,
		})
		return maybeLink(l, err)
	case strings.HasPrefix(progName, "xdp_"):
		l, err := attachXDP(progName, prog, cfg)
		return maybeLink(l, err)
	case strings.HasPrefix(progName, "sk_msg_"), strings.HasPrefix(progName, "sk_skb_"):
		// sockmap programs are attached by the sockmap orchestrator
		// (Cilium/own control plane), not by the loader.
		log.Info("ebpf: leaving sockmap program unattached", "program", progName)
		return nil, nil
	default:
		log.Debug("ebpf: unknown program naming convention, skipping attach", "program", progName)
		return nil, nil
	}
}

// attachUprobes installs one uprobe per DB-process target. The target's
// Binary (or /proc/<pid>/exe as fallback) provides the ELF; cilium/ebpf
// resolves the symbol address against the live process maps.
func attachUprobes(progName string, prog *ebpf.Program, cfg config.EBPFConfig,
	targets []Target, log *slog.Logger) ([]link.Link, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no DB process targets to attach uprobe %s", progName)
	}
	// Attach ONCE PER UNIQUE BINARY, process-wide (no PID filter). A DB server
	// forks a new backend process per connection, so a PID-scoped uprobe bound
	// to a startup backend never fires for the backend that actually runs a
	// query. A process-wide uprobe on the binary fires for every process that
	// executes it; the in-kernel target_pids wildcard gate then scopes events
	// to DB backends. Deduplicating by binary also avoids N identical probes.
	seen := map[string]bool{}
	var (
		links []link.Link
		errs  []error
	)
	for _, t := range targets {
		sym := symbolFor(t.Kind, progName, cfg)
		if sym == "" {
			continue // program is for a different engine than this target
		}
		exe := attachPath(t.PID, t.Binary)
		// Two MySQL dispatch_command ABIs need different handlers. Attach only
		// the one matching this binary's signature so we don't read the wrong
		// argument. MySQL 8.0's mangled name contains "COM_DATA"; MariaDB's
		// takes (char*,uint,bool) and does not.
		if progName == "uprobe_my_dispatch" || progName == "uprobe_my_dispatch80" {
			mangled := mangledSymbolInBinary(exe, "dispatch_command")
			isMySQL80 := strings.Contains(mangled, "COM_DATA")
			if progName == "uprobe_my_dispatch80" && !isMySQL80 {
				continue // binary is MariaDB; the 8.0 handler doesn't apply
			}
			if progName == "uprobe_my_dispatch" && isMySQL80 {
				continue // binary is MySQL 8.0; the MariaDB handler doesn't apply
			}
		}
		key := exe + "\x00" + sym
		if seen[key] {
			continue
		}
		seen[key] = true

		ex, err := link.OpenExecutable(exe)
		if err != nil {
			errs = append(errs, fmt.Errorf("target %s: open executable: %w", exe, err))
			continue
		}
		// process-wide attach by name
		l, err := ex.Uprobe(sym, prog, nil)
		// C++-mangled symbol (e.g. MySQL dispatch_command) often lives in the
		// binary's OWN dynsym under a mangled name like
		// _Z16dispatch_command...; resolve that by prefix and retry by name
		// before falling back to the debug file. No dbgsym needed for MySQL.
		if err != nil && (errors.Is(err, link.ErrNoSymbol) ||
			strings.Contains(err.Error(), "no symbol") ||
			strings.Contains(err.Error(), "not found")) {
			if mangled := mangledSymbolInBinary(exe, sym); mangled != "" && mangled != sym {
				if l2, e2 := ex.Uprobe(mangled, prog, nil); e2 == nil {
					log.Info("ebpf: uprobe attached (SQL query auditing active)",
						"program", progName, "engine", t.Kind, "symbol", mangled, "binary", exe)
					links = append(links, l2)
					continue
				}
			}
		}
		if err != nil && (errors.Is(err, link.ErrNoSymbol) ||
			strings.Contains(err.Error(), "no symbol") ||
			strings.Contains(err.Error(), "not found")) {
			// stripped binary: resolve the address from the separate debug
			// file (dbgsym) and attach by offset, still process-wide.
			if addr, derr := symbolAddrFromDebug(exe, sym); derr == nil {
				l, err = ex.Uprobe(sym, prog, &link.UprobeOptions{Address: addr})
				if err == nil {
					log.Info("ebpf: uprobe attached via debug symbols (SQL query auditing active)",
						"program", progName, "engine", t.Kind, "symbol", sym,
						"addr", fmt.Sprintf("0x%x", addr), "binary", exe)
					links = append(links, l)
					continue
				}
			} else {
				log.Warn("ebpf: uprobe symbol not found - SQL query auditing (SQLi/PII) INACTIVE for this engine (binary is stripped and no debug symbols found)",
					"engine", t.Kind, "symbol", sym, "binary", exe,
					"remedy", dbgsymHint(t.Kind))
				errs = append(errs, fmt.Errorf("binary %s symbol %s: %w (no debug file: %v)", exe, sym, err, derr))
				continue
			}
		}
		if err != nil {
			log.Warn("ebpf: uprobe attach failed",
				"program", progName, "symbol", sym, "binary", exe, "err", err)
			errs = append(errs, fmt.Errorf("binary %s symbol %s: %w", exe, sym, err))
			continue
		}
		log.Info("ebpf: uprobe attached (SQL query auditing active)",
			"program", progName, "engine", t.Kind, "symbol", sym, "binary", exe)
		links = append(links, l)
	}
	if len(links) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return links, errorsJoinOrNil(errs)
}

// attachPath resolves the on-disk path to a target's binary that this process
// can open to attach a uprobe. The discovery pass records Binary as the
// readlink of /proc/<pid>/exe, which is a path in the TARGET's mount namespace
// (e.g. /usr/lib/postgresql/16/bin/postgres). When dbguard runs in its own
// container (the DaemonSet case) that path does not exist in dbguard's
// filesystem, so OpenExecutable fails and the uprobe never attaches.
//
// Resolving through /proc/<pid>/root reaches the binary inside the target's
// root filesystem - the same inode the DB backends execute, so the inode-keyed
// uprobe fires for every backend. For a same-namespace host process (the
// single-host case) /proc/<pid>/root/<path> resolves to the identical file, so
// this is correct in both deployments. Falls back to the raw path, then to the
// /proc/<pid>/exe magic symlink.
func attachPath(pid uint32, binary string) string {
	if binary == "" {
		if pid != 0 {
			return fmt.Sprintf("/proc/%d/exe", pid)
		}
		return binary
	}
	if pid != 0 {
		ns := fmt.Sprintf("/proc/%d/root%s", pid, binary)
		if _, err := os.Stat(ns); err == nil {
			return ns
		}
	}
	if _, err := os.Stat(binary); err == nil {
		return binary
	}
	if pid != 0 {
		return fmt.Sprintf("/proc/%d/exe", pid)
	}
	return binary
}

// errorsJoinOrNil joins errs, returning nil when empty.
func errorsJoinOrNil(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// mangledSymbolInBinary looks in the binary's own symbol tables for a
// C++-mangled Itanium name of the demangled free function `sym`
// (_Z<len><sym>...), returning the full mangled name so it can be attached by
// name. This is how MySQL's dispatch_command (exported only as
// _Z16dispatch_command19enum_server_commandP3THDPcjb) is attached without any
// debug symbols. Returns "" if not found.
func mangledSymbolInBinary(binPath, sym string) string {
	f, err := elf.Open(binPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	prefix := fmt.Sprintf("_Z%d%s", len(sym), sym)
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	for _, s := range append(syms, dyn...) {
		if strings.HasPrefix(s.Name, prefix) {
			return s.Name
		}
	}
	return ""
}

// symbolAddrFromDebug resolves the virtual address of a symbol that is not in
// a stripped binary's own tables by reading the separate debug file that
// dbgsym/debuginfo installs. It locates that file by the binary's GNU build-id
// (/usr/lib/debug/.build-id/XX/YYYY.debug) and, as a fallback, by the
// .gnu_debuglink path (/usr/lib/debug/<path>.debug). Returns the symbol value
// (an offset suitable for UprobeOptions.Address on a PIE/ET_DYN binary).
func symbolAddrFromDebug(binPath, sym string) (uint64, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var candidates []string
	// 1. build-id path: /usr/lib/debug/.build-id/XX/YYYY.debug (Debian/Ubuntu
	//    dbgsym, and Fedora/RHEL debuginfo, both use this layout).
	if sect := f.Section(".note.gnu.build-id"); sect != nil {
		if data, derr := sect.Data(); derr == nil {
			if id := parseBuildID(data); id != "" {
				candidates = append(candidates,
					filepath.Join("/usr/lib/debug/.build-id", id[:2], id[2:]+".debug"),
					filepath.Join("/usr/lib/debug/.build-id", id[:2], id[2:]))
			}
		}
	}
	// 2. .gnu_debuglink: the binary names its own debug file; it's searched in
	//    the same dir, a .debug subdir, and under /usr/lib/debug/<dir>/.
	if sect := f.Section(".gnu_debuglink"); sect != nil {
		if data, derr := sect.Data(); derr == nil {
			name := cstr(data)
			if name != "" {
				dir := filepath.Dir(binPath)
				abs, _ := filepath.Abs(binPath)
				absDir := filepath.Dir(abs)
				candidates = append(candidates,
					filepath.Join(dir, name),
					filepath.Join(dir, ".debug", name),
					filepath.Join("/usr/lib/debug", absDir, name))
			}
		}
	}
	// 3. debuglink-by-path: /usr/lib/debug/<abs path of binary>[.debug]
	if abs, aerr := filepath.Abs(binPath); aerr == nil {
		candidates = append(candidates, filepath.Join("/usr/lib/debug", abs)+".debug",
			filepath.Join("/usr/lib/debug", abs))
	}

	var lastErr error
	for _, dbg := range candidates {
		if _, serr := os.Stat(dbg); serr != nil {
			lastErr = serr
			continue
		}
		addr, aerr := symbolValue(dbg, sym)
		if aerr == nil {
			return addr, nil
		}
		lastErr = aerr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no debug file found for %s", binPath)
	}
	return 0, lastErr
}

// parseBuildID extracts the hex build-id from a .note.gnu.build-id section.
func parseBuildID(note []byte) string {
	// ELF note: name_sz(4) desc_sz(4) type(4) name(padded) desc
	if len(note) < 16 {
		return ""
	}
	nameSz := binary.LittleEndian.Uint32(note[0:4])
	descSz := binary.LittleEndian.Uint32(note[4:8])
	off := 12 + ((int(nameSz) + 3) &^ 3)
	if off+int(descSz) > len(note) {
		return ""
	}
	return hex.EncodeToString(note[off : off+int(descSz)])
}

// symbolValue returns the value (address) of a named symbol in an ELF file,
// checking both the regular and dynamic symbol tables.
func symbolValue(path, sym string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	all := append(syms, dyn...)
	// exact match first
	for _, s := range all {
		if s.Name == sym {
			return s.Value, nil
		}
	}
	// C++-mangled match: MySQL's dispatch_command is exported mangled, e.g.
	// _Z16dispatch_command19enum_server_commandP3THD... . Itanium mangling for
	// a free function is _Z<len><name>..., so match _Z<len><sym> as a prefix.
	mangled := fmt.Sprintf("_Z%d%s", len(sym), sym)
	for _, s := range all {
		if strings.HasPrefix(s.Name, mangled) {
			return s.Value, nil
		}
	}
	return 0, fmt.Errorf("symbol %q not in %s", sym, path)
}

// dbgsymHint returns the distro command that installs the debug symbols
// needed to attach the query-auditing uprobes to a stripped DB binary.
func dbgsymHint(kind string) string {
	switch kind {
	case "postgres":
		return "run `sudo make dbgsym` (installs matching postgresql-NN-dbgsym from the ddebs -updates pocket), then restart dbguard"
	case "mysql":
		return "run `sudo make dbgsym` (installs matching mysql-server-core-8.0-dbgsym from the ddebs -updates pocket), then restart dbguard"
	default:
		return "install the DB server's debug-symbols (dbgsym/debuginfo) package, then restart dbguard"
	}
}

// symbolFor maps an uprobe program name plus engine kind onto an ELF
// symbol. Program names follow "uprobe_[engine-hint_]symbol", e.g.
// "uprobe_pg_exec_simple_query"; a recognised engine hint is stripped.
// Without a hint the first configured default symbol for the engine kind is
// used (see config.AttachConfig).
// uprobeProgram describes which DB engine a capture program belongs to and the
// real symbol in that engine's binary it must attach to. The program NAME alone
// (e.g. uprobe_pg_simple) does NOT equal the symbol name - mapping the two was
// the long-standing bug that made the loader look up bogus symbols like
// "simple"/"parse"/"dispatch" and never attach anything.
var uprobePrograms = map[string]struct {
	engine string
	symbol string
}{
	// PostgreSQL: exec_simple_query handles simple-protocol queries;
	// pg_parse_query handles the parse phase (extended protocol / prepared)
	// and is also reached from exec_simple_query, so it covers simple queries.
	"uprobe_pg_simple": {"postgres", "exec_simple_query"},
	"uprobe_pg_parse":  {"postgres", "pg_parse_query"},
	// MySQL/MariaDB. Primary: mysql_parse(THD*, char *rawbuf=SQL, ...) whose
	// PARM2 is the raw SQL on both flavors. Fallbacks: dispatch_command, whose
	// ABI differs by flavor (two handlers, chosen by the mangled signature).
	"uprobe_my_parse":      {"mysql", "mysql_parse"},
	"uprobe_my_dispatch":   {"mysql", "dispatch_command"},
	"uprobe_my_dispatch80": {"mysql", "dispatch_command"},
}

// symbolFor returns the real symbol a uprobe program must attach to for a given
// target engine, or "" when the program does not apply to that engine (so the
// caller skips it instead of attaching the wrong probe). Operator overrides in
// cfg.Attach.* take precedence when set.
func symbolFor(kind, progName string, cfg config.EBPFConfig) string {
	spec, ok := uprobePrograms[progName]
	if !ok {
		return ""
	}
	if spec.engine != kind {
		return "" // program is for a different engine than this target
	}
	switch kind {
	case "postgres":
		if len(cfg.Attach.PostgresSymbols) > 0 && progName == "uprobe_pg_simple" {
			return cfg.Attach.PostgresSymbols[0]
		}
	case "mysql":
		// Each mysql program maps to its own symbol in uprobePrograms
		// (uprobe_my_parse->mysql_parse, uprobe_my_dispatch->dispatch_command),
		// so we do NOT apply a blanket MySQLSymbols[0] override here - that
		// would force every program onto the same symbol. The per-program
		// spec.symbol below is authoritative.
	}
	return spec.symbol
}

// dbg32: 内核每接口仅允许挂一个 XDP prog; collections 按 Go map 随机序加载,
// 谁占用接口本会随重启漂移。这里登记本进程的 XDP 归属: xdp_sqi_guard
// (SQLi 防火墙) 永远接管接口, 其余 XDP 程序向它让位 (确定性归属)。
var (
	xdpOwners  = map[int]string{} // iface index -> 本进程已挂载的 prog 名
	xdpHandles = map[int]link.Link{}
	xdpMu      sync.Mutex
)

// attachXDP attaches an XDP program to the first configured interface,
// trying native (driver) mode first and falling back to generic mode.
func attachXDP(progName string, prog *ebpf.Program, cfg config.EBPFConfig) (link.Link, error) {
	if len(cfg.XDPInterfaces) == 0 {
		return nil, fmt.Errorf("xdp program %s: no ebpf.xdp_interfaces configured", progName)
	}
	ifName := cfg.XDPInterfaces[0]
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("xdp interface %s: %w", ifName, err)
	}

	// dbg32: 归属仲裁 -- 接口已被本进程另一个 dbguard XDP 程序占用时:
	//   * xdp_sqi_guard 到场 => 关闭旧 link (内核随之解挂), 顶替占用
	//   * 其他程序到场而 xdp_sqi_guard 在位 => 让位 (确定性错误, 不再撞 EBUSY)
	// collections 仍按 Go map 随机序加载, 但归属结果与顺序无关。
	xdpMu.Lock()
	owner, owned := xdpOwners[iface.Index]
	xdpMu.Unlock()
	if owned && owner != progName {
		if progName == "xdp_sqi_guard" {
			xdpMu.Lock()
			old := xdpHandles[iface.Index]
			delete(xdpOwners, iface.Index)
			delete(xdpHandles, iface.Index)
			xdpMu.Unlock()
			if old != nil {
				_ = old.Close() // BPF link 关闭即内核解挂
			}
		} else if owner == "xdp_sqi_guard" {
			return nil, fmt.Errorf("xdp program %s: %s held by %s (yield)", progName, ifName, owner)
		}
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		// driver mode requires NIC support - generic mode works everywhere
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return nil, fmt.Errorf("xdp attach on %s: %w", ifName, err)
		}
	}
	xdpMu.Lock()
	xdpOwners[iface.Index] = progName
	xdpHandles[iface.Index] = l
	xdpMu.Unlock()
	return l, nil
}

// maybeLink normalises (link, err) into the slice form used everywhere.
func maybeLink(l link.Link, err error) ([]link.Link, error) {
	if err != nil {
		return nil, err
	}
	return []link.Link{l}, nil
}
