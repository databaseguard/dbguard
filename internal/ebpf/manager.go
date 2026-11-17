// manager.go owns the kernel side of DBGuard: object loading, program
// attachment, ring-buffer pumping and the runtime control-plane maps
// (config_map, target_pids, blocked_paths, client_allow, exfil_quarantine).
//
// The Manager degrades gracefully: when ebpf is disabled in configuration it
// becomes a no-op (Start does nothing, Events stays empty); when eBPF is
// enabled but privileges are missing, Start reports an error so main can
// fall back to user-space-only operation.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// Target describes one DB server process to observe with uprobes and
// target-scoped kernel maps.
type Target struct {
	PID    uint32
	Binary string // absolute exe path ("" -> /proc/<pid>/exe)
	Kind   string // postgres|mysql|sqlite
}

// eventChanSize bounds the kernel->pipeline queue before drops kick in.
const eventChanSize = 4096

// Manager supervises loaded collections, their attachments and readers.
type Manager struct {
	cfg     config.EBPFConfig
	log     *slog.Logger
	enabled bool

	mu      sync.Mutex
	colls   map[string]*ebpf.Collection
	readers []*ringbuf.Reader
	links   []link.Link
	// uprobedPIDs tracks DB-process PIDs whose uprobes are already attached,
	// so EnsureUprobes only attaches newly discovered processes.
	uprobedPIDs map[uint32]bool

	events chan *events.Event
	wg     sync.WaitGroup

	closeOnce sync.Once
}

// NewManager validates configuration. When ebpf is disabled the manager is
// returned in disabled mode (all operations become no-ops) even if the
// object directory is missing - graceful degradation for dev machines.
func NewManager(cfg config.EBPFConfig, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		cfg:         cfg,
		log:         log,
		enabled:     cfg.Enabled,
		colls:       make(map[string]*ebpf.Collection),
		uprobedPIDs: make(map[uint32]bool),
		events:      make(chan *events.Event, eventChanSize),
	}
	if !cfg.Enabled {
		log.Info("ebpf: disabled, running user-space-only")
		return m, nil
	}
	if _, err := os.Stat(cfg.ObjectDir); err != nil {
		return nil, fmt.Errorf("ebpf: object dir %s: %w", cfg.ObjectDir, err)
	}
	return m, nil
}

// Start loads all objects, attaches programs and begins pumping ring
// buffers into Events(). It requires root or CAP_BPF+CAP_PERFMON when
// enabled; attachment failures on individual programs are logged and
// skipped so a partially supported kernel still yields events.
func (m *Manager) Start(ctx context.Context, targets []Target) error {
	if !m.enabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("ebpf: requires root or CAP_BPF+CAP_PERFMON (current euid %d)", os.Geteuid())
	}
	// LoadObjects loads each *.bpf.o independently and returns the ones that
	// loaded alongside a joined error for the ones that did not. A failure in
	// an OPTIONAL object (typically the lsm_* variants on a kernel without
	// CONFIG_BPF_LSM / "lsm=bpf") must not take down the whole data plane, so
	// we proceed with whatever loaded and only fail hard when nothing did.
	colls, err := LoadObjects(m.cfg)
	if err != nil {
		if len(colls) == 0 {
			return fmt.Errorf("ebpf: load objects: %w", err)
		}
		m.log.Warn("ebpf: some objects failed to load; continuing with the rest",
			"loaded", len(colls), "err", err)
	}
	m.mu.Lock()
	m.colls = colls
	m.mu.Unlock()

	for name, coll := range colls {
		links, aerr := attachCollectionLinks(name, coll, m.cfg, targets, m.log)
		m.mu.Lock()
		m.links = append(m.links, links...)
		m.mu.Unlock()
		if aerr != nil {
			m.log.Warn("ebpf: some attachments failed", "collection", name, "err", aerr)
		}
		if err := m.writeInitialConfig(coll); err != nil {
			m.log.Warn("ebpf: config_map init failed", "collection", name, "err", err)
		}
		m.startReader(ctx, name, coll)
	}
	m.UpdateTargets(targets)
	// Record the boot-time targets so EnsureUprobes treats only later-appearing
	// processes as new. attachCollectionLinks above already attached their
	// uprobes (for whatever targets were known at Start).
	m.mu.Lock()
	for _, t := range targets {
		if t.PID != 0 {
			m.uprobedPIDs[t.PID] = true
		}
	}
	m.mu.Unlock()
	m.log.Info("ebpf: started", "collections", len(colls), "targets", len(targets))
	return nil
}

// EnsureUprobes attaches the audit collection's uprobes to any target PIDs not
// already covered. Start attaches uprobes only for the DB processes known at
// boot; a process that appears later - or a DB that restarted under a new PID,
// or one simply not yet visible when dbguard started - otherwise lands only in
// target_pids, so its queries pass the kernel gate but NO uprobe ever fires for
// it and nothing is audited. The procwatch callback calls this on every newly
// discovered DB process so auditing is resilient to startup ordering.
func (m *Manager) EnsureUprobes(targets []Target) {
	if !m.enabled {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	coll := m.colls["audit"]
	if coll == nil {
		return
	}
	var fresh []Target
	for _, t := range targets {
		if t.PID != 0 && !m.uprobedPIDs[t.PID] {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) == 0 {
		return
	}
	for progName, prog := range coll.Programs {
		if !strings.HasPrefix(progName, "uprobe_") {
			continue
		}
		links, err := attachUprobes(progName, prog, m.cfg, fresh, m.log)
		if err != nil {
			// Expected for e.g. exec_simple_query on a stripped binary; the
			// primary pg_parse/dispatch probes still attach.
			m.log.Warn("ebpf: incremental uprobe attach", "program", progName, "err", err)
		}
		m.links = append(m.links, links...)
	}
	for _, t := range fresh {
		m.uprobedPIDs[t.PID] = true
	}
	m.log.Info("ebpf: uprobes attached for newly discovered DB processes", "count", len(fresh))
}

// writeInitialConfig seeds config_map with the EBPF-level settings; the
// full UpdateConfig call from main fills engine-module flags later.
func (m *Manager) writeInitialConfig(coll *ebpf.Collection) error {
	mp := coll.Maps["config_map"]
	if mp == nil {
		return nil // object without a config map: nothing to seed
	}
	val := ConfigMap{
		PGPort:      uint16(m.cfg.Ports.Postgres),
		MySQLPort:   uint16(m.cfg.Ports.MySQL),
		DropEnabled: boolU8(m.cfg.DropEnabled),
	}
	return mp.Put(uint32(0), val)
}

// startReader pumps the collection's "events" ring buffer, decoding each
// record and forwarding it to the Events() channel (drop on overflow).
// eventlessCollections lists collections that legitimately carry no
// `events` ring buffer. microseg_sockmap is a socket-layer redirection
// datapath (sk_skb/stream_parser + stream_verdict, sk_msg) owned by the
// sockmap orchestrator - it produces no pipeline events, so a missing
// ring buffer there is by design and must not WARN at runtime (dbg33).
var eventlessCollections = map[string]struct{}{
	"microseg_sockmap": {},
}

func (m *Manager) startReader(ctx context.Context, name string, coll *ebpf.Collection) {
	evMap, ok := coll.Maps["events"]
	if !ok {
		if _, evless := eventlessCollections[name]; evless {
			m.log.Debug("ebpf: collection has no events ring buffer (by design)", "collection", name)
		} else {
			m.log.Warn("ebpf: collection has no events ring buffer", "collection", name)
		}
		return
	}
	rd, err := ringbuf.NewReader(evMap)
	if err != nil {
		m.log.Warn("ebpf: ringbuf reader failed", "collection", name, "err", err)
		return
	}
	m.mu.Lock()
	m.readers = append(m.readers, rd)
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
					return
				}
				m.log.Debug("ebpf: ringbuf read failed", "collection", name, "err", err)
				continue
			}
			ev, err := DecodeEvent(rec.RawSample)
			if err != nil {
				m.log.Debug("ebpf: decode failed", "collection", name, "err", err)
				continue
			}
			select {
			case m.events <- ev:
			default:
				m.log.Debug("ebpf: event channel full, dropping", "collection", name)
			}
		}
	}()
}

// UpdateConfig pushes the full runtime configuration into every
// collection's config_map (single-element array, key 0).
func (m *Manager) UpdateConfig(cfg config.Config) {
	if !m.enabled {
		return
	}
	val := ConfigMap{
		PGPort:         uint16(cfg.EBPF.Ports.Postgres),
		MySQLPort:      uint16(cfg.EBPF.Ports.MySQL),
		SQLIEnabled:    boolU8(cfg.SQLi.Enabled),
		DropEnabled:    boolU8(cfg.EBPF.DropEnabled),
		PIIPrescan:     boolU8(cfg.PII.Enabled),
		ExfilEnabled:   boolU8(cfg.Exfil.Enabled),
		RIDSAlertOnly:  boolU8(cfg.RIDS.AlertOnly),
		LineageEnabled: boolU8(cfg.Lineage.Enabled),
	}
	for name, coll := range m.snapshotColls() {
		mp := coll.Maps["config_map"]
		if mp == nil {
			continue
		}
		if err := mp.Put(uint32(0), val); err != nil {
			m.log.Warn("ebpf: config_map update failed", "collection", name, "err", err)
		}
	}
}

// UpdateTargets rewrites target_pids: processes listed get an entry
// (pid -> 1), everything else is removed so stale pids never linger.
func (m *Manager) UpdateTargets(targets []Target) {
	if !m.enabled {
		return
	}
	for _, coll := range m.snapshotColls() {
		mp := coll.Maps["target_pids"]
		if mp == nil {
			continue
		}
		clearMap(mp, uint32(0), uint8(0))
		for _, t := range targets {
			if err := mp.Put(t.PID, uint8(1)); err != nil {
				m.log.Warn("ebpf: target_pids update failed", "pid", t.PID, "err", err)
			}
		}
		// Wildcard sentinel (key 0): audit EVERY backend of the discovered DB
		// binaries, not just the startup PIDs. A DB forks a new backend per
		// connection, so the query-handling pid is almost never one of the
		// discovered ones; without this, fresh-connection queries (psql -c,
		// new pool connections) are dropped in-kernel. The uprobe is already
		// scoped to the DB binary, so this stays correctly limited to DBs.
		if len(targets) > 0 {
			if err := mp.Put(uint32(0), uint8(1)); err != nil {
				m.log.Warn("ebpf: target_pids wildcard set failed", "err", err)
			}
		}
	}
}

// UpdateBlockedPaths rewrites blocked_paths: protected filesystem prefixes
// handed to the kernel RIDS checks (NUL-padded [64]byte keys).
func (m *Manager) UpdateBlockedPaths(paths []string) {
	if !m.enabled {
		return
	}
	for _, coll := range m.snapshotColls() {
		mp := coll.Maps["blocked_paths"]
		if mp == nil {
			continue
		}
		clearMap(mp, [64]byte{}, uint8(0))
		for _, p := range paths {
			key, err := blockedPathKey(p)
			if err != nil {
				m.log.Warn("ebpf: blocked path skipped", "path", p, "err", err)
				continue
			}
			if err := mp.Put(key, uint8(1)); err != nil {
				m.log.Warn("ebpf: blocked_paths update failed", "path", p, "err", err)
			}
		}
	}
}

// UpdateClientPolicy rewrites client_allow (LPM trie) from CIDR strings.
// Only IPv4 is supported by the kernel key layout; invalid entries are
// skipped with a warning.
func (m *Manager) UpdateClientPolicy(cidrs []string) {
	if !m.enabled {
		return
	}
	for _, coll := range m.snapshotColls() {
		mp := coll.Maps["client_allow"]
		if mp == nil {
			continue
		}
		clearMap(mp, lpmKey{}, uint8(0))
		for _, c := range cidrs {
			key, err := parseLPMKey(c)
			if err != nil {
				m.log.Warn("ebpf: client CIDR skipped", "cidr", c, "err", err)
				continue
			}
			if err := mp.Put(key, uint8(1)); err != nil {
				m.log.Warn("ebpf: client_allow update failed", "cidr", c, "err", err)
			}
		}
	}
}

// QuarantineIP marks an IPv4 address hostile in exfil_quarantine until
// expiry (unix nanoseconds), so kernel-side exfil enforcement can drop or
// reset its traffic.
func (m *Manager) QuarantineIP(ip string, d time.Duration) {
	if !m.enabled {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		m.log.Warn("ebpf: quarantine skipped, bad IP", "ip", ip, "err", err)
		return
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		m.log.Warn("ebpf: quarantine skipped, IPv6 unsupported", "ip", ip)
		return
	}
	a4 := addr.As4()
	key := binary.BigEndian.Uint32(a4[:])
	expiry := uint64(time.Now().Add(d).UnixNano())
	for name, coll := range m.snapshotColls() {
		mp := coll.Maps["exfil_quarantine"]
		if mp == nil {
			continue
		}
		if err := mp.Put(key, expiry); err != nil {
			m.log.Warn("ebpf: quarantine update failed", "ip", ip, "collection", name, "err", err)
		}
	}
	m.log.Info("ebpf: IP quarantined", "ip", ip, "duration", d)
}

// Events returns the stream of decoded kernel events.
func (m *Manager) Events() <-chan *events.Event {
	return m.events
}

// Close releases ring-buffer readers, links and collections and closes the
// Events channel. Idempotent.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		readers := m.readers
		m.readers = nil
		links := m.links
		m.links = nil
		colls := m.colls
		m.colls = make(map[string]*ebpf.Collection)
		m.mu.Unlock()

		for _, rd := range readers {
			rd.Close() // closes the Read() channel, readers exit
		}
		m.wg.Wait()
		for _, l := range links {
			if err := l.Close(); err != nil {
				m.log.Debug("ebpf: link close", "err", err)
			}
		}
		for _, c := range colls {
			c.Close()
		}
		close(m.events)
	})
	return nil
}

// snapshotColls returns a copy of the collection set.
func (m *Manager) snapshotColls() map[string]*ebpf.Collection {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]*ebpf.Collection, len(m.colls))
	for k, v := range m.colls {
		out[k] = v
	}
	return out
}

// clearMap deletes every entry of a hash or trie map. Keys are collected
// first because deleting while iterating a kernel LPM trie is unreliable.
func clearMap[K comparable, V any](mp *ebpf.Map, k K, v V) {
	var keys []K
	it := mp.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, key := range keys {
		_ = mp.Delete(key)
	}
}

// boolU8 maps a bool onto the kernel's u8 flag convention.
func boolU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// blockedPathKey normalises a protected path into the fixed [64]byte key
// used by the kernel blocked_paths map (trimmed, NUL padded).
func blockedPathKey(path string) ([64]byte, error) {
	var key [64]byte
	p := strings.TrimSpace(path)
	if p == "" {
		return key, fmt.Errorf("ebpf: empty blocked path")
	}
	if len(p) > 64 {
		return key, fmt.Errorf("ebpf: blocked path %q exceeds 64 bytes", p)
	}
	copy(key[:], p)
	return key, nil
}

// lpmKey mirrors the client_allow LPM-trie key {u32 prefixlen, u32 addr}.
// The address is stored big-endian (network order) as produced by inet_pton.
type lpmKey struct {
	PrefixLen uint32
	Addr      uint32
}

// parseLPMKey converts "10.0.0.0/8" (or a bare "10.0.0.1", treated as /32)
// into an lpmKey. IPv6 is rejected: the kernel map value only carries a u32
// address.
func parseLPMKey(cidr string) (lpmKey, error) {
	s := strings.TrimSpace(cidr)
	if s == "" {
		return lpmKey{}, fmt.Errorf("ebpf: empty CIDR")
	}
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return lpmKey{}, fmt.Errorf("ebpf: parse %q: %w", cidr, err)
	}
	addr := pfx.Addr().Unmap()
	if !addr.Is4() {
		return lpmKey{}, fmt.Errorf("ebpf: only IPv4 CIDRs supported, got %q", cidr)
	}
	if pfx.Bits() > 32 {
		return lpmKey{}, fmt.Errorf("ebpf: prefix length %d out of range for IPv4", pfx.Bits())
	}
	a4 := pfx.Masked().Addr().As4()
	return lpmKey{PrefixLen: uint32(pfx.Bits()), Addr: binary.BigEndian.Uint32(a4[:])}, nil
}
