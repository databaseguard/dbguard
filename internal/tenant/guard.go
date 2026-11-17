// Guard is the pipeline module for feature 9 (multi-tenant isolation).
//
// It evaluates four event shapes:
//
//   - EvFileAccess with Meta["path"] + Meta["tenant_id"]: the caller
//     tenant must own the path (Registry.OwnerForPath) - otherwise
//     tenant.cross_tenant_file (high) with deny (+quarantine unless
//     AlertOnly).
//   - EvTenant: the kernel's own verdict (Meta["tenant_id"] vs
//     Meta["owner_tenant"]); enriched with resolved tenant names, plus the
//     registry fallback when kernel metadata is absent.
//   - EvConnOpen: the client IP must fall inside the caller tenant's
//     AllowedCIDRs - otherwise tenant.network_violation (high). Tenants
//     without an explicit CIDR set are skipped (operator opted out of
//     network isolation for them).
//   - EvQueryAudit with Labels["tenant"]: a database name embedding
//     another tenant's name is tenant.db_mismatch (medium,
//     observability-only).
//
// SetSyncFunc wires the kernel-map sync used by SyncKernel/Run to push
// tenant IDs, cgroup IDs and path prefixes into the eBPF LPM maps.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// Finding kinds emitted by this module.
const (
	KindCrossTenantFile  = "tenant.cross_tenant_file"
	KindNetworkViolation = "tenant.network_violation"
	KindDBMismatch       = "tenant.db_mismatch"
)

// reconcileInterval is the Runner cadence for kernel-map reconciliation.
const reconcileInterval = 60 * time.Second

// Guard implements detect.Detector + detect.Runner for tenant isolation.
// Safe for concurrent use: the registry is immutable and the sync hook
// assignment is a single field.
type Guard struct {
	cfg  config.TenantConfig
	log  *slog.Logger
	pub  func(*events.Event)
	reg  *Registry
	sync func(tenantID uint32, cgroupIDs []uint64, prefixes []string) error
}

// New builds a Guard; tenant definitions are validated up front, so an
// invalid table surfaces at startup, not on the first event.
func New(cfg config.TenantConfig, log *slog.Logger, pub func(*events.Event)) (*Guard, error) {
	if log == nil {
		log = slog.Default()
	}
	reg, err := NewRegistry(cfg)
	if err != nil {
		return nil, err
	}
	return &Guard{cfg: cfg, log: log, pub: pub, reg: reg}, nil
}

// Name implements detect.Detector.
func (g *Guard) Name() string { return "tenant" }

// Registry exposes the resolved tenant table (API/CLI introspection).
func (g *Guard) Registry() *Registry { return g.reg }

// SetSyncFunc wires the kernel-map sync hook. The daemon connects it to
// the eBPF manager: for each tenant it must program tenantID → cgroupIDs
// and AllowedPaths prefixes into the maps consulted by the LSM file hooks
// and cgroup_skb programs. Called on the pipeline/reconcile goroutine; the
// implementation must be fast or defer work internally.
func (g *Guard) SetSyncFunc(f func(tenantID uint32, cgroupIDs []uint64, prefixes []string) error) {
	g.sync = f
}

// Evaluate implements detect.Detector.
func (g *Guard) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	switch ev.Type {
	case events.EvFileAccess:
		return g.evalFileAccess(ev)
	case events.EvTenant:
		return g.evalKernelTenant(ev)
	case events.EvConnOpen:
		return g.evalConn(ev)
	case events.EvQueryAudit:
		return g.evalQueryTenant(ev)
	default:
		return nil
	}
}

// evalFileAccess checks user-space-verifiable file isolation. A caller
// without tenant context (Meta["tenant_id"] absent/zero) cannot be judged;
// unowned paths are unmanaged, not violations.
func (g *Guard) evalFileAccess(ev *events.Event) []events.Finding {
	path := ev.MetaGet("path")
	if path == "" {
		return nil
	}
	callerID := parseID(ev.MetaGet("tenant_id"))
	if callerID == 0 {
		return nil
	}
	owner, ok := g.reg.OwnerForPath(path)
	if !ok || owner.ID == callerID {
		return nil
	}
	return g.crossTenantFinding(ev, path, callerID, owner)
}

// evalKernelTenant enriches the kernel verdict from dbg_tenant_event
// (Meta["tenant_id"] = caller, Meta["owner_tenant"] = owner). Both values
// are stable tenant IDs produced by StableID. When kernel metadata is
// missing it falls back to the registry-based path check.
func (g *Guard) evalKernelTenant(ev *events.Event) []events.Finding {
	callerID := parseID(ev.MetaGet("tenant_id"))
	ownerID := parseID(ev.MetaGet("owner_tenant"))
	if callerID != 0 && ownerID != 0 && callerID != ownerID {
		owner := Tenant{ID: ownerID, Name: tenantLabel(g.reg, ownerID)}
		return g.crossTenantFinding(ev, ev.MetaGet("path"), callerID, owner)
	}
	return g.evalFileAccess(ev)
}

// crossTenantFinding attaches the canonical cross-tenant file finding.
func (g *Guard) crossTenantFinding(ev *events.Event, path string, callerID uint32, owner Tenant) []events.Finding {
	caller := tenantLabel(g.reg, callerID)
	f := events.Finding{
		Kind: KindCrossTenantFile,
		Detail: fmt.Sprintf("tenant %q (id %d) accessed path %q owned by tenant %q (id %d)",
			caller, callerID, path, owner.Name, owner.ID),
		Confidence: 1.0,
		Snippet:    path,
	}
	ev.AddFinding(f)
	ev.Severity = maxSeverity(ev.Severity, events.SevHigh)
	ev.AddAction(events.ActDeny)
	if !g.cfg.AlertOnly {
		ev.AddAction(events.ActQuarantine)
	}
	g.publishViolation(ev, "cross_tenant_file", path)
	g.log.Warn("tenant: cross-tenant file access",
		"caller", caller, "owner", owner.Name, "path", path, "pid", ev.PID)
	return []events.Finding{f}
}

// evalConn enforces tenant network scoping on new connections. Only
// tenants with an explicit AllowedCIDRs set are checked (empty set = the
// operator opted out of network isolation for that tenant).
func (g *Guard) evalConn(ev *events.Event) []events.Finding {
	callerID := parseID(ev.MetaGet("tenant_id"))
	if callerID == 0 {
		return nil
	}
	t, ok := g.reg.ByID(callerID)
	if !ok || len(t.AllowedCIDRs) == 0 {
		return nil
	}
	ip := ev.ClientIP
	if ip == "" {
		ip = ev.MetaGet("client_ip")
	}
	if ip == "" {
		return nil
	}
	if g.reg.CIDRAllow(callerID, ip) {
		return nil
	}
	f := events.Finding{
		Kind: KindNetworkViolation,
		Detail: fmt.Sprintf("connection from %s outside allowed sources %v of tenant %q (id %d)",
			ip, t.AllowedCIDRs, t.Name, t.ID),
		Confidence: 1.0,
		Snippet:    ip,
	}
	ev.AddFinding(f)
	ev.Severity = maxSeverity(ev.Severity, events.SevHigh)
	ev.AddAction(events.ActDeny)
	if !g.cfg.AlertOnly {
		ev.AddAction(events.ActQuarantine)
	}
	g.publishViolation(ev, "network_violation", ip)
	g.log.Warn("tenant: network violation", "tenant", t.Name, "ip", ip, "pid", ev.PID)
	return []events.Finding{f}
}

// evalQueryTenant flags queries whose database name embeds another
// tenant's name while the application runtime claims a different tenant
// (Labels["tenant"], Meta["tenant"] fallback). Observability-only:
// naming conventions vary, so this is medium + alert, never enforcement.
func (g *Guard) evalQueryTenant(ev *events.Event) []events.Finding {
	if ev.Database == "" {
		return nil
	}
	label := ev.Labels["tenant"]
	if label == "" {
		label = ev.MetaGet("tenant")
	}
	if label == "" {
		return nil
	}
	claimed, ok := g.reg.ByName(label)
	if !ok {
		return nil // unknown label: not a verifiable claim
	}
	db := strings.ToLower(ev.Database)
	for _, t := range g.reg.Tenants() {
		if t.ID == claimed.ID || t.Name == "" {
			continue
		}
		if !strings.Contains(db, strings.ToLower(t.Name)) {
			continue
		}
		f := events.Finding{
			Kind: KindDBMismatch,
			Detail: fmt.Sprintf("workload claims tenant %q but queried database %q embeds tenant %q",
				claimed.Name, ev.Database, t.Name),
			Confidence: 0.8,
			Snippet:    ev.Database,
		}
		ev.AddFinding(f)
		ev.Severity = maxSeverity(ev.Severity, events.SevMedium)
		ev.AddAction(events.ActAlert)
		g.log.Warn("tenant: database mismatch",
			"claimed", claimed.Name, "embedded", t.Name, "database", ev.Database)
		return []events.Finding{f}
	}
	return nil
}

// publishViolation synthesizes a dedicated tenant.violation event so
// alert routing sees enforcement decisions even when the triggering event
// is a file/connection event (mirrors the rids FIM synthesis pattern).
func (g *Guard) publishViolation(ev *events.Event, kind, subject string) {
	if g.pub == nil {
		return
	}
	out := &events.Event{
		ID:       events.NewID(),
		Type:     events.EvTenant,
		Time:     time.Now().UTC(),
		Severity: ev.Severity,
		Source:   "tenant",
		Message:  fmt.Sprintf("tenant violation (%s): %s", kind, subject),
		PID:      ev.PID,
		UID:      ev.UID,
		CgroupID: ev.CgroupID,
	}
	out.MetaSet("kind", kind)
	out.MetaSet("subject", subject)
	out.MetaSet("origin_event_id", ev.ID)
	out.MetaSet("origin_event_type", string(ev.Type))
	g.pub(out)
}

// SyncKernel pushes the tenant table into the kernel maps via the wired
// sync hook (no-op with a debug log when unwired, so Run can call it
// unconditionally). Cgroup IDs are resolved per fragment: on cgroup v2 the
// kernel cgroup id is the inode number of the cgroup directory, which
// os.Stat provides directly; config fragments are usually *fragments*
// though, so when a path does not exist a stable FNV-1a hash of the
// fragment stands in - the daemon's eBPF manager is expected to override
// this resolver with real (ino-based) cgroup discovery.
func (g *Guard) SyncKernel() error {
	if g.sync == nil {
		g.log.Debug("tenant: no kernel sync hook wired; skipping reconcile")
		return nil
	}
	var errs []error
	for _, t := range g.reg.Tenants() {
		ids := make([]uint64, 0, len(t.Cgroups))
		for _, frag := range t.Cgroups {
			ids = append(ids, cgroupID(frag))
		}
		if err := g.sync(t.ID, ids, cloneStrings(t.AllowedPaths)); err != nil {
			errs = append(errs, fmt.Errorf("tenant: sync %s: %w", t.Name, err))
			continue
		}
		g.log.Debug("tenant: synced to kernel",
			"tenant", t.Name, "cgroups", len(ids), "prefixes", len(t.AllowedPaths))
	}
	return errors.Join(errs...)
}

// cgroupID resolves a cgroup fragment to a kernel cgroup id: the inode
// number when the path exists on this host, else a stable path hash
// (documented fallback, see SyncKernel).
func cgroupID(path string) uint64 {
	if path == "" {
		return 0
	}
	if fi, err := os.Stat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return st.Ino
		}
	}
	return fnv64(path)
}

// fnv64 is the 64-bit FNV-1a hash used for stable cgroup-id fallbacks.
func fnv64(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

// Run implements detect.Runner: reconcile the kernel maps immediately and
// then every 60s so config reloads and cgroup churn are reflected. Sync
// failures are logged (non-fatal) - the next tick retries.
func (g *Guard) Run(ctx context.Context) error {
	if err := g.SyncKernel(); err != nil {
		g.log.Warn("tenant: initial kernel sync failed", "err", err)
	}
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := g.SyncKernel(); err != nil {
				g.log.Warn("tenant: kernel reconcile failed", "err", err)
			}
		}
	}
}

// Close implements detect.Runner; the registry is read-only after
// construction, so there is nothing to release.
func (g *Guard) Close() error { return nil }

// parseID parses a decimal tenant id from event metadata; ""/garbage → 0.
func parseID(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// tenantLabel renders a tenant id for human-readable findings.
func tenantLabel(reg *Registry, id uint32) string {
	if t, ok := reg.ByID(id); ok {
		return t.Name
	}
	return fmt.Sprintf("tenant:%d", id)
}

// maxSeverity returns the more severe of a and b.
func maxSeverity(a, b events.Severity) events.Severity {
	if a.Order() >= b.Order() {
		return a
	}
	return b
}
