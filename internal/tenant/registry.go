// Package tenant implements the user-space half of feature 9: multi-tenant
// isolation guarding.
//
// Tenants are declared in config (config.TenantConfig) as named isolation
// domains with cgroup path fragments, filesystem path prefixes and network
// CIDR scopes. Registry resolves the static tenant table (stable FNV-1a
// IDs shared with the kernel maps); Guard is the pipeline module that
// flags cross-tenant file access, network-scope violations and
// database-name mismatches, and reconciles the kernel-side tenant maps via
// a sync hook wired by the daemon.
package tenant

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/databaseguard/dbguard/internal/config"
)

// Tenant is one isolation domain resolved from config.TenantDef.
type Tenant struct {
	ID           uint32
	Name         string
	Cgroups      []string
	AllowedPaths []string
	AllowedCIDRs []string
}

// StableID derives the deterministic 32-bit tenant ID (FNV-1a over the
// tenant name bytes). The same value must be used everywhere the kernel
// refers to a tenant (dbg_tenant_event.TenantID/OwnerTenant, the
// cgroup→tenant maps), so tenant names are identity: renaming a tenant
// changes its ID and requires a kernel-map resync. Exported so the daemon
// can populate kernel maps with identical values.
func StableID(name string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= prime32
	}
	return h
}

// Registry is the validated, immutable view of the configured tenants.
// Safe for concurrent use after construction (all methods are read-only).
type Registry struct {
	tenants []Tenant
	byID    map[uint32]int
	cidrs   map[uint32][]netip.Prefix
}

// NewRegistry validates and indexes cfg.Tenants: IDs must be unique and
// non-empty, CIDRs must parse. Parsing failures are fatal (a half-loaded
// tenant table would silently under-protect).
func NewRegistry(cfg config.TenantConfig) (*Registry, error) {
	r := &Registry{
		byID:  make(map[uint32]int, len(cfg.Tenants)),
		cidrs: make(map[uint32][]netip.Prefix, len(cfg.Tenants)),
	}
	for i, def := range cfg.Tenants {
		if def.ID == "" {
			return nil, fmt.Errorf("tenant: tenants[%d]: id is required", i)
		}
		id := StableID(def.ID)
		if _, dup := r.byID[id]; dup {
			return nil, fmt.Errorf("tenant: duplicate tenant %q", def.ID)
		}
		t := Tenant{
			ID:           id,
			Name:         def.ID,
			Cgroups:      cloneStrings(def.Cgroups),
			AllowedPaths: cloneStrings(def.AllowedPaths),
			AllowedCIDRs: cloneStrings(def.AllowedCIDRs),
		}
		prefixes := make([]netip.Prefix, 0, len(t.AllowedCIDRs))
		for _, cidr := range t.AllowedCIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("tenant: %s: parse cidr %q: %w", t.Name, cidr, err)
			}
			prefixes = append(prefixes, p.Masked())
		}
		r.tenants = append(r.tenants, t)
		r.byID[id] = len(r.tenants) - 1
		r.cidrs[id] = prefixes
	}
	return r, nil
}

// Tenants returns a copy of the tenant list in config order.
func (r *Registry) Tenants() []Tenant {
	out := make([]Tenant, len(r.tenants))
	copy(out, r.tenants)
	return out
}

// ByID resolves a tenant by its stable numeric ID.
func (r *Registry) ByID(id uint32) (Tenant, bool) {
	i, ok := r.byID[id]
	if !ok {
		return Tenant{}, false
	}
	return r.tenants[i], true
}

// ByName resolves a tenant by its configured name.
func (r *Registry) ByName(name string) (Tenant, bool) {
	for _, t := range r.tenants {
		if t.Name == name {
			return t, true
		}
	}
	return Tenant{}, false
}

// ByCgroup resolves the tenant owning a cgroup path by fragment match: a
// tenant matches when its configured fragment appears inside the full
// cgroup path (e.g. "acme.service" inside
// "/sys/fs/cgroup/system.slice/acme.service/app.service"). The longest
// matching fragment wins (most specific); ties keep config order.
func (r *Registry) ByCgroup(cgroupPathFragment string) (Tenant, bool) {
	if cgroupPathFragment == "" {
		return Tenant{}, false
	}
	best, bestLen := -1, -1
	for i, t := range r.tenants {
		for _, frag := range t.Cgroups {
			if frag == "" || len(frag) <= bestLen {
				continue
			}
			if strings.Contains(cgroupPathFragment, frag) {
				best, bestLen = i, len(frag)
			}
		}
	}
	if best < 0 {
		return Tenant{}, false
	}
	return r.tenants[best], true
}

// OwnerForPath returns the tenant owning path via the longest
// boundary-aware prefix match over every tenant's AllowedPaths. Paths no
// tenant owns return ok=false - unmanaged filesystem is not a violation,
// only cross-tenant access to *claimed* paths is enforced.
func (r *Registry) OwnerForPath(path string) (Tenant, bool) {
	best, bestLen := -1, -1
	for i, t := range r.tenants {
		for _, p := range t.AllowedPaths {
			if len(p) <= bestLen || !pathPrefixMatch(path, p) {
				continue
			}
			best, bestLen = i, len(p)
		}
	}
	if best < 0 {
		return Tenant{}, false
	}
	return r.tenants[best], true
}

// CIDRAllow reports whether ip falls inside tenant tenantID's allowed CIDR
// set. Unknown tenants and unparseable addresses deny; a tenant with no
// configured CIDRs also denies - Guard guards that case itself and skips
// network checks for such tenants (opted-out semantics), keeping the
// registry primitive strictly default-deny.
func (r *Registry) CIDRAllow(tenantID uint32, ip string) bool {
	prefixes, ok := r.cidrs[tenantID]
	if !ok {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap() // treat ::ffff:10.0.0.1 as 10.0.0.1
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// pathPrefixMatch is boundary-aware: /data/ac does not match /data/acme,
// closing the sibling-directory bypass.
func pathPrefixMatch(path, prefix string) bool {
	if prefix == "" || !strings.HasPrefix(path, prefix) {
		return false
	}
	if strings.HasSuffix(prefix, "/") || len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// cloneStrings copies a config slice (defensive isolation).
func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
