// Package enrich defines the identity-resolution contract used by the
// pipeline to attach workload identity (container, pod, labels) to events.
//
// The concrete implementation lives in internal/identity and may consult
// cgroups, container runtimes and Cilium. A no-op resolver is provided so
// DBGuard runs standalone without Kubernetes.
package enrich

import "sync"

// Identity is the resolved workload context for a process/cgroup pair.
type Identity struct {
	PID         uint32
	CgroupID    uint64
	ContainerID string
	PodName     string
	Namespace   string
	CiliumID    string
	Labels      map[string]string
}

// Resolver resolves (pid, cgroup) -> Identity. Implementations must be
// safe for concurrent use and should never block for long (hot path).
type Resolver interface {
	Resolve(pid uint32, cgroup uint64) Identity
}

// CiliumLookup is an optional capability a Resolver may implement: mapping a
// client IP to its Cilium security-identity id and labels (e.g.
// "k8s:app=api-server"). The pipeline and the inline proxy type-assert for it
// and, when present, stamp meta.cilium_identity onto events and let policy rules
// gate on identity. A resolver without Cilium enabled returns ("", nil, false),
// so callers treat it as "no information".
type CiliumLookup interface {
	LookupForIP(ip string) (id string, labels []string, ok bool)
}

// Noop returns empty identities; used when identity enrichment is disabled.
type Noop struct{}

// NewNoop returns the do-nothing resolver.
func NewNoop() *Noop { return &Noop{} }

// Resolve returns an empty Identity.
func (Noop) Resolve(uint32, uint64) Identity { return Identity{} }

// Cache wraps a Resolver with a small TTL-free LRU-ish map; the pipeline
// calls Resolve far more often than identity actually changes.
type Cache struct {
	mu    sync.RWMutex
	m     map[cacheKey]Identity
	max   int
	inner Resolver
}

type cacheKey struct {
	pid    uint32
	cgroup uint64
}

// NewCache builds a caching resolver with the given capacity.
func NewCache(inner Resolver, max int) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{m: make(map[cacheKey]Identity, 64), max: max, inner: inner}
}

// LookupForIP forwards to the inner resolver when it supports Cilium lookups
// (so the cache wrapper doesn't hide the capability). Returns ("", nil, false)
// when the inner resolver has no Cilium client.
func (c *Cache) LookupForIP(ip string) (string, []string, bool) {
	if l, ok := c.inner.(CiliumLookup); ok {
		return l.LookupForIP(ip)
	}
	return "", nil, false
}

// Resolve consults the cache, falling back to the inner resolver.
func (c *Cache) Resolve(pid uint32, cgroup uint64) Identity {
	k := cacheKey{pid, cgroup}
	c.mu.RLock()
	id, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		return id
	}
	id = c.inner.Resolve(pid, cgroup)
	c.mu.Lock()
	if len(c.m) >= c.max {
		// cheap reset; identity churn is low
		c.m = make(map[cacheKey]Identity, 64)
	}
	c.m[k] = id
	c.mu.Unlock()
	return id
}
