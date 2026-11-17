// Package identity - resolver.go implements enrich.Resolver by combining
// cgroup parsing, /proc introspection and (optionally) Cilium lookups to
// attach workload identity (container, pod, namespace) to events.
package identity

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/enrich"
)

// resolverCacheMax bounds the identity cache; identities churn slowly, so a
// full cache is simply reset (same strategy as enrich.Cache).
const resolverCacheMax = 8192

// kubeletPodsPrefix marks mountinfo lines that reveal the owning pod UID.
const kubeletPodsPrefix = "/var/lib/kubelet/pods/"

// serviceaccountNSPath is the projected namespace file inside a pod.
const serviceaccountNSPath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// resolveKey identifies one process/cgroup pair.
type resolveKey struct {
	pid    uint32
	cgroup uint64
}

// Resolver resolves (pid, cgroup) to an enrich.Identity. It implements
// enrich.Resolver and is safe for concurrent use; Resolve is on the hot
// path, so all work is bounded and results are cached.
type Resolver struct {
	hint   string // container_hint: auto|docker|containerd|crio
	log    *slog.Logger
	cilium *CiliumClient

	mu    sync.RWMutex
	cache map[resolveKey]enrich.Identity
}

// NewResolver validates cfg and returns a ready resolver. A Cilium client is
// only created when cfg.CiliumEnabled; the daemon wires lookups per client
// IP (see CiliumClient.IdentityForIP).
func NewResolver(cfg config.IdentityConfig, log *slog.Logger) (*Resolver, error) {
	if log == nil {
		log = slog.Default()
	}
	hint := cfg.ContainerHint
	if hint == "" {
		hint = "auto"
	}
	switch hint {
	case "auto", "docker", "containerd", "crio":
	default:
		return nil, fmt.Errorf("identity: container_hint %q must be auto|docker|containerd|crio", hint)
	}
	r := &Resolver{
		hint:  hint,
		log:   log,
		cache: make(map[resolveKey]enrich.Identity, 128),
	}
	if cfg.CiliumEnabled {
		r.cilium = NewCiliumClient(cfg.CiliumAPIURL, 2*time.Second)
		log.Info("identity: cilium enrichment enabled", "api", r.cilium.APIURL())
	}
	return r, nil
}

// Resolve implements enrich.Resolver. All failures degrade to a best-effort
// identity: missing /proc entries or unreadable files simply leave fields
// empty instead of erroring.
func (r *Resolver) Resolve(pid uint32, cgroup uint64) enrich.Identity {
	k := resolveKey{pid: pid, cgroup: cgroup}
	r.mu.RLock()
	if id, ok := r.cache[k]; ok {
		r.mu.RUnlock()
		return id
	}
	r.mu.RUnlock()

	id := r.resolveUncached(pid, cgroup)

	r.mu.Lock()
	if len(r.cache) >= resolverCacheMax {
		r.cache = make(map[resolveKey]enrich.Identity, 128)
	}
	r.cache[k] = id
	r.mu.Unlock()
	return id
}

// resolveUncached performs the actual /proc walk for one pid.
func (r *Resolver) resolveUncached(pid uint32, cgroup uint64) enrich.Identity {
	id := enrich.Identity{PID: pid, CgroupID: cgroup, Labels: map[string]string{}}

	// 1. Container ID from cgroup membership.
	for _, line := range procLines(fmt.Sprintf("/proc/%d/cgroup", pid)) {
		rt, cid := ParseCgroupPath(line)
		if cid == "" {
			continue
		}
		id.ContainerID = cid
		if rt != "" {
			id.Labels["runtime"] = rt
		}
		break
	}

	// 2. HOSTNAME from the process environment; inside containers this is
	// the pod name (Kubernetes) or the short container id (docker run).
	hostname := procEnv(pid, "HOSTNAME")
	if hostname == "" {
		hostname = readTrimmed(fmt.Sprintf("/proc/%d/root/etc/hostname", pid))
	}
	if id.ContainerID == "" && isShortHex(hostname) {
		// docker run default: hostname is the 12-hex short container id.
		id.ContainerID = hostname
		id.Labels["runtime"] = runtimeLabelForHint(r.hint)
	}

	// 3. mountinfo hints: kubelet pod volumes reveal the owning pod UID.
	if uid := podUIDFromMounts(pid); uid != "" {
		id.Labels["k8s_pod_uid"] = uid
	}

	// 4. Namespace via the projected service account token (best effort).
	if ns := readTrimmed(fmt.Sprintf("/proc/%d/root%s", pid, serviceaccountNSPath)); ns != "" {
		id.Namespace = ns
	}

	// 5. Pod name best-effort: the container hostname equals the pod name
	// in default Kubernetes deployments.
	if hostname != "" {
		id.PodName = hostname
	}
	return id
}

// runtimeLabelForHint maps the configured hint onto a label for bare-hex
// hostnames when socket detection found nothing.
func runtimeLabelForHint(hint string) string {
	switch hint {
	case "docker", "containerd", "crio":
		return hint
	default:
		return "unknown"
	}
}

// Cilium returns the optional Cilium client (nil when disabled).
func (r *Resolver) Cilium() *CiliumClient { return r.cilium }

// LookupForIP implements enrich.CiliumLookup: it maps a client IP to its Cilium
// security-identity id and labels via the local agent. Returns ("", nil, false)
// when Cilium is disabled or the agent has no identity for that IP, so callers
// simply omit the identity (and identity-scoped rules do not match).
func (r *Resolver) LookupForIP(ip string) (string, []string, bool) {
	if r.cilium == nil || ip == "" {
		return "", nil, false
	}
	return r.cilium.LookupForIP(ip)
}

// procLines reads a /proc file into non-empty, trimmed lines.
func procLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// procEnv extracts one variable from /proc/<pid>/environ.
func procEnv(pid uint32, key string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	for _, kv := range strings.Split(string(data), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// podUIDFromMounts scans /proc/<pid>/mountinfo for kubelet pod paths and
// extracts the pod UID.
func podUIDFromMounts(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.Index(line, kubeletPodsPrefix)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(kubeletPodsPrefix):]
		if end := strings.IndexAny(rest, "/ \t"); end > 0 {
			return rest[:end]
		}
	}
	return ""
}

// readTrimmed returns the first line of a file, or "" on any error.
func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// isShortHex reports whether s is a 12-hex docker short id.
func isShortHex(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
