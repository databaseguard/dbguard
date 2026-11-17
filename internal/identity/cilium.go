// Package identity - cilium.go queries the local Cilium agent for the security
// identity behind an IP address. Lookups degrade silently: when the agent is
// disabled or unreachable, LookupForIP returns ("", nil, false) and the pipeline
// proceeds without the cilium_identity metadata.
//
// The real Cilium agent serves its REST API over a unix socket
// (default /var/run/cilium/cilium.sock); the IP→identity mapping comes from the
// endpoint list: GET /v1/endpoint returns every local endpoint with its
// status.networking.addressing[] (ipv4/ipv6) and status.identity (id + labels).
// We match the client IP to an endpoint and read its identity.
//
// cilium_api_url accepts:
//   - unix:///var/run/cilium/cilium.sock   (default; the real agent)
//   - http://host:port                     (a proxy or a test stub)
//
// For an http base we also accept a simpler stub that answers
// GET /v1/identity?ip=<ip> with {security_identity:{id,labels}} - used by
// scripts/test-cilium.sh - as a fallback when /v1/endpoint yields nothing.
package identity

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// defaultCiliumAPI is the real local Cilium agent API socket.
	defaultCiliumAPI = "unix:///var/run/cilium/cilium.sock"
	// ciliumCacheTTL bounds both positive and negative lookups so an agent
	// outage cannot turn the pipeline hot path into a hot loop.
	ciliumCacheTTL = 60 * time.Second
	// ciliumCacheMax bounds the cache size; on overflow it resets.
	ciliumCacheMax = 4096
)

// CiliumClient is a tiny cached client for the Cilium agent identity API.
type CiliumClient struct {
	display string // configured value, for diagnostics
	baseURL string // request base (http://cilium for a unix socket)
	hc      *http.Client

	mu    sync.Mutex
	cache map[string]ciliumEntry
}

// ciliumEntry caches one lookup result (positive or negative) until exp.
type ciliumEntry struct {
	id     string
	labels []string
	ok     bool
	exp    time.Time
}

// ciliumEndpoint is the subset of the agent's /v1/endpoint objects we need.
type ciliumEndpoint struct {
	Status struct {
		Identity *struct {
			ID     json.Number `json:"id"`
			Labels []string    `json:"labels"`
		} `json:"identity"`
		Networking *struct {
			Addressing []struct {
				IPV4 string `json:"ipv4"`
				IPV6 string `json:"ipv6"`
			} `json:"addressing"`
		} `json:"networking"`
	} `json:"status"`
}

// ciliumIdentityResp is the simple fallback stub shape (GET /v1/identity?ip=).
type ciliumIdentityResp struct {
	ID               json.Number `json:"id"`
	SecurityIdentity *struct {
		ID     json.Number `json:"id"`
		Labels []string    `json:"labels"`
	} `json:"security_identity"`
	Identity *struct {
		ID json.Number `json:"id"`
	} `json:"identity"`
}

// NewCiliumClient returns a client for apiURL (empty = the default agent
// socket) with per-request timeout (<=0 = 2s).
func NewCiliumClient(apiURL string, timeout time.Duration) *CiliumClient {
	if apiURL == "" {
		apiURL = defaultCiliumAPI
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	hc := &http.Client{Timeout: timeout}
	base := strings.TrimRight(apiURL, "/")

	if strings.HasPrefix(apiURL, "unix://") {
		sock := strings.TrimPrefix(apiURL, "unix://")
		hc.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", sock)
			},
		}
		base = "http://cilium" // host is ignored by the unix dialer
	}
	return &CiliumClient{
		display: apiURL,
		baseURL: base,
		hc:      hc,
		cache:   make(map[string]ciliumEntry, 64),
	}
}

// APIURL returns the configured agent endpoint (for diagnostics).
func (c *CiliumClient) APIURL() string { return c.display }

// IdentityForIP returns the Cilium security identity id for ip (labels dropped).
func (c *CiliumClient) IdentityForIP(ip string) (string, bool) {
	id, _, ok := c.LookupForIP(ip)
	return id, ok
}

// LookupForIP returns the Cilium security identity id AND its labels for ip,
// cached for 60s. ok is false when the agent is disabled, unreachable or has no
// endpoint for that IP - callers treat that as "no information".
func (c *CiliumClient) LookupForIP(ip string) (string, []string, bool) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.cache[ip]; ok && now.Before(e.exp) {
		c.mu.Unlock()
		return e.id, e.labels, e.ok
	}
	c.mu.Unlock()

	id, labels, ok := c.lookup(ip)

	c.mu.Lock()
	if len(c.cache) >= ciliumCacheMax {
		c.cache = make(map[string]ciliumEntry, 64)
	}
	c.cache[ip] = ciliumEntry{id: id, labels: labels, ok: ok, exp: now.Add(ciliumCacheTTL)}
	c.mu.Unlock()
	return id, labels, ok
}

// lookup tries the real endpoint list first, then the simple stub endpoint.
func (c *CiliumClient) lookup(ip string) (string, []string, bool) {
	if id, labels, ok := c.lookupEndpoints(ip); ok {
		return id, labels, true
	}
	return c.lookupStub(ip)
}

// lookupEndpoints queries GET /v1/endpoint and matches the IP to an endpoint's
// identity - this is what the real Cilium agent serves.
func (c *CiliumClient) lookupEndpoints(ip string) (string, []string, bool) {
	body, ok := c.get(c.baseURL + "/v1/endpoint")
	if !ok {
		return "", nil, false
	}
	defer body.Close()
	var eps []ciliumEndpoint
	if err := json.NewDecoder(body).Decode(&eps); err != nil {
		return "", nil, false
	}
	for i := range eps {
		st := &eps[i].Status
		if st.Identity == nil || st.Networking == nil {
			continue
		}
		for _, a := range st.Networking.Addressing {
			if a.IPV4 == ip || a.IPV6 == ip {
				id := st.Identity.ID.String()
				if id == "" {
					return "", nil, false
				}
				return id, st.Identity.Labels, true
			}
		}
	}
	return "", nil, false
}

// lookupStub queries the simple GET /v1/identity?ip= shape (test stub / proxy).
func (c *CiliumClient) lookupStub(ip string) (string, []string, bool) {
	body, ok := c.get(c.baseURL + "/v1/identity?ip=" + url.QueryEscape(ip))
	if !ok {
		return "", nil, false
	}
	defer body.Close()
	var r ciliumIdentityResp
	if err := json.NewDecoder(body).Decode(&r); err != nil {
		return "", nil, false
	}
	switch {
	case r.SecurityIdentity != nil && r.SecurityIdentity.ID != "":
		return r.SecurityIdentity.ID.String(), r.SecurityIdentity.Labels, true
	case r.Identity != nil && r.Identity.ID != "":
		return r.Identity.ID.String(), nil, true
	case r.ID != "":
		return r.ID.String(), nil, true
	default:
		return "", nil, false
	}
}

// get performs a GET and returns the body on HTTP 200, else (nil,false). The
// caller closes the body. All transport errors degrade to (nil,false).
func (c *CiliumClient) get(endpoint string) (io.ReadCloser, bool) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, false
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, false
	}
	return resp.Body, true
}
