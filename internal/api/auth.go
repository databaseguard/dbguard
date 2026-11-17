// auth.go implements the API authentication middleware: bearer-token mode
// when a token is configured, loopback-only mode otherwise.
package api

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// withAuth enforces the admin API contract:
//
//   - Token configured: every request (except the /healthz and /readyz
//     probes) must present "Authorization: Bearer <token>"; the comparison
//     is constant-time (crypto/subtle).
//   - No token: only loopback remote addresses are served; anything else
//     gets 403 so a default install cannot be driven over the network.
func withAuth(token string, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// liveness/readiness probes stay unauthenticated for schedulers
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}
			if token == "" {
				if !isLoopbackRemote(r) {
					log.Warn("api: rejected non-loopback request without token",
						"remote", r.RemoteAddr, "path", r.URL.Path)
					errorJSON(w, http.StatusForbidden,
						"loopback only; configure api.token for remote access")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			got := bearerToken(r)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="dbguard"`)
				errorJSON(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken extracts the token from an "Authorization: Bearer x" header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(tok)
}

// isLoopbackRemote reports whether the request originates from a loopback
// address (IPv4 127.0.0.0/8, IPv6 ::1).
func isLoopbackRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
