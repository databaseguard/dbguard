// middleware.go provides the HTTP cross-cutting middlewares: panic recovery
// and structured request logging.
package api

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusRecorder captures the response status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status and delegates.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying ResponseWriter when it supports flushing.
// Without this method the embedded wrapper would mask the http.Flusher that
// the Server-Sent-Events handler type-asserts for, breaking streaming for
// any route that passes through the request-logging middleware.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withRecovery converts handler panics into 500 responses instead of
// tearing down the whole HTTP server.
func withRecovery(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				log.Error("api: panic recovered",
					"panic", p,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()))
				errorJSON(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withRequestLog emits one structured log line per request.
func withRequestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("api: request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds())
	})
}
