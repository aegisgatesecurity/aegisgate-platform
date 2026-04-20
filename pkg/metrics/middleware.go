// HTTP middleware for automatic Prometheus metrics collection.
// Uses cardinality-safe label values from the Phase 2 label system
// to prevent metrics explosion in production.
//
// # Usage
//
// Wrap any http.Handler to automatically record request duration,
// status codes, and active connections:
//
//	handler := metrics.WrapHandler("proxy", myHandler)
//	http.Handle("/", handler)
//
// Or use the Middleware directly for more control:
//
//	mw := metrics.NewMiddleware("dashboard", innerHandler)
//	http.Handle("/", mw)
package metrics

import (
	"net/http"
	"time"
)

// Middleware wraps an HTTP handler with Prometheus metrics collection.
// It records request duration, status codes, and active connections
// using cardinality-safe labels from the Phase 2 label system.
//
// The name parameter identifies the service component for the
// active_connections gauge (e.g., "proxy", "dashboard", "mcp").
type Middleware struct {
	next http.Handler
	name string
}

// NewMiddleware creates a new metrics middleware that wraps the given handler.
// The name is used as the service label for active connection tracking and
// appears in the aegisgate_active_connections gauge.
func NewMiddleware(name string, next http.Handler) *Middleware {
	return &Middleware{
		next: next,
		name: name,
	}
}

// ServeHTTP implements the http.Handler interface.
// For each request it:
//  1. Records the start time
//  2. Increments the active connections gauge for this service
//  3. Captures the response status code via a responseWriter wrapper
//  4. Defers decrement of the active connections gauge
//  5. Records request duration and status class via RecordHTTPRequest
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Create a response wrapper to capture the status code
	wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Track active connections using the service name as label
	IncActiveConnections(m.name)
	defer DecActiveConnections(m.name)

	// Forward the request to the wrapped handler
	m.next.ServeHTTP(wrapped, r)

	// Record metrics with cardinality-safe labels:
	//   - method: from the request (GET, POST, etc.)
	//   - endpoint: sanitized path (UUIDs → :uuid, IDs → :id, etc.)
	//   - status: class-based (2xx, 4xx, 5xx) rather than raw code
	duration := time.Since(start)
	RecordHTTPRequest(r.Method, r.URL.Path, wrapped.statusCode, duration)
}

// responseWriter wraps http.ResponseWriter to capture the response status code.
// This is necessary because Go's ResponseWriter doesn't expose the status code
// after WriteHeader is called.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter.
// Only the first call to WriteHeader is honored, matching Go's standard behavior.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write ensures WriteHeader(200) is called if no explicit status was set,
// matching Go's default behavior for http.ResponseWriter.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// WrapHandler wraps an http.Handler with the metrics middleware.
// The name parameter identifies the service component (e.g., "proxy", "dashboard").
func WrapHandler(name string, handler http.Handler) http.Handler {
	return NewMiddleware(name, handler)
}

// WrapHandlerFunc wraps an http.HandlerFunc with the metrics middleware.
// The name parameter identifies the service component.
func WrapHandlerFunc(name string, handler http.HandlerFunc) http.Handler {
	return NewMiddleware(name, handler)
}

// InstrumentRoute registers a handler on a ServeMux with metrics instrumentation.
// The pattern parameter is used as the service label and route pattern.
func InstrumentRoute(mux *http.ServeMux, pattern string, handler http.Handler) {
	mux.Handle(pattern, WrapHandler(pattern, handler))
}
