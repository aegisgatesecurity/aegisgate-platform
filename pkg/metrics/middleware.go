// Package metrics provides HTTP middleware for metrics collection.
package metrics

import (
	"net/http"
	"time"
)

// Middleware wraps an HTTP handler with Prometheus metrics
type Middleware struct {
	next http.Handler
	name string
}

// NewMiddleware creates a new metrics middleware
func NewMiddleware(name string, next http.Handler) *Middleware {
	return &Middleware{
		next: next,
		name: name,
	}
}

// ServeHTTP implements http.Handler
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	
	// Create a response wrapper to capture status code
	wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	
	// Increment active connections
	IncActiveConnections(m.name)
	defer DecActiveConnections(m.name)
	
	// Call the next handler
	m.next.ServeHTTP(wrapped, r)
	
	// Record metrics
	duration := time.Since(start)
	RecordHTTPRequest(r.Method, m.name, wrapped.statusCode, duration)
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// WrapHandler wraps an http.Handler with metrics
func WrapHandler(name string, handler http.Handler) http.Handler {
	return NewMiddleware(name, handler)
}

// WrapHandlerFunc wraps an http.HandlerFunc with metrics
func WrapHandlerFunc(name string, handler http.HandlerFunc) http.Handler {
	return NewMiddleware(name, handler)
}

// InstrumentRoute instruments a specific route pattern
func InstrumentRoute(mux *http.ServeMux, pattern string, handler http.Handler) {
	mux.Handle(pattern, WrapHandler(pattern, handler))
}
