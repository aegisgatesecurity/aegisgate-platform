// SPDX-FileCopyrightText: Copyright 2024-2026 AegisGate Security, LLC
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// ============================================================================
// HTTP Handler Logging
// ============================================================================

// HTTPHandler wraps an http.Handler with request logging
type HTTPHandler struct {
	logger      *Logger
	handler     http.Handler
	logRequest  bool
	logResponse bool
}

// NewHTTPHandler creates a new HTTP handler with logging
func NewHTTPHandler(handler http.Handler, logger *Logger) *HTTPHandler {
	return &HTTPHandler{
		logger:      logger,
		handler:     handler,
		logRequest:  true,
		logResponse: false,
	}
}

// SetLogResponse enables response logging
func (h *HTTPHandler) SetLogResponse(log bool) {
	h.logResponse = log
}

// ServeHTTP logs the request and response
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Wrap response writer to capture status code
	wrapper := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Log request
	if h.logRequest {
		h.logRequestStart(r)
	}

	// Serve the request
	h.handler.ServeHTTP(wrapper, r)

	// Log response
	duration := time.Since(start)
	fields := map[string]interface{}{
		"method":      r.Method,
		"path":        r.URL.Path,
		"status":      wrapper.statusCode,
		"duration_ms": duration.Milliseconds(),
		"remote_ip":   getClientIP(r),
	}

	if wrapper.size > 0 {
		fields["bytes"] = wrapper.size
	}

	level := LevelInfo
	if wrapper.statusCode >= 500 {
		level = LevelError
		h.logger.log(level, "HTTP request completed", fields)
	} else if wrapper.statusCode >= 400 {
		level = LevelWarn
		h.logger.log(level, "HTTP request completed", fields)
	} else {
		h.logger.log(level, "HTTP request completed", fields)
	}
}

func (h *HTTPHandler) logRequestStart(r *http.Request) {
	fields := map[string]interface{}{
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"remote_ip":  getClientIP(r),
		"user_agent": r.UserAgent(),
		"protocol":   r.Proto,
	}

	if r.ContentLength > 0 {
		fields["content_length"] = r.ContentLength
	}

	h.logger.log(LevelDebug, "HTTP request started", fields)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.size += len(b)
	return w.ResponseWriter.Write(b) // codeql[go/reflected-xss] — logging response writer: only records response size, does not render HTML
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check common headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if idx := indexByte(ip, ','); idx >= 0 {
			ip = ip[:idx]
		}
		return trim(ip)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Fallback to RemoteAddr
	addr := r.RemoteAddr
	if idx := indexByte(addr, ':'); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

// indexByte is strings.IndexByte for bytes
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// trim is strings.TrimSpace
func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// ============================================================================
// HTTP Middleware
// ============================================================================

// HTTPMiddleware creates a logging middleware
func HTTPMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return NewHTTPHandler(next, logger)
	}
}

// ============================================================================
// Request/Response Logging Entry
// ============================================================================

// HTTPEntry represents an HTTP log entry with more detail
type HTTPEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Query     string    `json:"query,omitempty"`
	Status    int       `json:"status"`
	Duration  int64     `json:"duration_ms"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent,omitempty"`
	BytesIn   int64     `json:"bytes_in,omitempty"`
	BytesOut  int64     `json:"bytes_out,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// ToEntry converts HTTPEntry to a log Entry
func (e *HTTPEntry) ToEntry(level Level, message string) *Entry {
	fields := map[string]interface{}{
		"method":      e.Method,
		"path":        e.Path,
		"status":      e.Status,
		"duration_ms": e.Duration,
		"client_ip":   e.ClientIP,
	}
	if e.Query != "" {
		fields["query"] = e.Query
	}
	if e.UserAgent != "" {
		fields["user_agent"] = e.UserAgent
	}
	if e.BytesIn > 0 {
		fields["bytes_in"] = e.BytesIn
	}
	if e.BytesOut > 0 {
		fields["bytes_out"] = e.BytesOut
	}
	if e.Error != "" {
		fields["error"] = e.Error
	}
	return &Entry{
		Timestamp: e.Timestamp,
		Level:     level.String(),
		Message:   message,
		Fields:    fields,
	}
}

// ============================================================================
// Log Grouping
// ============================================================================

// GroupKey groups related log entries
type GroupKey struct {
	RequestID string
	SessionID string
	TraceID   string
}

// LogGroup represents a group of related log entries
type LogGroup struct {
	Key     GroupKey
	Entries []*Entry
	Start   time.Time
	End     time.Time
}

// NewLogGroup creates a new log group
func NewLogGroup(requestID string) *LogGroup {
	return &LogGroup{
		Key:     GroupKey{RequestID: requestID},
		Entries: make([]*Entry, 0),
		Start:   time.Now(),
	}
}

// Add adds an entry to the group
func (g *LogGroup) Add(entry *Entry) {
	g.Entries = append(g.Entries, entry)
	g.End = time.Now()
}

// Duration returns the group duration
func (g *LogGroup) Duration() time.Duration {
	return g.End.Sub(g.Start)
}

// ToJSON converts the group to JSON
func (g *LogGroup) ToJSON() ([]byte, error) {
	return json.MarshalIndent(g, "", "  ")
}

// ============================================================================
// Buffered Logger
// ============================================================================

// BufferedLogger writes logs to a buffer before flushing
type BufferedLogger struct {
	*Logger
	buffer *bytes.Buffer
	size   int
	mu     bool // using Logger's mutex
}

// NewBufferedLogger creates a buffered logger
func NewBufferedLogger(size int) *BufferedLogger {
	buf := &bytes.Buffer{}
	return &BufferedLogger{
		Logger: NewWithOutput(buf),
		buffer: buf,
		size:   size,
	}
}

// Flush flushes the buffer
func (l *BufferedLogger) Flush() ([]byte, error) {
	return l.buffer.Bytes(), nil
}

// Reset resets the buffer
func (l *BufferedLogger) Reset() {
	l.buffer.Reset()
}

// String returns the buffer contents
func (l *BufferedLogger) String() string {
	return l.buffer.String()
}
