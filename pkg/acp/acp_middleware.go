// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Middleware
// =========================================================================
//
// HTTP middleware for ACP endpoints that applies security scanning.
// Can be integrated with any HTTP router (Echo, Gin, net/http, etc.)
//
// =========================================================================

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
)

// Middleware creates an HTTP middleware for ACP endpoints
type Middleware struct {
	scanner *ACPResponseScanner
	logger  *slog.Logger
}

// NewMiddleware creates a new ACP middleware
func NewMiddleware(scanner *ACPResponseScanner) *Middleware {
	return &Middleware{
		scanner: scanner,
		logger:  slog.Default().With("component", "acp-middleware"),
	}
}

// NewMiddlewareWithConfig creates middleware with custom config
func NewMiddlewareWithConfig(cfg *ACPGuardConfig) *Middleware {
	return &Middleware{
		scanner: NewACPResponseScannerWithConfig(cfg),
		logger:  slog.Default().With("component", "acp-middleware"),
	}
}

// WrapHandler wraps an ACP handler with security middleware
func (m *Middleware) WrapHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from request
		sessionID := extractSessionID(r)

		// Check rate limit
		identity := r.RemoteAddr
		if sessionID != "" {
			identity = sessionID
		}

		if err := m.scanner.CheckRateLimit(identity); err != nil {
			m.logger.Warn("Rate limit exceeded", "identity", identity)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Process request body for scanning
		if r.Body != nil {
			// SECURITY: Limit body size to 10MB to prevent DoS
			r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				m.logger.Error("Failed to read request body", "error", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			// Replace body for downstream handler
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Parse and validate ACP message
			msg, err := parseACPMessage(bodyBytes)
			if err != nil {
				m.logger.Warn("Failed to parse ACP message", "error", err)
				http.Error(w, "Invalid ACP message", http.StatusBadRequest)
				return
			}

			// Validate message structure
			if err := m.scanner.ValidateACPMessage(msg); err != nil {
				m.logger.Warn("Message validation failed", "error", err)
				http.Error(w, "Invalid message: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Put parsed message in context for handler
			ctx := context.WithValue(r.Context(), ACPMessageKey, msg)
			ctx = context.WithValue(ctx, SessionIDKey, sessionID)
			*r = *r.WithContext(ctx)
		}

		// Create response wrapper
		wrapper := &responseWriter{ResponseWriter: w, buffer: &bytes.Buffer{}}

		// Call handler
		handler.ServeHTTP(wrapper, r)

		// Scan response if we got content
		if wrapper.buffer.Len() > 0 {
			result, err := m.scanner.ScanResponse(r.Context(), wrapper.buffer.String(), sessionID)
			if err != nil {
				m.logger.Error("Response scan failed", "error", err)
			} else if !result.Allowed {
				m.logger.Warn("Response blocked by scanner",
					"sessionID", sessionID,
					"reason", result.BlockReason,
				)
				w.WriteHeader(http.StatusForbidden)
				// HTML-encode to prevent XSS in error message
				redacted := html.EscapeString("Content blocked")
				if _, writeErr := w.Write([]byte(redacted)); writeErr != nil {
					m.logger.Error("Failed to write blocked response", "error", writeErr)
				}
				return
			}
		}

		// Write response with security headers
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Prevent caching to avoid reflected XSS
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		if _, writeErr := w.Write(wrapper.buffer.Bytes()); writeErr != nil {
			m.logger.Error("Failed to write response", "error", writeErr)
		}
	})
}

// MiddlewareFunc is an http.HandlerFunc compatible middleware
func (m *Middleware) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID
		sessionID := extractSessionID(r)
		identity := sessionID
		if identity == "" {
			identity = r.RemoteAddr
		}

		// Rate limit check
		if err := m.scanner.CheckRateLimit(identity); err != nil {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Let the actual handler run
		next(w, r)
	}
}

// Context keys
type contextKey string

const (
	ACPMessageKey contextKey = "acp_message"
	SessionIDKey  contextKey = "session_id"
)

// responseWriter wraps http.ResponseWriter to capture response body
type responseWriter struct {
	http.ResponseWriter
	buffer *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.buffer.Write(b)
	return len(b), nil
}

func (rw *responseWriter) WriteString(s string) (int, error) {
	return rw.buffer.WriteString(s)
}

// extractSessionID extracts session ID from HTTP request
func extractSessionID(r *http.Request) string {
	// Try header first
	if session := r.Header.Get("X-ACP-Session"); session != "" {
		return session
	}

	// Try cookie
	if cookie, err := r.Cookie("acp_session"); err == nil {
		return cookie.Value
	}

	// Try query param
	if session := r.URL.Query().Get("session"); session != "" {
		return session
	}

	return ""
}

// parseACPMessage parses raw JSON bytes into an ACPMessage
func parseACPMessage(data []byte) (*ACPMessage, error) {
	if len(data) == 0 {
		return nil, ErrNilMessage
	}

	msg := &ACPMessage{}
	if err := json.Unmarshal(data, msg); err != nil {
		return nil, ErrInvalidMessage
	}

	if msg.Method == "" {
		return nil, ErrInvalidMethod
	}

	return msg, nil
}
