// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// CSRFConfig holds configuration for CSRF protection
type CSRFConfig struct {
	// TokenLength is the length of the CSRF token in bytes
	TokenLength int
	// CookieName is the name of the CSRF cookie
	CookieName string
	// CookieMaxAge is the max age of the cookie in seconds
	CookieMaxAge int
	// CookieSameSite sets the SameSite attribute
	CookieSameSite http.SameSite
	// CookieSecure ensures cookies are only sent over HTTPS
	CookieSecure bool
	// CookieHTTPOnly makes the cookie inaccessible to JavaScript
	CookieHTTPOnly bool
	// HeaderName is the header that contains the CSRF token
	HeaderName string
	// FormFieldName is the form field name for the CSRF token
	FormFieldName string
}

// DefaultCSRFConfig returns a secure default CSRF configuration
func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		TokenLength:    32,
		CookieName:     "csrf_token",
		CookieMaxAge:   86400, // 24 hours
		CookieSameSite: http.SameSiteStrictMode,
		CookieSecure:   true,
		CookieHTTPOnly: true,
		HeaderName:     "X-CSRF-Token",
		FormFieldName:  "_csrf_token",
	}
}

// CSRFMiddleware provides CSRF protection for HTTP handlers
type CSRFMiddleware struct {
	config  *CSRFConfig
	logger  *slog.Logger
	tokens  map[string]time.Time
	mu      sync.RWMutex
	cleanup *time.Ticker
}

// NewCSRFMiddleware creates a new CSRF protection middleware
func NewCSRFMiddleware(config *CSRFConfig) *CSRFMiddleware {
	if config == nil {
		config = DefaultCSRFConfig()
	}

	middleware := &CSRFMiddleware{
		config:  config,
		logger:  slog.Default().WithGroup("security.csrf"),
		tokens:  make(map[string]time.Time),
		cleanup: time.NewTicker(5 * time.Minute),
	}

	go middleware.cleanupLoop()
	return middleware
}

// WithLogger sets a custom logger
func (cm *CSRFMiddleware) WithLogger(logger *slog.Logger) *CSRFMiddleware {
	cm.logger = logger.WithGroup("security.csrf")
	return cm
}

// cleanupLoop periodically removes expired tokens
func (cm *CSRFMiddleware) cleanupLoop() {
	for range cm.cleanup.C {
		cm.mu.Lock()
		now := time.Now()
		for token, expiry := range cm.tokens {
			if now.After(expiry) {
				delete(cm.tokens, token)
			}
		}
		cm.mu.Unlock()
	}
}

// Stop halts the cleanup goroutine
func (cm *CSRFMiddleware) Stop() {
	if cm.cleanup != nil {
		cm.cleanup.Stop()
	}
}

// generateToken creates a cryptographically secure random token
func (cm *CSRFMiddleware) generateToken() string {
	bytes := make([]byte, cm.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		cm.logger.Error("Failed to generate CSRF token", "error", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// Handler wraps an HTTP handler with CSRF protection
func (cm *CSRFMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF protection
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			// Ensure token exists for safe methods
			cookie, err := r.Cookie(cm.config.CookieName)
			if err != nil || cookie.Value == "" {
				token := cm.generateToken()
				cm.setCSRFCookie(w, token)
				cm.storeToken(token)
			}
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods, validate CSRF token
		if !cm.validateRequest(w, r) {
			cm.logger.Warn("CSRF validation failed",
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)
			cm.writeError(w, "CSRF token validation failed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateRequest checks CSRF token validity
func (cm *CSRFMiddleware) validateRequest(w http.ResponseWriter, r *http.Request) bool {
	// Get token from cookie
	cookie, err := r.Cookie(cm.config.CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	cookieToken := cookie.Value
	headerToken := r.Header.Get(cm.config.HeaderName)
	if headerToken == "" {
		headerToken = r.FormValue(cm.config.FormFieldName)
	}

	if headerToken == "" {
		return false
	}

	// Constant time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
		return false
	}

	// Check if token exists and is not expired
	cm.mu.RLock()
	expiry, exists := cm.tokens[cookieToken]
	cm.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		cm.mu.Lock()
		delete(cm.tokens, cookieToken)
		cm.mu.Unlock()
		return false
	}

	return true
}

// setCSRFCookie sets the CSRF token cookie
func (cm *CSRFMiddleware) setCSRFCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     cm.config.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   cm.config.CookieMaxAge,
		HttpOnly: cm.config.CookieHTTPOnly,
		Secure:   cm.config.CookieSecure,
		SameSite: cm.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

// storeToken registers a token in the store with expiry
func (cm *CSRFMiddleware) storeToken(token string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.tokens[token] = time.Now().Add(time.Duration(cm.config.CookieMaxAge) * time.Second)
}

// writeError writes a JSON error response
func (cm *CSRFMiddleware) writeError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   false,
		"error":     message,
		"timestamp": time.Now(),
	})
}

// GetToken extracts the CSRF token from a request
func (cm *CSRFMiddleware) GetToken(r *http.Request) string {
	cookie, err := r.Cookie(cm.config.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// GenerateToken generates a new CSRF token and sets the cookie
func (cm *CSRFMiddleware) GenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := cm.generateToken()
	cm.setCSRFCookie(w, token)
	cm.storeToken(token)
	return token
}
