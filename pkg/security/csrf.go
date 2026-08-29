// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — CSRF Protection Middleware (v4.3.1)
//
// csrf.go implements double-submit cookie CSRF protection for all
// state-changing HTTP methods (POST, PUT, DELETE, PATCH). Safe
// methods (GET, HEAD, OPTIONS) receive a CSRF cookie if one is not
// already present.
//
// Design:
//   - Token: 32 bytes from crypto/rand, base64url-encoded
//   - Cookie: SameSite=Strict, Secure, HttpOnly
//   - Validation: constant-time comparison of cookie vs header/form
//   - Token store: in-memory map with 5-minute cleanup interval
//   - Token TTL: 24 hours (configurable)
//
// The middleware is opt-in: it is only applied when
// platformconfig.SecurityConfig.EnableCSRF is true. In development
// mode (CookieSecure=false), the cookie is sent over HTTP.

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

// CSRFConfig holds configuration for CSRF protection.
type CSRFConfig struct {
	// TokenLength is the length of the CSRF token in bytes (default 32).
	TokenLength int
	// CookieName is the name of the CSRF cookie (default "csrf_token").
	CookieName string
	// CookieMaxAge is the max age of the cookie in seconds (default 86400 = 24h).
	CookieMaxAge int
	// CookieSameSite sets the SameSite attribute (default Strict).
	CookieSameSite http.SameSite
	// CookieSecure ensures cookies are only sent over HTTPS (default true).
	CookieSecure bool
	// CookieHTTPOnly makes the cookie inaccessible to JavaScript (default true).
	CookieHTTPOnly bool
	// HeaderName is the header that contains the CSRF token (default "X-CSRF-Token").
	HeaderName string
	// FormFieldName is the form field name for the CSRF token (default "_csrf_token").
	FormFieldName string
}

// DefaultCSRFConfig returns secure default CSRF configuration.
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

// CSRFMiddleware provides CSRF protection for HTTP handlers.
type CSRFMiddleware struct {
	config  *CSRFConfig
	logger  *slog.Logger
	tokens  map[string]time.Time
	mu      sync.RWMutex
	cleanup *time.Ticker
}

// NewCSRFMiddleware creates a new CSRF protection middleware.
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

// WithLogger sets a custom logger.
func (cm *CSRFMiddleware) WithLogger(logger *slog.Logger) *CSRFMiddleware {
	cm.logger = logger.WithGroup("security.csrf")
	return cm
}

// Stop halts the cleanup goroutine. Call this on server shutdown.
func (cm *CSRFMiddleware) Stop() {
	if cm.cleanup != nil {
		cm.cleanup.Stop()
	}
}

// cleanupLoop periodically removes expired tokens.
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

// generateToken creates a cryptographically secure random token.
func (cm *CSRFMiddleware) generateToken() string {
	bytes := make([]byte, cm.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		cm.logger.Error("Failed to generate CSRF token", "error", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// Handler wraps an HTTP handler with CSRF protection.
// Safe methods (GET, HEAD, OPTIONS) are allowed through and receive
// a CSRF cookie if one is not already present. State-changing methods
// (POST, PUT, DELETE, PATCH) must include a valid CSRF token in the
// header or form field that matches the cookie value.
func (cm *CSRFMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF protection.
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			cookie, err := r.Cookie(cm.config.CookieName)
			if err != nil || cookie.Value == "" {
				token := cm.generateToken()
				cm.setCSRFCookie(w, token)
				cm.storeToken(token)
			}
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods, validate CSRF token.
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

// validateRequest checks CSRF token validity using the double-submit
// cookie pattern: the cookie value must match the header/form value,
// and the token must exist in the server-side store (not expired).
func (cm *CSRFMiddleware) validateRequest(w http.ResponseWriter, r *http.Request) bool {
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

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
		return false
	}

	// Check if token exists and is not expired.
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

// setCSRFCookie sets the CSRF token cookie on the response.
func (cm *CSRFMiddleware) setCSRFCookie(w http.ResponseWriter, token string) {
	//nolint:gosec // G124: cookie attributes are config-driven; DefaultCSRFConfig sets HttpOnly=true, Secure=true, SameSite=Strict
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

// storeToken registers a token in the server-side store with expiry.
func (cm *CSRFMiddleware) storeToken(token string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.tokens[token] = time.Now().Add(time.Duration(cm.config.CookieMaxAge) * time.Second)
}

// writeError writes a JSON error response for CSRF validation failures.
func (cm *CSRFMiddleware) writeError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   false,
		"error":     message,
		"timestamp": time.Now(),
	})
}

// GetToken extracts the CSRF token from a request's cookie.
func (cm *CSRFMiddleware) GetToken(r *http.Request) string {
	cookie, err := r.Cookie(cm.config.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// GenerateToken generates a new CSRF token, sets the cookie, and
// stores the token server-side. Returns the token string.
func (cm *CSRFMiddleware) GenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := cm.generateToken()
	cm.setCSRFCookie(w, token)
	cm.storeToken(token)
	return token
}
