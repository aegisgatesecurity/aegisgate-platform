// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — CSRF Middleware Tests

package security

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFMiddleware_SafeMethods(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if !called {
		t.Fatal("safe GET request was blocked by CSRF middleware")
	}

	// Check that a CSRF cookie was set
	cookie := rr.Result().Cookies()
	found := false
	for _, c := range cookie {
		if c.Name == "csrf_token" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("CSRF cookie was not set on safe GET request")
	}
}

func TestCSRFMiddleware_StateChangingMethod_NoToken(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	if called {
		t.Fatal("POST without CSRF token was allowed through")
	}

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestCSRFMiddleware_StateChangingMethod_ValidToken(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	// Generate a token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	// Extract the token from the cookie
	var token string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no CSRF token in cookie")
	}

	// Make a POST with matching token in header and cookie
	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(postRR, postReq)

	if !called {
		t.Fatal("POST with valid CSRF token was blocked")
	}

	if postRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", postRR.Code)
	}
}

func TestCSRFMiddleware_StateChangingMethod_MismatchedToken(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	req.Header.Set("X-CSRF-Token", "wrong-token")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "different-token"})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	if called {
		t.Fatal("POST with mismatched tokens was allowed through")
	}

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestCSRFMiddleware_GenerateToken(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token := mw.GenerateToken(rr, req)
	if token == "" {
		t.Fatal("GenerateToken returned empty string")
	}

	// Verify the token is in the cookie
	var cookieToken string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" {
			cookieToken = c.Value
		}
	}
	if cookieToken != token {
		t.Fatalf("cookie token %q != generated token %q", cookieToken, token)
	}

	// Verify the token can be used for state-changing requests
	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(postRR, postReq)

	if !called {
		t.Fatal("POST with generated token was blocked")
	}
}

func TestCSRFMiddleware_CustomConfig(t *testing.T) {
	config := &CSRFConfig{
		TokenLength:    16,
		CookieName:     "custom_csrf",
		CookieMaxAge:   3600,
		CookieSameSite: http.SameSiteLaxMode,
		CookieSecure:   false,
		CookieHTTPOnly: false,
		HeaderName:     "X-Custom-CSRF",
		FormFieldName:  "_custom_csrf",
	}
	mw := NewCSRFMiddleware(config)
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	// Check custom cookie name
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "custom_csrf" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom CSRF cookie name was not set")
	}
}

func TestCSRFMiddleware_WithLogger(t *testing.T) {
	mw := NewCSRFMiddleware(DefaultCSRFConfig())
	defer mw.Stop()
	result := mw.WithLogger(slog.Default())
	if result == nil {
		t.Fatal("WithLogger returned nil")
	}
	if result != mw {
		t.Fatal("WithLogger should return the same middleware instance")
	}
}

func TestCSRFMiddleware_GetToken(t *testing.T) {
	mw := NewCSRFMiddleware(DefaultCSRFConfig())
	defer mw.Stop()

	// No cookie → empty string
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token := mw.GetToken(req); token != "" {
		t.Errorf("GetToken() with no cookie = %q, want empty", token)
	}

	// With cookie → returns cookie value
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: DefaultCSRFConfig().CookieName, Value: "test-token-123"})
	if token := mw.GetToken(req2); token != "test-token-123" {
		t.Errorf("GetToken() = %q, want %q", token, "test-token-123")
	}
}

func TestCSRFMiddleware_GenerateToken_ServerSideStore(t *testing.T) {
	mw := NewCSRFMiddleware(DefaultCSRFConfig())
	defer mw.Stop()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := mw.GenerateToken(rr, req)

	if token == "" {
		t.Fatal("GenerateToken returned empty token")
	}
	// Verify cookie was set
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == DefaultCSRFConfig().CookieName && c.Value == token {
			found = true
		}
	}
	if !found {
		t.Fatal("GenerateToken did not set CSRF cookie")
	}
	// Verify token is stored server-side (can be validated)
	mw.mu.RLock()
	_, exists := mw.tokens[token]
	mw.mu.RUnlock()
	if !exists {
		t.Fatal("GenerateToken did not store token server-side")
	}
}
