// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Security Phase 1A Coverage Tests

package security

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestCSRFMiddleware_CleanupLoop_RemovesExpiredTokens verifies that cleanupLoop
// removes expired tokens while keeping valid ones.
func TestCSRFMiddleware_CleanupLoop_RemovesExpiredTokens(t *testing.T) {
	mw := &CSRFMiddleware{
		config:  DefaultCSRFConfig(),
		logger:  slog.Default().WithGroup("security.csrf"),
		tokens:  make(map[string]time.Time),
		cleanup: time.NewTicker(10 * time.Millisecond),
	}
	defer mw.Stop()

	go mw.cleanupLoop()

	// Add an expired token and a valid token
	mw.mu.Lock()
	mw.tokens["expired-token"] = time.Now().Add(-1 * time.Hour)
	mw.tokens["valid-token"] = time.Now().Add(1 * time.Hour)
	mw.mu.Unlock()

	// Wait for at least two cleanup cycles
	time.Sleep(50 * time.Millisecond)

	mw.mu.RLock()
	_, expiredExists := mw.tokens["expired-token"]
	_, validExists := mw.tokens["valid-token"]
	mw.mu.RUnlock()

	if expiredExists {
		t.Fatal("expired token was not cleaned up by cleanupLoop")
	}
	if !validExists {
		t.Fatal("valid token was incorrectly removed by cleanupLoop")
	}
}

// TestCSRFMiddleware_ValidateRequest_FormField covers the path where the
// CSRF token is submitted via a form field rather than a header.
func TestCSRFMiddleware_ValidateRequest_FormField(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	// Generate a token via a safe GET request
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	var token string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no CSRF token generated")
	}

	// POST with token in form field instead of header
	form := url.Values{}
	form.Set("_csrf_token", token)

	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(postRR, postReq)

	if !called {
		t.Fatal("POST with valid form field token was blocked")
	}
	if postRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", postRR.Code)
	}
}

// TestCSRFMiddleware_ValidateRequest_TokenNotInStore covers the path where
// cookie and header tokens match but the token is not in the server-side store.
func TestCSRFMiddleware_ValidateRequest_TokenNotInStore(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	token := "unstored-fake-token"

	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(postRR, postReq)

	if called {
		t.Fatal("POST with token not in server store was allowed through")
	}
	if postRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", postRR.Code)
	}
}

// TestCSRFMiddleware_ValidateRequest_ExpiredToken covers the path where the
// token exists in the store but has expired, and should be deleted.
func TestCSRFMiddleware_ValidateRequest_ExpiredToken(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	// Generate and store a valid token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := mw.GenerateToken(rr, req)
	if token == "" {
		t.Fatal("GenerateToken returned empty token")
	}

	// Manually expire the token in the store
	mw.mu.Lock()
	mw.tokens[token] = time.Now().Add(-1 * time.Hour)
	mw.mu.Unlock()

	// POST with the now-expired token
	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(postRR, postReq)

	if called {
		t.Fatal("POST with expired token was allowed through")
	}
	if postRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", postRR.Code)
	}

	// Verify the expired token was deleted from the store
	mw.mu.RLock()
	_, exists := mw.tokens[token]
	mw.mu.RUnlock()
	if exists {
		t.Fatal("expired token should have been deleted from server store")
	}
}

// TestCSRFMiddleware_ValidateRequest_CookieButNoHeaderOrForm covers the path
// where a cookie is present but neither header nor form field contains a token.
func TestCSRFMiddleware_ValidateRequest_CookieButNoHeaderOrForm(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: "some-token"})

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(postRR, postReq)

	if called {
		t.Fatal("POST with cookie but no header/form token was allowed through")
	}
	if postRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", postRR.Code)
	}
}

// TestCSRFMiddleware_ValidateRequest_EmptyCookieValue covers the path where
// the CSRF cookie is present but has an empty value.
func TestCSRFMiddleware_ValidateRequest_EmptyCookieValue(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	defer mw.Stop()

	postRR := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: ""})
	postReq.Header.Set("X-CSRF-Token", "some-token")

	called := false
	mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(postRR, postReq)

	if called {
		t.Fatal("POST with empty cookie value was allowed through")
	}
	if postRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", postRR.Code)
	}
}
