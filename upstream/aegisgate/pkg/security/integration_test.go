// Package security_test provides end-to-end integration tests for the security middleware chain.
// These tests verify that all security components work correctly together.
//
//go:build integration
// +build integration

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Test: Full Security Chain - Request Flow Validation
// =============================================================================

// TestFullSecurityChain validates that requests flow through all security
// middleware layers correctly: Recovery -> Headers -> CSRF -> Handler
func TestFullSecurityChain(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		setupRequest   func(*http.Request)
		expectedStatus int
		expectHeaders  map[string]string
		expectBody     string
	}{
		{
			name:           "GET request without CSRF token (allowed)",
			method:         http.MethodGet,
			path:           "/dashboard",
			expectedStatus: http.StatusOK,
			expectHeaders: map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "DENY",
			},
			expectBody: "success",
		},
		{
			name:           "HEAD request without CSRF token (allowed)",
			method:         http.MethodHead,
			path:           "/resources",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "OPTIONS request without CSRF token (allowed)",
			method:         http.MethodOptions,
			path:           "/dashboard",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST without CSRF token (blocked)",
			method:         http.MethodPost,
			path:           "/dashboard/update",
			body:           `{"test": "value"}`,
			expectedStatus: http.StatusForbidden,
			expectBody:     "CSRF",
		},
		{
			name:           "PUT without CSRF token (blocked)",
			method:         http.MethodPut,
			path:           "/dashboard/profile",
			body:           `{"name": "test"}`,
			expectedStatus: http.StatusForbidden,
			expectBody:     "CSRF",
		},
		{
			name:           "DELETE without CSRF token (blocked)",
			method:         http.MethodDelete,
			path:           "/dashboard/item",
			expectedStatus: http.StatusForbidden,
			expectBody:     "CSRF",
		},
		{
			name:           "PATCH without CSRF token (blocked)",
			method:         http.MethodPatch,
			path:           "/dashboard/partial",
			body:           `{"field": "data"}`,
			expectedStatus: http.StatusForbidden,
			expectBody:     "CSRF",
		},
		{
			name:   "POST with valid CSRF token (allowed)",
			method: http.MethodPost,
			path:   "/dashboard/update",
			body:   `{"test": "value"}`,
			setupRequest: func(req *http.Request) {
				req.Header.Set("Cookie", "csrf_token=dGVzdC10b2tlbi12YWx1ZQ")
				req.Header.Set("X-CSRF-Token", "dGVzdC10b2tlbi12YWx1ZQ")
			},
			expectedStatus: http.StatusOK,
			expectBody:     "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recovery := NewPanicRecoveryMiddleware()
			csrfConfig := DefaultCSRFConfig()
			csrfMiddleware := NewCSRFMiddleware(csrfConfig)
			defer csrfMiddleware.Stop()

			headersChain := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())

			appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.expectBody))
			})

			// Build chain
			chain := recovery.Handler(
				headersChain(
					csrfMiddleware.Handler(appHandler),
				),
			)

			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			if tt.setupRequest != nil {
				tt.setupRequest(req)
			}

			rr := httptest.NewRecorder()
			chain.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			for header, expectedValue := range tt.expectHeaders {
				if value := rr.Header().Get(header); value != expectedValue {
					t.Errorf("expected header %s=%s, got %s", header, expectedValue, value)
				}
			}

			if tt.expectBody != "" {
				if !strings.Contains(rr.Body.String(), tt.expectBody) {
					t.Errorf("expected body to contain %q, got %q", tt.expectBody, rr.Body.String())
				}
			}
		})
	}
}

// =============================================================================
// Test: Panic Recovery Integration
// =============================================================================

func TestPanicRecoveryWithSecurityChain(t *testing.T) {
	recovery := NewPanicRecoveryMiddleware()
	csrfConfig := DefaultCSRFConfig()
	csrfMiddleware := NewCSRFMiddleware(csrfConfig)
	defer csrfMiddleware.Stop()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated panic")
	})

	headersChain := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())
	chain := recovery.Handler(
		headersChain(
			csrfMiddleware.Handler(panicHandler),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}

	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header to be set")
	}
}

// =============================================================================
// Test: Concurrent Request Handling
// =============================================================================

func TestConcurrentSecurityChain(t *testing.T) {
	recovery := NewPanicRecoveryMiddleware()
	csrfConfig := DefaultCSRFConfig()
	csrfMiddleware := NewCSRFMiddleware(csrfConfig)
	defer csrfMiddleware.Stop()

	headersChain := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())

	var successCount int32
	var csrfBlocked int32

	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&successCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	chain := recovery.Handler(
		headersChain(
			csrfMiddleware.Handler(appHandler),
		),
	)

	numRequests := 50
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			if index%2 == 0 {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rr := httptest.NewRecorder()
				chain.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					errors <- fmt.Errorf("GET: expected 200, got %d", rr.Code)
				}
			} else {
				req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				chain.ServeHTTP(rr, req)
				if rr.Code == http.StatusForbidden {
					atomic.AddInt32(&csrfBlocked, 1)
				} else {
					errors <- fmt.Errorf("POST: expected 403, got %d", rr.Code)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	t.Logf("Successful: %d, Blocked: %d", successCount, csrfBlocked)

	if successCount != int32(numRequests/2) {
		t.Errorf("expected %d successful, got %d", numRequests/2, successCount)
	}
	if csrfBlocked != int32(numRequests/2) {
		t.Errorf("expected %d blocked, got %d", numRequests/2, csrfBlocked)
	}
}

// =============================================================================
// Test: CSRF Token Flow
// =============================================================================

func TestCSRFTokenFlow(t *testing.T) {
	csrfConfig := DefaultCSRFConfig()
	csrfMiddleware := NewCSRFMiddleware(csrfConfig)
	defer csrfMiddleware.Stop()

	// First request to get token
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// GET request should set CSRF cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	csrfMiddleware.Handler(appHandler).ServeHTTP(rr, req)

	// Extract cookie
	cookies := rr.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie to be set")
	}

	if csrfCookie.HttpOnly != true {
		t.Error("expected CSRF cookie to be HttpOnly")
	}

	if csrfCookie.Secure != true {
		t.Error("expected CSRF cookie to be Secure")
	}
}

// =============================================================================
// Test: Security Headers
// =============================================================================

func TestSecurityHeadersApplied(t *testing.T) {
	tests := []struct {
		name   string
		config SecurityHeadersConfig
		header string
		value  string
	}{
		{
			name:   "Default config sets X-Content-Type-Options",
			config: DefaultSecurityHeadersConfig(),
			header: "X-Content-Type-Options",
			value:  "nosniff",
		},
		{
			name:   "Default config sets X-Frame-Options",
			config: DefaultSecurityHeadersConfig(),
			header: "X-Frame-Options",
			value:  "DENY",
		},
		{
			name:   "API config sets different headers",
			config: APISecurityHeadersConfig(),
			header: "X-Frame-Options",
			value:  "SAMEORIGIN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headersChain := SecurityHeadersMiddleware(tt.config)

			handler := headersChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if got := rr.Header().Get(tt.header); got != tt.value {
				t.Errorf("expected %s=%q, got %q", tt.header, tt.value, got)
			}
		})
	}
}
