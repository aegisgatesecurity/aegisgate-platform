// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Security Headers Tests
// =========================================================================

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultSecurityHeadersConfig()
	wrapped := SecurityHeadersMiddleware(config)(handler)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET request", "GET", "/"},
		{"POST request", "POST", "/api/v1/scan"},
		{"PUT request", "PUT", "/api/v1/config"},
		{"DELETE request", "DELETE", "/api/v1/policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			// Check required headers
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("X-Content-Type-Options should be nosniff")
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Error("X-Frame-Options should be DENY")
			}
			if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
				t.Error("Referrer-Policy should be strict-origin-when-cross-origin")
			}
		})
	}
}

func TestAPIHeadersMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := APIHeadersMiddleware(handler)

	req := httptest.NewRequest("POST", "/api/v1/scan", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// API-specific headers
	csp := rec.Header().Get("Content-Security-Policy")
	if csp != "default-src 'none'" {
		t.Errorf("Expected CSP 'default-src \\'none\\'', got %s", csp)
	}

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}

	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Strict-Transport-Security should be set")
	}
}

func TestDashboardHeadersMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := DashboardHeadersMiddleware(handler)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// Dashboard headers should be more permissive
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Dashboard should have Content-Security-Policy")
	}

	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}
}

func TestCORSMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	origins := []string{"https://example.com", "https://app.example.com"}
	methods := []string{"GET", "POST", "PUT"}
	headers := []string{"Content-Type", "Authorization"}

	wrapped := CORSMiddleware(origins, methods, headers)(handler)

	t.Run("Preflight request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/scan", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Methods") != "GET, POST, PUT" {
			t.Error("Access-Control-Allow-Methods not set correctly")
		}
		if rec.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
			t.Error("Access-Control-Allow-Headers not set correctly")
		}
	})

	t.Run("Allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/scan", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
			t.Error("Access-Control-Allow-Origin not set for allowed origin")
		}
	})

	t.Run("Disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/scan", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Access-Control-Allow-Origin should not be set for disallowed origin")
		}
	})

	t.Run("Wildcard origin", func(t *testing.T) {
		wrappedWildcard := CORSMiddleware([]string{"*"}, nil, nil)(handler)
		req := httptest.NewRequest("GET", "/api/v1/scan", nil)
		req.Header.Set("Origin", "https://any.com")
		rec := httptest.NewRecorder()

		wrappedWildcard.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "https://any.com" {
			t.Error("Wildcard should allow any origin")
		}
	})
}

func TestEmptyConfig(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Empty config - no headers should be set
	config := SecurityHeadersConfig{}
	wrapped := SecurityHeadersMiddleware(config)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// Should still pass through
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestDefaultSecurityHeadersConfig(t *testing.T) {
	config := DefaultSecurityHeadersConfig()

	if config.XFrameOptions != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
	if config.XContentTypeOptions != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}
	if config.ContentSecurityPolicy == "" {
		t.Error("Content-Security-Policy should be set")
	}
}

func TestAPISecurityHeadersConfig(t *testing.T) {
	config := APISecurityHeadersConfig()

	// API should have restrictive CSP
	if config.ContentSecurityPolicy != "default-src 'none'" {
		t.Error("API CSP should be 'default-src \\'none\\''")
	}
	if config.XFrameOptions != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
}

func TestDashboardSecurityHeadersConfig(t *testing.T) {
	config := DashboardSecurityHeadersConfig()

	// Dashboard should have permissive CSP
	if config.ContentSecurityPolicy == "" {
		t.Error("Dashboard should have Content-Security-Policy")
	}
	if config.ContentSecurityPolicy == "default-src 'none'" {
		t.Error("Dashboard CSP should be more permissive than API")
	}
}

func TestPermissionsPolicy(t *testing.T) {
	config := DefaultSecurityHeadersConfig()

	// Should disable various browser features
	pp := config.PermissionsPolicy
	if pp == "" {
		t.Error("Permissions-Policy should be set")
	}
	if pp != "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" {
		t.Errorf("Unexpected Permissions-Policy: %s", pp)
	}
}
