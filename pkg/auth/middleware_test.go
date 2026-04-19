// Copyright (c) 2026 AegisGate Security Platform
// License: Business Source License 1.1 (see LICENSE.md)

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDefaultConfig tests default configuration
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if cfg.RequireAuth {
		t.Error("DefaultConfig should have RequireAuth=false")
	}
}

// TestConfigFromEnv tests environment variable loading
func TestConfigFromEnv(t *testing.T) {
	// Save original values
	origJWT := os.Getenv("JWT_SIGNING_KEY")
	origAPI := os.Getenv("API_AUTH_TOKEN")
	origReq := os.Getenv("REQUIRE_AUTH")
	defer func() {
		os.Setenv("JWT_SIGNING_KEY", origJWT)
		os.Setenv("API_AUTH_TOKEN", origAPI)
		os.Setenv("REQUIRE_AUTH", origReq)
	}()

	tests := []struct {
		name      string
		jwtKey    string
		apiToken  string
		require   string
		wantReq   bool
	}{
		{
			name:     "dev mode - no auth required",
			jwtKey:   "",
			apiToken: "",
			require:  "false",
			wantReq:  false,
		},
		{
			name:     "production mode - auth required",
			jwtKey:   "test-jwt-key-32bytes-long-key",
			apiToken: "test-api-token",
			require:  "true",
			wantReq:  true,
		},
		{
			name:     "production mode - uppercase TRUE",
			jwtKey:   "test-jwt-key-32bytes-long-key",
			apiToken: "test-api-token",
			require:  "TRUE",
			wantReq:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("JWT_SIGNING_KEY", tt.jwtKey)
			os.Setenv("API_AUTH_TOKEN", tt.apiToken)
			os.Setenv("REQUIRE_AUTH", tt.require)

			cfg := ConfigFromEnv()

			if cfg.RequireAuth != tt.wantReq {
				t.Errorf("RequireAuth = %v, want %v", cfg.RequireAuth, tt.wantReq)
			}

			if tt.wantReq {
				if cfg.JWTSigningKey == "" {
					t.Error("Expected JWT signing key to be set")
				}
				if cfg.APIToken == "" {
					t.Error("Expected API token to be set")
				}
			}
		})
	}
}

// TestNewMiddleware creates a new middleware instance
func TestNewMiddleware(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:   "test-jwt-key-32bytes-long-key",
		APIToken:        "test-api-token",
		TokenExpiration: time.Hour,
		RequireAuth:     false,
	}

	mw := NewMiddleware(cfg)
	if mw == nil {
		t.Fatal("NewMiddleware() returned nil")
	}

	if mw.config != cfg {
		t.Error("middleware config mismatch")
	}
}

// TestGenerateToken creates valid tokens
func TestGenerateToken(t *testing.T) {
	os.Setenv("JWT_SIGNING_KEY", "test-jwt-key-32bytes-long-key")
	defer os.Unsetenv("JWT_SIGNING_KEY")

	cfg := ConfigFromEnv()
	mw := NewMiddleware(cfg)

	tests := []struct {
		name    string
		userID  string
		tier    string
		wantErr bool
	}{
		{"valid community user", "user-123", "community", false},
		{"valid professional user", "user-456", "professional", false},
		{"valid enterprise user", "user-789", "enterprise", false},
		{"empty user", "", "community", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := mw.GenerateToken(tt.userID, tt.tier)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token == "" && !tt.wantErr {
				t.Error("GenerateToken() returned empty token")
			}
		})
	}
}

// TestRequireAuth validates the RequireAuth middleware
func TestRequireAuth(t *testing.T) {
	os.Setenv("JWT_SIGNING_KEY", "test-jwt-key-32bytes-long-key")
	os.Setenv("API_AUTH_TOKEN", "test-api-token")
	defer func() {
		os.Unsetenv("JWT_SIGNING_KEY")
		os.Unsetenv("API_AUTH_TOKEN")
	}()

	cfg := ConfigFromEnv()
	cfg.RequireAuth = true // Force auth for testing
	mw := NewMiddleware(cfg)

	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	// Test without auth header
	t.Run("no auth header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rec.Code)
		}
	})

	// Test with invalid API token
	t.Run("invalid api token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Token", "wrong-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rec.Code)
		}
	})

	// Test with valid API token
	t.Run("valid api token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Token", "test-api-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	// Test dev mode (RequireAuth: false)
	t.Run("dev mode allows request", func(t *testing.T) {
		cfg2 := ConfigFromEnv()
		cfg2.RequireAuth = false
		mw2 := NewMiddleware(cfg2)

		handler2 := mw2.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler2.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 in dev mode, got %d", rec.Code)
		}
	})
}

// TestGetUserIDFromContext validates context extraction
func TestGetUserIDFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{"from context", WithAuth(context.Background(), "user-123", "community"), "user-123"},
		{"empty context", context.Background(), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetUserID(tt.ctx)
			if result != tt.expected {
				t.Errorf("GetUserID() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetTierFromContext validates tier extraction
func TestGetTierFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{"from context", WithAuth(context.Background(), "user-123", "professional"), "professional"},
		{"empty context", context.Background(), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTier(tt.ctx)
			if result != tt.expected {
				t.Errorf("GetTier() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestWithAuth creates auth context
func TestWithAuth(t *testing.T) {
	ctx := WithAuth(context.Background(), "user-123", "enterprise")
	if GetUserID(ctx) != "user-123" {
		t.Error("WithAuth failed to set user ID")
	}
	if GetTier(ctx) != "enterprise" {
		t.Error("WithAuth failed to set tier")
	}
}

// BenchmarkGenerateToken benchmarks token generation
func BenchmarkGenerateToken(b *testing.B) {
	os.Setenv("JWT_SIGNING_KEY", "test-jwt-key-32bytes-long-key")
	defer os.Unsetenv("JWT_SIGNING_KEY")

	cfg := ConfigFromEnv()
	mw := NewMiddleware(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mw.GenerateToken("user-123", "community")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRequireAuth benchmarks middleware overhead
func BenchmarkRequireAuth(b *testing.B) {
	os.Setenv("JWT_SIGNING_KEY", "test-jwt-key-32bytes-long-key")
	os.Setenv("API_AUTH_TOKEN", "test-api-token")
	defer func() {
		os.Unsetenv("JWT_SIGNING_KEY")
		os.Unsetenv("API_AUTH_TOKEN")
	}()

	cfg := ConfigFromEnv()
	cfg.RequireAuth = true
	mw := NewMiddleware(cfg)

	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Token", "test-api-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Errorf("Expected 200, got %d", rec.Code)
		}
	}
}

// Helper function check
func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TokenExpiry != 24*time.Hour {
		t.Errorf("Expected default TokenExpiry of 24h, got %v", cfg.TokenExpiry)
	}
	if cfg.RequireAuth {
		t.Error("Default RequireAuth should be false")
	}
}
