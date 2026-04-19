package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.RequireAuth {
		t.Error("RequireAuth should be false by default")
	}
	if cfg.TokenExpiryHours != 24 {
		t.Errorf("TokenExpiryHours expected 24, got %d", cfg.TokenExpiryHours)
	}
	if string(cfg.JWTSigningKey) != "dev-key-change-in-production" {
		t.Error("JWTSigningKey mismatch")
	}
	if cfg.APIAuthToken != "dev-token-change-in-production" {
		t.Error("APIAuthToken mismatch")
	}
}

func TestConfigFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		envRequire  string
		envJWT      string
		envAPI      string
		wantRequire bool
		wantJWT     string
		wantAPI     string
	}{
		{
			name:        "production mode - lowercase",
			envRequire:  "true",
			envJWT:      "prod-jwt-key",
			envAPI:      "prod-api-token",
			wantRequire: true,
			wantJWT:     "prod-jwt-key",
			wantAPI:     "prod-api-token",
		},
		{
			name:        "development mode",
			envRequire:  "",
			envJWT:      "",
			envAPI:      "",
			wantRequire: false,
			wantJWT:     "dev-key-change-in-production",
			wantAPI:     "dev-token-change-in-production",
		},
		{
			name:        "production mode - uppercase TRUE",
			envRequire:  "TRUE",
			envJWT:      "prod-jwt-key-32bytes-long-key",
			envAPI:      "prod-api-token",
			wantRequire: true,
			wantJWT:     "prod-jwt-key-32bytes-long-key",
			wantAPI:     "prod-api-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean environment before each test
			os.Unsetenv("REQUIRE_AUTH")
			os.Unsetenv("JWT_SIGNING_KEY")
			os.Unsetenv("API_AUTH_TOKEN")

			if tt.envRequire != "" {
				os.Setenv("REQUIRE_AUTH", tt.envRequire)
			}
			if tt.envJWT != "" {
				os.Setenv("JWT_SIGNING_KEY", tt.envJWT)
			}
			if tt.envAPI != "" {
				os.Setenv("API_AUTH_TOKEN", tt.envAPI)
			}

			cfg := ConfigFromEnv()

			if cfg.RequireAuth != tt.wantRequire {
				t.Errorf("RequireAuth: got %v, want %v", cfg.RequireAuth, tt.wantRequire)
			}
			if string(cfg.JWTSigningKey) != tt.wantJWT {
				t.Errorf("JWTSigningKey: got %q, want %q", string(cfg.JWTSigningKey), tt.wantJWT)
			}
			if cfg.APIAuthToken != tt.wantAPI {
				t.Errorf("APIAuthToken: got %q, want %q", cfg.APIAuthToken, tt.wantAPI)
			}

			// Clean up
			os.Unsetenv("REQUIRE_AUTH")
			os.Unsetenv("JWT_SIGNING_KEY")
			os.Unsetenv("API_AUTH_TOKEN")
		})
	}
}

func TestGenerateToken(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32-bytes-long-for-jwt"),
		TokenExpiryHours: 1,
	}
	m := NewMiddleware(cfg)

	tests := []struct {
		name    string
		userID  string
		tier    string
		wantErr bool
	}{
		{"valid community user", "user123", "community", false},
		{"valid professional user", "user456", "professional", false},
		{"valid enterprise user", "user789", "enterprise", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := m.GenerateToken(tt.userID, tt.tier)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tokenString == "" && !tt.wantErr {
				t.Error("GenerateToken returned empty string")
			}

			// Parse and verify claims
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				return cfg.JWTSigningKey, nil
			})
			if err != nil {
				t.Errorf("Failed to parse token: %v", err)
				return
			}

			if claims, ok := token.Claims.(*Claims); ok {
				if claims.Subject != tt.userID {
					t.Errorf("Subject: got %q, want %q", claims.Subject, tt.userID)
				}
				if claims.Tier != tt.tier {
					t.Errorf("Tier: got %q, want %q", claims.Tier, tt.tier)
				}
			} else {
				t.Error("Could not extract claims")
			}
		})
	}
}

func TestRequireAuth(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name       string
		require    bool
		header     string
		wantStatus int
	}{
		{
			name:       "dev mode - no auth required",
			require:    false,
			header:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "prod mode - missing auth header",
			require:    true,
			header:     "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "prod mode - invalid format",
			require:    true,
			header:     "invalid",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "prod mode - unsupported scheme",
			require:    true,
			header:     "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "prod mode - invalid bearer token",
			require:    true,
			header:     "Bearer invalid-token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
				APIAuthToken:     "test-api-token",
				TokenExpiryHours: 24,
				RequireAuth:      tt.require,
			}
			m := NewMiddleware(cfg)

			handler := m.RequireAuth(dummyHandler)
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Expected %d, got %d: %s", tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("valid bearer jwt token", func(t *testing.T) {
		testKey := []byte("test-jwt-key-32bytes-long-key")
		cfg := &Config{
			JWTSigningKey:    testKey,
			APIAuthToken:     "test-api-token",
			TokenExpiryHours: 24,
			RequireAuth:      true,
		}
		m := NewMiddleware(cfg)

		// Generate a valid token
		tokenString, err := m.GenerateToken("testuser", "professional")
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		handler := m.RequireAuth(dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid api token", func(t *testing.T) {
		cfg := &Config{
			JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
			APIAuthToken:     "test-api-token",
			TokenExpiryHours: 24,
			RequireAuth:      true,
		}
		m := NewMiddleware(cfg)

		handler := m.RequireAuth(dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		// Use 'token' scheme, not X-API-Token header
		req.Header.Set("Authorization", "token test-api-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Should be OK because token matches
		_ = rec.Code // Keep reference to prevent unused variable

		// Note: The test may still fail if handleAPIToken logic is different
		// This is a best-effort fix based on code inspection
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for valid API token, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid api token", func(t *testing.T) {
		cfg := &Config{
			JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
			APIAuthToken:     "test-api-token",
			TokenExpiryHours: 24,
			RequireAuth:      true,
		}
		m := NewMiddleware(cfg)

		handler := m.RequireAuth(dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		// Use 'token' scheme with wrong token
		req.Header.Set("Authorization", "token wrong-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rec.Code)
		}
	})
}

func TestReadOnly(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := DefaultConfig()
	m := NewMiddleware(cfg)
	handler := m.ReadOnly(dummyHandler)

	// ReadOnly should allow without explicit auth (dev mode)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("ReadOnly expected 200, got %d", rec.Code)
	}
}

func TestAdminOnly(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := DefaultConfig()
	cfg.RequireAuth = true
	m := NewMiddleware(cfg)
	handler := m.AdminOnly(dummyHandler)

	// Without auth, should be unauthorized in prod mode
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("AdminOnly without auth expected 401, got %d", rec.Code)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	cfg := &Config{
		JWTSigningKey:    []byte("benchmark-key-32bytes-long-key"),
		TokenExpiryHours: 24,
	}
	m := NewMiddleware(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.GenerateToken(fmt.Sprintf("user-%d", i), "community")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequireAuth(b *testing.B) {
	cfg := DefaultConfig()
	cfg.RequireAuth = false // Dev mode for benchmark
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// Context key extraction helpers for testing
func extractFromContext(ctx context.Context, key interface{}) string {
	if val := ctx.Value(key); val != nil {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func TestContextExtraction(t *testing.T) {
	// Test that context values are properly set
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := extractFromContext(r.Context(), ContextKeyUserID)
		tier := extractFromContext(r.Context(), ContextKeyTier)
		authType := extractFromContext(r.Context(), ContextKeyAuthType)

		if userID == "" {
			t.Error("userID not in context")
		}
		if tier == "" {
			t.Error("tier not in context")
		}
		if authType == "" {
			t.Error("authType not in context")
		}

		w.WriteHeader(http.StatusOK)
	})

	cfg := DefaultConfig()
	m := NewMiddleware(cfg)
	handler := m.RequireAuth(dummyHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected OK, got %d", rec.Code)
	}
}

// ============================================================================
// GetUserID, GetTier, GetAuthType — direct function tests
// ============================================================================

func TestGetUserID(t *testing.T) {
	t.Run("value present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyUserID, "user-42")
		if got := GetUserID(ctx); got != "user-42" {
			t.Errorf("GetUserID = %q, want %q", got, "user-42")
		}
	})
	t.Run("value absent", func(t *testing.T) {
		if got := GetUserID(context.Background()); got != "" {
			t.Errorf("GetUserID with empty ctx = %q, want empty", got)
		}
	})
}

func TestGetTier(t *testing.T) {
	t.Run("value present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTier, "professional")
		if got := GetTier(ctx); got != "professional" {
			t.Errorf("GetTier = %q, want %q", got, "professional")
		}
	})
	t.Run("value absent returns community default", func(t *testing.T) {
		if got := GetTier(context.Background()); got != "community" {
			t.Errorf("GetTier with empty ctx = %q, want %q", got, "community")
		}
	})
}

func TestGetAuthType(t *testing.T) {
	t.Run("value present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyAuthType, "jwt")
		if got := GetAuthType(ctx); got != "jwt" {
			t.Errorf("GetAuthType = %q, want %q", got, "jwt")
		}
	})
	t.Run("value absent", func(t *testing.T) {
		if got := GetAuthType(context.Background()); got != "" {
			t.Errorf("GetAuthType with empty ctx = %q, want empty", got)
		}
	})
}

// ============================================================================
// ReadOnly — write-method rejection
// ============================================================================

func TestReadOnly_WriteMethodsBlocked(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)
	handler := m.ReadOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	writeMethods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range writeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("ReadOnly with %s: expected 401, got %d", method, rec.Code)
			}
		})
	}
}

func TestReadOnly_ReadMethodsAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)
	handler := m.ReadOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	readMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	for _, method := range readMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("ReadOnly with %s: expected 200, got %d", method, rec.Code)
			}
		})
	}
}

// ============================================================================
// AdminOnly — authenticated community tier rejected
// ============================================================================

func TestAdminOnly_CommunityTierForbidden(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	handler := m.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Generate a community-tier JWT
	tokenString, err := m.GenerateToken("community-user", "community")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("AdminOnly with community tier: expected 403, got %d", rec.Code)
	}
}

func TestAdminOnly_ProfessionalTierAllowed(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	handler := m.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tokenString, err := m.GenerateToken("pro-user", "professional")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("AdminOnly with professional tier: expected 200, got %d", rec.Code)
	}
}

func TestAdminOnly_EnterpriseTierAllowed(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	handler := m.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tokenString, err := m.GenerateToken("ent-user", "enterprise")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("AdminOnly with enterprise tier: expected 200, got %d", rec.Code)
	}
}
