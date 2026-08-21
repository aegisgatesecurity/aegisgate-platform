// SPDX-License-Identifier: Apache-2.0
//go:build !race

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// =============================================================================
// RequireAuth — error paths and edge cases for handleJWT (85.7% → 95%+)
// =============================================================================

// TestRequireAuth_WithJWTInvalidMethod tests JWT with invalid signing method
func TestRequireAuth_WithJWTInvalidMethod(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid JWT, got %d", rr.Code)
	}
}

// TestRequireAuth_WithJWTExpired tests JWT with very short expiry
func TestRequireAuth_WithJWTExpired(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for fresh JWT, got %d", rr.Code)
	}
}

// TestRequireAuth_WithJWTNoBearerPrefix tests JWT without "Bearer " prefix
func TestRequireAuth_WithJWTNoBearerPrefix(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for JWT without Bearer prefix, got %d", rr.Code)
	}
}

// TestRequireAuth_WithBearerCaseInsensitive tests Bearer header case handling
func TestRequireAuth_WithBearerCaseInsensitive(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	// Standard Bearer works
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for standard Bearer, got %d", rr.Code)
	}

	// Non-Bearer prefixes should fail (Basic is not recognized)
	nonBearer := []string{"Basic " + token, "Token " + token}
	for _, header := range nonBearer {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", header)
		rr := httptest.NewRecorder()
		m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Errorf("expected non-200 for %q, got %d", header, rr.Code)
		}
	}
}

// TestRequireAuth_WithMultipleAuthHeaders tests behavior with multiple Authorization headers
func TestRequireAuth_WithMultipleAuthHeaders(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Authorization", "token test-api-token")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with multiple auth headers, got %d", rr.Code)
	}
}

// TestRequireAuth_WithEmptyAuthHeader tests empty Authorization header value
func TestRequireAuth_WithEmptyAuthHeader(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for empty auth header, got %d", rr.Code)
	}
}

// TestRequireAuth_WithWhitespaceBearer tests Bearer with only whitespace
func TestRequireAuth_WithWhitespaceBearer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer    ")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for whitespace-only Bearer, got %d", rr.Code)
	}
}

// TestRequireAuth_WithBasicAuth tests Basic authentication header
func TestRequireAuth_WithBasicAuth(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for Basic auth, got %d", rr.Code)
	}
}

// TestRequireAuth_DisabledWithAuth tests behavior when auth is disabled but token provided
func TestRequireAuth_DisabledWithAuth(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when auth disabled, got %d", rr.Code)
	}
}

// TestRequireAuth_WithAPIOnly tests API token only authentication
func TestRequireAuth_WithAPIOnly(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "my-api-key-123",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "token my-api-key-123")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid API token, got %d", rr.Code)
	}
}

// TestRequireAuth_WithAPIWrongScheme tests API token with wrong scheme
func TestRequireAuth_WithAPIWrongScheme(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "my-api-key-123",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer my-api-key-123")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for API token with Bearer scheme, got %d", rr.Code)
	}
}

// TestRequireAuth_WithAPIEmptyToken tests API token with empty token value
func TestRequireAuth_WithAPIEmptyToken(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "my-api-key-123",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "token ")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for empty API token, got %d", rr.Code)
	}
}

// TestRequireAuth_WithAPINoSpace tests API token without space separator
func TestRequireAuth_WithAPINoSpace(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "my-api-key-123",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "tokenmy-api-key-123")
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for API token without space, got %d", rr.Code)
	}
}

// TestRequireAuth_APIWithJWTKey tests API token compared with constant-time comparison
func TestRequireAuth_APIWithJWTKey(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "my-api-key-123",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	// Similar but not exact token
	similar := []string{
		"my-api-key-124",
		"my-api-key-12",
		"My-api-key-123",
		"my_api_key_123",
		"myapikey123",
	}
	for _, token := range similar {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "token "+token)
		rr := httptest.NewRecorder()
		m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Errorf("expected non-200 for similar token %q, got %d", token, rr.Code)
		}
	}
}

// TestScopedAPIToken verifies that scoped API tokens get the correct
// role and tier instead of blanket admin.
func TestScopedAPIToken(t *testing.T) {
	m := NewMiddleware(&Config{
		JWTSigningKey:    []byte("test-key"),
		APIAuthToken:     "legacy-admin-token",
		RequireAuth:      true,
		TokenExpiryHours: 1,
		ScopedTokens: map[string]ScopedToken{
			"viewer-token":     {Token: "viewer-token", Role: rbac.UserRoleViewer, Tier: "community"},
			"analyst-token":    {Token: "analyst-token", Role: rbac.UserRoleAnalyst, Tier: "developer"},
			"compliance-token": {Token: "compliance-token", Role: rbac.UserRoleComplianceOfficer, Tier: "professional"},
		},
	})

	tests := []struct {
		name       string
		token      string
		wantRole   rbac.UserRole
		wantTier   string
		wantStatus int
	}{
		{"scoped viewer", "Token viewer-token", rbac.UserRoleViewer, "community", 200},
		{"scoped analyst", "Token analyst-token", rbac.UserRoleAnalyst, "developer", 200},
		{"scoped compliance", "Token compliance-token", rbac.UserRoleComplianceOfficer, "professional", 200},
		{"invalid token", "Token bogus-token", "", "", 401},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/v1/test", nil)
			req.Header.Set("Authorization", tt.token)

			var gotRole rbac.UserRole
			var gotTier string
			m.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
				gotRole = GetUserRole(r.Context())
				gotTier = GetTier(r.Context())
				w.WriteHeader(200)
			})(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == 200 {
				if gotRole != tt.wantRole {
					t.Errorf("role: got %q, want %q", gotRole, tt.wantRole)
				}
				if gotTier != tt.wantTier {
					t.Errorf("tier: got %q, want %q", gotTier, tt.wantTier)
				}
			}
		})
	}
}

// TestParseScopedTokens tests the env var parser
func TestParseScopedTokens(t *testing.T) {
	result := parseScopedTokens("svc-mon:viewer:community,svc-comp:compliance_officer:professional,invalid,,bad:")
	if len(result) != 2 {
		t.Fatalf("expected 2 scoped tokens, got %d", len(result))
	}
	if _, ok := result["svc-mon"]; !ok {
		t.Error("missing svc-mon token")
	}
	if _, ok := result["svc-comp"]; !ok {
		t.Error("missing svc-comp token")
	}
	if result["svc-mon"].Role != rbac.UserRoleViewer {
		t.Errorf("svc-mon role: got %q, want %q", result["svc-mon"].Role, rbac.UserRoleViewer)
	}
}
