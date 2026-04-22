// SPDX-License-Identifier: Apache-2.0
// Package license — Integration tests for license enforcement flow.
//
// These tests verify the complete license lifecycle:
//  1. No license key → Community tier
//  2. Valid license key → correct tier from license
//  3. Invalid license key → Community tier fallback
//  4. License middleware gates features correctly
//  5. License middleware injects context properly
//  6. X-License-Key header overrides AEGISGATE_LICENSE_KEY env
//
// Run: go test -race ./pkg/license/
package license

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// TestNoLicenseKeyReturnsCommunity verifies that without any license key,
// the platform resolves to Community tier.
func TestNoLicenseKeyReturnsCommunity(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	result := mgr.Validate("")
	if result.Valid != true {
		t.Errorf("Expected Valid=true for empty key, got Valid=%v", result.Valid)
	}
	if result.Tier != tier.TierCommunity {
		t.Errorf("Expected TierCommunity for empty key, got %v", result.Tier)
	}
	if result.Message == "" {
		t.Error("Expected non-empty message")
	}
}

// TestInvalidLicenseKeyFallsBackToCommunity verifies that a malformed
// license key results in Community tier fallback.
func TestInvalidLicenseKeyFallsBackToCommunity(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	result := mgr.Validate("not-a-valid-base64-license!!!")
	if result.Valid == true {
		t.Error("Expected Valid=false for invalid key")
	}
	if result.Tier != tier.TierCommunity {
		t.Errorf("Expected TierCommunity for invalid key, got %v", result.Tier)
	}
}

// TestWellFormedButUnsignedKeyFallsBackToCommunity verifies that a
// well-formed (valid base64 JSON) but unsigned license key is rejected.
func TestWellFormedButUnsignedKeyFallsBackToCommunity(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	// Create a valid JSON structure but with an invalid signature
	keyFormat := LicenseKeyFormat{
		Payload: LicensePayload{
			LicenseID: "test-forge-123",
			Tier:      "enterprise",
			Customer:  "Attacker Corp",
			MaxUsers:  9999,
		},
		Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)), // All zeros = invalid
	}

	jsonBytes, err := json.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("Failed to marshal test key: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(jsonBytes)

	result := mgr.Validate(encoded)
	if result.Valid == true {
		t.Error("Expected Valid=false for forged signature")
	}
	if result.Tier != tier.TierCommunity {
		t.Errorf("Expected TierCommunity for forged key, got %v", result.Tier)
	}
}

// TestManagerSetLicenseKeyAndResolve verifies that SetLicenseKey persists
// and GetLicenseKey retrieves the same value.
func TestManagerSetLicenseKeyAndResolve(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	testKey := "test-license-key-abc"
	mgr.SetLicenseKey(testKey)

	if mgr.GetLicenseKey() != testKey {
		t.Errorf("GetLicenseKey() = %q, want %q", mgr.GetLicenseKey(), testKey)
	}
}

// TestGetTierFromInvalidResult verifies GetTier returns Community for
// invalid validation results.
func TestGetTierFromInvalidResult(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	result := mgr.Validate("garbage")
	resolved := mgr.GetTier(&result)
	if resolved != tier.TierCommunity {
		t.Errorf("GetTier(invalid) = %v, want TierCommunity", resolved)
	}
}

// TestGetTierFromNilResult verifies GetTier returns Community for nil result.
func TestGetTierFromNilResult(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	resolved := mgr.GetTier(nil)
	if resolved != tier.TierCommunity {
		t.Errorf("GetTier(nil) = %v, want TierCommunity", resolved)
	}
}

// TestIsFeatureLicensedCommunityOnly verifies that without a valid license,
// only Community-tier features are available.
func TestIsFeatureLicensedCommunityOnly(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	result := mgr.Validate("")

	// Community features should be available
	if !mgr.IsFeatureLicensed(&result, tier.FeatureAIProxy) {
		t.Error("FeatureAIProxy should be available on Community")
	}

	// Non-community features should be blocked (OAuth SSO requires Developer+)
	if mgr.IsFeatureLicensed(&result, tier.FeatureOAuthSSO) {
		t.Error("FeatureOAuthSSO should NOT be available on Community")
	}
}

// ============================================================
// Middleware integration tests
// ============================================================

// TestLicenseMiddlewareInjectLicenseContext verifies that
// InjectLicenseContext reads the key from env and injects it into context.
func TestLicenseMiddlewareInjectLicenseContext(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)

	os.Setenv("AEGISGATE_LICENSE_KEY", "")
	defer os.Unsetenv("AEGISGATE_LICENSE_KEY")

	called := false
	handler := lm.InjectLicenseContext(func(w http.ResponseWriter, r *http.Request) {
		called = true
		tierStr, ok := r.Context().Value(CtxKeyTier).(string)
		if !ok {
			t.Error("CtxKeyTier not found in context")
		}
		if tierStr != "community" {
			t.Errorf("CtxKeyTier = %q, want %q", tierStr, "community")
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("Handler was not called")
	}
}

// TestLicenseMiddlewareRequireLicenseFallback verifies RequireLicense
// falls back to Community for invalid keys (does NOT block).
func TestLicenseMiddlewareRequireLicenseFallback(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("invalid-key")

	called := false
	handler := lm.RequireLicense(func(w http.ResponseWriter, r *http.Request) {
		called = true
		tierStr, _ := r.Context().Value(CtxKeyTier).(string)
		if tierStr != "community" {
			t.Errorf("Expected community tier fallback, got %q", tierStr)
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("Handler was not called — RequireLicense should fall back to Community, not block")
	}
}

// TestLicenseMiddlewareRequireTierBlocked verifies RequireTier returns 403
// when the tier is insufficient.
func TestLicenseMiddlewareRequireTierBlocked(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("") // Community tier

	handler := lm.RequireTier(tier.TierDeveloper)(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called — tier is insufficient")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(ContextWithManager(req.Context(), mgr))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

// TestLicenseMiddlewareRequireTierAllowed verifies RequireTier passes
// when the tier is sufficient.
func TestLicenseMiddlewareRequireTierAllowed(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("") // Community tier

	called := false
	handler := lm.RequireTier(tier.TierCommunity)(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(ContextWithManager(req.Context(), mgr))
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("Handler should have been called — Community should access Community tier")
	}
}

// TestLicenseMiddlewareRequireFeatureBlocked verifies RequireFeature returns 403
// when the feature is not available in the current tier.
func TestLicenseMiddlewareRequireFeatureBlocked(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("") // Community tier

	handler := lm.RequireFeature(tier.FeatureOAuthSSO)(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called — OAuth SSO requires Developer+ tier")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(ContextWithManager(req.Context(), mgr))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for SSO on Community tier, got %d", w.Code)
	}
}

// TestLicenseMiddlewareRequireFeatureAllowed verifies RequireFeature passes
// when the feature is available in the current tier.
func TestLicenseMiddlewareRequireFeatureAllowed(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("") // Community tier

	called := false
	handler := lm.RequireFeature(tier.FeatureAIProxy)(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(ContextWithManager(req.Context(), mgr))
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("Handler should have been called — AI Proxy is a Community feature")
	}
}

// TestLicenseMiddlewareLicenseStatusEndpoint verifies the LicenseStatus
// handler returns correct JSON for Community tier.
func TestLicenseMiddlewareLicenseStatusEndpoint(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)
	mgr.SetLicenseKey("")

	handler := lm.LicenseStatus()

	req := httptest.NewRequest("GET", "/api/v1/license/status", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp["tier"] != "community" {
		t.Errorf("Expected tier=community, got %v", resp["tier"])
	}
	if resp["valid"] != true {
		t.Errorf("Expected valid=true for Community, got %v", resp["valid"])
	}
}

// TestLicenseMiddlewareXLicenseKeyHeaderOverridesEnv verifies that the
// X-License-Key header takes precedence over AEGISGATE_LICENSE_KEY env.
func TestLicenseMiddlewareXLicenseKeyHeaderOverridesEnv(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	lm := NewLicenseMiddleware(mgr)

	os.Setenv("AEGISGATE_LICENSE_KEY", "env-key-value")
	defer os.Unsetenv("AEGISGATE_LICENSE_KEY")

	called := false
	handler := lm.InjectLicenseContext(func(w http.ResponseWriter, r *http.Request) {
		called = true
		key, _ := r.Context().Value(CtxKeyLicenseKey).(string)
		if key != "header-key-value" {
			t.Errorf("Expected header-key-value in context, got %q", key)
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-License-Key", "header-key-value")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("Handler was not called")
	}
}
