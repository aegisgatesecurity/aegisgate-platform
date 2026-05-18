// SPDX-License-Identifier: Apache-2.0
//go:build !race

// Coverage tests for license middleware functions:
//   - LicenseStatus: context key resolution, zero ExpiresAt, grace period
//   - RequireLicense: key propagation when context key is empty but payload has LicenseID
//   - resolveTierFromContext: invalid tier string in CtxKeyTier, authTierKey, and Manager fallback
package license

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ---------- LicenseStatus: context key override, zero ExpiresAt, grace period ----------

func TestLicenseStatus_ContextKeyOverridesManager(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	// Developer key on manager
	devKey := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "mgr-dev",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)
	mgr.SetLicenseKey(devKey)

	// Enterprise key via context
	entKey := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "ctx-ent",
		Tier:      "enterprise",
		Customer:  "BigCorp",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}, 64)

	lm := NewLicenseMiddleware(mgr)
	handler := lm.LicenseStatus()

	req := httptest.NewRequest("GET", "/status", nil)
	ctx := ContextWithLicenseKey(req.Context(), entKey)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	// Context key should override manager key, giving enterprise
	body := rec.Body.String()
	if !contains(body, `"tier":"enterprise"`) {
		t.Errorf("expected tier=enterprise in body, got: %s", body)
	}
}

func TestLicenseStatus_ZeroExpiresAt(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	// No license key → community → ExpiresAt should be empty string
	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()
	lm.LicenseStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// With no license, ExpiresAt field should be empty string
	if !contains(body, `"expires_at":""`) {
		t.Errorf("expected empty expires_at for community, got: %s", body)
	}
}

func TestLicenseStatus_GracePeriod(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	// Expired but within grace period
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "grace-test",
		Tier:      "developer",
		Customer:  "Acme",
		IssuedAt:  time.Now().Add(-20 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-2 * time.Hour), // expired 2 hours ago
	}, 64)
	mgr.SetLicenseKey(key)

	lm := NewLicenseMiddleware(mgr)
	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()
	lm.LicenseStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, `"grace_period":true`) {
		t.Errorf("expected grace_period=true in body, got: %s", body)
	}
}

func TestLicenseStatus_InvalidKeyInContext(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	req := httptest.NewRequest("GET", "/status", nil)
	ctx := ContextWithLicenseKey(req.Context(), "invalid-key!!!")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	lm.LicenseStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, `"valid":false`) {
		t.Errorf("expected valid=false for invalid key, got: %s", body)
	}
	if !contains(body, `"tier":"community"`) {
		t.Errorf("expected tier=community for invalid key, got: %s", body)
	}
}

// ---------- RequireLicense: key propagation when context key empty but payload has LicenseID ----------

func TestRequireLicense_KeyPropagationFromManagerKey(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "propagate-test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)
	mgr.SetLicenseKey(key)

	lm := NewLicenseMiddleware(mgr)
	handlerCalled := false
	licenseKeyInCtx := ""

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Check that the context has the license key propagated
		if k, ok := r.Context().Value(CtxKeyLicenseKey).(string); ok {
			licenseKeyInCtx = k
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No key in context — RequireLicense should fall back to manager key
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called for valid developer key")
	}
	if licenseKeyInCtx != key {
		t.Errorf("license key in context = %q, want %q", licenseKeyInCtx, key)
	}
}

func TestRequireLicense_CommunityFallsBackNoPropagation(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	hasManager := false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		hasManager = r.Context().Value(CtxKeyManager) != nil
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No key in context and no key on manager → community fallback
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called for community fallback")
	}
	if !hasManager {
		t.Error("expected Manager in context even for community tier")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200 for community", rec.Code)
	}
}

// ---------- resolveTierFromContext: invalid tier string paths ----------

func TestResolveTierFromContext_InvalidTierInLicenseKey(t *testing.T) {
	mgr, _ := NewManager()
	// Put an invalid tier string in CtxKeyTier
	ctx := context.WithValue(context.Background(), CtxKeyTier, "invalid_tier_name")
	result := resolveTierFromContext(ctx, mgr)
	// Invalid tier string should fall through to Manager
	if result != tier.TierCommunity {
		t.Errorf("resolveTierFromContext with invalid tier string = %v, want Community", result)
	}
}

func TestResolveTierFromContext_InvalidAuthTierKey(t *testing.T) {
	mgr, _ := NewManager()
	// Empty CtxKeyTier, then invalid authTierKey
	ctx := context.WithValue(context.Background(), authTierKey, "not_a_real_tier")
	result := resolveTierFromContext(ctx, mgr)
	// Invalid auth tier string should fall through to Manager
	if result != tier.TierCommunity {
		t.Errorf("resolveTierFromContext with invalid auth tier = %v, want Community", result)
	}
}

func TestResolveTierFromContext_ManagerFallbackCommunity(t *testing.T) {
	mgr, _ := NewManager()
	// No tier keys in context, no license key on manager → Community
	ctx := context.Background()
	result := resolveTierFromContext(ctx, mgr)
	if result != tier.TierCommunity {
		t.Errorf("resolveTierFromContext fallback = %v, want Community", result)
	}
}

func TestResolveTierFromContext_InvalidStringInContext(t *testing.T) {
	mgr, _ := NewManager()
	// String value in context at CtxKeyTier that fails ParseTier
	ctx := context.WithValue(context.Background(), CtxKeyTier, "superelite")
	result := resolveTierFromContext(ctx, mgr)
	// Should fall through invalid string → Manager → Community
	if result != tier.TierCommunity {
		t.Errorf("resolveTierFromContext('superelite') = %v, want Community", result)
	}
}

func TestResolveTierFromContext_AuthTierKeyWithValidTier(t *testing.T) {
	mgr, _ := NewManager()
	// No CtxKeyTier, but valid authTierKey
	ctx := context.WithValue(context.Background(), authTierKey, "enterprise")
	result := resolveTierFromContext(ctx, mgr)
	if result != tier.TierEnterprise {
		t.Errorf("resolveTierFromContext via authTierKey = %v, want Enterprise", result)
	}
}

// ---------- InjectLicenseContext: env fallback and validation ----------

func TestInjectLicenseContext_EnvVarFallback(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "env-test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)

	// Set environment variable
	t.Setenv("AEGISGATE_LICENSE_KEY", key)
	defer t.Setenv("AEGISGATE_LICENSE_KEY", "")

	lm := NewLicenseMiddleware(mgr)
	handlerCalled := false
	receivedTier := ""

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		receivedTier = r.Context().Value(CtxKeyTier).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No X-License-Key header set → should fall back to env var
	rec := httptest.NewRecorder()
	lm.InjectLicenseContext(handler).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called with env var key")
	}
	if receivedTier != "developer" {
		t.Errorf("tier = %q, want 'developer'", receivedTier)
	}
}

func TestInjectLicenseContext_HeaderOverridesEnv(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	// Env var: community (empty)
	t.Setenv("AEGISGATE_LICENSE_KEY", "")
	defer t.Setenv("AEGISGATE_LICENSE_KEY", "")

	// Header: enterprise
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "header-override",
		Tier:      "enterprise",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}, 64)

	lm := NewLicenseMiddleware(mgr)
	handlerCalled := false
	receivedTier := ""

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		receivedTier = r.Context().Value(CtxKeyTier).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-License-Key", key)
	rec := httptest.NewRecorder()
	lm.InjectLicenseContext(handler).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called")
	}
	if receivedTier != "enterprise" {
		t.Errorf("tier = %q, want 'enterprise' (header override)", receivedTier)
	}
}

func TestInjectLicenseContext_InvalidKeyFromHeader(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	receivedTier := ""

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		receivedTier = r.Context().Value(CtxKeyTier).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-License-Key", "bad-key!!!")
	rec := httptest.NewRecorder()
	lm.InjectLicenseContext(handler).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called even with invalid key (InjectLicenseContext passes through)")
	}
	if receivedTier != tier.TierCommunity.String() {
		t.Errorf("tier = %q, want 'community' for invalid key", receivedTier)
	}
}

func TestInjectLicenseContext_SetsManagerOnKey(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "setkey-test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)

	lm := NewLicenseMiddleware(mgr)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-License-Key", key)
	rec := httptest.NewRecorder()
	lm.InjectLicenseContext(handler).ServeHTTP(rec, req)

	// Manager should have the key set on it
	if mgr.GetLicenseKey() != key {
		t.Errorf("manager.GetLicenseKey() = %q, want %q", mgr.GetLicenseKey(), key)
	}
}

// ---------- verifySignature: nil publicKey and json.Marshal error ----------

func TestVerifySignature_PublicKeyNil(t *testing.T) {
	mgr := &Manager{
		publicKey:    nil,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}

	// Create a license key format to pass directly
	lk := LicenseKeyFormat{
		Payload:   LicensePayload{Tier: "developer", LicenseID: "test"},
		Signature: "AAAA",
	}

	err := mgr.verifySignature(&lk)
	if err == nil {
		t.Error("expected error when publicKey is nil")
	}
	if err.Error() != "no public key available for verification" {
		t.Errorf("error = %q, want 'no public key available for verification'", err.Error())
	}
}

func TestVerifySignature_NilPublicKeyDirectCall(t *testing.T) {
	mgr := &Manager{
		publicKey:    nil,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}

	lk := LicenseKeyFormat{
		Payload: LicensePayload{
			LicenseID: "nil-pubkey-test",
			Tier:      "enterprise",
			Customer:  "test",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		},
		Signature: base64Encode(make([]byte, 64)),
	}

	err := mgr.verifySignature(&lk)
	if err == nil {
		t.Error("expected error for nil publicKey")
	}
}

// ---------- NewManager: error path (embedded key parse failure) ----------

func TestNewManager_ProducesNilPublicKeyManager(t *testing.T) {
	// NewManager always succeeds — if GetEmbeddedPublicKey fails,
	// it returns a manager with nil publicKey.
	// We can't easily force the embedded key to fail, but we can
	// verify the nil-publicKey path works correctly.
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager should never fail: %v", err)
	}

	// Validate with empty key should give community
	result := mgr.Validate("")
	if !result.Valid {
		t.Error("empty key should be valid (community)")
	}
	if result.Tier != tier.TierCommunity {
		t.Errorf("tier = %v, want Community", result.Tier)
	}
}

// Helper: base64 encode bytes
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// contains checks if a string contains another string
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s != "" && substr != "" && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
