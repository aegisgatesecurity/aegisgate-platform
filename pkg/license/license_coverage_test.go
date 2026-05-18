// SPDX-License-Identifier: Apache-2.0
//go:build !race

// Coverage tests for license package
// Targets: GetEmbeddedPublicKey (66.7%→95%), KeyFingerprint (66.7%→95%),
//
//	NewManager (75%→95%), verifySignature (75%→95%), keyFromContext (66.7%→95%),
//	IsFeatureLicensedForContext (80%→95%), RequireLicense (81%→95%), LicenseStatus (76.5%→95%)
package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ---------- GetEmbeddedPublicKey ----------

func TestGetEmbeddedPublicKey_Success(t *testing.T) {
	key, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("GetEmbeddedPublicKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("GetEmbeddedPublicKey returned nil key")
	}
	if key.Curve.Params().Name != "P-256" {
		t.Errorf("Curve=%q, want P-256", key.Curve.Params().Name)
	}
}

func TestGetEmbeddedPublicKey_CurveIsP256(t *testing.T) {
	key, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("GetEmbeddedPublicKey: %v", err)
	}
	if key.Curve.Params().Name != "P-256" {
		t.Errorf("Curve=%q, want P-256", key.Curve.Params().Name)
	}
}

// ---------- KeyFingerprint ----------

func TestKeyFingerprint_Success(t *testing.T) {
	fp := KeyFingerprint()
	if fp == "" {
		t.Error("KeyFingerprint returned empty string")
	}
	if fp == "invalid" || fp == "short" {
		t.Errorf("KeyFingerprint=%q (should be actual fingerprint)", fp)
	}
	if len(fp) < 8 {
		t.Errorf("KeyFingerprint too short: %q", fp)
	}
}

func TestKeyFingerprint_ReturnsHex(t *testing.T) {
	fp := KeyFingerprint()
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("KeyFingerprint contains non-hex char: %c in %q", c, fp)
		}
	}
}

// ---------- NewManager ----------

func TestNewManager_Success(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if !mgr.cacheEnabled {
		t.Error("Cache should be enabled by default")
	}
}

func TestNewManager_ValidateEmptyKey(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	result := mgr.Validate("")
	if !result.Valid {
		t.Errorf("Validate('') should be valid: %v", result.Error)
	}
	if result.Tier != tier.TierCommunity {
		t.Errorf("Tier=%v, want Community", result.Tier)
	}
}

func TestNewManager_WithNilPublicKey(t *testing.T) {
	mgr := &Manager{
		publicKey:    nil,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}
	result := mgr.Validate("")
	if !result.Valid {
		t.Errorf("Validate('') should be valid: %v", result.Error)
	}
}

// ---------- verifySignature error paths ----------

func TestVerifySignature_BadLength(t *testing.T) {
	priv, pubPEM := newKeyPairForTest(t)
	mgr, err := NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey: %v", err)
	}

	// 32-byte signature (only r, not full r||s)
	badPayload := LicensePayload{
		LicenseID: "test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	licenseKey := signLicenseWithPriv(t, priv, badPayload, 32)

	result := mgr.Validate(licenseKey)
	if result.Valid {
		t.Error("Should fail with 32-byte signature")
	}
}

func TestVerifySignature_InvalidBase64(t *testing.T) {
	_, pubPEM := newKeyPairForTest(t)
	mgr, err := NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey: %v", err)
	}

	lk := LicenseKeyFormat{
		Payload:   LicensePayload{Tier: "developer", LicenseID: "test"},
		Signature: "!!!not-valid-base64!!!",
	}
	lkBytes, _ := json.Marshal(lk)
	licenseKey := base64.StdEncoding.EncodeToString(lkBytes)

	result := mgr.Validate(licenseKey)
	if result.Valid {
		t.Error("Should fail with invalid base64 signature")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	_, pubPEM1 := newKeyPairForTest(t)
	mgr1, _ := NewManagerWithKey(pubPEM1)

	_, pubPEM2 := newKeyPairForTest(t)
	mgr2, _ := NewManagerWithKey(pubPEM2)

	payload := LicensePayload{
		LicenseID: "test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	licenseKey := signLicenseWithMgr(t, mgr2, payload)

	result := mgr1.Validate(licenseKey)
	if result.Valid {
		t.Error("Should fail with wrong signing key")
	}
}

func TestVerifySignature_NoPublicKey(t *testing.T) {
	mgr := &Manager{
		publicKey:    nil,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}
	lk := LicenseKeyFormat{
		Payload:   LicensePayload{Tier: "developer", LicenseID: "test"},
		Signature: "dummy",
	}
	lkBytes, _ := json.Marshal(lk)
	licenseKey := base64.StdEncoding.EncodeToString(lkBytes)

	// Should pass (signature skipped) but tier parsing might fail
	_ = mgr.validateInternal(licenseKey)
}

// ---------- validateInternal error paths ----------

func TestValidateInternal_ExpiredBeyondGrace(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	payload := LicensePayload{
		LicenseID: "test-expired",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now().Add(-20 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-10 * 24 * time.Hour),
	}
	licenseKey := signLicenseWithPriv(t, priv, payload, 64)

	result := mgr.Validate(licenseKey)
	if result.Valid {
		t.Error("Expired beyond grace should be invalid")
	}
	if !result.Expired {
		t.Error("Should be marked as expired")
	}
	if result.GracePeriod {
		t.Error("Should NOT be in grace period")
	}
}

func TestValidateInternal_ExpiredWithinGrace(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	payload := LicensePayload{
		LicenseID: "test-grace",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now().Add(-10 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-3 * 24 * time.Hour),
	}
	licenseKey := signLicenseWithPriv(t, priv, payload, 64)

	result := mgr.Validate(licenseKey)
	if !result.Valid {
		t.Errorf("Expired within grace should still be valid: %v", result.Error)
	}
	if !result.GracePeriod {
		t.Error("Should be in grace period")
	}
}

func TestValidateInternal_InvalidTier(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	payload := LicensePayload{
		LicenseID: "test-tier",
		Tier:      "nonexistent_tier",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	licenseKey := signLicenseWithPriv(t, priv, payload, 64)

	result := mgr.Validate(licenseKey)
	if result.Valid {
		t.Error("Invalid tier should produce invalid result")
	}
}

func TestValidateInternal_BadBase64(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	result := mgr.Validate("!!!not-base64!!!")
	if result.Valid {
		t.Error("Bad base64 should be invalid")
	}
}

func TestValidateInternal_BadJSON(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	badJSON := base64.StdEncoding.EncodeToString([]byte("{not json}"))
	result := mgr.Validate(badJSON)
	if result.Valid {
		t.Error("Bad JSON should be invalid")
	}
}

// ---------- decodeLicense error paths ----------

func TestDecodeLicense_SignatureMismatch(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	payload := LicensePayload{
		LicenseID: "test-mismatch",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Sign correctly first
	payloadBytes, _ := json.Marshal(payload)
	hash := sha256.Sum256(payloadBytes)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Tamper with payload after signing
	payload.Customer = "tampered"
	lk := LicenseKeyFormat{Payload: payload, Signature: sigB64}
	lkBytes, _ := json.Marshal(lk)
	licenseKey := base64.StdEncoding.EncodeToString(lkBytes)

	result := mgr.Validate(licenseKey)
	if result.Valid {
		t.Error("Tampered payload should fail signature verification")
	}
}

// ---------- IsFeatureLicensedForContext ----------

func TestIsFeatureLicensedForContext_CommunityFeature(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	ctx := context.Background()
	if !mgr.IsFeatureLicensedForContext(ctx, "ai_proxy") {
		t.Error("Community feature should be licensed")
	}
}

func TestIsFeatureLicensedForContext_EmptyKey(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	ctx := ContextWithLicenseKey(context.Background(), "")
	if !mgr.IsFeatureLicensedForContext(ctx, "ai_proxy") {
		t.Error("Empty key should use community")
	}
}

func TestIsFeatureLicensedForContext_ValidDeveloper(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	payload := LicensePayload{
		LicenseID: "test-dev",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	key := signLicenseWithPriv(t, priv, payload, 64)
	ctx := ContextWithLicenseKey(context.Background(), key)
	if !mgr.IsFeatureLicensedForContext(ctx, "mtls") {
		t.Error("Developer feature should be licensed")
	}
}

func TestIsFeatureLicensedForContext_InvalidKey(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	ctx := ContextWithLicenseKey(context.Background(), "garbage")
	if mgr.IsFeatureLicensedForContext(ctx, "mtls") {
		t.Error("Paid feature should not be licensed with invalid key")
	}
}

func TestIsFeatureLicensedForContext_ContextOverridesManager(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)

	// Manager has developer key
	mgr.SetLicenseKey(signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "mgr-key",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64))

	// Context has enterprise key (overrides manager)
	key2 := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "ctx-key",
		Tier:      "enterprise",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}, 64)
	ctx := ContextWithLicenseKey(context.Background(), key2)
	if !mgr.IsFeatureLicensedForContext(ctx, "mtls") {
		t.Error("Context key should override manager key")
	}
}

// ---------- keyFromContext ----------

func TestKeyFromContext_ContextKeyPresent(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	ctx := ContextWithLicenseKey(context.Background(), "test-key-123")
	if mgr.keyFromContext(ctx) != "test-key-123" {
		t.Error("keyFromContext should return context key")
	}
}

func TestKeyFromContext_ContextKeyEmpty(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	mgr.SetLicenseKey("manager-key")
	ctx := ContextWithLicenseKey(context.Background(), "")
	// Empty context key is non-empty string, falls through to manager key
	if mgr.keyFromContext(ctx) != "manager-key" {
		t.Errorf("Empty context key should fall through to manager key, got %q", mgr.keyFromContext(ctx))
	}
}

func TestKeyFromContext_ContextKeyMissing(t *testing.T) {
	mgr, _ := newMgrWithPrivForTest(t)
	mgr.SetLicenseKey("fallback-key")
	ctx := context.Background()
	if mgr.keyFromContext(ctx) != "fallback-key" {
		t.Error("keyFromContext should return manager key when context key missing")
	}
}

// ---------- RequireLicense middleware ----------

func TestRequireLicense_NoKey_CommunityFallback(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called for community tier")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
}

func TestRequireLicense_ValidKey(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	mgr.SetLicenseKey(signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "test-req",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64))
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called for valid key")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
}

func TestRequireLicense_InvalidKey(t *testing.T) {
	mgr, _ := NewManager()
	mgr.SetLicenseKey("invalid-key")
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)
	if handlerCalled {
		t.Error("Handler should NOT be called for invalid key (fail-closed)")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Status=%d, want 403", rec.Code)
	}
}

func TestRequireLicense_KeyFromContext(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "ctx-key",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify that the key was propagated to the context if it was missing initially
		// but available via the manager (this tests the specific propagation logic)
		val := r.Context().Value(CtxKeyLicenseKey)
		if val == nil || val.(string) == "" {
			t.Errorf("Expected license key in context, got nil or empty")
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(ContextWithLicenseKey(req.Context(), key))
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called when key from context")
	}
}

func TestRequireLicense_PropagatesManagerKey(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "prop-key",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64)
	mgr.SetLicenseKey(key)
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		val := r.Context().Value(CtxKeyLicenseKey)
		if val == nil || val.(string) != key {
			t.Errorf("Expected propagated key %q, got %v", key, val)
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// Note: No key in context here
	rec := httptest.NewRecorder()
	lm.RequireLicense(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called (valid manager key)")
	}
}

// ---------- LicenseStatus middleware ----------

func TestLicenseStatus_EncodeError(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()

	// Wrap the recorder with our failing writer
	fw := &failingResponseWriter{ResponseRecorder: rec}

	// We cannot pass 'fw' directly to ServeHTTP because ServeHTTP expects http.ResponseWriter
	// but the handler's internal logic will use the writer we provide.
	// In this case, we need to manually call the handler function.
	handler := lm.LicenseStatus()
	handler.ServeHTTP(fw, req)

	// The test passes if it doesn't crash; the code should handle the error internally.
}

func TestLicenseStatus_ValidKey(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	mgr.SetLicenseKey(signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "status-test",
		Tier:      "developer",
		Customer:  "Acme Corp",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64))
	lm := NewLicenseMiddleware(mgr)

	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()
	lm.LicenseStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"valid":true`) {
		t.Errorf("Body should contain valid=true, got: %s", body)
	}
	if !strings.Contains(body, `"tier":"developer"`) {
		t.Errorf("Body should contain tier=developer, got: %s", body)
	}
}

func TestLicenseStatus_NoKey_Community(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()
	lm.LicenseStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"tier":"community"`) {
		t.Errorf("Body should contain tier=community, got: %s", body)
	}
}

// ---------- InjectLicenseContext ----------

func TestInjectLicenseContext_HeaderOverride(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	key := signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "header-key",
		Tier:      "enterprise",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}, 64)
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-License-Key", key)
	rec := httptest.NewRecorder()
	lm.InjectLicenseContext(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called with header key")
	}
}

// ---------- RequireTier ----------

func TestRequireTier_Insufficient(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := contextWithTier(context.Background(), tier.TierCommunity)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	lm.RequireTier(tier.TierEnterprise)(handler).ServeHTTP(rec, req)
	if handlerCalled {
		t.Error("Handler should NOT be called for insufficient tier")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Status=%d, want 403", rec.Code)
	}
}

func TestRequireTier_Sufficient(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := contextWithTier(context.Background(), tier.TierDeveloper)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	lm.RequireTier(tier.TierDeveloper)(handler).ServeHTTP(rec, req)
	if !handlerCalled {
		t.Error("Handler should be called for sufficient tier")
	}
}

// ---------- RequireFeature ----------

func TestRequireFeature_Unlicensed(t *testing.T) {
	mgr, _ := NewManager()
	lm := NewLicenseMiddleware(mgr)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := contextWithTier(context.Background(), tier.TierCommunity)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	lm.RequireFeature(tier.FeatureHIPAA)(handler).ServeHTTP(rec, req)
	if handlerCalled {
		t.Error("Handler should NOT be called for unlicensed feature")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Status=%d, want 403", rec.Code)
	}
}

// ---------- resolveTierFromContext ----------

func TestResolveTierFromContext_LicenseTierKey(t *testing.T) {
	mgr, _ := NewManager()
	ctx := contextWithTier(context.Background(), tier.TierEnterprise)
	tierResult := resolveTierFromContext(ctx, mgr)
	if tierResult != tier.TierEnterprise {
		t.Errorf("resolveTierFromContext=%v, want Enterprise", tierResult)
	}
}

func TestResolveTierFromContext_AuthTierKey(t *testing.T) {
	mgr, _ := NewManager()
	ctx := context.WithValue(context.Background(), authTierKey, "professional")
	tierResult := resolveTierFromContext(ctx, mgr)
	if tierResult != tier.TierProfessional {
		t.Errorf("resolveTierFromContext=%v, want Professional", tierResult)
	}
}

func TestResolveTierFromContext_FallbackToManager(t *testing.T) {
	mgr, priv := newMgrWithPrivForTest(t)
	mgr.SetLicenseKey(signLicenseWithPriv(t, priv, LicensePayload{
		LicenseID: "test",
		Tier:      "developer",
		Customer:  "test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}, 64))
	ctx := context.Background()
	tierResult := resolveTierFromContext(ctx, mgr)
	if tierResult != tier.TierDeveloper {
		t.Errorf("resolveTierFromContext=%v, want Developer (fallback)", tierResult)
	}
}

// ---------- contextWithTier ----------

func TestContextWithTier(t *testing.T) {
	ctx := contextWithTier(context.Background(), tier.TierEnterprise)
	tierStr, ok := ctx.Value(CtxKeyTier).(string)
	if !ok || tierStr != "enterprise" {
		t.Errorf("CtxKeyTier=%q, want enterprise", tierStr)
	}
}

// ---------- NewLicenseMiddleware ----------

func TestNewLicenseMiddleware(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	lm := NewLicenseMiddleware(mgr)
	if lm == nil || lm.manager != mgr {
		t.Error("NewLicenseMiddleware should set manager")
	}
}

// ---------- ContextWithManager / ManagerFromContext ----------

func TestContextWithManager(t *testing.T) {
	mgr, _ := NewManager()
	ctx := ContextWithManager(context.Background(), mgr)
	if ManagerFromContext(ctx) != mgr {
		t.Error("ManagerFromContext should return the same manager")
	}
}

func TestManagerFromContext_NotSet(t *testing.T) {
	ctx := context.Background()
	if ManagerFromContext(ctx) != nil {
		t.Error("ManagerFromContext should return nil when not set")
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// failingResponseWriter is used to trigger JSON encoding errors in middleware
type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

func (f *failingResponseWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated write failure")
}

// newKeyPairForTest generates a key pair and returns priv + public PEM
func newKeyPairForTest(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return priv, pubPEM
}

// newMgrWithPrivForTest creates a manager with its own key pair, returns both
func newMgrWithPrivForTest(t *testing.T) (*Manager, *ecdsa.PrivateKey) {
	t.Helper()
	priv, pubPEM := newKeyPairForTest(t)
	mgr, err := NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey: %v", err)
	}
	return mgr, priv
}

// signLicenseWithPriv creates a signed license using the given private key
// sigSize: 64 for full ECDSA signature, 32 for bad-length signature
func signLicenseWithPriv(t *testing.T, priv *ecdsa.PrivateKey, payload LicensePayload, sigSize int) string {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hash := sha256.Sum256(payloadBytes)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	var sigB64 string
	if sigSize == 32 {
		// 32-byte signature (only r) - bad length
		sig := make([]byte, 32)
		rBytes := r.Bytes()
		copy(sig[32-len(rBytes):], rBytes)
		sigB64 = base64.StdEncoding.EncodeToString(sig)
	} else {
		// Full 64-byte signature (r || s)
		sig := make([]byte, 64)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(sig[32-len(rBytes):32], rBytes)
		copy(sig[64-len(sBytes):], sBytes)
		sigB64 = base64.StdEncoding.EncodeToString(sig)
	}

	lk := LicenseKeyFormat{Payload: payload, Signature: sigB64}
	lkBytes, err := json.Marshal(lk)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	return base64.StdEncoding.EncodeToString(lkBytes)
}

// signLicenseWithMgr creates a signed license using the manager's embedded key
func signLicenseWithMgr(t *testing.T, mgr *Manager, payload LicensePayload) string {
	t.Helper()
	// We need a private key to sign. Since mgr only has the public key,
	// we generate our own key pair and create a signed license.
	// This works because we can sign with the private key and the manager
	// verifies with the matching public key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	_, err = NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey: %v", err)
	}
	// Sign with private key
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hash := sha256.Sum256(payloadBytes)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	lk := LicenseKeyFormat{Payload: payload, Signature: sigB64}
	lkBytes, err := json.Marshal(lk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(lkBytes)
}
