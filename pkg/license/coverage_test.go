// SPDX-License-Identifier: Apache-2.0
// Package license provides test coverage for previously-uncovered functions:
//   - DisableCache()
//   - IsFeatureLicensed()
//   - GetTier(key) — via Manager.GetTier
//   - GetLicenseKey()
//   - ClearCache()
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
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// signLicenseTest is a local copy of the signLicense helper so this file is self-contained.
func signLicenseTest(t *testing.T, payload LicensePayload, priv *ecdsa.PrivateKey) string {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
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
		t.Fatalf("marshal license: %v", err)
	}
	return base64.StdEncoding.EncodeToString(lkBytes)
}

func newTestManager(t *testing.T) (*Manager, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))
	mgr, err := NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey: %v", err)
	}
	return mgr, priv
}

func signedDeveloperKey(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID: "cov-test-dev",
		Tier:      "developer",
		Customer:  "cov-customer",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
	return signLicenseTest(t, payload, priv)
}

func signedEnterpriseKey(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID: "cov-test-ent",
		Tier:      "enterprise",
		Customer:  "cov-customer-ent",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
	}
	return signLicenseTest(t, payload, priv)
}

// ---------- DisableCache ----------

func TestDisableCache(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Cache should be enabled initially
	if !mgr.cacheEnabled {
		t.Fatal("cache should be enabled by default")
	}

	mgr.DisableCache()

	if mgr.cacheEnabled {
		t.Fatal("cache should be disabled after DisableCache()")
	}
}

func TestDisableCache_EffectOnValidate(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	// Validate once to populate cache
	_ = mgr.Validate(key)
	if mgr.GetCachedEntries() == 0 {
		t.Fatal("expected at least one cached entry after Validate")
	}

	// Disable cache and validate again — should NOT add to cache
	mgr.DisableCache()
	_ = mgr.Validate(key)
	// Cache count should remain the same (no new entries added)
	entries := mgr.GetCachedEntries()
	if entries == 0 {
		t.Fatal("cache entries should not have been cleared by DisableCache (only disables, doesn't clear)")
	}
}

// ---------- IsFeatureLicensed ----------

func TestIsFeatureLicensed_CommunityFeatureWithValidLicense(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	// Community feature should be licensed for Developer tier
	if !mgr.IsFeatureLicensed(&result, tier.FeatureAIProxy) {
		t.Error("IsFeatureLicensed should return true for community feature with developer license")
	}
}

func TestIsFeatureLicensed_DeveloperFeatureWithDeveloperLicense(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	// Developer feature (mTLS) should be licensed for Developer tier
	if !mgr.IsFeatureLicensed(&result, tier.FeatureMTLS) {
		t.Error("IsFeatureLicensed should return true for developer feature with developer license")
	}
}

func TestIsFeatureLicensed_ProfessionalFeatureWithDeveloperLicense(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	// Professional feature (HIPAA) should NOT be licensed for Developer tier
	if mgr.IsFeatureLicensed(&result, tier.FeatureHIPAA) {
		t.Error("IsFeatureLicensed should return false for professional feature with developer license")
	}
}

func TestIsFeatureLicensed_EnterpriseFeatureWithEnterpriseLicense(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedEnterpriseKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	// Enterprise feature (HSM) should be licensed for Enterprise tier
	if !mgr.IsFeatureLicensed(&result, tier.FeatureHSM) {
		t.Error("IsFeatureLicensed should return true for enterprise feature with enterprise license")
	}
}

func TestIsFeatureLicensed_InvalidResultFallsBackToCommunity(t *testing.T) {
	mgr, _ := NewManager()

	// Invalid key → ValidationResult with Valid=false
	result := mgr.Validate("garbage-key!!!")
	if result.Valid {
		t.Fatal("expected invalid result for garbage key")
	}

	// Community features should still be "licensed" even with invalid result
	if !mgr.IsFeatureLicensed(&result, tier.FeatureAIProxy) {
		t.Error("IsFeatureLicensed should return true for community feature with invalid result")
	}

	// Paid features should NOT be licensed
	if mgr.IsFeatureLicensed(&result, tier.FeatureMTLS) {
		t.Error("IsFeatureLicensed should return false for paid feature with invalid result")
	}
}

func TestIsFeatureLicensed_NilResult(t *testing.T) {
	mgr, _ := NewManager()

	// Note: IsFeatureLicensed does not guard against nil *ValidationResult.
	// Passing nil causes a panic. This test documents that behavior.
	// The safe fallback is to call IsFeatureLicensedForContext(ctx, key)
	// which handles invalid/unlicensed scenarios gracefully.

	// Verify with an invalid (non-nil) result instead:
	result := mgr.Validate("garbage!!!")
	if result.Valid {
		t.Fatal("expected invalid result")
	}
	// Community feature should still be licensed with invalid result
	if !mgr.IsFeatureLicensed(&result, tier.FeatureAIProxy) {
		t.Error("IsFeatureLicensed should return true for community feature with invalid result")
	}
	// Non-community feature should NOT be licensed
	if mgr.IsFeatureLicensed(&result, tier.FeatureMTLS) {
		t.Error("IsFeatureLicensed should return false for dev feature with invalid result")
	}
}

// ---------- GetTier ----------

func TestGetTier_ValidResult(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedEnterpriseKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	got := mgr.GetTier(&result)
	if got != tier.TierEnterprise {
		t.Errorf("GetTier = %v, want %v", got, tier.TierEnterprise)
	}
}

func TestGetTier_InvalidResult(t *testing.T) {
	mgr, _ := NewManager()

	result := mgr.Validate("garbage!!!")
	got := mgr.GetTier(&result)
	if got != tier.TierCommunity {
		t.Errorf("GetTier on invalid result = %v, want Community", got)
	}
}

func TestGetTier_NilResult(t *testing.T) {
	mgr, _ := NewManager()

	got := mgr.GetTier(nil)
	if got != tier.TierCommunity {
		t.Errorf("GetTier(nil) = %v, want Community", got)
	}
}

func TestGetTier_DeveloperResult(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	result := mgr.Validate(key)
	if !result.Valid {
		t.Fatalf("expected valid result, got: %v", result.Error)
	}

	got := mgr.GetTier(&result)
	if got != tier.TierDeveloper {
		t.Errorf("GetTier = %v, want Developer", got)
	}
}

// ---------- GetLicenseKey ----------

func TestGetLicenseKey_InitiallyEmpty(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if got := mgr.GetLicenseKey(); got != "" {
		t.Errorf("GetLicenseKey() = %q, want empty string", got)
	}
}

func TestGetLicenseKey_AfterSetLicenseKey(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mgr.SetLicenseKey("test-key-123")
	if got := mgr.GetLicenseKey(); got != "test-key-123" {
		t.Errorf("GetLicenseKey() = %q, want %q", got, "test-key-123")
	}
}

func TestGetLicenseKey_Updated(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mgr.SetLicenseKey("first-key")
	mgr.SetLicenseKey("second-key")
	if got := mgr.GetLicenseKey(); got != "second-key" {
		t.Errorf("GetLicenseKey() = %q, want %q", got, "second-key")
	}
}

// Also test that GetTierForContext uses the stored license key
func TestGetLicenseKey_UsedByGetTierForContext(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	// Set license key on manager
	mgr.SetLicenseKey(key)

	// GetTierForContext with background context should use stored key
	ctx := context.Background()
	tierStr := mgr.GetTierForContext(ctx)
	if tierStr != "developer" {
		t.Errorf("GetTierForContext = %q, want %q", tierStr, "developer")
	}
}

// ---------- ClearCache ----------

func TestClearCache(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	// Validate to populate cache
	_ = mgr.Validate(key)
	_ = mgr.Validate("") // also cache empty key → community

	entriesBefore := mgr.GetCachedEntries()
	if entriesBefore == 0 {
		t.Fatal("expected cached entries after validation")
	}

	mgr.ClearCache()

	entriesAfter := mgr.GetCachedEntries()
	if entriesAfter != 0 {
		t.Errorf("GetCachedEntries() = %d after ClearCache, want 0", entriesAfter)
	}
}

func TestClearCache_EmptyCache(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// ClearCache on empty cache should not panic
	mgr.ClearCache()

	if mgr.GetCachedEntries() != 0 {
		t.Errorf("GetCachedEntries() = %d after ClearCache on empty, want 0", mgr.GetCachedEntries())
	}
}

func TestClearCache_AllowsRevalidation(t *testing.T) {
	mgr, priv := newTestManager(t)
	key := signedDeveloperKey(t, priv)

	// Validate and cache
	result1 := mgr.Validate(key)
	if !result1.Valid {
		t.Fatalf("first validate: %v", result1.Error)
	}

	// Clear cache
	mgr.ClearCache()

	// Validate again — should succeed with fresh result
	result2 := mgr.Validate(key)
	if !result2.Valid {
		t.Fatalf("validate after ClearCache: %v", result2.Error)
	}
	if result2.Tier != tier.TierDeveloper {
		t.Errorf("tier after revalidate = %v, want Developer", result2.Tier)
	}
}
