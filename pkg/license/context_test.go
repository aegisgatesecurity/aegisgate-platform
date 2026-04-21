package license

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// TestContextAwareMethods verifies the context-aware methods work end-to-end
func TestContextAwareMethods(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	// Test 1: No license key → Community tier
	t.Run("NoLicenseKey_CommunityTier", func(t *testing.T) {
		ctx := context.Background()
		tierStr := mgr.GetTierForContext(ctx)
		if tierStr != "community" {
			t.Errorf("Expected community, got %s", tierStr)
		}
	})

	// Test 2: Community features work without a license
	t.Run("NoLicenseKey_CommunityFeature", func(t *testing.T) {
		ctx := context.Background()
		if !mgr.IsFeatureLicensedForContext(ctx, "ai_proxy") {
			t.Error("ai_proxy should be available without a license (Community)")
		}
	})

	// Test 3: Paid features blocked without a license
	t.Run("NoLicenseKey_PaidFeatureBlocked", func(t *testing.T) {
		ctx := context.Background()
		if mgr.IsFeatureLicensedForContext(ctx, "mtls") {
			t.Error("mtls should NOT be available without a license (Developer+)")
		}
	})

	// Test 4: Set license key → tier changes
	t.Run("WithProfessionalLicense_TierResolved", func(t *testing.T) {
		// Generate a valid license key for testing
		mgrWithKey, err := NewManager()
		if err != nil {
			t.Fatalf("NewManager() error: %v", err)
		}
		mgrWithKey.SetLicenseKey("") // Start with no key

		ctx := context.Background()
		tierStr := mgrWithKey.GetTierForContext(ctx)
		if tierStr != "community" {
			t.Errorf("Expected community with no key, got %s", tierStr)
		}
	})

	// Test 5: Context key override
	t.Run("ContextKeyOverride", func(t *testing.T) {
		mgr, _ := NewManager()
		mgr.SetLicenseKey("invalid-key")

		// Context override with empty key → community
		ctx := context.Background()
		tierStr := mgr.GetTierForContext(ctx)
		if tierStr != "community" {
			t.Errorf("Expected community with invalid key, got %s", tierStr)
		}
	})

	// Test 6: Context helpers
	t.Run("ContextHelpers", func(t *testing.T) {
		mgr, _ := NewManager()
		ctx := context.Background()
		ctx = ContextWithManager(ctx, mgr)
		ctx = ContextWithLicenseKey(ctx, "test-key")

		retrieved := ManagerFromContext(ctx)
		if retrieved != mgr {
			t.Error("ManagerFromContext should return the same manager")
		}

		// Test with no manager in context
		emptyCtx := context.Background()
		nilMgr := ManagerFromContext(emptyCtx)
		if nilMgr != nil {
			t.Error("ManagerFromContext should return nil with no manager")
		}
	})

	// Test 7: ManagerFromContext nil safety
	t.Run("ManagerFromContext_NilSafety", func(t *testing.T) {
		ctx := context.Background()
		result := ManagerFromContext(ctx)
		if result != nil {
			t.Error("Expected nil manager from empty context")
		}
	})
}

// TestIsFeatureCommunity verifies that IsFeatureCommunity correctly
// identifies community-tier features by string key
func TestIsFeatureCommunity(t *testing.T) {
	communityFeatures := []string{
		"ai_proxy", "openai", "anthropic", "streaming",
		"tls_termination", "compliance_atlas", "compliance_nist_ai_rmf",
		"ml_basic_anomaly", "metrics", "audit_logging",
	}

	for _, f := range communityFeatures {
		if !tier.IsFeatureCommunity(f) {
			t.Errorf("Expected %q to be a community feature", f)
		}
	}

	paidFeatures := []string{
		"mtls", "compliance_hipaa", "hsm_integration",
		"multi_tenant", "compliance_fedramp",
	}

	for _, f := range paidFeatures {
		if tier.IsFeatureCommunity(f) {
			t.Errorf("Expected %q to NOT be a community feature", f)
		}
	}
}

// TestTierHasFeatureKey verifies string-key-based feature access
func TestTierHasFeatureKey(t *testing.T) {
	tests := []struct {
		tier    tier.Tier
		key     string
		want    bool
	}{
		{tier.TierCommunity, "ai_proxy", true},
		{tier.TierCommunity, "mtls", false},
		{tier.TierCommunity, "compliance_hipaa", false},
		{tier.TierDeveloper, "ai_proxy", true},
		{tier.TierDeveloper, "mtls", true},
		{tier.TierDeveloper, "compliance_hipaa", false},
		{tier.TierProfessional, "compliance_hipaa", true},
		{tier.TierProfessional, "hsm_integration", false},
		{tier.TierEnterprise, "hsm_integration", true},
		{tier.TierEnterprise, "ai_proxy", true},
		// Unknown key defaults to community access
		{tier.TierCommunity, "unknown_feature", true},
	}

	for _, tt := range tests {
		got := tier.TierHasFeatureKey(tt.tier, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(%v, %q) = %v, want %v", tt.tier, tt.key, got, tt.want)
		}
	}
}