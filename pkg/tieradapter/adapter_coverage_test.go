// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - TierAdapter Coverage Tests
// =========================================================================
// Targeted tests for uncovered branches in adapter.go (54.1% → target 80%)
// Covers: PlatformFeatureToAegisGate, PlatformFeatureToAegisGuard,
// FeatureAccessibleInAll, ToAegisGateTier/ToAegisGuardTier default branches,
// FromAegisGateTier/FromAegisGuardTier default branches
// =========================================================================

package tieradapter

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	aglicense "github.com/aegisguardsecurity/aegisguard/pkg/license"
)

// TestPlatformFeatureToAegisGate_KnownFeatures tests the feature mapping table.
func TestPlatformFeatureToAegisGate_KnownFeatures(t *testing.T) {
	tests := []struct {
		feature tier.Feature
		wantOK  bool
	}{
		{tier.FeatureAIProxy, true},
		{tier.FeatureOpenAI, true},
		{tier.FeatureAnthropic, true},
	}

	for _, tc := range tests {
		name, ok := PlatformFeatureToAegisGate(tc.feature)
		if ok != tc.wantOK {
			t.Errorf("PlatformFeatureToAegisGate(%s) ok = %v, want %v", tc.feature, ok, tc.wantOK)
		}
		if ok && name == "" {
			t.Errorf("PlatformFeatureToAegisGate(%s) returned ok=true but empty name", tc.feature)
		}
	}
}

// TestPlatformFeatureToAegisGate_UnknownFeature tests an unmapped feature.
func TestPlatformFeatureToAegisGate_UnknownFeature(t *testing.T) {
	name, ok := PlatformFeatureToAegisGate("nonexistent_feature_xyz")
	if ok {
		t.Errorf("PlatformFeatureToAegisGate(nonexistent) ok = true, want false; name = %q", name)
	}
}

// TestPlatformFeatureToAegisGuard_KnownFeatures tests the AegisGuard feature mapping table.
func TestPlatformFeatureToAegisGuard_KnownFeatures(t *testing.T) {
	tests := []struct {
		feature tier.Feature
		wantOK  bool
	}{
		{tier.FeatureMCPSessionIsolation, true},
		{tier.FeatureAuditLogging, true},
		{tier.FeatureOpenAI, true},
	}

	for _, tc := range tests {
		name, ok := PlatformFeatureToAegisGuard(tc.feature)
		if ok != tc.wantOK {
			t.Errorf("PlatformFeatureToAegisGuard(%s) ok = %v, want %v", tc.feature, ok, tc.wantOK)
		}
		if ok && name == "" {
			t.Errorf("PlatformFeatureToAegisGuard(%s) returned ok=true but empty name", tc.feature)
		}
	}
}

// TestPlatformFeatureToAegisGuard_UnknownFeature tests an unmapped feature.
func TestPlatformFeatureToAegisGuard_UnknownFeature(t *testing.T) {
	name, ok := PlatformFeatureToAegisGuard("nonexistent_feature_xyz")
	if ok {
		t.Errorf("PlatformFeatureToAegisGuard(nonexistent) ok = true, want false; name = %q", name)
	}
}

// TestFeatureAccessibleInAll_CommunityFeature tests a feature accessible at Community tier
// across all systems.
func TestFeatureAccessibleInAll_CommunityFeature(t *testing.T) {
	result := FeatureAccessibleInAll(tier.FeatureAIProxy, tier.TierCommunity)
	if !result {
		t.Error("FeatureAccessibleInAll(AIProxy, Community) = false, want true")
	}
}

// TestFeatureAccessibleInAll_HighTierFeature tests a Developer+ feature at Community tier.
func TestFeatureAccessibleInAll_HighTierFeature(t *testing.T) {
	result := FeatureAccessibleInAll(tier.FeatureOAuthSSO, tier.TierCommunity)
	if result {
		t.Error("FeatureAccessibleInAll(OAuthSSO, Community) = true, want false (SSO requires Developer+)")
	}
}

// TestToAegisGateTier_DefaultBranch tests the default case for invalid tier values.
func TestToAegisGateTier_DefaultBranch(t *testing.T) {
	result := ToAegisGateTier(tier.Tier(255))
	if result != core.TierCommunity {
		t.Errorf("ToAegisGateTier(255) = %d, want %d (Community)", result, core.TierCommunity)
	}
}

// TestToAegisGateTier_AllValidTiers tests all valid tier conversions.
func TestToAegisGateTier_AllValidTiers(t *testing.T) {
	tests := []struct {
		input    tier.Tier
		expected core.Tier
	}{
		{tier.TierCommunity, core.TierCommunity},
		{tier.TierDeveloper, core.TierDeveloper},
		{tier.TierProfessional, core.TierProfessional},
		{tier.TierEnterprise, core.TierEnterprise},
	}

	for _, tc := range tests {
		result := ToAegisGateTier(tc.input)
		if result != tc.expected {
			t.Errorf("ToAegisGateTier(%d) = %d, want %d", tc.input, result, tc.expected)
		}
	}
}

// TestToAegisGuardTier_DefaultBranch tests the default case for invalid tier values.
func TestToAegisGuardTier_DefaultBranch(t *testing.T) {
	result := ToAegisGuardTier(tier.Tier(255))
	if result != aglicense.TierCommunity {
		t.Errorf("ToAegisGuardTier(255) = %d, want %d (Community)", result, aglicense.TierCommunity)
	}
}

// TestToAegisGuardTier_AllValidTiers tests all valid tier conversions.
func TestToAegisGuardTier_AllValidTiers(t *testing.T) {
	tests := []struct {
		input    tier.Tier
		expected aglicense.Tier
	}{
		{tier.TierCommunity, aglicense.TierCommunity},
		{tier.TierDeveloper, aglicense.TierDeveloper},
		{tier.TierProfessional, aglicense.TierProfessional},
		{tier.TierEnterprise, aglicense.TierEnterprise},
	}

	for _, tc := range tests {
		result := ToAegisGuardTier(tc.input)
		if result != tc.expected {
			t.Errorf("ToAegisGuardTier(%d) = %d, want %d", tc.input, result, tc.expected)
		}
	}
}

// TestFromAegisGateTier_DefaultBranch tests the default case for invalid AegisGate tier values.
func TestFromAegisGateTier_DefaultBranch(t *testing.T) {
	result := FromAegisGateTier(core.Tier(255))
	if result != tier.TierCommunity {
		t.Errorf("FromAegisGateTier(255) = %d, want %d (Community)", result, tier.TierCommunity)
	}
}

// TestFromAegisGuardTier_DefaultBranch tests the default case for invalid AegisGuard tier values.
func TestFromAegisGuardTier_DefaultBranch(t *testing.T) {
	result := FromAegisGuardTier(aglicense.Tier(255))
	if result != tier.TierCommunity {
		t.Errorf("FromAegisGuardTier(255) = %d, want %d (Community)", result, tier.TierCommunity)
	}
}

// TestRoundTripConversions tests that ToX → FromX round-trips return the original value.
func TestRoundTripConversions(t *testing.T) {
	tiers := []tier.Tier{
		tier.TierCommunity,
		tier.TierDeveloper,
		tier.TierProfessional,
		tier.TierEnterprise,
	}

	for _, orig := range tiers {
		// AegisGate round-trip
		agResult := FromAegisGateTier(ToAegisGateTier(orig))
		if agResult != orig {
			t.Errorf("AegisGate round-trip: %d → %d → %d", orig, ToAegisGateTier(orig), agResult)
		}

		// AegisGuard round-trip
		augResult := FromAegisGuardTier(ToAegisGuardTier(orig))
		if augResult != orig {
			t.Errorf("AegisGuard round-trip: %d → %d → %d", orig, ToAegisGuardTier(orig), augResult)
		}
	}
}
