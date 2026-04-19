// SPDX-License-Identifier: MIT
// Package tier provides additional test coverage for the tier package,
// targeting the uncovered switch-case branches and default paths.
package tier

import "testing"

// TestStringAllTiers verifies String() returns correct values for all 4 tiers
// and the default "unknown" for an invalid Tier value.
func TestStringAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierCommunity, "community"},
		{TierDeveloper, "developer"},
		{TierProfessional, "professional"},
		{TierEnterprise, "enterprise"},
		{Tier(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.tier.String()
		if got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// TestDisplayNameAllTiers verifies DisplayName() for all tiers including default.
func TestDisplayNameAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierCommunity, "Community"},
		{TierDeveloper, "Developer"},
		{TierProfessional, "Professional"},
		{TierEnterprise, "Enterprise"},
		{Tier(99), "Unknown"},
	}
	for _, tt := range tests {
		got := tt.tier.DisplayName()
		if got != tt.want {
			t.Errorf("Tier(%d).DisplayName() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// TestMaxUsersAllTiers verifies MaxUsers() for all tiers including default.
func TestMaxUsersAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 3},
		{TierDeveloper, 10},
		{TierProfessional, 50},
		{TierEnterprise, -1},
		{Tier(99), 3},
	}
	for _, tt := range tests {
		got := tt.tier.MaxUsers()
		if got != tt.want {
			t.Errorf("Tier(%d).MaxUsers() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestMaxAgentsAllTiers verifies MaxAgents() for all tiers including default.
func TestMaxAgentsAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 2},
		{TierDeveloper, 5},
		{TierProfessional, 25},
		{TierEnterprise, -1},
		{Tier(99), 2},
	}
	for _, tt := range tests {
		got := tt.tier.MaxAgents()
		if got != tt.want {
			t.Errorf("Tier(%d).MaxAgents() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestSupportLevelAllTiers verifies SupportLevel() for all tiers including default.
func TestSupportLevelAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierCommunity, "community"},
		{TierDeveloper, "email"},
		{TierProfessional, "priority"},
		{TierEnterprise, "24x7"},
		{Tier(99), "community"},
	}
	for _, tt := range tests {
		got := tt.tier.SupportLevel()
		if got != tt.want {
			t.Errorf("Tier(%d).SupportLevel() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// TestMaxConcurrentMCPAllTiers verifies MaxConcurrentMCP() for all tiers including default.
func TestMaxConcurrentMCPAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 5},
		{TierDeveloper, 25},
		{TierProfessional, 100},
		{TierEnterprise, -1},
		{Tier(99), 5},
	}
	for _, tt := range tests {
		got := tt.tier.MaxConcurrentMCP()
		if got != tt.want {
			t.Errorf("Tier(%d).MaxConcurrentMCP() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestMaxMCPToolsPerSessionAllTiers verifies MaxMCPToolsPerSession() for all tiers including default.
func TestMaxMCPToolsPerSessionAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 20},
		{TierDeveloper, 50},
		{TierProfessional, -1},
		{TierEnterprise, -1},
		{Tier(99), 20},
	}
	for _, tt := range tests {
		got := tt.tier.MaxMCPToolsPerSession()
		if got != tt.want {
			t.Errorf("Tier(%d).MaxMCPToolsPerSession() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestMCPExecTimeoutSecondsAllTiers verifies MCPExecTimeoutSeconds() for all tiers including default.
func TestMCPExecTimeoutSecondsAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 30},
		{TierDeveloper, 60},
		{TierProfessional, 300},
		{TierEnterprise, -1},
		{Tier(99), 30},
	}
	for _, tt := range tests {
		got := tt.tier.MCPExecTimeoutSeconds()
		if got != tt.want {
			t.Errorf("Tier(%d).MCPExecTimeoutSeconds() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestMaxMCPSandboxMemoryMBAllTiers verifies MaxMCPSandboxMemoryMB() for all tiers including default.
func TestMaxMCPSandboxMemoryMBAllTiers(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 256},
		{TierDeveloper, 512},
		{TierProfessional, 2048},
		{TierEnterprise, -1},
		{Tier(99), 256},
	}
	for _, tt := range tests {
		got := tt.tier.MaxMCPSandboxMemoryMB()
		if got != tt.want {
			t.Errorf("Tier(%d).MaxMCPSandboxMemoryMB() = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestInvalidTierDefaultBranches exercises all methods with an invalid Tier value
// to ensure the default branches are covered.
func TestInvalidTierDefaultBranches(t *testing.T) {
	invalid := Tier(99)

	// Verify RateLimitProxy default fallback
	if got := invalid.RateLimitProxy(); got != 120 {
		t.Errorf("Invalid Tier RateLimitProxy() = %d, want 120", got)
	}
	// Verify RateLimitMCP default fallback
	if got := invalid.RateLimitMCP(); got != 60 {
		t.Errorf("Invalid Tier RateLimitMCP() = %d, want 60", got)
	}
	// Verify LogRetentionDays default fallback
	if got := invalid.LogRetentionDays(); got != 7 {
		t.Errorf("Invalid Tier LogRetentionDays() = %d, want 7", got)
	}
}

// TestCanAccessAllTiers exercises CanAccess across all tier combinations.
func TestCanAccessAllTiers(t *testing.T) {
	tests := []struct {
		tier     Tier
		required Tier
		want     bool
	}{
		// Same tier always has access
		{TierCommunity, TierCommunity, true},
		{TierDeveloper, TierDeveloper, true},
		{TierProfessional, TierProfessional, true},
		{TierEnterprise, TierEnterprise, true},
		// Higher tier can access lower-tier features
		{TierDeveloper, TierCommunity, true},
		{TierProfessional, TierDeveloper, true},
		{TierEnterprise, TierProfessional, true},
		// Lower tier cannot access higher-tier features
		{TierCommunity, TierDeveloper, false},
		{TierCommunity, TierProfessional, false},
		{TierCommunity, TierEnterprise, false},
		{TierDeveloper, TierProfessional, false},
		{TierDeveloper, TierEnterprise, false},
		{TierProfessional, TierEnterprise, false},
	}
	for _, tt := range tests {
		got := tt.tier.CanAccess(tt.required)
		if got != tt.want {
			t.Errorf("Tier(%d).CanAccess(%d) = %v, want %v", tt.tier, tt.required, got, tt.want)
		}
	}
}

// TestParseTierAliases tests additional ParseTier alias inputs.
func TestParseTierAliases(t *testing.T) {
	tests := []struct {
		input string
		want  Tier
		err   bool
	}{
		{"Community", TierCommunity, false},           // case-insensitive
		{"DEVELOPER", TierDeveloper, false},           // uppercase
		{"  professional  ", TierProfessional, false}, // whitespace
		{"dev", TierDeveloper, false},
		{"ent", TierEnterprise, false},
		{"", TierCommunity, true}, // empty string
		{" unknown ", TierCommunity, true},
	}
	for _, tt := range tests {
		got, err := ParseTier(tt.input)
		if tt.err && err == nil {
			t.Errorf("ParseTier(%q) expected error, got nil", tt.input)
		}
		if !tt.err && got != tt.want {
			t.Errorf("ParseTier(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestAllFeaturesCounts verifies AllFeatures returns the expected number of features per tier.
func TestAllFeaturesCounts(t *testing.T) {
	tests := []struct {
		tier        Tier
		minFeatures int
	}{
		{TierCommunity, 30},
		{TierDeveloper, 53}, // Community 30 + Developer 23
		{TierProfessional, 73},
		{TierEnterprise, 91},
	}
	for _, tt := range tests {
		got := AllFeatures(tt.tier)
		if len(got) < tt.minFeatures {
			t.Errorf("AllFeatures(%s) returned %d features, want at least %d", tt.tier, len(got), tt.minFeatures)
		}
		// Should never exceed total features
		total := len(allFeatures())
		if len(got) > total {
			t.Errorf("AllFeatures(%s) returned %d features, more than total %d", tt.tier, len(got), total)
		}
	}
}

// TestHasFeatureCrossTier verifies HasFeature across tier boundaries for specific features.
func TestHasFeatureCrossTier(t *testing.T) {
	// Community features available to all tiers
	commFeatures := []Feature{FeatureAIProxy, FeatureStreaming, FeatureTLS, FeatureSBOM}
	for _, f := range commFeatures {
		for _, tier := range []Tier{TierCommunity, TierDeveloper, TierProfessional, TierEnterprise} {
			if !HasFeature(tier, f) {
				t.Errorf("HasFeature(%s, %s) = false, want true", tier, f)
			}
		}
	}

	// Developer-only features not available to Community
	devFeatures := []Feature{FeatureOAuthSSO, FeatureMTLS, FeatureGrafana}
	for _, f := range devFeatures {
		if HasFeature(TierCommunity, f) {
			t.Errorf("HasFeature(Community, %s) = true, want false", f)
		}
	}

	// Professional-only features
	proFeatures := []Feature{FeatureHIPAA, FeaturePCI, FeatureKubernetes}
	for _, f := range proFeatures {
		if HasFeature(TierDeveloper, f) {
			t.Errorf("HasFeature(Developer, %s) = true, want false", f)
		}
		if !HasFeature(TierProfessional, f) {
			t.Errorf("HasFeature(Professional, %s) = false, want true", f)
		}
	}

	// Enterprise-only features
	entFeatures := []Feature{FeatureHSM, FeatureFIPS, FeatureAirGapped}
	for _, f := range entFeatures {
		if HasFeature(TierProfessional, f) {
			t.Errorf("HasFeature(Professional, %s) = true, want false", f)
		}
		if !HasFeature(TierEnterprise, f) {
			t.Errorf("HasFeature(Enterprise, %s) = false, want true", f)
		}
	}
}

// TestRequiredTierUnknownFeature verifies RequiredTier returns Community for unknown features.
func TestRequiredTierUnknownFeature(t *testing.T) {
	unknown := Feature("nonexistent_feature_xyz")
	got := RequiredTier(unknown)
	if got != TierCommunity {
		t.Errorf("RequiredTier(unknown) = %s, want Community", got)
	}
}
