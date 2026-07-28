// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// tieradapter Coverage Hardening — Round 2
// Target: FeatureAccessibleInAll (70.0% → 95%+)
// =========================================================================

//go:build !race

package tieradapter

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

func TestFeatureAccessibleInAll_TierDeveloper_OAuthSSO(t *testing.T) {
	// OAuthSSO requires Developer tier
	result := FeatureAccessibleInAll(tier.FeatureOAuthSSO, tier.TierDeveloper)
	if !result {
		t.Error("FeatureAccessibleInAll(OAuthSSO, Developer) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierProfessional_OAuthSSO(t *testing.T) {
	// OAuthSSO available at Professional tier
	result := FeatureAccessibleInAll(tier.FeatureOAuthSSO, tier.TierProfessional)
	if !result {
		t.Error("FeatureAccessibleInAll(OAuthSSO, Professional) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierEnterprise_OAuthSSO(t *testing.T) {
	// OAuthSSO available at Enterprise tier
	result := FeatureAccessibleInAll(tier.FeatureOAuthSSO, tier.TierEnterprise)
	if !result {
		t.Error("FeatureAccessibleInAll(OAuthSSO, Enterprise) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierEnterprise_ATLAS(t *testing.T) {
	// ATLAS compliance maps to Enterprise-tier feature in AegisGate core,
	// so it's only accessible at Enterprise tier (not Developer).
	result := FeatureAccessibleInAll(tier.FeatureATLAS, tier.TierEnterprise)
	if !result {
		t.Error("FeatureAccessibleInAll(ATLAS, Enterprise) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierCommunity_Streaming(t *testing.T) {
	// Streaming is a Community feature
	result := FeatureAccessibleInAll(tier.FeatureStreaming, tier.TierCommunity)
	if !result {
		t.Error("FeatureAccessibleInAll(Streaming, Community) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierCommunity_BasicAnomaly(t *testing.T) {
	result := FeatureAccessibleInAll(tier.FeatureBasicAnomaly, tier.TierCommunity)
	if !result {
		t.Error("FeatureAccessibleInAll(BasicAnomaly, Community) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierCommunity_MCPSessionIsolation(t *testing.T) {
	// MCPSessionIsolation is only in AegisGuard feature map (not AegisGate).
	// This forces the third block (aglicense.CanAccess) to execute.
	result := FeatureAccessibleInAll(tier.FeatureMCPSessionIsolation, tier.TierCommunity)
	if !result {
		t.Error("FeatureAccessibleInAll(MCPSessionIsolation, Community) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierDeveloper_MCPBasicRBAC(t *testing.T) {
	// MCPBasicRBAC is only in AegisGuard feature map.
	// Tests the aglicense.CanAccess path at Developer tier.
	result := FeatureAccessibleInAll(tier.FeatureMCPBasicRBAC, tier.TierDeveloper)
	if !result {
		t.Error("FeatureAccessibleInAll(MCPBasicRBAC, Developer) = false, want true")
	}
}

func TestFeatureAccessibleInAll_TierProfessional_CodeExecSandbox(t *testing.T) {
	// CodeExecSandbox is only in AegisGuard feature map.
	result := FeatureAccessibleInAll(tier.FeatureCodeExecSandbox, tier.TierProfessional)
	if !result {
		t.Error("FeatureAccessibleInAll(CodeExecSandbox, Professional) = false, want true")
	}
}

// ---------------------------------------------------------------------------
// T2: Rate limit wiring tests
// ---------------------------------------------------------------------------

func TestProxyRateLimitForTier_AllTiers(t *testing.T) {
	tests := []struct {
		name     string
		tier     tier.Tier
		expected int
	}{
		{"Community unlimited", tier.TierCommunity, -1},
		{"Developer 1000", tier.TierDeveloper, 1000},
		{"Professional 10000", tier.TierProfessional, 10000},
		{"Enterprise unlimited", tier.TierEnterprise, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProxyRateLimitForTier(tt.tier)
			if got != tt.expected {
				t.Errorf("ProxyRateLimitForTier(%s) = %d, want %d", tt.tier, got, tt.expected)
			}
		})
	}
}

func TestMCPRateLimitForTier_AllTiers(t *testing.T) {
	tests := []struct {
		name     string
		tier     tier.Tier
		expected int
	}{
		{"Community unlimited", tier.TierCommunity, -1},
		{"Developer 500", tier.TierDeveloper, 500},
		{"Professional 5000", tier.TierProfessional, 5000},
		{"Enterprise unlimited", tier.TierEnterprise, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MCPRateLimitForTier(tt.tier)
			if got != tt.expected {
				t.Errorf("MCPRateLimitForTier(%s) = %d, want %d", tt.tier, got, tt.expected)
			}
		})
	}
}

func TestProxyRateLimitForTier_MatchesTierMethod(t *testing.T) {
	tiers := []tier.Tier{tier.TierCommunity, tier.TierDeveloper, tier.TierProfessional, tier.TierEnterprise}
	for _, t2 := range tiers {
		got := ProxyRateLimitForTier(t2)
		want := t2.RateLimitProxy()
		if got != want {
			t.Errorf("ProxyRateLimitForTier(%s) = %d, want %d (from RateLimitProxy)", t2, got, want)
		}
	}
}

func TestMCPRateLimitForTier_MatchesTierMethod(t *testing.T) {
	tiers := []tier.Tier{tier.TierCommunity, tier.TierDeveloper, tier.TierProfessional, tier.TierEnterprise}
	for _, t2 := range tiers {
		got := MCPRateLimitForTier(t2)
		want := t2.RateLimitMCP()
		if got != want {
			t.Errorf("MCPRateLimitForTier(%s) = %d, want %d (from RateLimitMCP)", t2, got, want)
		}
	}
}
