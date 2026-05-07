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
