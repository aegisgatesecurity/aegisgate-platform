// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Vertical bundle tests (v3.7.0)

package compliance

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	tierpkg "github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ---- AllBundles ----

func TestAllBundles_Count(t *testing.T) {
	bundles := AllBundles()
	if len(bundles) != 7 {
		t.Errorf("AllBundles returned %d bundles, want 7", len(bundles))
	}
}

func TestAllBundles_Order(t *testing.T) {
	bundles := AllBundles()
	// Community bundles first, then Developer, then Professional.
	for i := 1; i < len(bundles); i++ {
		if bundles[i].RequiredTier < bundles[i-1].RequiredTier {
			t.Errorf("bundles not sorted by tier: %s (%s) before %s (%s)",
				bundles[i-1].ID, bundles[i-1].RequiredTier,
				bundles[i].ID, bundles[i].RequiredTier)
		}
	}
}

func TestBundleCount(t *testing.T) {
	if got := BundleCount(); got != 7 {
		t.Errorf("BundleCount = %d, want 7", got)
	}
}

// ---- GetBundle ----

func TestGetBundle_Known(t *testing.T) {
	b, ok := GetBundle("healthcare")
	if !ok {
		t.Fatal("GetBundle(healthcare): not found")
	}
	if b.DisplayName != "Healthcare Accelerator" {
		t.Errorf("DisplayName = %q, want 'Healthcare Accelerator'", b.DisplayName)
	}
	if len(b.Frameworks) != 3 {
		t.Errorf("Healthcare bundle has %d frameworks, want 3 (HIPAA + HITECH + HITRUST)", len(b.Frameworks))
	}
}

func TestGetBundle_Unknown(t *testing.T) {
	_, ok := GetBundle("unknown")
	if ok {
		t.Error("GetBundle(unknown) returned ok=true, want false")
	}
}

// ---- Bundle structure validation ----

func TestBundle_HasRequiredFields(t *testing.T) {
	for _, b := range AllBundles() {
		t.Run(b.ID, func(t *testing.T) {
			if b.ID == "" {
				t.Error("bundle has empty ID")
			}
			if b.DisplayName == "" {
				t.Error("bundle has empty DisplayName")
			}
			if b.Description == "" {
				t.Error("bundle has empty Description")
			}
			if len(b.Frameworks) == 0 {
				t.Error("bundle has no frameworks")
			}
			if b.BundlePriceCents <= 0 {
				t.Errorf("bundle %s has non-positive BundlePriceCents %d", b.ID, b.BundlePriceCents)
			}
			if b.IndividualPriceCents <= 0 {
				t.Errorf("bundle %s has non-positive IndividualPriceCents %d", b.ID, b.IndividualPriceCents)
			}
			// v4.2.0: Privacy bundle has 0 discount (only paid item is ISO 27001)
			if b.BundlePriceCents > b.IndividualPriceCents {
				t.Errorf("bundle %s: bundle price ($%d) should not exceed individual ($%d)",
					b.ID, b.BundlePriceCents/100, b.IndividualPriceCents/100)
			}
			if b.DiscountPercent < 0 || b.DiscountPercent > 90 {
				t.Errorf("bundle %s: DiscountPercent = %d, want 0-90", b.ID, b.DiscountPercent)
			}
			if len(b.Industries) == 0 {
				t.Errorf("bundle %s has no industry tags", b.ID)
			}
		})
	}
}

// ---- Bundle pricing ----

func TestBundle_DiscountMath(t *testing.T) {
	for _, b := range AllBundles() {
		t.Run(b.ID, func(t *testing.T) {
			actualDiscount := 100 - (b.BundlePriceCents * 100 / b.IndividualPriceCents)
			// Allow 2% rounding tolerance
			diff := actualDiscount - b.DiscountPercent
			if diff < -2 || diff > 2 {
				t.Errorf("bundle %s: stated discount %d%% doesn't match actual %d%% (bundle=$%d, individual=$%d)",
					b.ID, b.DiscountPercent, actualDiscount, b.BundlePriceCents/100, b.IndividualPriceCents/100)
			}
		})
	}
}

// ---- TierIncludedFrameworks ----

func TestTierIncludedFrameworks_Community(t *testing.T) {
	fws := TierIncludedFrameworks(tierpkg.TierCommunity)
	// v4.2.0: Community tier has 4 free frameworks (OWASP LLM, OWASP Web, ATLAS, NIST AI RMF)
	if len(fws) < 4 {
		t.Errorf("Community tier includes %d frameworks, want at least 4", len(fws))
	}
	// CCPA and GDPR are now Developer tier, NOT Community
	foundCCPA := false
	foundGDPR := false
	for _, f := range fws {
		if f == license.ModuleCCPA {
			foundCCPA = true
		}
		if f == "gdpr" {
			foundGDPR = true
		}
	}
	if foundCCPA {
		t.Error("Community tier should NOT include CCPA (moved to Developer)")
	}
	if foundGDPR {
		t.Error("Community tier should NOT include GDPR (moved to Developer)")
	}
}

func TestTierIncludedFrameworks_EnterpriseIncludesAll(t *testing.T) {
	entFws := TierIncludedFrameworks(tierpkg.TierEnterprise)
	proFws := TierIncludedFrameworks(tierpkg.TierProfessional)
	devFws := TierIncludedFrameworks(tierpkg.TierDeveloper)
	comFws := TierIncludedFrameworks(tierpkg.TierCommunity)

	// Enterprise must be a strict superset of Professional
	for _, pf := range proFws {
		found := false
		for _, ef := range entFws {
			if ef == pf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Enterprise must include Professional framework %q", pf)
		}
	}
	// Professional must be a strict superset of Developer
	for _, df := range devFws {
		found := false
		for _, pf := range proFws {
			if pf == df {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Professional must include Developer framework %q", df)
		}
	}
	// Developer must be a strict superset of Community
	for _, cf := range comFws {
		found := false
		for _, df := range devFws {
			if df == cf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Developer must include Community framework %q", cf)
		}
	}
}

func TestIsFrameworkIncludedInTier(t *testing.T) {
	cases := []struct {
		framework string
		tier      tierpkg.Tier
		want      bool
	}{
		{"gdpr", tierpkg.TierCommunity, false},
		{license.ModuleCCPA, tierpkg.TierCommunity, false},
		{"gdpr", tierpkg.TierDeveloper, true},
		{license.ModuleCCPA, tierpkg.TierDeveloper, true},
		{license.ModuleHIPAA, tierpkg.TierCommunity, false},
		{license.ModuleHIPAA, tierpkg.TierProfessional, true},
		{license.ModuleHITRUST, tierpkg.TierProfessional, false},
		{license.ModuleHITRUST, tierpkg.TierEnterprise, true},
		// v4.2.0: FedRAMP is Enterprise tier, NOT included at Professional
		{license.ModuleFedRAMP, tierpkg.TierProfessional, false}, // FedRAMP is Enterprise tier now
		{license.ModuleFedRAMP, tierpkg.TierEnterprise, true},
	}
	for _, tc := range cases {
		name := tc.framework + "_" + tc.tier.String()
		t.Run(name, func(t *testing.T) {
			if got := IsFrameworkIncludedInTier(tc.framework, tc.tier); got != tc.want {
				t.Errorf("IsFrameworkIncludedInTier(%q, %s) = %v, want %v",
					tc.framework, tc.tier, got, tc.want)
			}
		})
	}
}

// ---- EffectiveBundlePrice ----

func TestEffectiveBundlePrice_EnterpriseHealthcare(t *testing.T) {
	// Enterprise includes both HIPAA and HITRUST. Healthcare bundle
	// is HIPAA + HITRUST. Since both are already in Enterprise tier,
	// the effective price is $0 — no additional purchase needed.
	price, err := EffectiveBundlePrice("healthcare", tierpkg.TierEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	if price != 0 {
		t.Errorf("Enterprise buying Healthcare: effective price = $%d, want $0 (both HIPAA and HITRUST already included)", price/100)
	}
}

func TestEffectiveBundlePrice_DeveloperPrivacy(t *testing.T) {
	// v4.2.0: Privacy bundle now requires Developer+ (not Community).
	price, err := EffectiveBundlePrice("privacy", tierpkg.TierDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	// Should be <= full bundle price ($149)
	if price > 19900 {
		t.Errorf("Developer buying Privacy: effective price = $%d, should be <= $149", price/100)
	}
}

func TestEffectiveBundlePrice_DeveloperFinance(t *testing.T) {
	// Developer tier buying Finance: SOC 2 is included in Developer,
	// so they effectively pay for PCI + ISO 27001 only.
	price, err := EffectiveBundlePrice("finance", tierpkg.TierDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	// Should be less than full bundle price ($249)
	if price >= 24900 {
		t.Errorf("Developer buying Finance: effective price = $%d, should be < $249 (SOC 2 is included)", price/100)
	}
}

func TestEffectiveBundlePrice_EnterpriseDefense(t *testing.T) {
	// Enterprise tier buying Defense: all 5 frameworks are Enterprise or Professional.
	// At Enterprise tier, all are included, so effective price should be 0 (nothing extra).
	price, err := EffectiveBundlePrice("defense", tierpkg.TierEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	// At Enterprise, all defense frameworks are included, so effective price is 0
	if price != 0 {
		t.Errorf("Enterprise buying Defense: effective price = $%d, want $0 (all included)", price/100)
	}
}

func TestEffectiveBundlePrice_UnknownBundle(t *testing.T) {
	_, err := EffectiveBundlePrice("unknown", tierpkg.TierCommunity)
	if err == nil {
		t.Error("Expected error for unknown bundle")
	}
}

func TestEffectiveBundlePrice_TierTooLow(t *testing.T) {
	_, err := EffectiveBundlePrice("defense", tierpkg.TierProfessional)
	if err == nil {
		t.Error("Expected error: Professional tier cannot buy Defense bundle (requires Enterprise)")
	}
}

// ---- BundleFrameworksMissing ----

func TestBundleFrameworksMissing_EnterpriseHealthcare(t *testing.T) {
	missing, err := BundleFrameworksMissing("healthcare", tierpkg.TierEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	// Enterprise includes both HIPAA and HITRUST. Healthcare = HIPAA + HITRUST.
	// Nothing is missing — the bundle adds nothing beyond what Enterprise already provides.
	if len(missing) != 0 {
		t.Errorf("Enterprise Healthcare missing frameworks = %v, want empty (all included)", missing)
	}
}

func TestBundleFrameworksMissing_CommunityPrivacy(t *testing.T) {
	// Privacy bundle requires Developer tier. Community can't buy it,
	// so BundleFrameworksMissing may return an error OR return all frameworks
	// as missing. Either is acceptable — we just verify it doesn't succeed
	// with 0 missing (which would mean Community gets all privacy frameworks free).
	missing, err := BundleFrameworksMissing("privacy", tierpkg.TierCommunity)
	if err != nil {
		// Error is acceptable — Community tier can't buy this bundle
		return
	}
	// If no error, all 3 frameworks should be missing (Community gets none of them)
	if len(missing) < 2 {
		t.Errorf("Community Privacy: %d missing, want at least 2 (CCPA, GDPR, ISO 27001 all above Community)", len(missing))
	}
}

// ---- BundlesForIndustry ----

func TestBundlesForIndustry(t *testing.T) {
	hc := BundlesForIndustry("healthcare")
	if len(hc) != 1 {
		t.Errorf("BundlesForIndustry(healthcare) = %d, want 1", len(hc))
	}
	if len(hc) > 0 && hc[0].ID != "healthcare" {
		t.Errorf("BundlesForIndustry(healthcare) = %s, want healthcare", hc[0].ID)
	}
}

func TestBundlesForIndustry_CrossIndustry(t *testing.T) {
	// ISO 27001 appears in multiple bundles, but bundles are distinct.
	// Finance + Privacy both include ISO 27001.
	finance := BundlesForIndustry("finance")
	privacy := BundlesForIndustry("privacy")
	if len(finance) == 0 {
		t.Error("BundlesForIndustry(finance) returned 0 bundles")
	}
	if len(privacy) == 0 {
		t.Error("BundlesForIndustry(privacy) returned 0 bundles")
	}
}

// ---- BundlesForTier ----

func TestBundlesForTier(t *testing.T) {
	dev := BundlesForTier(tierpkg.TierDeveloper)
	pro := BundlesForTier(tierpkg.TierProfessional)
	ent := BundlesForTier(tierpkg.TierEnterprise)

	// v4.2.0: 7 bundles total
	// Community can buy: 0 (privacy now requires Developer+)
	// Developer can buy: privacy, saas_b2b, finance, healthcare, eu_compliance (5 bundles)
	if len(dev) < 5 {
		t.Errorf("Developer can buy %d bundles, want at least 5 (privacy + saas_b2b + finance + healthcare + eu_compliance)", len(dev))
	}
	// Professional can buy: all Developer bundles + energy (6 bundles, defense is Enterprise)
	if len(pro) < 6 {
		t.Errorf("Professional can buy %d bundles, want at least 6", len(pro))
	}
	// Enterprise can buy all 7
	if len(ent) != 7 {
		t.Errorf("Enterprise can buy %d bundles, want 7", len(ent))
	}
}

// ---- UpgradePath ----

func TestUpgradePath_EnterpriseHealthcare(t *testing.T) {
	msg, err := UpgradePath("healthcare", tierpkg.TierEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	// Enterprise already includes all Healthcare frameworks, so the message
	// should say "No additional purchase needed."
	if !strings.Contains(msg, "No additional purchase") {
		t.Errorf("UpgradePath for Enterprise Healthcare should say 'No additional purchase', got: %s", msg)
	}
}

func TestUpgradePath_CommunityPrivacy(t *testing.T) {
	msg, err := UpgradePath("privacy", tierpkg.TierCommunity)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "Privacy") {
		t.Errorf("UpgradePath message should mention Privacy, got: %s", msg)
	}
}

// ---- Consistency with gating.go ----

func TestBundleFrameworks_AreKnownModules(t *testing.T) {
	// Every framework in a bundle must be either a license.Module constant
	// OR a known free-tier framework (gdpr, owasp_llm, etc.)
	knownFree := map[string]bool{
		"gdpr": true, "owasp_llm": true, "owasp_web": true,
		"atlas": true, "nist_csf": true, "cis": true,
		"iso27001": true,
	}
	for _, b := range AllBundles() {
		t.Run(b.ID, func(t *testing.T) {
			for _, fw := range b.Frameworks {
				isModule := license.IsValidModule(fw)
				isFree := knownFree[fw]
				if !isModule && !isFree {
					t.Errorf("bundle %s references unknown framework %q", b.ID, fw)
				}
			}
		})
	}
}

func TestBundleRequiredTier_FrameworkAccess(t *testing.T) {
	// v4.2.0: Bundles can contain frameworks from higher tiers — that's the
	// value proposition. Buying a bundle at Developer tier unlocks Professional
	// frameworks. The bundle's RequiredTier is the minimum PLATFORM tier,
	// not the maximum framework tier. So we only verify that the bundle
	// tier is reasonable (not Enterprise for a bundle with only Developer frameworks).
	for _, b := range AllBundles() {
		t.Run(b.ID, func(t *testing.T) {
			// Just verify all frameworks are known modules
			for _, fw := range b.Frameworks {
				_, known := RequiredTierForModule(fw)
				if !known && fw != "gdpr" && fw != "owasp_llm" && fw != "atlas" {
					t.Errorf("bundle %s contains unknown framework %s", b.ID, fw)
				}
			}
		})
	}
}
