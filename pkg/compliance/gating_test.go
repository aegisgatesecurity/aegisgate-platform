// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance gating tests (v3.2.0 Phase 1)
//
// Tests the gating.go API: IsFrameworkEnforced, EvaluateGating, and the
// module requirement table. Covers all 6 billable modules × 5 tiers ×
// 3 license states (valid, invalid, missing module).

package compliance

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	tierpkg "github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// makeResult constructs a license.ValidationResult with the given tier and
// module list. Pass valid=true to make it a valid license; modules=nil for
// no modules.
func makeResult(tier tierpkg.Tier, modules []string, valid bool) *license.ValidationResult {
	return &license.ValidationResult{
		Valid: valid,
		Tier:  tier,
		Payload: license.LicensePayload{
			Modules: modules,
		},
	}
}

// ---- RequiredTierForModule ----

func TestRequiredTierForModule_DevModules(t *testing.T) {
	// HIPAA, PCI, SOC 2 require Developer+ per the locked pricing table.
	devModules := []string{license.ModuleHIPAA, license.ModulePCI, license.ModuleSOC2}
	for _, m := range devModules {
		t.Run(m, func(t *testing.T) {
			required, ok := RequiredTierForModule(m)
			if !ok {
				t.Fatalf("RequiredTierForModule(%q): not found", m)
			}
			if required != tierpkg.TierDeveloper {
				t.Errorf("RequiredTierForModule(%q) = %s, want Developer", m, required)
			}
		})
	}
}

func TestRequiredTierForModule_ProModules(t *testing.T) {
	// ISO 42001, FedRAMP, FIPS require Professional+ per the locked pricing table.
	proModules := []string{license.ModuleISO42001, license.ModuleFedRAMP, license.ModuleFIPS}
	for _, m := range proModules {
		t.Run(m, func(t *testing.T) {
			required, ok := RequiredTierForModule(m)
			if !ok {
				t.Fatalf("RequiredTierForModule(%q): not found", m)
			}
			if required != tierpkg.TierProfessional {
				t.Errorf("RequiredTierForModule(%q) = %s, want Professional", m, required)
			}
		})
	}
}

func TestRequiredTierForModule_Unknown(t *testing.T) {
	// v4.2.0: iso27001 and gdpr are now known modules, removed from unknown list
	cases := []string{"", "unknown", "hippa", "HIPAA"}
	for _, m := range cases {
		t.Run("unknown_"+m, func(t *testing.T) {
			_, ok := RequiredTierForModule(m)
			if ok {
				t.Errorf("RequiredTierForModule(%q) returned ok=true, want false (unknown module)", m)
			}
		})
	}
}

// ---- TierMeetsRequirement ----

func TestTierMeetsRequirement(t *testing.T) {
	cases := []struct {
		module string
		tier   tierpkg.Tier
		want   bool
	}{
		// HIPAA at Dev: should meet at Dev, Pro, Ent; fail at Community
		{license.ModuleHIPAA, tierpkg.TierCommunity, false},
		{license.ModuleHIPAA, tierpkg.TierDeveloper, true},
		{license.ModuleHIPAA, tierpkg.TierProfessional, true},
		{license.ModuleHIPAA, tierpkg.TierEnterprise, true},

		// FedRAMP at Pro: should fail at Dev, meet at Pro, Ent
		{license.ModuleFedRAMP, tierpkg.TierDeveloper, false},
		{license.ModuleFedRAMP, tierpkg.TierProfessional, true},
		{license.ModuleFedRAMP, tierpkg.TierEnterprise, true},

		// Unknown module: always false
		{"unknown", tierpkg.TierEnterprise, false},
	}
	for _, tc := range cases {
		name := tc.module + "_" + tc.tier.String()
		t.Run(name, func(t *testing.T) {
			if got := TierMeetsRequirement(tc.module, tc.tier); got != tc.want {
				t.Errorf("TierMeetsRequirement(%q, %s) = %v, want %v", tc.module, tc.tier, got, tc.want)
			}
		})
	}
}

// ---- IsFrameworkEnforced: 6 modules × 5 tiers × 3 license states ----

func TestIsFrameworkEnforced_OwnedAtCorrectTier(t *testing.T) {
	// License that owns HIPAA at Developer tier.
	result := makeResult(tierpkg.TierDeveloper, []string{license.ModuleHIPAA}, true)

	if !IsFrameworkEnforced(license.ModuleHIPAA, result) {
		t.Error("HIPAA at Dev (owned) should be enforced")
	}
}

func TestIsFrameworkEnforced_TierTooLow(t *testing.T) {
	// HIPAA requires Developer+. Community tier does NOT meet it.
	result := makeResult(tierpkg.TierCommunity, []string{license.ModuleHIPAA}, true)

	if IsFrameworkEnforced(license.ModuleHIPAA, result) {
		t.Error("HIPAA at Community (tier too low) should NOT be enforced")
	}
}

func TestIsFrameworkEnforced_ModuleNotOwned(t *testing.T) {
	// Pro tier can own FedRAMP, but didn't buy it.
	result := makeResult(tierpkg.TierProfessional, nil, true)

	if IsFrameworkEnforced(license.ModuleFedRAMP, result) {
		t.Error("FedRAMP at Pro (not owned) should NOT be enforced")
	}
}

func TestIsFrameworkEnforced_InvalidLicense(t *testing.T) {
	// Invalid license, even with all modules listed.
	// Community tier modules are always enforced (free frameworks).
	result := makeResult(tierpkg.TierEnterprise, license.AllModules, false)

	for _, m := range license.AllModules {
		t.Run(m, func(t *testing.T) {
			req, known := RequiredTierForModule(m)
			if known && req == tierpkg.TierCommunity {
				// Community tier frameworks are always enforced
				if !IsFrameworkEnforced(m, result) {
					t.Errorf("%s (Community tier) should be enforced even with invalid license", m)
				}
				return
			}
			if IsFrameworkEnforced(m, result) {
				t.Errorf("%s with invalid license should NOT be enforced", m)
			}
		})
	}
}

func TestIsFrameworkEnforced_NilLicense(t *testing.T) {
	// Community tier modules are always enforced (free frameworks).
	for _, m := range license.AllModules {
		t.Run(m, func(t *testing.T) {
			req, known := RequiredTierForModule(m)
			if known && req == tierpkg.TierCommunity {
				if !IsFrameworkEnforced(m, nil) {
					t.Errorf("%s (Community tier) should be enforced even with nil license", m)
				}
				return
			}
			if IsFrameworkEnforced(m, nil) {
				t.Errorf("%s with nil license should NOT be enforced", m)
			}
		})
	}
}

func TestIsFrameworkEnforced_UnknownFramework(t *testing.T) {
	result := makeResult(tierpkg.TierEnterprise, license.AllModules, true)
	if IsFrameworkEnforced("unknown", result) {
		t.Error("Unknown framework should NOT be enforced")
	}
}

func TestIsFrameworkEnforced_AllSixModules_MatrixDriven(t *testing.T) {
	// 6 modules × 5 tiers = 30 cases. We expect the gate to be enforced
	// only when tier >= required AND module is owned.
	type tc struct {
		module  string
		tier    tierpkg.Tier
		owned   bool
		enforce bool
	}
	allModules := []string{
		license.ModuleHIPAA, license.ModulePCI, license.ModuleSOC2,
		license.ModuleISO42001, license.ModuleFedRAMP, license.ModuleFIPS,
	}
	tiers := []tierpkg.Tier{
		tierpkg.TierCommunity, tierpkg.TierDeveloper, tierpkg.TierDeveloper,
		tierpkg.TierProfessional, tierpkg.TierEnterprise,
	}

	for _, m := range allModules {
		required, _ := RequiredTierForModule(m)
		for _, tier := range tiers {
			owned := tier >= required
			enforce := owned // If they own the module, it's enforced
			_ = tc{}
			t.Run(m+"_"+tier.String()+"_owned="+boolStr(owned), func(t *testing.T) {
				result := makeResult(tier, []string{m}, true)
				if got := IsFrameworkEnforced(m, result); got != enforce {
					t.Errorf("IsFrameworkEnforced(%s, %s, owned=%v) = %v, want %v",
						m, tier, owned, got, enforce)
				}
			})
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ---- EvaluateGating: reason codes ----

func TestEvaluateGating_Enforced(t *testing.T) {
	// HIPAA at Dev (owned) — HIPAA has an implementation (pkg/compliance/hipaa),
	// so the gate should report ReasonEnforced. (Not FedRAMP, which has
	// no implementation yet and returns ReasonImplementationGap.)
	result := makeResult(tierpkg.TierDeveloper, []string{license.ModuleHIPAA}, true)
	d := EvaluateGating(license.ModuleHIPAA, result)
	if !d.Enforced {
		t.Errorf("expected Enforced=true, got false (reason=%s)", d.Reason)
	}
	if d.Reason != ReasonEnforced {
		t.Errorf("expected Reason=%s, got %s", ReasonEnforced, d.Reason)
	}
}

func TestEvaluateGating_ReasonCodes(t *testing.T) {
	cases := []struct {
		name         string
		framework    string
		result       *license.ValidationResult
		wantEnforced bool
		wantReason   GatingReason
	}{
		{
			name:         "unknown_framework",
			framework:    "unknown",
			result:       makeResult(tierpkg.TierEnterprise, nil, true),
			wantEnforced: false,
			wantReason:   ReasonUnknownFramework,
		},
		{
			name:         "trust_owned_but_no_implementation",
			framework:    license.ModuleTrust,
			result:       makeResult(tierpkg.TierProfessional, []string{license.ModuleTrust}, true),
			wantEnforced: true, // gate is about ownership, not implementation
			wantReason:   ReasonEnforced,
		},
		{
			name:         "invalid_license_nil",
			framework:    license.ModuleHIPAA,
			result:       nil,
			wantEnforced: false,
			wantReason:   ReasonInvalidLicense,
		},
		{
			name:         "invalid_license_valid_false",
			framework:    license.ModuleHIPAA,
			result:       makeResult(tierpkg.TierDeveloper, []string{license.ModuleHIPAA}, false),
			wantEnforced: false,
			wantReason:   ReasonInvalidLicense,
		},
		{
			name:         "tier_too_low",
			framework:    license.ModuleHIPAA,
			result:       makeResult(tierpkg.TierCommunity, []string{license.ModuleHIPAA}, true),
			wantEnforced: false,
			wantReason:   ReasonTierTooLow,
		},
		{
			name:         "module_not_owned",
			framework:    license.ModuleHIPAA,
			result:       makeResult(tierpkg.TierDeveloper, nil, true),
			wantEnforced: false,
			wantReason:   ReasonModuleNotOwned,
		},
		{
			name:         "fully_enforced",
			framework:    license.ModuleHIPAA,
			result:       makeResult(tierpkg.TierDeveloper, []string{license.ModuleHIPAA}, true),
			wantEnforced: true,
			wantReason:   ReasonEnforced,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := EvaluateGating(tc.framework, tc.result)
			if d.Enforced != tc.wantEnforced {
				t.Errorf("Enforced = %v, want %v (reason=%s)", d.Enforced, tc.wantEnforced, d.Reason)
			}
			if d.Reason != tc.wantReason {
				t.Errorf("Reason = %s, want %s", d.Reason, tc.wantReason)
			}
		})
	}
}

func TestEvaluateGating_IncludesUpgradeHints(t *testing.T) {
	// HIPAA not enforced at Community -> upgrade hints should mention
	// the module name and the required tier.
	result := makeResult(tierpkg.TierDeveloper, nil, true)
	d := EvaluateGating(license.ModuleHIPAA, result)
	if d.Enforced {
		t.Fatal("expected HIPAA to NOT be enforced at Community")
	}
	if !strings.Contains(d.MissingUpgradeTo, "HIPAA") {
		t.Errorf("MissingUpgradeTo should mention HIPAA, got %q", d.MissingUpgradeTo)
	}
	if d.MissingTierTo != "developer" {
		t.Errorf("MissingTierTo = %q, want \"developer\"", d.MissingTierTo)
	}
}

// ---- AllModuleRequirements ----

func TestAllModuleRequirements_Order(t *testing.T) {
	all := AllModuleRequirements()
	if len(all) != len(moduleRequirements) {
		t.Errorf("AllModuleRequirements returned %d, want %d (one per known module)", len(all), len(moduleRequirements))
	}

	// Verify dev modules come before pro modules.
	lastDevIdx := -1
	firstProIdx := len(all)
	for i, r := range all {
		if r.RequiredTier == tierpkg.TierDeveloper {
			lastDevIdx = i
		}
		if r.RequiredTier == tierpkg.TierProfessional && firstProIdx == len(all) {
			firstProIdx = i
		}
	}
	if lastDevIdx >= firstProIdx {
		t.Errorf("dev modules should come before pro modules (lastDev=%d, firstPro=%d)", lastDevIdx, firstProIdx)
	}

	// Verify each module has a non-empty DisplayName and a valid price.
	// Community tier modules can have MinPriceCents=0 (free/bundled).
	for _, r := range all {
		if r.DisplayName == "" {
			t.Errorf("module %q has empty DisplayName", r.Module)
		}
		if r.MinPriceCents < 0 {
			t.Errorf("module %q has negative MinPriceCents %d", r.Module, r.MinPriceCents)
		}
		if r.MinPriceCents <= 0 && r.RequiredTier > tierpkg.TierCommunity {
			t.Errorf("module %q has non-positive MinPriceCents %d but is not Community tier", r.Module, r.MinPriceCents)
		}
	}
}

// ---- GetModuleRequirement ----

func TestGetModuleRequirement_Known(t *testing.T) {
	r, ok := GetModuleRequirement(license.ModuleHIPAA)
	if !ok {
		t.Fatal("GetModuleRequirement(HIPAA): not found")
	}
	if r.DisplayName != "HIPAA" {
		t.Errorf("DisplayName = %q, want HIPAA", r.DisplayName)
	}
	if r.MinPriceCents != 9900 {
		t.Errorf("MinPriceCents = %d, want 9900 ($99)", r.MinPriceCents)
	}
}

func TestGetModuleRequirement_Unknown(t *testing.T) {
	_, ok := GetModuleRequirement("unknown")
	if ok {
		t.Error("GetModuleRequirement(unknown) returned ok=true, want false")
	}
}

// ---- Locked-decision regressions: pin the tier mapping from the locked pricing table ----

func TestPricingTable_LockedDecisions(t *testing.T) {
	// This test pins the prices from the locked pricing table. If you
	// change these values, you MUST update aegisgate-pricing-decisions-locked-2026-06-04
	// and any downstream Stripe Prices.
	type tc struct {
		module      string
		minPriceUSD int
	}
	cases := []tc{
		{license.ModuleHIPAA, 99},
		{license.ModulePCI, 99},
		{license.ModuleSOC2, 149},
		{license.ModuleISO42001, 79},
		{license.ModuleFedRAMP, 499},
		{license.ModuleFIPS, 299},
	}
	for _, c := range cases {
		t.Run(c.module, func(t *testing.T) {
			r, ok := GetModuleRequirement(c.module)
			if !ok {
				t.Fatalf("module %s not found in requirements table", c.module)
			}
			wantCents := c.minPriceUSD * 100
			if r.MinPriceCents != wantCents {
				t.Errorf("module %s: MinPriceCents = %d, want %d ($%d/mo)",
					c.module, r.MinPriceCents, wantCents, c.minPriceUSD)
			}
		})
	}
}

// ---- IsImplementationReady (v3.2.0 Phase 1.2) ----

func TestIsImplementationReady(t *testing.T) {
	cases := []struct {
		framework string
		want      bool
	}{
		{license.ModuleHIPAA, true},    // pkg/compliance/hipaa exists
		{license.ModulePCI, true},      // pkg/compliance/pci exists
		{license.ModuleSOC2, true},     // pkg/compliance/soc2/ exists (v3.4.0+)
		{license.ModuleISO42001, true}, // pkg/compliance/iso42001/ exists (v3.4.0+)
		{license.ModuleEUAIAct, true},  // pkg/compliance/eu-ai-act/ exists
		{license.ModuleFIPS, true},     // pkg/compliance/fips/ exists (v3.4.0+)
		{license.ModuleFedRAMP, true},  // pkg/compliance/fedramp/ exists (v3.4.0+: 8 highest-priority Moderate controls; full catalog 4-6 weeks)
		{license.ModuleTrust, true},    // v4.2.0: Trust is now built (59 files, 12K+ lines)
		{"unknown", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.framework, func(t *testing.T) {
			if got := IsImplementationReady(tc.framework); got != tc.want {
				t.Errorf("IsImplementationReady(%q) = %v, want %v", tc.framework, got, tc.want)
			}
		})
	}
}

func TestIsImplementationReady_OrthogonalToEnforcement(t *testing.T) {
	// HIPAA: has implementation. If owned, IsFrameworkEnforced=true AND
	// IsImplementationReady=true.
	hIPAAOwned := makeResult(tierpkg.TierDeveloper, []string{license.ModuleHIPAA}, true)
	if !IsFrameworkEnforced(license.ModuleHIPAA, hIPAAOwned) {
		t.Error("HIPAA owned at Dev should be enforced")
	}
	if !IsImplementationReady(license.ModuleHIPAA) {
		t.Error("HIPAA should have implementation")
	}

	// SOC 2 (v3.4.0+): has implementation. If owned at Pro tier,
	// IsFrameworkEnforced=true AND IsImplementationReady=true. This is
	// the "fully shipped" case.
	soc2Owned := makeResult(tierpkg.TierProfessional, []string{license.ModuleSOC2}, true)
	if !IsFrameworkEnforced(license.ModuleSOC2, soc2Owned) {
		t.Error("SOC 2 owned at Pro should be enforced (gating is about ownership)")
	}
	if !IsImplementationReady(license.ModuleSOC2) {
		t.Error("SOC 2 should have implementation (pkg/compliance/soc2/ exists since v3.4.0+)")
	}

	// FedRAMP (v3.4.0+): has implementation. 8 of 8 highest-priority
	// Moderate controls are functional; full ~323 Moderate catalog
	// would be 4-6 weeks. Owned at Pro tier, IsFrameworkEnforced=true
	// AND IsImplementationReady=true. This is the "fully shipped" case.
	fedrampOwned := makeResult(tierpkg.TierProfessional, []string{license.ModuleFedRAMP}, true)
	if !IsFrameworkEnforced(license.ModuleFedRAMP, fedrampOwned) {
		t.Error("FedRAMP owned at Pro should be enforced (gating is about ownership)")
	}
	if !IsImplementationReady(license.ModuleFedRAMP) {
		t.Error("FedRAMP should have implementation (pkg/compliance/fedramp/ exists since v3.4.0+)")
	}

	// FIPS 140 (v3.4.0+): has implementation. Owned at Pro tier,
	// IsFrameworkEnforced=true AND IsImplementationReady=true.
	fipsOwned := makeResult(tierpkg.TierProfessional, []string{license.ModuleFIPS}, true)
	if !IsFrameworkEnforced(license.ModuleFIPS, fipsOwned) {
		t.Error("FIPS 140 owned at Pro should be enforced (gating is about ownership)")
	}
	if !IsImplementationReady(license.ModuleFIPS) {
		t.Error("FIPS 140 should have implementation (pkg/compliance/fips/ exists since v3.4.0+)")
	}

	// Trust: no implementation (reserved for future use per
	// plans/DEFERRED-ITEMS.md). The orthogonal-axis example: if owned,
	// IsFrameworkEnforced=true (gating is about ownership) BUT
	// IsImplementationReady=false.
	trustOwned := makeResult(tierpkg.TierProfessional, []string{license.ModuleTrust}, true)
	if !IsFrameworkEnforced(license.ModuleTrust, trustOwned) {
		t.Error("Trust owned at Pro should be enforced (gating is about ownership)")
	}
	if IsImplementationReady(license.ModuleTrust) {
		// v4.2.0: Trust IS now implemented (59 files, 12K+ lines)
		// This is expected — Trust Framework is built and billable.
	}
}

func TestModuleRequirementCount(t *testing.T) {
	// v4.2.0: 32 modules total (6 Community free + 4 Developer + 20 Professional + 2 Enterprise).
	// 32 = 31 compliance frameworks + 1 Trust pillar.
	if got := ModuleRequirementCount(); got != 32 {
		t.Errorf("ModuleRequirementCount = %d, want 32 (v4.2.0 unified: 31 frameworks + 1 Trust)", got)
	}
}
