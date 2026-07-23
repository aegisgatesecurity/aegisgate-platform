// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Module ownership tests (v3.2.0 Phase 1)
//
// Tests the HasModule, Modules, and IsValidModule helpers added in v3.2.0.
// These helpers enable the 7 billable compliance modules (hipaa, pci, soc2,
// iso42001, fedramp, fips, eu_ai_act) to be checked on a LicensePayload.
// v3.3.0 Phase 1 added eu_ai_act as the 7th billable module.

package license

import (
	"testing"
)

// makeValidResult constructs a ValidationResult with the given tier and
// module list. The result is marked Valid: true. No signature is required
// for HasModule tests (we test the helper, not the signature path).
func makeValidResult(modules []string) *ValidationResult {
	return &ValidationResult{
		Valid: true,
		Tier:  0, // placeholder; not used by HasModule
		Payload: LicensePayload{
			LicenseID: "test-license",
			Modules:   modules,
		},
	}
}

func TestIsValidModule_AllKnownModules(t *testing.T) {
	cases := []struct {
		module string
		want   bool
	}{
		// Billable modules (6).
		{ModuleHIPAA, true},
		{ModulePCI, true},
		{ModuleSOC2, true},
		{ModuleISO42001, true},
		{ModuleFedRAMP, true},
		{ModuleFIPS, true},
		{ModuleEUAIAct, true}, // v3.3.0 Phase 1
		// Reserved for future use (Trust Framework Phase 4).
		{ModuleTrust, true},
		// Unknown module names.
		{"", false},
		{"unknown", false},
		{"hippa", false},    // typo
		{"HIPAA", false},    // wrong case
		{"hipaa ", false},   // trailing space
		{" hipaa", false},   // leading space
		{"gdpr", false},     // GDPR is a feature constant in tier.go but not a billable module
		{"iso27001", false}, // ISO 27001 is a feature constant but not a billable module
		{"soc2_type2", false},
	}
	for _, tc := range cases {
		t.Run(tc.module, func(t *testing.T) {
			if got := IsValidModule(tc.module); got != tc.want {
				t.Errorf("IsValidModule(%q) = %v, want %v", tc.module, got, tc.want)
			}
		})
	}
}

func TestHasModule_AllValidModules_Owned(t *testing.T) {
	// License owns all 7 modules.
	result := makeValidResult([]string{
		ModuleHIPAA, ModulePCI, ModuleSOC2, ModuleISO42001, ModuleFedRAMP, ModuleFIPS, ModuleEUAIAct,
	})

	modules := []string{
		ModuleHIPAA, ModulePCI, ModuleSOC2, ModuleISO42001, ModuleFedRAMP, ModuleFIPS, ModuleEUAIAct,
	}
	for _, m := range modules {
		t.Run(m, func(t *testing.T) {
			// Need a Manager to call HasModule (it's a method).
			mgr := &Manager{}
			if !mgr.HasModule(result, m) {
				t.Errorf("HasModule(%q) = false, want true (license owns it)", m)
			}
		})
	}
}

func TestHasModule_NotOwned(t *testing.T) {
	// License owns only HIPAA.
	result := makeValidResult([]string{ModuleHIPAA})
	mgr := &Manager{}

	// Not owned:
	notOwned := []string{ModulePCI, ModuleSOC2, ModuleISO42001, ModuleFedRAMP, ModuleFIPS, ModuleTrust}
	for _, m := range notOwned {
		t.Run("not_owned_"+m, func(t *testing.T) {
			if mgr.HasModule(result, m) {
				t.Errorf("HasModule(%q) = true, want false (license does not own it)", m)
			}
		})
	}
}

func TestHasModule_EmptyLicense(t *testing.T) {
	// License with no modules at all.
	result := makeValidResult(nil)
	mgr := &Manager{}

	for _, m := range AllModules {
		t.Run(m, func(t *testing.T) {
			if mgr.HasModule(result, m) {
				t.Errorf("HasModule(%q) = true, want false (empty license)", m)
			}
		})
	}
}

func TestHasModule_InvalidResult(t *testing.T) {
	mgr := &Manager{}

	// nil result.
	if mgr.HasModule(nil, ModuleHIPAA) {
		t.Error("HasModule(nil, HIPAA) = true, want false")
	}

	// invalid result.
	invalid := &ValidationResult{Valid: false, Payload: LicensePayload{Modules: []string{ModuleHIPAA}}}
	if mgr.HasModule(invalid, ModuleHIPAA) {
		t.Error("HasModule(invalid, HIPAA) = true, want false")
	}
}

func TestHasModule_RejectsInvalidModuleName(t *testing.T) {
	// Even if the license "owns" an invalid module name (e.g., from a
	// corrupted license file), HasModule should reject the lookup.
	result := makeValidResult([]string{"bogus_module", "hipaa", "another_bogus"})
	mgr := &Manager{}

	if mgr.HasModule(result, "bogus_module") {
		t.Error("HasModule(bogus_module) = true, want false (invalid module name)")
	}
	if mgr.HasModule(result, "another_bogus") {
		t.Error("HasModule(another_bogus) = true, want false (invalid module name)")
	}
	// The valid one still works.
	if !mgr.HasModule(result, ModuleHIPAA) {
		t.Error("HasModule(HIPAA) = false, want true (license owns it)")
	}
}

func TestModules_ReturnsValidSubset(t *testing.T) {
	result := makeValidResult([]string{
		ModuleHIPAA,
		"bogus_module", // filtered out
		ModulePCI,
		"another_bogus", // filtered out
		ModuleSOC2,
	})
	mgr := &Manager{}

	got := mgr.Modules(result)
	want := []string{ModuleHIPAA, ModulePCI, ModuleSOC2}

	if len(got) != len(want) {
		t.Fatalf("Modules() returned %d items, want %d (got %v, want %v)", len(got), len(want), got, want)
	}
	for i, m := range want {
		if got[i] != m {
			t.Errorf("Modules()[%d] = %q, want %q", i, got[i], m)
		}
	}
}

func TestModules_EmptyAndInvalid(t *testing.T) {
	mgr := &Manager{}

	// nil result.
	if got := mgr.Modules(nil); got != nil {
		t.Errorf("Modules(nil) = %v, want nil", got)
	}

	// invalid result.
	invalid := &ValidationResult{Valid: false}
	if got := mgr.Modules(invalid); got != nil {
		t.Errorf("Modules(invalid) = %v, want nil", got)
	}

	// empty modules.
	result := makeValidResult([]string{})
	if got := mgr.Modules(result); got == nil || len(got) != 0 {
		t.Errorf("Modules(empty) = %v, want empty slice", got)
	}
}

func TestAllModules_Count(t *testing.T) {
	// 7 billable modules (HIPAA, PCI, SOC2, ISO42001, FedRAMP, FIPS, EU AI Act) + 1 reserved (Trust) = 8 total
	// defined in license.go, but AllModules slice only contains the 7 billable ones (Trust is in IsValidModule
	// only as a reserved future item, not in the billable list).
	// This test pins the contract so accidental additions/removals are noticed.
	if len(AllModules) != 13 {
		t.Errorf("AllModules has %d items, want 13 (HIPAA, PCI, SOC2, ISO42001, FedRAMP, FIPS, EU AI Act, CMMC L2, NIST 800-171, HITRUST, TISAX, CCPA, NIST AI RMF)", len(AllModules))
	}
}
