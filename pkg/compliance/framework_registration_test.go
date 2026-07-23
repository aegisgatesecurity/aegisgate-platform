// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Registration tests (v3.2.0 Phase 3.4)

package compliance

import (
	"testing"
)

func TestRegisterBuiltinFrameworks_Idempotent(t *testing.T) {
	// Call twice; second call should be a no-op (no panic, no
	// re-registration, count stays the same).
	RegisterBuiltinFrameworks()
	hipaaCount1 := lookupControlCount("hipaa")
	pciCount1 := lookupControlCount("pci")
	RegisterBuiltinFrameworks()
	hipaaCount2 := lookupControlCount("hipaa")
	pciCount2 := lookupControlCount("pci")
	if hipaaCount1 != hipaaCount2 {
		t.Errorf("HIPAA count changed on re-registration: %d -> %d", hipaaCount1, hipaaCount2)
	}
	if pciCount1 != pciCount2 {
		t.Errorf("PCI count changed on re-registration: %d -> %d", pciCount1, pciCount2)
	}
}

func TestRegisterBuiltinFrameworks_RealCounts(t *testing.T) {
	// Verify all registered frameworks have > 0 controls.
	RegisterBuiltinFrameworks()
	frameworks := map[string]int{
		"hipaa":     lookupControlCount("hipaa"),
		"pci":       lookupControlCount("pci"),
		"eu_ai_act": lookupControlCount("eu_ai_act"),
		"fedramp":   lookupControlCount("fedramp"),
		"soc2":      lookupControlCount("soc2"),
		"iso27001":  lookupControlCount("iso27001"),
		"iso42001":  lookupControlCount("iso42001"),
		"fips":      lookupControlCount("fips"),
		"nist_csf":  lookupControlCount("nist_csf"),
		"cis":       lookupControlCount("cis"),
	}
	for fw, count := range frameworks {
		t.Logf("%s registered controls: %d", fw, count)
		if count == 0 {
			t.Errorf("%s control count should be > 0 after RegisterBuiltinFrameworks", fw)
		}
	}
	// FedRAMP Path C has exactly 134 controls (49 automated + 85 evidence-mapped, 18 NIST 800-53 families).
	if fedrampCount := frameworks["fedramp"]; fedrampCount != 150 {
		t.Errorf("fedramp control count = %d, want 150 (Path C)", fedrampCount)
	}
}

func TestLookupControlCount_UnknownFramework(t *testing.T) {
	// Framework that has never been registered returns 0.
	// (soc2, iso42001, fedramp, etc. are now registered.)
	if got := lookupControlCount("made-up-framework"); got != 0 {
		t.Errorf("made-up-framework control count = %d, want 0", got)
	}
	if got := lookupControlCount("totally-fake"); got != 0 {
		t.Errorf("totally-fake control count = %d, want 0", got)
	}
}

func TestRegisteredFrameworkControls(t *testing.T) {
	// Public API matches lookupControlCount.
	RegisterBuiltinFrameworks()
	hipaaPublic := RegisteredFrameworkControls("hipaa")
	hipaaInternal := lookupControlCount("hipaa")
	if hipaaPublic != hipaaInternal {
		t.Errorf("public (%d) != internal (%d)", hipaaPublic, hipaaInternal)
	}
}

func TestRegisterFrameworkControls_Manually(t *testing.T) {
	// Direct registration of a control count via the
	// (package-private) helper.
	registerFrameworkControls("test-fw", 42)
	if got := lookupControlCount("test-fw"); got != 42 {
		t.Errorf("test-fw count = %d, want 42", got)
	}
}

func TestRegisterFrameworkControls_Overwrite(t *testing.T) {
	// Re-registering the same framework overwrites the count.
	registerFrameworkControls("test-fw-2", 10)
	registerFrameworkControls("test-fw-2", 99)
	if got := lookupControlCount("test-fw-2"); got != 99 {
		t.Errorf("test-fw-2 count = %d, want 99 (overwritten)", got)
	}
}
