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
	// The HIPAA module registers a known number of controls.
	// Verify they're > 0 (sanity check that the registration
	// actually worked).
	RegisterBuiltinFrameworks()
	hipaaCount := lookupControlCount("hipaa")
	pciCount := lookupControlCount("pci")
	if hipaaCount == 0 {
		t.Error("HIPAA control count should be > 0 after RegisterBuiltinFrameworks")
	}
	if pciCount == 0 {
		t.Error("PCI control count should be > 0 after RegisterBuiltinFrameworks")
	}
	t.Logf("HIPAA registered controls: %d", hipaaCount)
	t.Logf("PCI registered controls: %d", pciCount)
}

func TestLookupControlCount_UnknownFramework(t *testing.T) {
	// Framework that has never been registered returns 0.
	if got := lookupControlCount("soc2"); got != 0 {
		t.Errorf("soc2 control count = %d, want 0 (not registered)", got)
	}
	if got := lookupControlCount("iso42001"); got != 0 {
		t.Errorf("iso42001 control count = %d, want 0 (not registered)", got)
	}
	if got := lookupControlCount("made-up-framework"); got != 0 {
		t.Errorf("made-up-framework control count = %d, want 0", got)
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
