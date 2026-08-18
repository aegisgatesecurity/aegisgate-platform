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
	// Verify all 24 registered frameworks + 3 community frameworks have > 0 controls.
	RegisterBuiltinFrameworks()
	frameworks := map[string]int{
		// v3.2.0 originals
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
		// v3.4.0 Path B additions
		"cmmcl2":     lookupControlCount("cmmcl2"),
		"nist800171": lookupControlCount("nist800171"),
		"hitrust":    lookupControlCount("hitrust"),
		"tisax":      lookupControlCount("tisax"),
		"ccpa":       lookupControlCount("ccpa"),
		// v3.6.0 additions
		"nist_ai_rmf":   lookupControlCount("nist_ai_rmf"),
		"csa_star":      lookupControlCount("csa_star"),
		"nist_ai_600_1": lookupControlCount("nist_ai_600_1"),
		"owasp_web":     lookupControlCount("owasp_web"),
		// v3.6.2 additions
		"cjis":     lookupControlCount("cjis"),
		"ferpa":    lookupControlCount("ferpa"),
		"sox":      lookupControlCount("sox"),
		"glba":     lookupControlCount("glba"),
		"nerc_cip": lookupControlCount("nerc_cip"),
		// Community frameworks (static counts)
		"atlas": lookupControlCount("atlas"),
		"gdpr":  lookupControlCount("gdpr"),
		"owasp": lookupControlCount("owasp"),
	}
	for fw, count := range frameworks {
		t.Logf("%s registered controls: %d", fw, count)
		if count == 0 {
			t.Errorf("%s control count should be > 0 after RegisterBuiltinFrameworks", fw)
		}
	}
	// Verify total framework count (24 registered + 3 community = 27)
	if got := len(frameworks); got != 27 {
		t.Errorf("total framework count = %d, want 27", got)
	}
	// FedRAMP v3.6.0: 170 controls (151 automated CheckFuncs + 19 evidence-mapped).
	if fedrampCount := frameworks["fedramp"]; fedrampCount != 170 {
		t.Errorf("fedramp control count = %d, want 170", fedrampCount)
	}
	// v3.6.2 new frameworks: verify specific control counts
	if cjisCount := frameworks["cjis"]; cjisCount != 64 {
		t.Errorf("cjis control count = %d, want 64", cjisCount)
	}
	if ferpaCount := frameworks["ferpa"]; ferpaCount != 16 {
		t.Errorf("ferpa control count = %d, want 16", ferpaCount)
	}
	if soxCount := frameworks["sox"]; soxCount != 80 {
		t.Errorf("sox control count = %d, want 80", soxCount)
	}
	if glbaCount := frameworks["glba"]; glbaCount != 14 {
		t.Errorf("glba control count = %d, want 14", glbaCount)
	}
	// NIST CSF 2.0: 131 subcategories (23 automated + 108 manual)
	if nistCSFCount := frameworks["nist_csf"]; nistCSFCount != 131 {
		t.Errorf("nist_csf control count = %d, want 131", nistCSFCount)
	}
	// GDPR: 99 article controls (12 automated + 87 manual)
	if gdprCount := frameworks["gdpr"]; gdprCount != 99 {
		t.Errorf("gdpr control count = %d, want 99", gdprCount)
	}
	if nercCipCount := frameworks["nerc_cip"]; nercCipCount != 18 {
		t.Errorf("nerc_cip control count = %d, want 18", nercCipCount)
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
