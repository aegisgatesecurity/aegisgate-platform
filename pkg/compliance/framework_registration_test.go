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
		// v3.8.0 additions
		"iso21434": lookupControlCount("iso21434"),
		// P2 expansions
		"hitech": lookupControlCount("hitech"),
		"ffiec":  lookupControlCount("ffiec"),
		"tsa_sd": lookupControlCount("tsa_sd"),
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
	// Verify total framework count (31 registered + community frameworks)
	if got := len(frameworks); got != 31 {
		t.Errorf("total framework count = %d, want 31", got)
	}
	// FedRAMP v3.6.0: 170 controls (151 automated CheckFuncs + 19 evidence-mapped).
	if fedrampCount := frameworks["fedramp"]; fedrampCount != 170 {
		t.Errorf("fedramp control count = %d, want 170", fedrampCount)
	}
	// v3.6.2 new frameworks: verify specific control counts
	if cjisCount := frameworks["cjis"]; cjisCount != 64 {
		t.Errorf("cjis control count = %d, want 64", cjisCount)
	}
	if ferpaCount := frameworks["ferpa"]; ferpaCount != 45 {
		t.Errorf("ferpa control count = %d, want 45", ferpaCount)
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
	// HIPAA: 54 Security Rule controls (24 automated + 30 manual)
	if hipaaCount := frameworks["hipaa"]; hipaaCount != 54 {
		t.Errorf("hipaa control count = %d, want 54", hipaaCount)
	}
	// PCI-DSS v4.0: 152 controls (75 automated + 77 manual)
	if pciCount := frameworks["pci"]; pciCount != 152 {
		t.Errorf("pci control count = %d, want 152", pciCount)
	}
	// SOC 2 v2.0: 64 controls (32 automated + 32 manual)
	if soc2Count := frameworks["soc2"]; soc2Count != 64 {
		t.Errorf("soc2 control count = %d, want 64", soc2Count)
	}
	// CCPA/CPRA v2.0: 26 controls (14 automated + 12 manual)
	if ccpaCount := frameworks["ccpa"]; ccpaCount != 26 {
		t.Errorf("ccpa control count = %d, want 26", ccpaCount)
	}
	if nercCipCount := frameworks["nerc_cip"]; nercCipCount != 55 {
		t.Errorf("nerc_cip control count = %d, want 55", nercCipCount)
	}
	// FIPS 140-2/140-3 v2.0: 40 controls (27 automated + 13 manual)
	if fipsCount := frameworks["fips"]; fipsCount != 40 {
		t.Errorf("fips control count = %d, want 40", fipsCount)
	}
	// ISO 42001 v2.0: 38 controls (18 automated + 20 manual)
	if iso42001Count := frameworks["iso42001"]; iso42001Count != 38 {
		t.Errorf("iso42001 control count = %d, want 38", iso42001Count)
	}
	// ISO 21434 v2.0: 42 controls (25 automated + 17 manual)
	if iso21434Count := frameworks["iso21434"]; iso21434Count != 42 {
		t.Errorf("iso21434 control count = %d, want 42", iso21434Count)
	}
	// HITECH Act: 35 controls (23 automated + 12 manual)
	if hitechCount := frameworks["hitech"]; hitechCount != 35 {
		t.Errorf("hitech control count = %d, want 35", hitechCount)
	}
	// FFIEC: 40 controls (25 automated + 15 manual)
	if ffiecCount := frameworks["ffiec"]; ffiecCount != 40 {
		t.Errorf("ffiec control count = %d, want 40", ffiecCount)
	}
	// TSA SD: 35 controls (22 automated + 13 manual)
	if tsaSdCount := frameworks["tsa_sd"]; tsaSdCount != 35 {
		t.Errorf("tsa_sd control count = %d, want 35", tsaSdCount)
	}
	// EU AI Act: 120 controls (17 automated + 103 manual)
	if euAiActCount := frameworks["eu_ai_act"]; euAiActCount != 120 {
		t.Errorf("eu_ai_act control count = %d, want 120", euAiActCount)
	}
	// CIS v8 v2.0: 50 controls (38 automated + 12 manual)
	if cisCount := frameworks["cis"]; cisCount != 50 {
		t.Errorf("cis control count = %d, want 50", cisCount)
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
