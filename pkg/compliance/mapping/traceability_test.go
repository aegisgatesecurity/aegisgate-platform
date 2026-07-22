// SPDX-License-Identifier: Apache-2.0
// Cross-Framework Traceability API Tests
//
// Tests the full web of traceability: when a FedRAMP control fires,
// it traces to SOC 2, ISO 27001, HIPAA, PCI, etc.

package mapping

import (
	"strings"
	"testing"
)

// TestCrossReference_FedRAMPAC2 verifies the classic case: FedRAMP AC-2
// (Account Management) traces to SOC 2 CC6.1, ISO 27001 A.9.2.1,
// HIPAA §164.312(a), etc.
func TestCrossReference_FedRAMPAC2(t *testing.T) {
	results := CrossReference("fedramp", "FedRAMP-AC-2")
	if len(results) == 0 {
		t.Fatal("CrossReference(fedramp, FedRAMP-AC-2) returned no results")
	}

	// Must include SOC 2, ISO 27001, HIPAA, PCI at minimum
	frameworks := make(map[string]bool)
	for _, r := range results {
		frameworks[r.TargetFramework] = true
	}
	required := []string{"soc2", "iso27001", "hipaa", "pci", "nist_csf"}
	for _, fw := range required {
		if !frameworks[fw] {
			t.Errorf("FedRAMP-AC-2 cross-reference missing %s (got frameworks: %v)", fw, frameworks)
		}
	}

	// Source fields must be set correctly
	for _, r := range results {
		if r.SourceFramework != "fedramp" {
			t.Errorf("SourceFramework = %q, want fedramp", r.SourceFramework)
		}
		if r.SourceControlID != "FedRAMP-AC-2" {
			t.Errorf("SourceControlID = %q, want FedRAMP-AC-2", r.SourceControlID)
		}
		if r.AegisGateControl == "" {
			t.Error("AegisGateControl should not be empty")
		}
	}
}

// TestCrossReference_NonExistentControl returns nil for unknown controls.
func TestCrossReference_NonExistentControl(t *testing.T) {
	results := CrossReference("fedramp", "FedRAMP-ZZ-999")
	if results != nil {
		t.Errorf("CrossReference for nonexistent control should return nil, got %d results", len(results))
	}
}

// TestCrossReference_SOC2CC61 verifies reverse: SOC 2 CC6.1 traces to
// FedRAMP, ISO 27001, HIPAA, etc.
func TestCrossReference_SOC2CC61(t *testing.T) {
	results := CrossReference("soc2", "CC6.1")
	if len(results) == 0 {
		t.Fatal("CrossReference(soc2, CC6.1) returned no results")
	}

	// Must include FedRAMP
	hasFedRAMP := false
	for _, r := range results {
		if r.TargetFramework == "fedramp" {
			hasFedRAMP = true
			break
		}
	}
	if !hasFedRAMP {
		t.Error("SOC 2 CC6.1 cross-reference should include FedRAMP controls")
	}
}

// TestCrossReference_Symmetric verifies that if FedRAMP-AC-2 traces to
// SOC 2 CC6.1, then SOC 2 CC6.1 also traces back to FedRAMP-AC-2.
func TestCrossReference_Symmetric(t *testing.T) {
	// Forward: fedramp -> soc2
	forwardResults := CrossReference("fedramp", "FedRAMP-AC-2")
	soc2Controls := map[string]bool{}
	for _, r := range forwardResults {
		if r.TargetFramework == "soc2" {
			soc2Controls[r.TargetControlID] = true
		}
	}

	// For each SOC 2 control found, reverse lookup must include FedRAMP-AC-2
	for soc2ID := range soc2Controls {
		reverseResults := CrossReference("soc2", soc2ID)
		hasAC2 := false
		for _, r := range reverseResults {
			if r.TargetFramework == "fedramp" && r.TargetControlID == "FedRAMP-AC-2" {
				hasAC2 = true
				break
			}
		}
		if !hasAC2 {
			t.Errorf("Symmetry broken: FedRAMP-AC-2 -> SOC 2 %s, but SOC 2 %s -> FedRAMP does not include AC-2",
				soc2ID, soc2ID)
		}
	}
}

// TestCrossReference_AllFrameworks verifies that calling CrossReference
// with any framework produces results for at least 3 other frameworks.
func TestCrossReference_AllFrameworks(t *testing.T) {
	// Pick one well-known control from each framework
	testCases := map[string]string{
		"fedramp":     "FedRAMP-AC-2",
		"soc2":        "CC6.1",
		"iso27001":    "A.9.2.1",
		"hipaa":       "§164.312(a)(1)",
		"pci":         "7.1",
		"nist_csf":    "PR.AC-4",
		"cis":         "CIS-5",
		"owasp_web":   "OWASPWeb-A01",
		"owasp_llm":   "LLM02",
		"nist_ai_rmf": "GOVERN 2.2",
	}

	for fw, ctrl := range testCases {
		results := CrossReference(fw, ctrl)
		otherFrameworks := make(map[string]bool)
		for _, r := range results {
			otherFrameworks[r.TargetFramework] = true
		}
		if len(otherFrameworks) < 3 {
			t.Errorf("CrossReference(%s, %s) only maps to %d other frameworks: %v",
				fw, ctrl, len(otherFrameworks), otherFrameworks)
		}
	}
}

// TestCrossReference_NoSelfReference ensures CrossReference never returns
// controls from the same framework as the source.
func TestCrossReference_NoSelfReference(t *testing.T) {
	results := CrossReference("fedramp", "FedRAMP-AC-2")
	for _, r := range results {
		if r.TargetFramework == r.SourceFramework {
			t.Errorf("CrossReference should not return same-framework controls: %s -> %s:%s",
				r.SourceControlID, r.TargetFramework, r.TargetControlID)
		}
	}
}

// TestGetRelatedControls verifies the full control group for a detection.
func TestGetRelatedControls_FedRAMPAC2(t *testing.T) {
	groups := GetRelatedControls("fedramp", "FedRAMP-AC-2")
	if len(groups) == 0 {
		t.Fatal("GetRelatedControls(fedramp, FedRAMP-AC-2) returned no groups")
	}

	// Must include AG-AUTH-RBAC-MFA
	foundRBAC := false
	for _, g := range groups {
		if g.AegisGateControl == "AG-AUTH-RBAC-MFA" {
			foundRBAC = true
			if len(g.FrameworkControls) < 5 {
				t.Errorf("AG-AUTH-RBAC-MFA has %d framework controls, want at least 5",
					len(g.FrameworkControls))
			}
		}
	}
	if !foundRBAC {
		t.Error("GetRelatedControls(fedramp, FedRAMP-AC-2) should include AG-AUTH-RBAC-MFA")
	}
}

// TestGetRelatedControls_UnknownControl returns nil.
func TestGetRelatedControls_UnknownControl(t *testing.T) {
	groups := GetRelatedControls("fedramp", "FedRAMP-ZZ-999")
	if groups != nil {
		t.Errorf("GetRelatedControls for unknown control should return nil, got %d groups", len(groups))
	}
}

// TestFullTraceabilityMatrix verifies the matrix is non-empty and covers
// all frameworks.
func TestFullTraceabilityMatrix(t *testing.T) {
	matrix := FullTraceabilityMatrix()
	if len(matrix) == 0 {
		t.Fatal("FullTraceabilityMatrix returned empty matrix")
	}

	// Must have entries for fedramp
	fedrampEntries := 0
	for key := range matrix {
		if strings.HasPrefix(key, "fedramp:") {
			fedrampEntries++
		}
	}
	if fedrampEntries == 0 {
		t.Error("FullTraceabilityMatrix has no FedRAMP entries")
	}
	if fedrampEntries < 50 {
		t.Errorf("FullTraceabilityMatrix has only %d FedRAMP entries, want at least 50", fedrampEntries)
	}

	// Total entries should be substantial (each framework control has cross-refs)
	totalRefs := 0
	for _, refs := range matrix {
		totalRefs += len(refs)
	}
	if totalRefs < 100 {
		t.Errorf("FullTraceabilityMatrix has only %d total cross-references, want at least 100", totalRefs)
	}
}

// TestCrossReference_FedRAMPToHIPAA verifies FedRAMP controls that map
// to HIPAA — this is the critical path for healthcare customers who
// need both FedRAMP and HIPAA compliance.
func TestCrossReference_FedRAMPToHIPAA(t *testing.T) {
	// FedRAMP AU-2 (Audit Events) should trace to HIPAA audit controls
	results := CrossReference("fedramp", "FedRAMP-AU-2")
	hasHIPAA := false
	for _, r := range results {
		if r.TargetFramework == "hipaa" {
			hasHIPAA = true
			break
		}
	}
	if !hasHIPAA {
		t.Error("FedRAMP-AU-2 should cross-reference HIPAA audit controls")
	}
}

// TestCrossReference_FedRAMPToPCI verifies FedRAMP controls that map
// to PCI-DSS — critical for payment processing customers.
func TestCrossReference_FedRAMPToPCI(t *testing.T) {
	// FedRAMP SC-8 (Transmission Confidentiality) should trace to PCI encryption controls
	results := CrossReference("fedramp", "FedRAMP-SC-8")
	hasPCI := false
	for _, r := range results {
		if r.TargetFramework == "pci" {
			hasPCI = true
			break
		}
	}
	if !hasPCI {
		t.Error("FedRAMP-SC-8 should cross-reference PCI encryption controls")
	}
}

// TestCrossReference_MultiAlarmFanout simulates the key scenario:
// a detection alarm fires, and the operator sees ALL frameworks affected.
func TestCrossReference_MultiAlarmFanout(t *testing.T) {
	// Simulate: AU-2 (Audit Events) alarm fires
	results := CrossReference("fedramp", "FedRAMP-AU-2")

	// The alarm should surface controls across many frameworks
	frameworks := make(map[string]int)
	for _, r := range results {
		frameworks[r.TargetFramework]++
	}

	// Should reach at least 5 frameworks (SOC 2, ISO 27001, HIPAA, PCI, NIST CSF, etc.)
	if len(frameworks) < 5 {
		t.Errorf("FedRAMP-AU-2 alarm only reaches %d frameworks: %v", len(frameworks), frameworks)
	}

	// Each framework should have at least 1 control
	for fw, count := range frameworks {
		if count < 1 {
			t.Errorf("Framework %s has %d controls from AU-2 alarm (want 1+)", fw, count)
		}
	}
}
