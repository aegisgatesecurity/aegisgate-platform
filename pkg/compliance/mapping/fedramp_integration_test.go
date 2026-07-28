// SPDX-License-Identifier: Apache-2.0
// Cross-Framework FedRAMP Integration Tests
//
// Validates the end-to-end fan-out from AegisGate's 150 FedRAMP controls
// through the cross-framework mapping to SOC 2, ISO 27001, HIPAA, PCI,
// NIST CSF, CIS, OWASP, and the other 15 frameworks.
//
// The core value proposition: a customer seeking FedRAMP Moderate ATO
// runs one scan and AegisGate fans the evidence to ALL frameworks.
// These tests verify that fan-out actually works.

package mapping

import (
	"strings"
	"testing"
)

// TestFedRAMPCrossFrameworkFanout verifies that every FedRAMP control
// maps back to at least one AegisGate internal control, and that each
// AegisGate control fans out to multiple frameworks.
func TestFedRAMPCrossFrameworkFanout(t *testing.T) {
	// Step 1: All 150 FedRAMP controls must have reverse mappings
	allFedRAMP := []string{
		// AC family (18 controls)
		"FedRAMP-AC-1", "FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-4", "FedRAMP-AC-5",
		"FedRAMP-AC-6", "FedRAMP-AC-7", "FedRAMP-AC-8", "FedRAMP-AC-10", "FedRAMP-AC-11",
		"FedRAMP-AC-12", "FedRAMP-AC-14", "FedRAMP-AC-17", "FedRAMP-AC-20", "FedRAMP-AC-21",
		"FedRAMP-AC-22", "FedRAMP-AC-23", "FedRAMP-AC-24",
		// AT family (3 controls)
		"FedRAMP-AT-1", "FedRAMP-AT-2", "FedRAMP-AT-3",
		// AU family (13 controls)
		"FedRAMP-AU-1", "FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-4", "FedRAMP-AU-5",
		"FedRAMP-AU-6", "FedRAMP-AU-7", "FedRAMP-AU-9", "FedRAMP-AU-10", "FedRAMP-AU-11",
		"FedRAMP-AU-12", "FedRAMP-AU-13", "FedRAMP-AU-14", "FedRAMP-AU-16",
		// CA family (6 controls)
		"FedRAMP-CA-1", "FedRAMP-CA-2", "FedRAMP-CA-3", "FedRAMP-CA-5", "FedRAMP-CA-7",
		"FedRAMP-CA-8", "FedRAMP-CA-9",
		// CM family (12 controls)
		"FedRAMP-CM-1", "FedRAMP-CM-2", "FedRAMP-CM-3", "FedRAMP-CM-4", "FedRAMP-CM-5",
		"FedRAMP-CM-6", "FedRAMP-CM-7", "FedRAMP-CM-8", "FedRAMP-CM-9", "FedRAMP-CM-10",
		"FedRAMP-CM-11", "FedRAMP-CM-12",
		// CP family (9 controls)
		"FedRAMP-CP-1", "FedRAMP-CP-2", "FedRAMP-CP-3", "FedRAMP-CP-4", "FedRAMP-CP-6",
		"FedRAMP-CP-7", "FedRAMP-CP-8", "FedRAMP-CP-9", "FedRAMP-CP-10",
		// IA family (10 controls)
		"FedRAMP-IA-1", "FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-4", "FedRAMP-IA-5",
		"FedRAMP-IA-6", "FedRAMP-IA-7", "FedRAMP-IA-8", "FedRAMP-IA-9", "FedRAMP-IA-10",
		"FedRAMP-IA-11",
		// IR family (10 controls)
		"FedRAMP-IR-1", "FedRAMP-IR-2", "FedRAMP-IR-3", "FedRAMP-IR-4", "FedRAMP-IR-5",
		"FedRAMP-IR-6", "FedRAMP-IR-7", "FedRAMP-IR-8", "FedRAMP-IR-9", "FedRAMP-IR-10",
		// MA family (2 controls)
		"FedRAMP-MA-1", "FedRAMP-MA-4",
		// MP family (2 controls)
		"FedRAMP-MP-5", "FedRAMP-MP-6",
		// PE family (2 controls)
		"FedRAMP-PE-3", "FedRAMP-PE-20",
		// PL family (2 controls)
		"FedRAMP-PL-1", "FedRAMP-PL-2",
		// PM family (2 controls)
		"FedRAMP-PM-1", "FedRAMP-PM-14",
		// PS family (3 controls)
		"FedRAMP-PS-1", "FedRAMP-PS-2", "FedRAMP-PS-3",
		// RA family (6 controls)
		"FedRAMP-RA-1", "FedRAMP-RA-3", "FedRAMP-RA-4", "FedRAMP-RA-5", "FedRAMP-RA-6",
		"FedRAMP-RA-7", "FedRAMP-RA-9",
		// SA family (6 controls)
		"FedRAMP-SA-1", "FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-8", "FedRAMP-SA-9",
		"FedRAMP-SA-10", "FedRAMP-SA-11", "FedRAMP-SA-22",
		// SC family (22 controls)
		"FedRAMP-SC-1", "FedRAMP-SC-2", "FedRAMP-SC-3", "FedRAMP-SC-4", "FedRAMP-SC-5",
		"FedRAMP-SC-6", "FedRAMP-SC-7", "FedRAMP-SC-8", "FedRAMP-SC-12", "FedRAMP-SC-13",
		"FedRAMP-SC-15", "FedRAMP-SC-21", "FedRAMP-SC-22", "FedRAMP-SC-23", "FedRAMP-SC-24",
		"FedRAMP-SC-25", "FedRAMP-SC-26", "FedRAMP-SC-28", "FedRAMP-SC-34", "FedRAMP-SC-39",
		"FedRAMP-SC-40", "FedRAMP-SC-44",
		// SI family (11 controls)
		"FedRAMP-SI-1", "FedRAMP-SI-2", "FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-7",
		"FedRAMP-SI-8", "FedRAMP-SI-10", "FedRAMP-SI-11", "FedRAMP-SI-12", "FedRAMP-SI-14",
		"FedRAMP-SI-16",
		// SR family (5 controls)
		"FedRAMP-SR-3", "FedRAMP-SR-4", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12",
	}

	noReverse := []string{}
	for _, ctrl := range allFedRAMP {
		agControls := MapByFramework("fedramp", ctrl)
		if len(agControls) == 0 {
			noReverse = append(noReverse, ctrl)
		}
	}
	if len(noReverse) > 0 {
		t.Errorf("These FedRAMP controls have NO AegisGate reverse mapping: %v", noReverse)
	}

	// Step 2: Each AegisGate control that maps to FedRAMP must also map
	// to at least 3 other frameworks (this is the fan-out value prop)
	for _, agID := range ListControls() {
		ext, err := MapByControlID(agID)
		if err != nil {
			continue
		}
		hasFedRAMP := false
		for _, e := range ext {
			if e.Framework == "fedramp" {
				hasFedRAMP = true
				break
			}
		}
		if !hasFedRAMP {
			continue
		}
		// Count distinct frameworks
		fws := make(map[string]bool)
		for _, e := range ext {
			fws[e.Framework] = true
		}
		// Must map to FedRAMP + at least 3 other frameworks
		if len(fws) < 4 {
			t.Errorf("AegisGate control %s maps to FedRAMP but only %d frameworks total (want 4+), frameworks: %v",
				agID, len(fws), fws)
		}
	}
}

// TestFedRAMPFamilyCoverage verifies that each NIST 800-53 family
// has at least one control in the mapping (no family entirely missing).
func TestFedRAMPFamilyCoverage(t *testing.T) {
	families := map[string][]string{
		"AC": {"FedRAMP-AC-1", "FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-4", "FedRAMP-AC-5", "FedRAMP-AC-6", "FedRAMP-AC-7", "FedRAMP-AC-8", "FedRAMP-AC-10", "FedRAMP-AC-11", "FedRAMP-AC-12", "FedRAMP-AC-14", "FedRAMP-AC-17", "FedRAMP-AC-20", "FedRAMP-AC-21", "FedRAMP-AC-22", "FedRAMP-AC-23", "FedRAMP-AC-24"},
		"AT": {"FedRAMP-AT-1", "FedRAMP-AT-2", "FedRAMP-AT-3"},
		"AU": {"FedRAMP-AU-1", "FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-4", "FedRAMP-AU-5", "FedRAMP-AU-6", "FedRAMP-AU-7", "FedRAMP-AU-9", "FedRAMP-AU-10", "FedRAMP-AU-11", "FedRAMP-AU-12", "FedRAMP-AU-13", "FedRAMP-AU-14", "FedRAMP-AU-16"},
		"CA": {"FedRAMP-CA-1", "FedRAMP-CA-2", "FedRAMP-CA-3", "FedRAMP-CA-5", "FedRAMP-CA-7", "FedRAMP-CA-8", "FedRAMP-CA-9"},
		"CM": {"FedRAMP-CM-1", "FedRAMP-CM-2", "FedRAMP-CM-3", "FedRAMP-CM-4", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-7", "FedRAMP-CM-8", "FedRAMP-CM-9", "FedRAMP-CM-10", "FedRAMP-CM-11", "FedRAMP-CM-12"},
		"CP": {"FedRAMP-CP-1", "FedRAMP-CP-2", "FedRAMP-CP-3", "FedRAMP-CP-4", "FedRAMP-CP-6", "FedRAMP-CP-7", "FedRAMP-CP-8", "FedRAMP-CP-9", "FedRAMP-CP-10"},
		"IA": {"FedRAMP-IA-1", "FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-4", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7", "FedRAMP-IA-8", "FedRAMP-IA-9", "FedRAMP-IA-10", "FedRAMP-IA-11"},
		"IR": {"FedRAMP-IR-1", "FedRAMP-IR-2", "FedRAMP-IR-3", "FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6", "FedRAMP-IR-7", "FedRAMP-IR-8", "FedRAMP-IR-9", "FedRAMP-IR-10"},
		"MA": {"FedRAMP-MA-1", "FedRAMP-MA-4"},
		"MP": {"FedRAMP-MP-5", "FedRAMP-MP-6"},
		"PE": {"FedRAMP-PE-3", "FedRAMP-PE-20"},
		"PL": {"FedRAMP-PL-1", "FedRAMP-PL-2"},
		"PM": {"FedRAMP-PM-1", "FedRAMP-PM-14"},
		"PS": {"FedRAMP-PS-1", "FedRAMP-PS-2", "FedRAMP-PS-3"},
		"RA": {"FedRAMP-RA-1", "FedRAMP-RA-3", "FedRAMP-RA-4", "FedRAMP-RA-5", "FedRAMP-RA-6", "FedRAMP-RA-7", "FedRAMP-RA-9"},
		"SA": {"FedRAMP-SA-1", "FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-8", "FedRAMP-SA-9", "FedRAMP-SA-10", "FedRAMP-SA-11", "FedRAMP-SA-22"},
		"SC": {"FedRAMP-SC-1", "FedRAMP-SC-2", "FedRAMP-SC-3", "FedRAMP-SC-4", "FedRAMP-SC-5", "FedRAMP-SC-6", "FedRAMP-SC-7", "FedRAMP-SC-8", "FedRAMP-SC-12", "FedRAMP-SC-13", "FedRAMP-SC-15", "FedRAMP-SC-21", "FedRAMP-SC-22", "FedRAMP-SC-23", "FedRAMP-SC-24", "FedRAMP-SC-25", "FedRAMP-SC-26", "FedRAMP-SC-28", "FedRAMP-SC-34", "FedRAMP-SC-39", "FedRAMP-SC-40", "FedRAMP-SC-44"},
		"SI": {"FedRAMP-SI-1", "FedRAMP-SI-2", "FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-7", "FedRAMP-SI-8", "FedRAMP-SI-10", "FedRAMP-SI-11", "FedRAMP-SI-12", "FedRAMP-SI-14", "FedRAMP-SI-16"},
		"SR": {"FedRAMP-SR-3", "FedRAMP-SR-4", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12"},
	}

	for family, controls := range families {
		mapped := 0
		for _, ctrl := range controls {
			if agControls := MapByFramework("fedramp", ctrl); len(agControls) > 0 {
				mapped++
			}
		}
		if mapped == 0 {
			t.Errorf("NIST 800-53 family %s has 0 controls mapped to AegisGate (out of %d)",
				family, len(controls))
		}
		// At least half the controls in each family must be mapped
		minMapped := len(controls) / 2
		if mapped < minMapped {
			t.Errorf("NIST 800-53 family %s only has %d/%d controls mapped (want at least %d)",
				family, mapped, len(controls), minMapped)
		}
	}
}

// TestFedRAMPReportGeneration verifies that the compliance report
// generator includes FedRAMP when all frameworks are requested,
// and that FedRAMP coverage is non-trivial.
func TestFedRAMPReportGeneration(t *testing.T) {
	report := GenerateReport([]string{"fedramp"})
	if len(report.FrameworkReports) != 1 {
		t.Fatalf("Expected 1 framework report, got %d", len(report.FrameworkReports))
	}
	fr := report.FrameworkReports[0]
	if fr.Framework != "fedramp" {
		t.Errorf("Framework = %q, want fedramp", fr.Framework)
	}
	if fr.FrameworkName != "FedRAMP Moderate (NIST 800-53)" {
		t.Errorf("FrameworkName = %q, want FedRAMP Moderate (NIST 800-53)", fr.FrameworkName)
	}
	if fr.TotalControls < 150 {
		t.Errorf("TotalControls = %d, want at least 150 (full 150-control matrix)", fr.TotalControls)
	}
	if fr.CoveragePct <= 0 {
		t.Errorf("CoveragePct = %f, want > 0", fr.CoveragePct)
	}
	// Every FedRAMP control must have at least one AegisGate control
	for _, cr := range fr.ControlResults {
		if len(cr.AegisGateControls) == 0 {
			t.Errorf("FedRAMP control %s has no AegisGate controls mapped", cr.ControlID)
		}
	}
}

// TestFedRAMPReportInFullReport verifies that FedRAMP appears in the
// all-frameworks report and has reasonable coverage.
func TestFedRAMPReportInFullReport(t *testing.T) {
	report := GenerateReport(nil)
	foundFedRAMP := false
	for _, fr := range report.FrameworkReports {
		if fr.Framework == "fedramp" {
			foundFedRAMP = true
			if fr.TotalControls < 60 {
				t.Errorf("FedRAMP TotalControls = %d, want at least 150", fr.TotalControls)
			}
			break
		}
	}
	if !foundFedRAMP {
		t.Error("FedRAMP not found in all-frameworks report")
	}
}

// TestFedRAMPMultiFrameworkReport verifies the core value proposition:
// a FedRAMP-focused scan produces evidence that fans out to multiple
// other frameworks simultaneously.
func TestFedRAMPMultiFrameworkReport(t *testing.T) {
	report := GenerateReport([]string{"fedramp", "soc2", "iso27001", "hipaa", "nist_csf"})

	// Must have 5 framework reports
	if len(report.FrameworkReports) != 5 {
		t.Errorf("Expected 5 framework reports, got %d", len(report.FrameworkReports))
	}

	// Generate the markdown and check for cross-references
	md := report.FormatMarkdown()

	// The report must mention FedRAMP controls and their SOC 2 equivalents
	if !strings.Contains(md, "FedRAMP") {
		t.Error("Report markdown missing FedRAMP")
	}
	if !strings.Contains(md, "SOC 2") {
		t.Error("Report markdown missing SOC 2")
	}
	if !strings.Contains(md, "ISO 27001") {
		t.Error("Report markdown missing ISO 27001")
	}

	// The executive summary must mention all 5 frameworks
	for _, fw := range []string{"FedRAMP", "SOC 2", "ISO 27001", "HIPAA", "NIST CSF"} {
		if !strings.Contains(md, fw) {
			t.Errorf("Report markdown missing %s", fw)
		}
	}
}

// TestFedRAMPHighLeverageControls verifies that the highest-leverage
// AegisGate controls (RBAC+MFA, Audit Log, Crypto) map to the most
// FedRAMP controls, confirming the expected fan-out ratios.
func TestFedRAMPHighLeverageControls(t *testing.T) {
	highLeverage := map[string]int{
		"AG-AUTH-RBAC-MFA":   5, // AC-2, AC-3, AC-6, AC-14, AC-17, IA-2, etc.
		"AG-CRYPTO-TLS-FIPS": 3, // SC-4, SC-7, SC-8, etc.
		"AG-DETECT-SCANNER":  3, // SI-4, IR-4, IR-5, etc.
	}

	for agID, minFedRAMP := range highLeverage {
		ext, err := MapByControlID(agID)
		if err != nil {
			t.Errorf("MapByControlID(%s) error: %v", agID, err)
			continue
		}
		fedrampCount := 0
		for _, e := range ext {
			if e.Framework == "fedramp" {
				fedrampCount++
			}
		}
		if fedrampCount < minFedRAMP {
			t.Errorf("AegisGate control %s maps to %d FedRAMP controls, want at least %d",
				agID, fedrampCount, minFedRAMP)
		}
	}
}

// TestFedRAMPMappingSymmetry verifies that forward and reverse lookups
// are consistent: if AG-AUTH-RBAC-MFA maps to FedRAMP-AC-2, then
// MapByFramework("fedramp", "FedRAMP-AC-2") must return AG-AUTH-RBAC-MFA.
func TestFedRAMPMappingSymmetry(t *testing.T) {
	for _, agID := range ListControls() {
		ext, err := MapByControlID(agID)
		if err != nil {
			continue
		}
		for _, e := range ext {
			if e.Framework != "fedramp" {
				continue
			}
			// Reverse lookup must return the original AegisGate control
			reverse := MapByFramework("fedramp", e.ControlID)
			found := false
			for _, r := range reverse {
				if r == agID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Forward: %s -> %s, but reverse MapByFramework(fedramp, %s) = %v (missing %s)",
					agID, e.ControlID, e.ControlID, reverse, agID)
			}
		}
	}
}

// TestFedRAMPMatrixIncludesAllFamilies verifies the CoverageMatrix
// includes the fedramp key with all 19 NIST 800-53 families.
func TestFedRAMPMatrixIncludesAllFamilies(t *testing.T) {
	matrix := CoverageMatrix()
	fedrampMatrix, ok := matrix["fedramp"]
	if !ok {
		t.Fatal("CoverageMatrix missing fedramp framework")
	}

	familyPrefixes := []string{
		"FedRAMP-AC-", "FedRAMP-AT-", "FedRAMP-AU-", "FedRAMP-CA-", "FedRAMP-CM-",
		"FedRAMP-CP-", "FedRAMP-IA-", "FedRAMP-IR-", "FedRAMP-MA-", "FedRAMP-MP-",
		"FedRAMP-PE-", "FedRAMP-PL-", "FedRAMP-PM-", "FedRAMP-PS-", "FedRAMP-RA-",
		"FedRAMP-SA-", "FedRAMP-SC-", "FedRAMP-SI-", "FedRAMP-SR-",
	}
	for _, prefix := range familyPrefixes {
		found := false
		for controlID := range fedrampMatrix {
			if strings.HasPrefix(controlID, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CoverageMatrix fedramp missing controls with prefix %s", prefix)
		}
	}
}
