// SPDX-License-Identifier: Apache-2.0
// Cross-Framework Control Mapping - Unit Tests

package mapping

import (
	"strings"
	"testing"
)

func TestMapByControlID(t *testing.T) {
	tests := []struct {
		name        string
		aegisgateID string
		wantCount   int
		wantErr     bool
	}{
		{"RBAC+MFA maps to many frameworks", "AG-AUTH-RBAC-MFA", 25, false},
		{"Audit log maps to many frameworks", "AG-AUDIT-LOG-HASH-CHAIN", 17, false},
		{"TLS+FIPS maps to many frameworks", "AG-CRYPTO-TLS-FIPS", 20, false},
		{"Vuln scanning maps to many frameworks", "AG-VULN-CI-SCANNING", 17, false},
		{"Detection scanner maps to many frameworks", "AG-DETECT-SCANNER", 20, false},
		{"Trust framework maps to many frameworks", "AG-TRUST-AGENT-ATTESTATION", 15, false},
		{"Output filter maps to many frameworks", "AG-OUTPUT-PII-SECRET-FILTER", 14, false},
		{"Config baseline maps to many frameworks", "AG-CM-BASELINE-CONFIG", 10, false},
		{"Continuous monitoring maps to many frameworks", "AG-CA-CONTINUOUS-MONITORING", 10, false},
		{"Incident response maps to many frameworks", "AG-IR-INCIDENT-RESPONSE", 10, false},
		{"Boundary protection maps to many frameworks", "AG-SC-BOUNDARY-PROTECTION", 10, false},
		{"Unknown control ID", "AG-FAKE-1234", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := MapByControlID(tt.aegisgateID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %q, got nil", tt.aegisgateID)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(ext) < tt.wantCount {
				t.Errorf("MapByControlID(%q) returned %d controls, want at least %d",
					tt.aegisgateID, len(ext), tt.wantCount)
			}
		})
	}
}

func TestMapByFramework(t *testing.T) {
	// Every AegisGate control with SOC 2 CC6.1 should map back to AG-AUTH-RBAC-MFA
	results := MapByFramework("soc2", "CC6.1")
	if len(results) == 0 {
		t.Errorf("MapByFramework(soc2, CC6.1) returned no results")
	}
	found := false
	for _, r := range results {
		if r == "AG-AUTH-RBAC-MFA" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MapByFramework(soc2, CC6.1) missing AG-AUTH-RBAC-MFA, got %v", results)
	}
}

func TestListFrameworks(t *testing.T) {
	frameworks := ListFrameworks()
	if len(frameworks) < 10 {
		t.Errorf("ListFrameworks() returned %d frameworks, want at least 10", len(frameworks))
	}
	// Check that all major frameworks are present
	required := []string{"soc2", "iso27001", "hipaa", "pci", "nist_ai_rmf", "nist_csf", "cis", "fedramp", "fips_140", "iso_42001", "atlas", "eu_ai_act", "gdpr", "owasp_web", "owasp_llm"}
	have := make(map[string]bool)
	for _, f := range frameworks {
		have[f] = true
	}
	for _, r := range required {
		if !have[r] {
			t.Errorf("ListFrameworks() missing required framework: %s", r)
		}
	}
}

func TestListControls(t *testing.T) {
	controls := ListControls()
	if len(controls) < 19 {
		t.Errorf("ListControls() returned %d controls, want at least 19", len(controls))
	}
}

func TestCoverageMatrix(t *testing.T) {
	matrix := CoverageMatrix()
	// Check that SOC 2 is in the matrix
	soc2Matrix, ok := matrix["soc2"]
	if !ok {
		t.Errorf("CoverageMatrix missing soc2 framework")
	}
	// Check that CC6.1 is in the SOC 2 matrix and has AegisGate controls
	agIDs, ok := soc2Matrix["CC6.1"]
	if !ok {
		t.Errorf("CoverageMatrix soc2 missing CC6.1")
	}
	if len(agIDs) == 0 {
		t.Errorf("CoverageMatrix soc2 CC6.1 has no AegisGate controls")
	}
}

func TestGenerateCoverageReport(t *testing.T) {
	report := GenerateCoverageReport()
	if report.TotalAegisGateControls < 19 {
		t.Errorf("TotalAegisGateControls = %d, want at least 19", report.TotalAegisGateControls)
	}
	if report.TotalFrameworkMappings < 100 {
		t.Errorf("TotalFrameworkMappings = %d, want at least 100", report.TotalFrameworkMappings)
	}
	if len(report.FrameworksCovered) < 10 {
		t.Errorf("FrameworksCovered = %d, want at least 10", len(report.FrameworksCovered))
	}
}

func TestCoverageReport_FormatReport(t *testing.T) {
	report := GenerateCoverageReport()
	formatted := report.FormatReport()
	// Check key sections (use lenient substring matching for the ISO
	// family since "ISO 27001" and "ISO/IEC 42001" share the prefix)
	requiredSections := []string{
		"Cross-Framework Coverage Report",
		"Framework Coverage",
		"AegisGate Control Coverage",
		"SOC 2",
		"27001", // ISO 27001 prefix
		"HIPAA",
		"PCI",
		"NIST CSF",
		"CIS",
		"OWASP",
		"FedRAMP",
		"FIPS 140",
		"MITRE ATLAS",
		"EU AI Act",
		"GDPR",
		"42001", // ISO 42001 prefix
		"NIST AI RMF",
	}
	for _, section := range requiredSections {
		if !strings.Contains(formatted, section) {
			t.Errorf("FormatReport() missing section: %q", section)
		}
	}
}

func TestCoverageReport_AegisGateControl_Breadth(t *testing.T) {
	// The RBAC+MFA control should map to many frameworks (the
	// breadth test ensures we don't have any single control that
	// only maps to 1-2 frameworks)
	report := GenerateCoverageReport()
	rbacCount := report.AegisGateCoverage["AG-AUTH-RBAC-MFA"]
	if rbacCount < 10 {
		t.Errorf("AG-AUTH-RBAC-MFA maps to %d framework controls, want at least 10 (control should have high cross-framework coverage)",
			rbacCount)
	}
}

func TestCoverageReport_FrameworkCount(t *testing.T) {
	// Each major framework should have at least 5 AegisGate-mapped controls
	report := GenerateCoverageReport()
	majorFrameworks := []string{"soc2", "hipaa", "pci", "nist_csf", "cis", "fedramp", "fips_140", "iso_42001", "eu_ai_act", "gdpr"}
	for _, fw := range majorFrameworks {
		count := report.FrameworkControlCount[fw]
		if count < 3 {
			t.Errorf("Framework %s only has %d AegisGate-mapped controls, want at least 3",
				fw, count)
		}
	}
}

// TestMapping_AllFrameworkKeysAreRegistered is a regression test for a
// bug uncovered by the v3.x close-out cross-framework matrix audit
// (2026-07-22). Three ISO 42001 control references in the AG-TRUST
// control used the typo key "iso42001" (no underscore) instead of the
// canonical "iso_42001" registered in FrameworkName. The result: 3
// framework mappings were silently dropped from every compliance
// report, the ISO 42001 coverage was underreported by 3, and an
// orphan framework with no human-readable name appeared in the
// coverage header.
//
// This test fails if any AegisGate control references a framework
// key that is not in FrameworkName. It catches the same class of
// typo in the future (e.g., a new AegisGate control that references
// "owaspllm" instead of "owasp_llm").
func TestMapping_AllFrameworkKeysAreRegistered(t *testing.T) {
	knownFrameworks := make(map[string]bool, len(FrameworkName))
	for fw := range FrameworkName {
		knownFrameworks[fw] = true
	}
	for agID, ctrl := range Mapping {
		for _, ext := range ctrl.ExternalControls {
			if !knownFrameworks[ext.Framework] {
				t.Errorf("AegisGate control %s references unregistered framework key %q (control ID %s, title %q). Add it to FrameworkName, or fix the typo.",
					agID, ext.Framework, ext.ControlID, ext.Title)
			}
		}
	}
}

// TestMapping_AGTrust_HasFullISO42001Coverage is the targeted
// regression test for the specific bug: AG-TRUST-AGENT-ATTESTATION
// should have at least 3 ISO 42001 control references (the 3 that
// were previously typo'd). This complements the generic
// TestMapping_AllFrameworkKeysAreRegistered by asserting a specific
// coverage floor.
func TestMapping_AGTrust_HasFullISO42001Coverage(t *testing.T) {
	ext, err := MapByControlID("AG-TRUST-AGENT-ATTESTATION")
	if err != nil {
		t.Fatalf("MapByControlID: %v", err)
	}
	iso42001Count := 0
	for _, e := range ext {
		if e.Framework == "iso_42001" {
			iso42001Count++
		}
	}
	if iso42001Count < 3 {
		t.Errorf("AG-TRUST-AGENT-ATTESTATION has %d ISO 42001 mappings, want at least 3 (the fix for the 2026-07-22 typo)",
			iso42001Count)
	}
}

// TestMapping_FedRAMPCoverage verifies that all 60 FedRAMP Path C controls
// are mapped in the cross-framework mapping table. This is the Day 4
// wiring deliverable: every FedRAMP control in the module must appear
// in at least one AegisGate control's ExternalControls list.
func TestMapping_FedRAMPCoverage(t *testing.T) {
	// All 60 FedRAMP Moderate controls from the Path C implementation
	// (pkg/compliance/fedramp/)
	allFedRAMPControls := []string{
		"FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-6", "FedRAMP-AC-14", "FedRAMP-AC-17", "FedRAMP-AC-24",
		"FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-6", "FedRAMP-AU-9", "FedRAMP-AU-10", "FedRAMP-AU-12", "FedRAMP-AU-16",
		"FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7", "FedRAMP-IA-8",
		"FedRAMP-SC-4", "FedRAMP-SC-7", "FedRAMP-SC-8", "FedRAMP-SC-12", "FedRAMP-SC-13", "FedRAMP-SC-23", "FedRAMP-SC-28",
		"FedRAMP-CM-2", "FedRAMP-CM-3", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-8",
		"FedRAMP-SI-2", "FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-7", "FedRAMP-SI-8", "FedRAMP-SI-10",
		"FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6", "FedRAMP-IR-7", "FedRAMP-IR-8",
		"FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-9", "FedRAMP-SA-11", "FedRAMP-SA-22",
		"FedRAMP-SR-3", "FedRAMP-SR-4", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12",
		"FedRAMP-RA-3", "FedRAMP-RA-5", "FedRAMP-RA-6", "FedRAMP-RA-7",
		"FedRAMP-CA-2", "FedRAMP-CA-7", "FedRAMP-CA-8", "FedRAMP-CA-9",
	}

	// Build a set of all FedRAMP controls in the mapping table
	mappedFedRAMP := make(map[string]bool)
	for _, ctrl := range Mapping {
		for _, ext := range ctrl.ExternalControls {
			if ext.Framework == "fedramp" {
				mappedFedRAMP[ext.ControlID] = true
			}
		}
	}

	// Every control in the module must be in the mapping
	unmapped := []string{}
	for _, c := range allFedRAMPControls {
		if !mappedFedRAMP[c] {
			unmapped = append(unmapped, c)
		}
	}
	if len(unmapped) > 0 {
		t.Errorf("The following %d FedRAMP controls are NOT in the cross-framework mapping: %v",
			len(unmapped), unmapped)
	}

	// The mapping must cover all 60 controls
	if len(mappedFedRAMP) < 60 {
		t.Errorf("Cross-framework mapping has %d FedRAMP controls, want at least 60", len(mappedFedRAMP))
	}
}

// TestMapping_FedRAMPEveryControlMappedToAegisGate verifies that each
// FedRAMP control in the mapping maps back to at least one AegisGate
// control via the reverse lookup (MapByFramework).
func TestMapping_FedRAMPEveryControlMappedToAegisGate(t *testing.T) {
	allFedRAMPControls := []string{
		"FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-6", "FedRAMP-AC-14", "FedRAMP-AC-17", "FedRAMP-AC-24",
		"FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-6", "FedRAMP-AU-9", "FedRAMP-AU-10", "FedRAMP-AU-12", "FedRAMP-AU-16",
		"FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7", "FedRAMP-IA-8",
		"FedRAMP-SC-4", "FedRAMP-SC-7", "FedRAMP-SC-8", "FedRAMP-SC-12", "FedRAMP-SC-13", "FedRAMP-SC-23", "FedRAMP-SC-28",
		"FedRAMP-CM-2", "FedRAMP-CM-3", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-8",
		"FedRAMP-SI-2", "FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-7", "FedRAMP-SI-8", "FedRAMP-SI-10",
		"FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6", "FedRAMP-IR-7", "FedRAMP-IR-8",
		"FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-9", "FedRAMP-SA-11", "FedRAMP-SA-22",
		"FedRAMP-SR-3", "FedRAMP-SR-4", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12",
		"FedRAMP-RA-3", "FedRAMP-RA-5", "FedRAMP-RA-6", "FedRAMP-RA-7",
		"FedRAMP-CA-2", "FedRAMP-CA-7", "FedRAMP-CA-8", "FedRAMP-CA-9",
	}

	unmapped := []string{}
	for _, fedrampID := range allFedRAMPControls {
		agControls := MapByFramework("fedramp", fedrampID)
		if len(agControls) == 0 {
			unmapped = append(unmapped, fedrampID)
		}
	}
	if len(unmapped) > 0 {
		t.Errorf("The following %d FedRAMP controls have NO AegisGate reverse mapping: %v",
			len(unmapped), unmapped)
	}
}

// TestMapping_NewAegisGateControlsExist verifies the 4 new AegisGate
// controls added for the Path C FedRAMP mapping are present.
func TestMapping_NewAegisGateControlsExist(t *testing.T) {
	newControls := []string{
		"AG-CM-BASELINE-CONFIG",
		"AG-CA-CONTINUOUS-MONITORING",
		"AG-IR-INCIDENT-RESPONSE",
		"AG-SC-BOUNDARY-PROTECTION",
	}
	for _, id := range newControls {
		ctrl, exists := Mapping[id]
		if !exists {
			t.Errorf("AegisGate control %s not found in Mapping", id)
			continue
		}
		if len(ctrl.ExternalControls) < 5 {
			t.Errorf("AegisGate control %s has only %d external controls, want at least 5",
				id, len(ctrl.ExternalControls))
		}
		// Each new control must map to at least 1 FedRAMP control
		hasFedRAMP := false
		for _, ext := range ctrl.ExternalControls {
			if ext.Framework == "fedramp" {
				hasFedRAMP = true
				break
			}
		}
		if !hasFedRAMP {
			t.Errorf("AegisGate control %s has no FedRAMP mappings", id)
		}
	}
}
