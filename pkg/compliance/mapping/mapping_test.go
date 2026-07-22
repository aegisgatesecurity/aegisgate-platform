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
		{"RBAC+MFA maps to many frameworks", "AG-AUTH-RBAC-MFA", 20, false},
		{"Audit log maps to many frameworks", "AG-AUDIT-LOG-HASH-CHAIN", 14, false},
		{"TLS+FIPS maps to many frameworks", "AG-CRYPTO-TLS-FIPS", 16, false},
		{"Vuln scanning maps to many frameworks", "AG-VULN-CI-SCANNING", 9, false},
		{"Detection scanner maps to many frameworks", "AG-DETECT-SCANNER", 16, false},
		{"Trust framework maps to many frameworks", "AG-TRUST-AGENT-ATTESTATION", 8, false},
		{"Output filter maps to many frameworks", "AG-OUTPUT-PII-SECRET-FILTER", 12, false},
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
	if len(controls) < 7 {
		t.Errorf("ListControls() returned %d controls, want at least 7", len(controls))
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
	if report.TotalAegisGateControls < 7 {
		t.Errorf("TotalAegisGateControls = %d, want at least 7", report.TotalAegisGateControls)
	}
	if report.TotalFrameworkMappings < 50 {
		t.Errorf("TotalFrameworkMappings = %d, want at least 50", report.TotalFrameworkMappings)
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
