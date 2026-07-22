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
