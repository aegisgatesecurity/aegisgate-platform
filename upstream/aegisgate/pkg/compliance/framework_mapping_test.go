// SPDX-License-Identifier: Apache-2.0
//

package compliance

import (
	"testing"
)

func TestNewFrameworkMapping(t *testing.T) {
	mapping := NewFrameworkMapping()
	if mapping == nil {
		t.Fatal("NewFrameworkMapping() returned nil")
	}

	if mapping.Name == "" {
		t.Error("Mapping.Name should not be empty")
	}

	if mapping.Description == "" {
		t.Error("Mapping.Description should not be empty")
	}

	if mapping.ControlToTechnique == nil {
		t.Error("Mapping.ControlToTechnique should be initialized")
	}

	if mapping.TechniqueToControl == nil {
		t.Error("Mapping.TechniqueToControl should be initialized")
	}
}

func TestFrameworkMapping_AddMapping(t *testing.T) {
	mapping := NewFrameworkMapping()

	initialCount := len(mapping.ControlToTechnique)

	// Add a new mapping
	mapping.AddMapping("TEST1", []string{"T0001", "T0002"}, "supports", 0.9, "Test mapping")

	if len(mapping.ControlToTechnique) <= initialCount {
		t.Error("AddMapping() should add entry to ControlToTechnique")
	}

	// Verify bidirectional mapping
	if !containsTechnique(mapping.ControlToTechnique["TEST1"], "T0001") {
		t.Error("ControlToTechnique should contain T0001")
	}

	if !containsTechnique(mapping.TechniqueToControl["T0001"], "TEST1") {
		t.Error("TechniqueToControl should contain TEST1")
	}
}

func containsTechnique(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestFrameworkMapping_GetTechniquesForControl(t *testing.T) {
	mapping := NewFrameworkMapping()

	// Test existing control
	techniques := mapping.GetTechniquesForControl("GV1")
	if len(techniques) == 0 {
		t.Error("GetTechniquesForControl(GV1) should return techniques")
	}

	// Test non-existent control - may return nil or empty slice
	techniques = mapping.GetTechniquesForControl("NONEXISTENT")
	// Both nil and empty slice are acceptable
	t.Logf("GetTechniquesForControl(NONEXISTENT) returned %d techniques", len(techniques))
}

func TestFrameworkMapping_GetControlsForTechnique(t *testing.T) {
	mapping := NewFrameworkMapping()

	// Test existing technique
	controls := mapping.GetControlsForTechnique("T1535")
	if len(controls) == 0 {
		t.Error("GetControlsForTechnique(T1535) should return controls")
	}

	// Test non-existent technique - may return nil or empty slice
	controls = mapping.GetControlsForTechnique("T9999")
	// Both nil and empty slice are acceptable
	t.Logf("GetControlsForTechnique(T9999) returned %d controls", len(controls))
}

func TestFrameworkMapping_BidirectionalMapping(t *testing.T) {
	mapping := NewFrameworkMapping()

	// Test that mappings are bidirectional
	for control, techniques := range mapping.ControlToTechnique {
		for _, technique := range techniques {
			controls := mapping.TechniqueToControl[technique]
			if !containsTechnique(controls, control) {
				t.Errorf("TechniqueToControl[%s] should contain %s", technique, control)
			}
		}
	}
}

func TestFrameworkMapping_GetControlsForTechnique_MultipleControls(t *testing.T) {
	mapping := NewFrameworkMapping()

	// T1535 should map to multiple controls
	controls := mapping.GetControlsForTechnique("T1535")

	if len(controls) < 2 {
		t.Errorf("T1535 should map to multiple controls, got %d", len(controls))
	}
}

func TestFrameworkMapping_GetMappingsForControl(t *testing.T) {
	mapping := NewFrameworkMapping()

	// Get mappings for GV1
	mappings := mapping.GetMappingsForControl("GV1")
	if mappings == nil {
		t.Error("GetMappingsForControl() should not return nil")
	}
}

func TestFrameworkMapping_MappingRelationship(t *testing.T) {
	rel := MappingRelationship{
		SourceFramework: "NIST-AI-RMF",
		SourceControl:   "GV1",
		TargetFramework: "MITRE-ATLAS",
		TargetControls:  []string{"T1535", "T1484"},
		Relationship:    "supports",
		Confidence:      0.9,
		Description:     "Test mapping",
	}

	if rel.SourceFramework != "NIST-AI-RMF" {
		t.Errorf("MappingRelationship.SourceFramework = %s, want NIST-AI-RMF", rel.SourceFramework)
	}

	if len(rel.TargetControls) != 2 {
		t.Errorf("MappingRelationship.TargetControls length = %d, want 2", len(rel.TargetControls))
	}
}

func TestConsolidatedFinding(t *testing.T) {
	finding := ConsolidatedFinding{
		ID:          "Finding-001",
		Title:       "Test Finding",
		Description: "Test description",
		Severity:    "high",
		Frameworks:  []string{"NIST", "SOC2"},
		Controls:    []string{"GV1", "CC6.1"},
		Techniques:  []string{"T1535", "T1484"},
		Remediation: "Apply patch",
		RiskScore:   7.5,
	}

	if finding.ID != "Finding-001" {
		t.Errorf("Finding.ID = %s, want Finding-001", finding.ID)
	}

	if finding.Severity != "high" {
		t.Errorf("Finding.Severity = %s, want high", finding.Severity)
	}

	if len(finding.Frameworks) != 2 {
		t.Errorf("Finding.Frameworks length = %d, want 2", len(finding.Frameworks))
	}
}

func TestUnifiedComplianceReport(t *testing.T) {
	report := UnifiedComplianceReport{
		Frameworks:       []string{"NIST", "SOC2", "HIPAA"},
		TotalFindings:    10,
		CriticalFindings: 2,
		HighFindings:     3,
		MediumFindings:   3,
		LowFindings:      2,
		ComplianceScore:  85.5,
	}

	if len(report.Frameworks) != 3 {
		t.Errorf("Report.Frameworks length = %d, want 3", len(report.Frameworks))
	}

	if report.TotalFindings != 10 {
		t.Errorf("Report.TotalFindings = %d, want 10", report.TotalFindings)
	}
}

func TestComplianceGap(t *testing.T) {
	gap := ComplianceGap{
		ID:              "GAP-001",
		Title:           "Missing Control",
		Description:     "Security control not implemented",
		MissingControls: []string{"GV1", "MP1"},
		RiskLevel:       "high",
		Recommendations: []string{"Implement GV1", "Implement MP1"},
	}

	if gap.ID != "GAP-001" {
		t.Errorf("Gap.ID = %s, want GAP-001", gap.ID)
	}

	if len(gap.MissingControls) != 2 {
		t.Errorf("Gap.MissingControls length = %d, want 2", len(gap.MissingControls))
	}
}

// Signed-off-by: jcolvin <josh@aegisgatesecurity.io>
