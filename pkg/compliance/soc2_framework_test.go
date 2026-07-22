// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"testing"
)

// =============================================================================
// SOC2Framework — New, initTrustCriteria, initControls
// =============================================================================

func TestNewSOC2Framework(t *testing.T) {
	fw := NewSOC2Framework()
	if fw == nil {
		t.Fatal("expected non-nil framework")
	}
	if fw.Name != "SOC 2 Type II" {
		t.Errorf("expected name 'SOC 2 Type II', got '%s'", fw.Name)
	}
	if fw.ControlMap == nil {
		t.Error("expected non-nil ControlMap")
	}
	if len(fw.TrustCriteria) != 5 {
		t.Errorf("expected 5 trust criteria, got %d", len(fw.TrustCriteria))
	}
	if len(fw.Controls) != 9 {
		t.Errorf("expected 9 controls, got %d", len(fw.Controls))
	}
	if len(fw.AIControls) != 8 {
		t.Errorf("expected 8 AI controls, got %d", len(fw.AIControls))
	}
}

func TestInitTrustCriteria(t *testing.T) {
	fw := NewSOC2Framework()

	criteriaIDs := make(map[string]bool)
	for _, tc := range fw.TrustCriteria {
		criteriaIDs[tc.ID] = true
	}

	expected := []string{"CC", "A", "PI", "C", "P"}
	for _, id := range expected {
		if !criteriaIDs[id] {
			t.Errorf("expected criteria %q not found", id)
		}
	}

	// CC should have 9 controls
	for _, tc := range fw.TrustCriteria {
		if tc.ID == "CC" {
			if len(tc.Controls) != 9 {
				t.Errorf("CC expected 9 controls, got %d", len(tc.Controls))
			}
		}
	}
}

func TestInitControls(t *testing.T) {
	fw := NewSOC2Framework()

	expectedIDs := []string{"CC1.1", "CC3.2", "CC5.4", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "PI1.2"}
	for _, id := range expectedIDs {
		if _, exists := fw.ControlMap[id]; !exists {
			t.Errorf("expected control %q in ControlMap", id)
		}
	}

	// AI controls list should match
	for _, id := range fw.AIControls {
		if _, exists := fw.ControlMap[id]; !exists {
			t.Errorf("AI control %q not in ControlMap", id)
		}
	}
}

// =============================================================================
// SOC2Framework — GetControl, GetControlsByCriteria, GetAIControls
// =============================================================================

func TestGetControl_Found(t *testing.T) {
	fw := NewSOC2Framework()
	ctrl, err := fw.GetControl("CC3.2")
	if err != nil {
		t.Fatalf("expected control CC3.2, got error: %v", err)
	}
	if ctrl.ID != "CC3.2" {
		t.Errorf("expected ID CC3.2, got %s", ctrl.ID)
	}
	if ctrl.Name != "AI-Specific Risk Assessment" {
		t.Errorf("unexpected name: %s", ctrl.Name)
	}
}

func TestGetControl_NotFound(t *testing.T) {
	fw := NewSOC2Framework()
	_, err := fw.GetControl("XX99.9")
	if err == nil {
		t.Fatal("expected error for non-existent control")
	}
	expected := "control XX99.9 not found"
	if err.Error() != expected {
		t.Errorf("expected %q, got %v", expected, err)
	}
}

func TestGetControlsByCriteria(t *testing.T) {
	fw := NewSOC2Framework()

	// PI1 has Criteria "PI1", so GetControlsByCriteria("PI1") matches
	pi := fw.GetControlsByCriteria("PI1")
	if len(pi) != 1 {
		t.Errorf("PI1 criteria expected 1 control, got %d", len(pi))
	}
	if len(pi) > 0 && pi[0].ID != "PI1.2" {
		t.Errorf("expected control PI1.2, got %s", pi[0].ID)
	}

	// CC6 has Criteria "CC6"
	cc6 := fw.GetControlsByCriteria("CC6")
	if len(cc6) != 5 {
		t.Errorf("CC6 criteria expected 5 controls, got %d", len(cc6))
	}

	// No controls have Criteria "CC" (they use CC3, CC5, CC6)
	cc := fw.GetControlsByCriteria("CC")
	if len(cc) != 0 {
		t.Errorf("CC criteria expected 0 controls, got %d", len(cc))
	}

	// Unknown criteria
	none := fw.GetControlsByCriteria("XX")
	if len(none) != 0 {
		t.Errorf("unknown criteria expected 0 controls, got %d", len(none))
	}
}

func TestGetAIControls(t *testing.T) {
	fw := NewSOC2Framework()
	controls := fw.GetAIControls()
	if len(controls) != 8 {
		t.Errorf("expected 8 AI controls, got %d", len(controls))
	}
	for _, ctrl := range controls {
		found := false
		for _, id := range fw.AIControls {
			if id == ctrl.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("control %s not in AIControls list", ctrl.ID)
		}
	}
}

// =============================================================================
// SOC2Assessment — New, AddControlFinding, calculateScore, GenerateReport
// =============================================================================

func TestNewSOC2Assessment(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Alice Auditor", []string{"auth-service", "ml-pipeline"})
	if assessment == nil {
		t.Fatal("expected non-nil assessment")
	}
	if assessment.Framework != fw {
		t.Error("Framework not set correctly")
	}
	if assessment.Auditor != "Alice Auditor" {
		t.Errorf("expected auditor 'Alice Auditor', got '%s'", assessment.Auditor)
	}
	if len(assessment.Scope) != 2 {
		t.Errorf("expected scope len 2, got %d", len(assessment.Scope))
	}
	if len(assessment.ControlFindings) != 0 {
		t.Errorf("expected 0 control findings, got %d", len(assessment.ControlFindings))
	}
	if assessment.OverallRating != "In Progress" {
		t.Errorf("expected initial rating 'In Progress', got '%s'", assessment.OverallRating)
	}
}

func TestAddControlFinding_Pass(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Bob", nil)

	assessment.AddControlFinding(SOC2ControlFinding{
		ControlID:   "CC3.2",
		ControlName: "AI Risk Assessment",
		Status:      "Pass",
		Severity:    "Low",
		Description: "All requirements met",
	})

	if assessment.ComplianceScore != 100.0 {
		t.Errorf("expected score 100, got %.2f", assessment.ComplianceScore)
	}
	if assessment.OverallRating != "Effective" {
		t.Errorf("expected rating 'Effective', got '%s'", assessment.OverallRating)
	}
}

func TestAddControlFinding_Mixed(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Carol", nil)

	// 3 Pass, 1 Fail → 75% → "Needs Improvement"
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC3.2", Status: "Pass", Severity: "Low"})
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC5.4", Status: "Pass", Severity: "Low"})
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC6.2", Status: "Pass", Severity: "Low"})
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC6.3", Status: "Fail", Severity: "High"})

	if assessment.ComplianceScore != 75.0 {
		t.Errorf("expected score 75.0, got %.2f", assessment.ComplianceScore)
	}
	if assessment.OverallRating != "Needs Improvement" {
		t.Errorf("expected 'Needs Improvement', got '%s'", assessment.OverallRating)
	}
}

func TestAddControlFinding_AllFail(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Dave", nil)

	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC3.2", Status: "Fail", Severity: "Critical"})
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC5.4", Status: "Fail", Severity: "Critical"})

	if assessment.ComplianceScore != 0 {
		t.Errorf("expected score 0, got %.2f", assessment.ComplianceScore)
	}
	if assessment.OverallRating != "Ineffective" {
		t.Errorf("expected 'Ineffective', got '%s'", assessment.OverallRating)
	}
}

func TestAddControlFinding_EmptyFindings(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Eve", nil)

	// calculateScore called on empty list
	if assessment.ComplianceScore != 0 {
		t.Errorf("expected 0 on empty findings, got %.2f", assessment.ComplianceScore)
	}
}

func TestCalculateScore_EffectiveThreshold(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Frank", nil)

	// Exactly 9 Pass out of 10 → 90% → Effective
	for i := 0; i < 9; i++ {
		assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC3.2", Status: "Pass", Severity: "Low"})
	}
	assessment.AddControlFinding(SOC2ControlFinding{ControlID: "CC5.4", Status: "Fail", Severity: "Medium"})

	if assessment.ComplianceScore != 90.0 {
		t.Errorf("expected score 90, got %.2f", assessment.ComplianceScore)
	}
	if assessment.OverallRating != "Effective" {
		t.Errorf("expected 'Effective' at 90%%, got '%s'", assessment.OverallRating)
	}
}

func TestGenerateReport(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Grace", []string{"service-a"})
	assessment.AddControlFinding(SOC2ControlFinding{
		ControlID:   "CC6.4",
		ControlName: "Adversarial Defense",
		Status:      "Pass",
		Severity:    "Low",
		Description: "Model hardening in place",
		Remediation: "Continue monitoring",
	})

	report := assessment.GenerateReport()
	if report == "" {
		t.Fatal("expected non-empty report")
	}
	if !contains(report, "SOC 2 Compliance Assessment Report") {
		t.Error("report missing header")
	}
	if !contains(report, "Grace") {
		t.Error("report missing auditor")
	}
	if !contains(report, "Effective") {
		t.Error("report missing overall rating")
	}
	if !contains(report, "CC6.4") {
		t.Error("report missing control ID")
	}
	if !contains(report, "Pass") {
		t.Error("report missing status")
	}
	if !contains(report, "Continue monitoring") {
		t.Error("report missing remediation")
	}
}

func TestGenerateReport_EmptyFindings(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Henry", nil)
	report := assessment.GenerateReport()
	if !contains(report, "Control Findings:") {
		t.Error("empty findings report missing header")
	}
}

func TestGenerateReport_NoRemediation(t *testing.T) {
	fw := NewSOC2Framework()
	assessment := fw.NewSOC2Assessment("Irene", nil)
	assessment.AddControlFinding(SOC2ControlFinding{
		ControlID:   "CC3.2",
		ControlName: "Test",
		Status:      "Pass",
		Severity:    "Low",
		Description: "No remediation needed",
		Remediation: "", // empty
	})
	report := assessment.GenerateReport()
	// Should not crash and should handle empty remediation gracefully
	if report == "" {
		t.Fatal("expected non-empty report")
	}
}

// =============================================================================
// Helper
// =============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
