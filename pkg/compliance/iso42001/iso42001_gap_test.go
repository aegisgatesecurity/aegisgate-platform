// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ISO 42001 Coverage Gap Tests
// =========================================================================
// Tests for the 14 check functions at 0% coverage.
// =========================================================================

package iso42001

import (
	"context"
	"testing"
)

// Regex-pattern functions: matched >= 2 = compliant, 1 = partial, 0 = non-compliant

func TestCheckAIMSProcesses_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIMSProcesses(context.Background(), []byte(`aims process_definition ai_management_system`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-4.4" {
		t.Errorf("ControlID = %q, want ISO42001-4.4", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckAIMSProcesses_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIMSProcesses(context.Background(), []byte(`aims`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIMSProcesses_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIMSProcesses(context.Background(), []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIGovernance_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIGovernance(context.Background(), []byte(`ai_governance ai_committee`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-5.P1" {
		t.Errorf("ControlID = %q, want ISO42001-5.P1", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIGovernance_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIGovernance(context.Background(), []byte(`ai_board`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIGovernance_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIGovernance(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIImpactAssess_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIImpactAssess(context.Background(), []byte(`impact_assessment ai_impact`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-6.3" {
		t.Errorf("ControlID = %q, want ISO42001-6.3", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIImpactAssess_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIImpactAssess(context.Background(), []byte(`societal_impact`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIImpactAssess_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIImpactAssess(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIAwareness_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIAwareness(context.Background(), []byte(`ai_awareness training`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-7.3" {
		t.Errorf("ControlID = %q, want ISO42001-7.3", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIAwareness_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIAwareness(context.Background(), []byte(`ai_literacy`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIAwareness_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIAwareness(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIVerification_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIVerification(context.Background(), []byte(`ai_verification model_validation`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-8.4" {
		t.Errorf("ControlID = %q, want ISO42001-8.4", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIVerification_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIVerification(context.Background(), []byte(`ai_testing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIVerification_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIVerification(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIPerformanceMetrics_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIPerformanceMetrics(context.Background(), []byte(`ai_metrics performance_metrics`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-9.P1" {
		t.Errorf("ControlID = %q, want ISO42001-9.P1", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIPerformanceMetrics_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIPerformanceMetrics(context.Background(), []byte(`model_performance`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIPerformanceMetrics_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIPerformanceMetrics(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIModelSecurity_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIModelSecurity(context.Background(), []byte(`model_security adversarial`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-AI-01" {
		t.Errorf("ControlID = %q, want ISO42001-AI-01", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIModelSecurity_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIModelSecurity(context.Background(), []byte(`model_protection`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIModelSecurity_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIModelSecurity(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckDataProvenance_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkDataProvenance(context.Background(), []byte(`data_provenance data_lineage`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-AI-02" {
		t.Errorf("ControlID = %q, want ISO42001-AI-02", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckDataProvenance_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkDataProvenance(context.Background(), []byte(`data_tracking`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckDataProvenance_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkDataProvenance(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// String-Contains functions: both keywords = compliant, else = non-compliant

func TestCheckAIRequirements_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIRequirements(context.Background(), []byte(`ai_requirements system_design safety`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-8.2" {
		t.Errorf("ControlID = %q, want ISO42001-8.2", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckAIRequirements_Partial(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIRequirements(context.Background(), []byte(`fairness`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAIRequirements_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIRequirements(context.Background(), []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIOperationMonitoring_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIOperationMonitoring(context.Background(), []byte(`ai_operation operational_metrics`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-8.5" {
		t.Errorf("ControlID = %q, want ISO42001-8.5", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIOperationMonitoring_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIOperationMonitoring(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIIncidentManagement_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIIncidentManagement(context.Background(), []byte(`ai_incident incident_procedure`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-8.6" {
		t.Errorf("ControlID = %q, want ISO42001-8.6", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIIncidentManagement_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIIncidentManagement(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIDataManagement_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIDataManagement(context.Background(), []byte(`data_management data_quality`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-8.7" {
		t.Errorf("ControlID = %q, want ISO42001-8.7", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIDataManagement_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIDataManagement(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckBiasFairnessEvaluation_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkBiasFairnessEvaluation(context.Background(), []byte(`bias_detection bias_metrics`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-9.P2" {
		t.Errorf("ControlID = %q, want ISO42001-9.P2", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckBiasFairnessEvaluation_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkBiasFairnessEvaluation(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

func TestCheckAIModelDocumentation_Compliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIModelDocumentation(context.Background(), []byte(`model_documentation model_card`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "ISO42001-AI-03" {
		t.Errorf("ControlID = %q, want ISO42001-AI-03", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAIModelDocumentation_NonCompliant(t *testing.T) {
	m := NewISO42001Module()
	r, err := m.checkAIModelDocumentation(context.Background(), []byte(`nothing`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}
