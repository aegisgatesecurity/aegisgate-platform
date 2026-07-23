// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - NIST AI RMF 1.0 Coverage Gap Tests
// =========================================================================
// Targets 13 check functions at 0% coverage to push from 32.9% → 80%+.
// Each check function tests: compliant, partial, non_compliant paths.
// =========================================================================

package nist_ai_rmf

import (
	"context"
	"testing"
)

// compliantConfig contains keywords for all 15 automated checks.
var compliantConfig = `{
	"ai_policy": true,
	"ai_governance": true,
	"risk_management_policy": true,
	"responsible_ai": true,
	"compliance_scan": true,
	"/api/v1/compliance": true,
	"accountability": true,
	"role": true,
	"responsibility": true,
	"attestation": true,
	"trust": true,
	"risk_tolerance": true,
	"risk_assessment": true,
	"risk_register": true,
	"risk_profile": true,
	"roles": true,
	"responsibilities": true,
	"rbac": true,
	"communication": true,
	"audit_log": true,
	"reporting": true,
	"asset_inventory": true,
	"model_registry": true,
	"model_inventory": true,
	"risk_governance": true,
	"enterprise_risk": true,
	"risk_management_framework": true,
	"use_case": true,
	"deployment": true,
	"context": true,
	"model_id": true,
	"threat_model": true,
	"risk_category": true,
	"risk_level": true,
	"severity": true,
	"metrics": true,
	"performance_metric": true,
	"kpi": true,
	"monitoring_enabled": true,
	"continuous_monitor": true,
	"anomaly_detect": true,
	"drift_detect": true,
	"security": true,
	"scanner": true,
	"threat_detection": true,
	"fairness": true,
	"bias": true,
	"privacy": true,
	"pii_scanner": true,
	"data_protection": true,
	"transparency": true,
	"explainability": true,
	"drift": true,
	"degradation": true,
	"mitigation": true,
	"risk_treatment": true,
	"rationale": true,
	"risk_acceptance": true,
	"incident_response": true,
	"ir_plan": true,
	"kill_switch": true,
	"abort": true,
	"feedback": true,
	"continuous_improvement": true,
	"lessons_learned": true,
	"audit_trail": true,
	"logging": true
}`

func TestNISTAIRMF_GV12(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (accountability + attestation)", input: `{"accountability": true, "attestation": true}`, wantStatus: "compliant"},
		{name: "compliant (role + trust)", input: `{"role": true, "trust": true}`, wantStatus: "compliant"},
		{name: "partial (accountability only)", input: `{"accountability": true, "role": true}`, wantStatus: "partial"},
		// Note: checkGV12 requires hasAccountability for partial; attestation alone → non_compliant
		{name: "non_compliant (attestation only)", input: `{"attestation": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkGV12(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkGV12: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("checkGV12(%q) status = %q; want %q, msg=%s", tt.name, result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_GV21(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (risk_tolerance)", input: `{"risk_tolerance": true}`, wantStatus: "compliant"},
		{name: "compliant (risk_assessment)", input: `{"risk_assessment": true}`, wantStatus: "compliant"},
		{name: "compliant (risk_register)", input: `{"risk_register": true}`, wantStatus: "compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkGV21(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkGV21: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_GV22(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (roles + communication)", input: `{"roles": true, "communication": true}`, wantStatus: "compliant"},
		{name: "compliant (rbac + audit_log)", input: `{"rbac": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "partial (roles only)", input: `{"roles": true, "responsibilities": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkGV22(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkGV22: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_GV31(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (inventory + risk_profile)", input: `{"asset_inventory": true, "risk_profile": true}`, wantStatus: "compliant"},
		{name: "compliant (model_registry + risk_assessment)", input: `{"model_registry": true, "risk_assessment": true}`, wantStatus: "compliant"},
		{name: "partial (inventory only)", input: `{"asset_inventory": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkGV31(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkGV31: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_GV41(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (ai_policy + enterprise_risk)", input: `{"ai_policy": true, "enterprise_risk": true}`, wantStatus: "compliant"},
		{name: "compliant (risk_governance + risk_management_framework)", input: `{"risk_governance": true, "risk_management_framework": true}`, wantStatus: "compliant"},
		{name: "partial (ai_governance only)", input: `{"ai_governance": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkGV41(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkGV41: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MP11(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (use_case + model_registry)", input: `{"use_case": true, "model_registry": true}`, wantStatus: "compliant"},
		{name: "compliant (deployment + model_id)", input: `{"deployment": true, "model_id": "abc"}`, wantStatus: "compliant"},
		{name: "partial (model_registry only)", input: `{"model_registry": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMP11(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMP11: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MP31(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (risk_assessment + risk_category)", input: `{"risk_assessment": true, "risk_category": true}`, wantStatus: "compliant"},
		{name: "compliant (threat_model + severity)", input: `{"threat_model": true, "severity": true}`, wantStatus: "compliant"},
		{name: "partial (risk_register only)", input: `{"risk_register": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMP31(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMP31: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MS11(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (metrics + compliance_scan)", input: `{"metrics": true, "compliance_scan": true}`, wantStatus: "compliant"},
		{name: "compliant (kpi + monitoring_enabled)", input: `{"kpi": true, "monitoring_enabled": true}`, wantStatus: "compliant"},
		{name: "partial (metrics only)", input: `{"metrics": true, "kpi": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMS11(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMS11: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MS21(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (3+ trustworthiness)", input: `{"security": true, "fairness": true, "privacy": true, "transparency": true}`, wantStatus: "compliant"},
		{name: "compliant (scanner + bias + pii_scanner + explainability)", input: `{"scanner": true, "bias": true, "pii_scanner": true, "explainability": true}`, wantStatus: "compliant"},
		{name: "partial (1 trustworthiness)", input: `{"security": true}`, wantStatus: "partial"},
		{name: "partial (2 trustworthiness)", input: `{"security": true, "fairness": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMS21(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMS21: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MS22_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (monitoring + drift)", input: `{"monitoring_enabled": true, "drift": true}`, wantStatus: "compliant"},
		{name: "compliant (continuous_monitor + degradation)", input: `{"continuous_monitor": true, "degradation": true}`, wantStatus: "compliant"},
		{name: "partial (monitoring only)", input: `{"monitoring_enabled": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMS22(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMS22: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MG11(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (mitigation + rationale)", input: `{"mitigation": true, "rationale": true}`, wantStatus: "compliant"},
		{name: "compliant (risk_treatment + risk_acceptance)", input: `{"risk_treatment": true, "risk_acceptance": true}`, wantStatus: "compliant"},
		{name: "partial (mitigation only)", input: `{"mitigation": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMG11(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMG11: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MG12_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (ir_plan + kill_switch)", input: `{"incident_response": true, "kill_switch": true}`, wantStatus: "compliant"},
		{name: "partial (ir_plan only)", input: `{"ir_plan": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMG12(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMG12: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MG22(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (transparency + audit_log)", input: `{"transparency": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant (explainability + logging)", input: `{"explainability": true, "logging": true}`, wantStatus: "compliant"},
		{name: "partial (audit_trail only)", input: `{"audit_trail": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMG22(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMG22: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNISTAIRMF_MG31(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (feedback + continuous_monitor)", input: `{"feedback": true, "continuous_monitor": true}`, wantStatus: "compliant"},
		{name: "compliant (lessons_learned + monitoring_enabled)", input: `{"lessons_learned": true, "monitoring_enabled": true}`, wantStatus: "compliant"},
		{name: "partial (monitoring only)", input: `{"monitoring_enabled": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMG31(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMG31: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// =====================================================================
// Full compliant config test — verify all 15 automated checks pass
// =====================================================================

func TestNISTAIRMF_AllAutomatedChecks_Compliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	controls := m.Controls()
	automatedCount := 0
	for _, c := range controls {
		if c.Automated && c.CheckFunc != nil {
			automatedCount++
			result, err := c.CheckFunc(ctx, []byte(compliantConfig))
			if err != nil {
				t.Errorf("Control %s CheckFunc error: %v", c.ID, err)
				continue
			}
			if string(result.Status) != "compliant" {
				t.Errorf("Control %s: status=%s, expected compliant, msg=%s", c.ID, result.Status, result.Message)
			}
		}
	}
	t.Logf("Verified %d automated controls all return compliant", automatedCount)
}

func TestNISTAIRMF_Dependencies_Coverage(t *testing.T) {
	m := NewNISTAIRMFModule()
	deps := m.Dependencies()
	if len(deps) == 0 {
		t.Error("Dependencies() returned empty list")
	}
}