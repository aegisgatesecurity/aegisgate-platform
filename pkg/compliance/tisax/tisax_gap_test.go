// SPDX-License-Identifier: Apache-2.0
// TISAX AL2 — Coverage Gap Tests (Phase 2)
//
// Targets functions at <100% coverage to push package coverage above 90%.
// Uses same-package access (no compliance import to avoid cycle).

package tisax

import (
	"context"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkNetworkMonitoring (73.3%)
// ---------------------------------------------------------------------------

func TestCheckNetworkMonitoringGap_Compliant_All(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkNetworkMonitoring(ctx, []byte(`ids traffic_analysis alerting siem`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items, got %d", len(r.Evidence))
	}
}

func TestCheckNetworkMonitoringGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkNetworkMonitoring(ctx, []byte(`nothing relevant here`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckNetworkMonitoringGap_PartialIDS(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkNetworkMonitoring(ctx, []byte(`ids traffic_analysis`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// IDS + traffic => compliant even without alerting
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) != 2 {
		t.Errorf("expected 2 evidence items without alerting, got %d", len(r.Evidence))
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkEndpointSecurity (64.7%)
// ---------------------------------------------------------------------------

func TestCheckEndpointSecurityGap_Compliant_Mgmt(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointSecurity(ctx, []byte(`edr mdm device_management`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckEndpointSecurityGap_Compliant_Compliance(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointSecurity(ctx, []byte(`edr device_compliance posture`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckEndpointSecurityGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointSecurity(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckEndpointSecurityGap_NonCompliant_NoComplianceNoMgmt(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointSecurity(ctx, []byte(`edr_only`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkCloudSecurity (64.7%)
// ---------------------------------------------------------------------------

func TestCheckCloudSecurityGap_Compliant_Encryption(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCloudSecurity(ctx, []byte(`cspm encryption at rest aes_256`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckCloudSecurityGap_Compliant_Workload(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCloudSecurity(ctx, []byte(`cspm cwpp workload_protection`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckCloudSecurityGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCloudSecurity(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckCloudSecurityGap_NonCompliant_NoWorkloadNoEncryption(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCloudSecurity(ctx, []byte(`cspm_only`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkDLP (73.3%)
// ---------------------------------------------------------------------------

func TestCheckDLPGap_Compliant_WithBlocking(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDLP(ctx, []byte(`dlp dlp_policy blocking quarantine`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with blocking, got %d", len(r.Evidence))
	}
}

func TestCheckDLPGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDLP(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckDLPGap_NonCompliant_NoPolicy(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDLP(ctx, []byte(`data_loss_prevention`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkSecureConfig (64.7%)
// ---------------------------------------------------------------------------

func TestCheckSecureConfigGap_Compliant_Scanning(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureConfig(ctx, []byte(`baseline cis_benchmark config_scan`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecureConfigGap_Compliant_Drift(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureConfig(ctx, []byte(`hardening drift_detection`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecureConfigGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureConfig(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckSecureConfigGap_NonCompliant_NoDriftNoScan(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureConfig(ctx, []byte(`config_baseline`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkPatchMgmt (58.8%)
// ---------------------------------------------------------------------------

func TestCheckPatchMgmtGap_Compliant_SLA(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPatchMgmt(ctx, []byte(`patch_management patch_sla`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPatchMgmtGap_Compliant_Automated(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPatchMgmt(ctx, []byte(`patching auto_patch scheduled`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPatchMgmtGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPatchMgmt(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckPatchMgmtGap_NonCompliant_NoSLANoAuto(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPatchMgmt(ctx, []byte(`patch_management`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkDataSubjectRights (58.8%)
// ---------------------------------------------------------------------------

func TestCheckDataSubjectRightsGap_Compliant_Access(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataSubjectRights(ctx, []byte(`data_subject_rights access_request`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckDataSubjectRightsGap_Compliant_Erasure(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataSubjectRights(ctx, []byte(`dsr erasure right_to_be_forgotten`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckDataSubjectRightsGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataSubjectRights(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckDataSubjectRightsGap_NonCompliant_NoAccessNoErasure(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataSubjectRights(ctx, []byte(`subject_rights`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkThreatModeling (58.8%)
// ---------------------------------------------------------------------------

func TestCheckThreatModelingGap_Compliant_Methodology(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkThreatModeling(ctx, []byte(`threat_model stride methodology`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckThreatModelingGap_Compliant_Mitigation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkThreatModeling(ctx, []byte(`threat_modeling mitigation countermeasure`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckThreatModelingGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkThreatModeling(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckThreatModelingGap_NonCompliant_NoMethodNoMitigation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkThreatModeling(ctx, []byte(`threat_model`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkPenTest (64.7%)
// ---------------------------------------------------------------------------

func TestCheckPenTestGap_Compliant_Schedule(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPenTest(ctx, []byte(`penetration_test scheduled annual`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPenTestGap_Compliant_Remediation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPenTest(ctx, []byte(`pentest remediation findings`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPenTestGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPenTest(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckPenTestGap_NonCompliant_NoScheduleNoRemediation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPenTest(ctx, []byte(`pen_test`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — checkSecureCICD (73.3%)
// ---------------------------------------------------------------------------

func TestCheckSecureCICDGap_Compliant_WithAutomation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureCICD(ctx, []byte(`ci_cd security_gate sast automated_scan`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with automation, got %d", len(r.Evidence))
	}
}

func TestCheckSecureCICDGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureCICD(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckSecureCICDGap_NonCompliant_NoSecurityGate(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureCICD(ctx, []byte(`pipeline`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// dsc_pp_dp.go — promoted check functions (80%)
// ---------------------------------------------------------------------------

func TestCheckTisaxDataClassificationGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxDataClassification(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckTisaxChangeMgmtGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxChangeMgmt(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckTisaxMDMGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxMDM(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckTisaxAIMLSecurityGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxAIMLSecurity(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckTisaxDataRetentionGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxDataRetention(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckTisaxPrivacyPolicyGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkTisaxPrivacyPolicy(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// is_or.go — checkVulnMgmt (73.3%)
// ---------------------------------------------------------------------------

func TestCheckVulnMgmtGap_Compliant_WithSeverity(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnMgmt(ctx, []byte(`vulnerability_scan remediation tracking severity cvss`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with severity, got %d", len(r.Evidence))
	}
}

func TestCheckVulnMgmtGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnMgmt(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckVulnMgmtGap_NonCompliant_NoTracking(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnMgmt(ctx, []byte(`cve`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// is_or.go — checkIncidentResponsePlan (73.3%)
// ---------------------------------------------------------------------------

func TestCheckIncidentResponsePlanGap_Compliant_WithEscalation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentResponsePlan(ctx, []byte(`incident_response_plan roles escalation_path notification`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with escalation, got %d", len(r.Evidence))
	}
}

func TestCheckIncidentResponsePlanGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentResponsePlan(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckIncidentResponsePlanGap_NonCompliant_NoRoles(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentResponsePlan(ctx, []byte(`ir_plan`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// is_or.go — checkComplianceMonitoring (58.8%)
// ---------------------------------------------------------------------------

func TestCheckComplianceMonitoringGap_Compliant_Reporting(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkComplianceMonitoring(ctx, []byte(`compliance_monitoring reporting dashboard`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckComplianceMonitoringGap_Compliant_Deviations(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkComplianceMonitoring(ctx, []byte(`continuous_monitoring deviation non_conformity`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckComplianceMonitoringGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkComplianceMonitoring(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckComplianceMonitoringGap_NonCompliant_NoDeviationsNoReporting(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkComplianceMonitoring(ctx, []byte(`compliance_monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// is_or.go — checkRiskMonitoring (66.7%)
// ---------------------------------------------------------------------------

func TestCheckRiskMonitoringGap_Compliant_WithRegister(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskMonitoring(ctx, []byte(`risk_monitoring periodic risk_register`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with register, got %d", len(r.Evidence))
	}
}

func TestCheckRiskMonitoringGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskMonitoring(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckRiskMonitoringGap_NonCompliant_NoPeriodic(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskMonitoring(ctx, []byte(`risk_monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// is_or.go — checkSecurityMetrics (73.3%)
// ---------------------------------------------------------------------------

func TestCheckSecurityMetricsGap_Compliant_WithMgmt(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityMetrics(ctx, []byte(`metrics kpi tracking dashboard management review`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected 3 evidence items with mgmt, got %d", len(r.Evidence))
	}
}

func TestCheckSecurityMetricsGap_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityMetrics(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckSecurityMetricsGap_NonCompliant_NoTracking(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityMetrics(ctx, []byte(`security_metrics`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}
