// SPDX-License-Identifier: Apache-2.0
// CMMC Level 2 — Coverage Gap Tests (Phase 2)
//
// Targets the compliant and partial code paths of functions that were
// previously only exercised via the non_compliant path. Goal: 90%+ coverage.

package cmmcl2

import (
	"context"
	"strings"
	"testing"
)

// checkResultStatus verifies that a check function returned the expected status.
func checkResultStatus(t *testing.T, status, controlID, want string, msg string) {
	t.Helper()
	if strings.ToLower(status) != strings.ToLower(want) {
		t.Errorf("control %s: expected %q, got %q: %s", controlID, want, status, msg)
	}
}

// =====================================================================
// AC Domain — Gap tests for compliant paths
// =====================================================================

func TestCheckSessionControl_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	// Compliant: both timeout and concurrent
	r, err := m.checkSessionControl(ctx, []byte(`{"session_timeout":900,"concurrent_sessions":1}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: timeout only
	r, err = m.checkSessionControl(ctx, []byte(`{"session_timeout":900}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckWirelessAccessRestrictions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkWirelessAccessRestrictions(ctx, []byte(`{"wireless_auth":true,"wpa3":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAccountManagement_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAccountManagement(ctx, []byte(`{"account_management":true,"deprovisioning":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckPortableStorageRestriction_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPortableStorageRestriction(ctx, []byte(`{"portable_storage":true,"removable_media":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckNetworkAccessControl_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkNetworkAccessControl(ctx, []byte(`{"network_segmentation":true,"firewall":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only segmentation
	r, err = m.checkNetworkAccessControl(ctx, []byte(`{"network_segmentation":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCUILabeling_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCUILabeling(ctx, []byte(`{"classification_label":true,"data_classification":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only classification
	r, err = m.checkCUILabeling(ctx, []byte(`{"classification_label":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckAuthenticatedAccess_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuthenticatedAccess(ctx, []byte(`{"authenticated_access":true,"auth_required":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckLeastFunctionality_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkLeastFunctionality(ctx, []byte(`{"least_functionality":true,"disable_unnecessary":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckPublicFacingSystemAccess_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPublicFacingSystemAccess(ctx, []byte(`{"public_access":true,"bastion":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckPermittedActions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPermittedActions(ctx, []byte(`{"permitted_actions":true,"allowed_operations":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAuthorizedUsers_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuthorizedUsers(ctx, []byte(`{"authorized_users":true,"access_authorization":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckLeastPrivilege_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkLeastPrivilege(ctx, []byte(`{"least_privilege":true,"minimal_access":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only least_privilege (satisfies first condition but not minimal_access)
	r, err = m.checkLeastPrivilege(ctx, []byte(`{"need_to_know":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckControlCUIFlow_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkControlCUIFlow(ctx, []byte(`{"cui_flow":true,"flow_control":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckPolicyDocumentation_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPolicyDocumentation(ctx, []byte(`{"policy_documentation":true,"policy_enforcement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAutoSessionTermination_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAutoSessionTermination(ctx, []byte(`{"session_termination":true,"idle_termination":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckDataAtRestAccess_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkDataAtRestAccess(ctx, []byte(`{"encryption_at_rest":true,"rbac":true,"disk_encryption":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only encryption
	r, err = m.checkDataAtRestAccess(ctx, []byte(`{"encryption_at_rest":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckInfoSharing_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkInfoSharing(ctx, []byte(`{"information_sharing":true,"rbac":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only sharing
	r, err = m.checkInfoSharing(ctx, []byte(`{"information_sharing":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// AU Domain — Gap tests
// =====================================================================

func TestCheckAuditLogRetention_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditLogRetention(ctx, []byte(`{"retention":"365d","hash_chain":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAuditReviewAnalysis_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditReviewAnalysis(ctx, []byte(`{"audit_review":true,"anomaly_detection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only review
	r, err = m.checkAuditReviewAnalysis(ctx, []byte(`{"audit_review":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckTimeStamps_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTimeStamps(ctx, []byte(`{"timestamp":true,"ntp":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAuditReview_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditReview(ctx, []byte(`{"audit_review":true,"review":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only review
	r, err = m.checkAuditReview(ctx, []byte(`{"audit_review":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckAuditProtection_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditProtection(ctx, []byte(`{"audit_protection":true,"audit_integrity":true,"access_control":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only protection
	r, err = m.checkAuditProtection(ctx, []byte(`{"audit_protection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckAuditReduction_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditReduction(ctx, []byte(`{"audit_reduction":true,"reporting":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only reduction
	r, err = m.checkAuditReduction(ctx, []byte(`{"audit_reduction":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// CA/CM Domain — Gap tests
// =====================================================================

func TestCheckComponentInventory_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkComponentInventory(ctx, []byte(`{"sbom":true,"dependencies":true,"version":"1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckSoftwareRestrictions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSoftwareRestrictions(ctx, []byte(`{"allowlist":true,"software_restriction":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckConfigurationChangeLog_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkConfigurationChangeLog(ctx, []byte(`{"change_log":true,"approval":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only change_log
	r, err = m.checkConfigurationChangeLog(ctx, []byte(`{"change_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckBaselineEnforcement_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkBaselineEnforcement(ctx, []byte(`{"baseline":true,"drift_detection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only baseline
	r, err = m.checkBaselineEnforcement(ctx, []byte(`{"baseline":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMBaselineConfig_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMBaselineConfig(ctx, []byte(`{"baseline_configuration":true,"drift_detection":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only baseline
	r, err = m.checkCMBaselineConfig(ctx, []byte(`{"baseline_configuration":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMConfigRestrictions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMConfigRestrictions(ctx, []byte(`{"config_restrictions":true,"enforcement":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only restrictions
	r, err = m.checkCMConfigRestrictions(ctx, []byte(`{"config_restrictions":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMSecureConfig_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMSecureConfig(ctx, []byte(`{"secure_configuration":true,"hardening":true,"enforcement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only secure
	r, err = m.checkCMSecureConfig(ctx, []byte(`{"secure_configuration":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMConfigDocs_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMConfigDocs(ctx, []byte(`{"configuration_documentation":true,"configuration_settings":true,"version_control":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only docs
	r, err = m.checkCMConfigDocs(ctx, []byte(`{"configuration_documentation":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// IA/IR Domain — Gap tests
// =====================================================================

func TestCheckAuthenticatorFeedback_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuthenticatorFeedback(ctx, []byte(`{"mask":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Also test no_echo path
	r, err = m.checkAuthenticatorFeedback(ctx, []byte(`{"no_echo":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckIncidentResponseTesting_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkIncidentResponseTesting(ctx, []byte(`{"incident_testing":true,"incident_response":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckIncidentResponseReporting_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkIncidentResponseReporting(ctx, []byte(`{"incident_reporting":true,"tracking":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only reporting
	r, err = m.checkIncidentResponseReporting(ctx, []byte(`{"incident_reporting":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCentralizedAuthentication_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCentralizedAuthentication(ctx, []byte(`{"sso":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckSessionLock_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSessionLock(ctx, []byte(`{"session_lock":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckIRTesting_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkIRTesting(ctx, []byte(`{"ir_testing":true,"incident_response":true,"scheduled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only testing
	r, err = m.checkIRTesting(ctx, []byte(`{"ir_testing":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// MA/MP/PE Domain — Gap tests
// =====================================================================

func TestCheckMaintenanceLogging_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkMaintenanceLogging(ctx, []byte(`{"maintenance_log":true,"review":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only maintenance_log
	r, err = m.checkMaintenanceLogging(ctx, []byte(`{"maintenance_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// AT/PS Domain — Gap tests
// =====================================================================

func TestCheckSecurityAwarenessTraining_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSecurityAwarenessTraining(ctx, []byte(`{"security_training":true,"cui":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckTrainingRecords_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTrainingRecords(ctx, []byte(`{"training_records":true,"completion":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckAccessRevocation_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAccessRevocation(ctx, []byte(`{"access_revocation":true,"automated":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckPersonnelSanctions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPersonnelSanctions(ctx, []byte(`{"sanctions":true,"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

// =====================================================================
// AM Domain — Gap tests
// =====================================================================

func TestCheckAssetInventory_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAssetInventory(ctx, []byte(`{"sbom":true,"dependencies":true,"version":"1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

// =====================================================================
// RA/SA/SC/SI Domain — Gap tests
// =====================================================================

func TestCheckInsiderThreat_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkInsiderThreat(ctx, []byte(`{"insider_threat":true,"monitoring":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckSecurityAlerts_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSecurityAlerts(ctx, []byte(`{"security_alerts":true,"notification":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckRARiskResponse_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkRARiskResponse(ctx, []byte(`{"risk_response":true,"risk_assessment":true,"tracking":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only response
	r, err = m.checkRARiskResponse(ctx, []byte(`{"risk_response":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSIInfoHandling_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSIInfoHandling(ctx, []byte(`{"information_handling":true,"policy":true,"enforcement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only handling
	r, err = m.checkSIInfoHandling(ctx, []byte(`{"information_handling":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// SC Extended Domain — Gap tests
// =====================================================================

func TestCheckSystemBoundaryMonitoring_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSystemBoundaryMonitoring(ctx, []byte(`{"boundary_monitoring":true,"intrusion_detection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckExternalNetworkAccess_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkExternalNetworkAccess(ctx, []byte(`{"vpn":true,"gateway":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckTransmissionConfidentiality_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTransmissionConfidentiality(ctx, []byte(`{"encryption_in_transit":true,"tls":"1.3"}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only encryption_in_transit (no tls/ipsec)
	r, err = m.checkTransmissionConfidentiality(ctx, []byte(`{"encryption_in_transit":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckNetworkIntegrity_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkNetworkIntegrity(ctx, []byte(`{"network_integrity":true,"integrity_check":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only network_integrity
	r, err = m.checkNetworkIntegrity(ctx, []byte(`{"network_integrity":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCryptographicKeyManagement_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCryptographicKeyManagement(ctx, []byte(`{"key_management":true,"key_store":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only key_management
	r, err = m.checkCryptographicKeyManagement(ctx, []byte(`{"key_rotation":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSessionAuthenticity_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSessionAuthenticity(ctx, []byte(`{"session_authenticity":true,"nonce":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckFIPSValidatedCryptography_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkFIPSValidatedCryptography(ctx, []byte(`{"fips_140":true,"validated_crypto":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only cmvp (satisfies hasFIPS but not hasValidatedCrypto)
	r, err = m.checkFIPSValidatedCryptography(ctx, []byte(`{"cmvp":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSharedResourceIsolation_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSharedResourceIsolation(ctx, []byte(`{"resource_isolation":true,"sandbox":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckConnectionTimeout_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkConnectionTimeout(ctx, []byte(`{"connection_timeout":900,"timeout":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only connection_timeout (no generic "timeout")
	// Actually "connection_timeout" contains "timeout" so both conditions are met.
	// Use a string that satisfies only hasConnectionTimeout but not hasTimeout.
	// hasConnectionTimeout = "connection_timeout" || "idle_timeout" || "session_timeout"
	// hasTimeout = "timeout" || "connection_timeout" || "idle_timeout"
	// All three overlap, so it's impossible to have one without the other.
	// We'll just test the non_compliant case with empty input.
	r, err = m.checkConnectionTimeout(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCryptographicProtection_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCryptographicProtection(ctx, []byte(`{"cryptographic_protection":true,"tamper_proof":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
}

func TestCheckSCBoundaryProtection_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSCBoundaryProtection(ctx, []byte(`{"boundary_protection":true,"firewall":true,"monitoring":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only boundary
	r, err = m.checkSCBoundaryProtection(ctx, []byte(`{"boundary_protection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSCNetworkArch_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSCNetworkArch(ctx, []byte(`{"network_architecture":true,"network_isolation":true,"enforcement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only arch
	r, err = m.checkSCNetworkArch(ctx, []byte(`{"network_architecture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSCTrustedConnection_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSCTrustedConnection(ctx, []byte(`{"trusted_connection":true,"authentication":true,"tls":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only trusted
	r, err = m.checkSCTrustedConnection(ctx, []byte(`{"trusted_connection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// Expanded Domain — Gap tests (3-path: compliant, partial, non_compliant)
// =====================================================================

func TestCheckPAM_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	// Compliant
	r, err := m.checkPAM(ctx, []byte(`{"pam":true,"session_recording":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Partial
	r, err = m.checkPAM(ctx, []byte(`{"pam":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	// Non-compliant
	r, err = m.checkPAM(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSessionLockExpanded_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSessionLockExpanded(ctx, []byte(`{"session_lock":true,"session_timeout":900}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkSessionLockExpanded(ctx, []byte(`{"session_lock":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkSessionLockExpanded(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckAuditGeneration_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAuditGeneration(ctx, []byte(`{"audit_log":true,"automated_logging":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkAuditGeneration(ctx, []byte(`{"audit_log":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkAuditGeneration(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckTimeStamp_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTimeStamp(ctx, []byte(`{"ntp":true,"time_stamp_protection":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkTimeStamp(ctx, []byte(`{"ntp":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkTimeStamp(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckPOAM_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkPOAM(ctx, []byte(`{"poam":true,"milestones":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkPOAM(ctx, []byte(`{"poam":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkPOAM(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckUserInstalledSoftware_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkUserInstalledSoftware(ctx, []byte(`{"software_whitelist":true,"software_monitoring":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkUserInstalledSoftware(ctx, []byte(`{"software_whitelist":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkUserInstalledSoftware(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckDeviceAuth_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkDeviceAuth(ctx, []byte(`{"device_identification":true,"device_certificate":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkDeviceAuth(ctx, []byte(`{"device_identification":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkDeviceAuth(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCryptoModuleAuth_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCryptoModuleAuth(ctx, []byte(`{"fips_140":true,"crypto_module":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCryptoModuleAuth(ctx, []byte(`{"fips_140":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkCryptoModuleAuth(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckIncidentMonitoringExpanded_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkIncidentMonitoringExpanded(ctx, []byte(`{"incident_tracking":true,"siem":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkIncidentMonitoringExpanded(ctx, []byte(`{"incident_tracking":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkIncidentMonitoringExpanded(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckMediaTransport_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkMediaTransport(ctx, []byte(`{"encryption":true,"media_tracking":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkMediaTransport(ctx, []byte(`{"encryption":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkMediaTransport(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckMediaSanitizationExpanded_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkMediaSanitizationExpanded(ctx, []byte(`{"sanitization":true,"sanitization_verification":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkMediaSanitizationExpanded(ctx, []byte(`{"sanitization":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkMediaSanitizationExpanded(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckAccessAgreements_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkAccessAgreements(ctx, []byte(`{"access_agreement":true,"signed_agreement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkAccessAgreements(ctx, []byte(`{"access_agreement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkAccessAgreements(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckVulnMonitoring_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkVulnMonitoring(ctx, []byte(`{"vulnerability_scan":true,"cvss":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkVulnMonitoring(ctx, []byte(`{"vulnerability_scan":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkVulnMonitoring(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckTransmissionConf_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTransmissionConf(ctx, []byte(`{"encryption":true,"fips_140":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkTransmissionConf(ctx, []byte(`{"encryption":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkTransmissionConf(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckTransmissionIntegrity_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkTransmissionIntegrity(ctx, []byte(`{"integrity_check":true,"cryptographic_integrity":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkTransmissionIntegrity(ctx, []byte(`{"integrity_check":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkTransmissionIntegrity(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckMaliciousCode_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkMaliciousCode(ctx, []byte(`{"antivirus":true,"heuristic":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkMaliciousCode(ctx, []byte(`{"antivirus":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkMaliciousCode(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckSpamProtection_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkSpamProtection(ctx, []byte(`{"spam_filter":true,"email_security":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkSpamProtection(ctx, []byte(`{"spam_filter":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkSpamProtection(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCUIAccess_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCUIAccess(ctx, []byte(`{"cui_access":true,"need_to_know":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCUIAccess(ctx, []byte(`{"cui_access":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkCUIAccess(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCUITransmission_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCUITransmission(ctx, []byte(`{"encryption":true,"fips_140":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCUITransmission(ctx, []byte(`{"encryption":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkCUITransmission(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCUIIncidentReporting_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCUIIncidentReporting(ctx, []byte(`{"incident_reporting":true,"cui_incident":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCUIIncidentReporting(ctx, []byte(`{"incident_reporting":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "partial", r.Message)
	r, err = m.checkCUIIncidentReporting(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCUIIdentification_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCUIIdentification(ctx, []byte(`{"cui_marking":true,"classification_labels":true,"enforcement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	// Non-compliant: only marking
	r, err = m.checkCUIIdentification(ctx, []byte(`{"cui_marking":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

// =====================================================================
// Expanded Domain — 2-path functions (compliant + non_compliant)
// =====================================================================

func TestCheckCMMCSecImpact_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCSecImpact(ctx, []byte(`{"security_impact":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCSecImpact(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCSecFuncIsolation_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCSecFuncIsolation(ctx, []byte(`{"security_function_isolation":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCSecFuncIsolation(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCSWUsage_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCSWUsage(ctx, []byte(`{"software_usage_restriction":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCSWUsage(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCIRTesting_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCIRTesting(ctx, []byte(`{"ir_testing":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCIRTesting(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCNonRepudiation_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCNonRepudiation(ctx, []byte(`{"non_repudiation":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCNonRepudiation(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCRiskResponse_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCRiskResponse(ctx, []byte(`{"risk_response":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCRiskResponse(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCCUIStorageDisposal_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCCUIStorageDisposal(ctx, []byte(`{"cui_storage":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCCUIStorageDisposal(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCMobileDevice_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCMobileDevice(ctx, []byte(`{"mobile_device_restriction":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCMobileDevice(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCPermittedActions_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCPermittedActions(ctx, []byte(`{"permitted_actions":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCPermittedActions(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCSessionAudit_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCSessionAudit(ctx, []byte(`{"session_audit":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCSessionAudit(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCCryptoAuth_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCCryptoAuth(ctx, []byte(`{"cryptographic_module_auth":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCCryptoAuth(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}

func TestCheckCMMCIdentifierMgmt_Gap(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	r, err := m.checkCMMCIdentifierMgmt(ctx, []byte(`{"identifier_management":true}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "compliant", r.Message)
	r, err = m.checkCMMCIdentifierMgmt(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	checkResultStatus(t, string(r.Status), r.ControlID, "non_compliant", r.Message)
}
