// SPDX-License-Identifier: Apache-2.0
// HITRUST CSF Compliance Module - Coverage Gap Tests
//
// Tests exercising uncovered/partially covered branches to reach 80%+ coverage.
// All check methods return (*compliance.ControlCheckResult, error) but we use
// string(r.Status) to avoid importing the compliance package (import cycle).

package hitrust

import (
	"context"
	"strings"
	"testing"
)

// --- Non-compliant branch tests for AM family ---

func TestCheckLogicalAccess_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		wantContains string
	}{
		{
			name:         "no rbac no auth no least_privilege",
			input:        `{"nothing": true}`,
			wantContains: "RBAC not configured",
		},
		{
			name:         "only rbac",
			input:        `{"rbac": true}`,
			wantContains: "authentication not enabled",
		},
		{
			name:         "rbac + auth but no least_privilege",
			input:        `{"rbac": true, "authentication": true}`,
			wantContains: "least privilege",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkLogicalAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkLogicalAccess: %v", err)
			}
			if strings.ToLower(string(r.Status)) != "non_compliant" {
				t.Errorf("expected non_compliant, got %q", string(r.Status))
			}
			if !strings.Contains(r.Message, tt.wantContains) {
				t.Errorf("message %q should contain %q", r.Message, tt.wantContains)
			}
		})
	}
}

func TestCheckAccessReview_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		wantContains string
	}{
		{
			name:         "nothing configured",
			input:        `{"nothing": true}`,
			wantContains: "RBAC not configured",
		},
		{
			name:         "rbac only no audit no review",
			input:        `{"rbac": true}`,
			wantContains: "audit logging",
		},
		{
			name:         "rbac + audit no review",
			input:        `{"rbac": true, "audit_log": true}`,
			wantContains: "periodic access review",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkAccessReview(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccessReview: %v", err)
			}
			if strings.ToLower(string(r.Status)) != "non_compliant" {
				t.Errorf("expected non_compliant, got %q", string(r.Status))
			}
			if !strings.Contains(r.Message, tt.wantContains) {
				t.Errorf("message %q should contain %q", r.Message, tt.wantContains)
			}
		})
	}
}

func TestCheckSessionManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkSessionManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkSessionManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckPrivilegedAccess_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkPrivilegedAccess(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkPrivilegedAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckMFA_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMFA(ctx, []byte(`{"authentication": true}`))
	if err != nil {
		t.Fatalf("checkMFA: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckUserAuthentication_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkUserAuthentication(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkUserAuthentication: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckPasswordManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkPasswordManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkPasswordManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for ID family ---

func TestCheckIdentityVerification_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkIdentityVerification(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckAuthenticatorManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAuthenticatorManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckCredentialManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkCredentialManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkCredentialManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for IP family ---

func TestCheckEncryptionAtRest_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkEncryptionAtRest(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkEncryptionAtRest: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckEncryptionInTransit_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkEncryptionInTransit(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkEncryptionInTransit: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckKeyManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkKeyManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkKeyManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckDataMasking_PartialAndNonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Partial: masking but no env or PII
	r, err := m.checkDataMasking(ctx, []byte(`{"data_masking": true}`))
	if err != nil {
		t.Fatalf("checkDataMasking: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "partial" {
		t.Errorf("expected partial, got %q", string(r.Status))
	}

	// Non-compliant: nothing
	r2, err := m.checkDataMasking(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkDataMasking: %v", err)
	}
	if strings.ToLower(string(r2.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r2.Status))
	}
}

func TestCheckEndpointProtection_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkEndpointProtection(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckNetworkProtection_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkNetworkProtection(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckMalwareProtection_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMalwareProtection(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckVulnerabilityManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkVulnerabilityManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckBackupAndRecovery_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkBackupAndRecovery(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for new automated controls ---

func TestCheckRemoteAccess_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkRemoteAccess(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkRemoteAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckAccountMonitoring_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAccountMonitoring(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkAccountMonitoring: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckNAC_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkNAC(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkNAC: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckDeviceIdentification_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkDeviceIdentification(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkDeviceIdentification: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckDLP_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkDLP(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkDLP: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckStorageEncryption_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkStorageEncryption(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkStorageEncryption: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckEDR_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkEDR(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkEDR: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckMDM_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMDM(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkMDM: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckFullDiskEncryption_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkFullDiskEncryption(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkFullDiskEncryption: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckAntiMalwareUpdates_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAntiMalwareUpdates(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkAntiMalwareUpdates: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckPatchManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkPatchManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkPatchManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for OP/OR/PR ---

func TestCheckConfigManagement_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkConfigManagement(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkConfigManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckChangeControl_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkChangeControl(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkChangeControl: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckConfigSettings_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkConfigSettings(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkConfigSettings: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckComponentInventory_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkComponentInventory(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkComponentInventory: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckControlledMaintenance_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkControlledMaintenance(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkControlledMaintenance: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckRiskAssessment_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkRiskAssessment: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckVulnerabilityScanning_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityScanning(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityScanning: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckVulnRemediation_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkVulnRemediation(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkVulnRemediation: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckSecurityAwareness_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkSecurityAwareness(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkSecurityAwareness: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckRoleBasedTraining_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkRoleBasedTraining(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkRoleBasedTraining: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for BC/RA/CA ---

func TestCheckSystemBackup_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkSystemBackup(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkSystemBackup: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckSecurityAssessment_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkSecurityAssessment(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkSecurityAssessment: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckContinuousMonitoring_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkContinuousMonitoring(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkContinuousMonitoring: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckCAComponentInventory_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkCAComponentInventory(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkCAComponentInventory: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for IR/SD/AI ---

func TestCheckIRPlan_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkIRPlan(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkIRPlan: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckIncidentMonitoring_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkIncidentMonitoring(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkIncidentMonitoring: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckIncidentHandling_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkIncidentHandling(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkIncidentHandling: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckSystemDocumentation_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkSystemDocumentation(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkSystemDocumentation: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckAIModelDataProtection_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkAIModelDataProtection(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkAIModelDataProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckAIAuditTrail_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkAIAuditTrail(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("checkAIAuditTrail: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

// --- Alternate keyword tests ---

func TestCheckMalwareProtection_AlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMalwareProtection(ctx, []byte(`{"malware_protection": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with malware_protection, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckMalwareProtection_AlternateAutoUpdate(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMalwareProtection(ctx, []byte(`{"anti_malware": true, "auto_update": true, "email_scan": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
}

// --- Control count by family ---

func TestHITRUSTControlCountByFamily(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	if len(controls) != 200 {
		t.Errorf("len(Controls()) = %d, want 200", len(controls))
	}

	familyCount := map[string]int{}
	for _, c := range controls {
		familyCount[c.Category]++
	}

	expectedFamilies := map[string]int{
		"Access Management":      25,
		"Identity Management":    10,
		"Information Protection": 25,
		"Privacy and Endpoint":   25,
		"Operations":             20,
		"Organizational Risk":    10,
		"Program":                15,
		"Business Continuity":    10,
		"Regulatory Assessment":  10,
		"Change Management":      10,
		"Incident Response":      15,
		"Supplier/Development":   15,
		"AI Controls":            10,
	}

	for family, expected := range expectedFamilies {
		if familyCount[family] != expected {
			t.Errorf("family %q: got %d controls, want %d", family, familyCount[family], expected)
		}
	}
}
