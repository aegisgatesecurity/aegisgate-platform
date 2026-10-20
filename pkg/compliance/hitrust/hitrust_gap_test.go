// SPDX-License-Identifier: Apache-2.0
// HITRUST CSF Compliance Module - Coverage Gap Tests (Phase 2)
//
// Tests exercising uncovered branches for 42.9% and 80% functions
// to bring package coverage from 82.0% to 90%+.

package hitrust

import (
	"context"
	"testing"
)

// gapNonCompliantInput has none of the gap-function keywords.
const gapNonCompliantInput = `{"nothing_relevant": true}`

// --- 42.9% functions: test both compliant and non_compliant paths ---

func TestCheckPublicAccessGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Non-compliant: no keywords
	r, err := m.checkPublicAccess(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkPublicAccess: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-17" {
		t.Errorf("ControlID = %q, want HITRUST-AM-17", r.ControlID)
	}

	// Compliant: all three conditions
	compliant := `{"public_access": true, "audit_log": true, "authentication": true}`
	r2, err := m.checkPublicAccess(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkPublicAccess compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckSharedAccountProhibitionGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkSharedAccountProhibition(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkSharedAccountProhibition: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-20" {
		t.Errorf("ControlID = %q, want HITRUST-AM-20", r.ControlID)
	}

	compliant := `{"shared_account_prohibition": true, "unique_user": true, "enforcement": true}`
	r2, err := m.checkSharedAccountProhibition(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkSharedAccountProhibition compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckInfoFlowEnforcementGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkInfoFlowEnforcement(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkInfoFlowEnforcement: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-22" {
		t.Errorf("ControlID = %q, want HITRUST-AM-22", r.ControlID)
	}

	compliant := `{"information_flow": true, "flow_policy": true, "enforcement": true}`
	r2, err := m.checkInfoFlowEnforcement(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkInfoFlowEnforcement compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckPrivilegedAccountInventoryGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkPrivilegedAccountInventory(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkPrivilegedAccountInventory: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-24" {
		t.Errorf("ControlID = %q, want HITRUST-AM-24", r.ControlID)
	}

	compliant := `{"privileged_account_inventory": true, "inventory": true, "audit_log": true}`
	r2, err := m.checkPrivilegedAccountInventory(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkPrivilegedAccountInventory compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckConcurrentSessionControlGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkConcurrentSessionControl(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkConcurrentSessionControl: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-25" {
		t.Errorf("ControlID = %q, want HITRUST-AM-25", r.ControlID)
	}

	compliant := `{"concurrent_session": true, "authentication": true, "enforcement": true}`
	r2, err := m.checkConcurrentSessionControl(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkConcurrentSessionControl compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckContingencyTestGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkContingencyTest(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkContingencyTest: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-04" {
		t.Errorf("ControlID = %q, want HITRUST-BC-04", r.ControlID)
	}

	compliant := `{"recovery_test": true, "scheduled": true, "recovery": true}`
	r2, err := m.checkContingencyTest(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkContingencyTest compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckAlternateStorageGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAlternateStorage(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkAlternateStorage: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-05" {
		t.Errorf("ControlID = %q, want HITRUST-BC-05", r.ControlID)
	}

	compliant := `{"offsite": true, "backup": true, "aes_256": true}`
	r2, err := m.checkAlternateStorage(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkAlternateStorage compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckSystemRecoveryGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkSystemRecovery(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkSystemRecovery: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-07" {
		t.Errorf("ControlID = %q, want HITRUST-BC-07", r.ControlID)
	}

	compliant := `{"system_recovery": true, "reconstitution": true, "recovery_test": true}`
	r2, err := m.checkSystemRecovery(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkSystemRecovery compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckAlternateProcessingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAlternateProcessing(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkAlternateProcessing: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-09" {
		t.Errorf("ControlID = %q, want HITRUST-BC-09", r.ControlID)
	}

	compliant := `{"alternate_processing": true, "automated_failover": true, "failover_test": true}`
	r2, err := m.checkAlternateProcessing(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkAlternateProcessing compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckConfigBaselineGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkConfigBaseline(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkConfigBaseline: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-CA-02" {
		t.Errorf("ControlID = %q, want HITRUST-CA-02", r.ControlID)
	}

	compliant := `{"baseline_configuration": true, "configuration_documentation": true, "enforcement": true}`
	r2, err := m.checkConfigBaseline(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkConfigBaseline compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckChangeAccessRestrictionsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkChangeAccessRestrictions(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkChangeAccessRestrictions: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-CA-05" {
		t.Errorf("ControlID = %q, want HITRUST-CA-05", r.ControlID)
	}

	compliant := `{"change_access_restriction": true, "rbac": true, "audit_log": true}`
	r2, err := m.checkChangeAccessRestrictions(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkChangeAccessRestrictions compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckCAConfigSettingsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkCAConfigSettings(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkCAConfigSettings: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-CA-06" {
		t.Errorf("ControlID = %q, want HITRUST-CA-06", r.ControlID)
	}

	compliant := `{"configuration_settings": true, "enforcement": true, "documentation": true}`
	r2, err := m.checkCAConfigSettings(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkCAConfigSettings compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckLeastFunctionalityGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkLeastFunctionality(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkLeastFunctionality: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-CA-07" {
		t.Errorf("ControlID = %q, want HITRUST-CA-07", r.ControlID)
	}

	compliant := `{"least_functionality": true, "functionality_restriction": true, "enforcement": true}`
	r2, err := m.checkLeastFunctionality(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkLeastFunctionality compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckCryptoModuleAuthGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkCryptoModuleAuth(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkCryptoModuleAuth: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-ID-08" {
		t.Errorf("ControlID = %q, want HITRUST-ID-08", r.ControlID)
	}

	compliant := `{"cryptographic_module": true, "authentication": true, "cmvp": true}`
	r2, err := m.checkCryptoModuleAuth(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkCryptoModuleAuth compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckAuthenticatorTypeGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAuthenticatorType(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkAuthenticatorType: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-ID-09" {
		t.Errorf("ControlID = %q, want HITRUST-ID-09", r.ControlID)
	}

	compliant := `{"authenticator_type": true, "mfa": true, "authenticator_policy": true}`
	r2, err := m.checkAuthenticatorType(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkAuthenticatorType compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckAuthTokenProtectionGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAuthTokenProtection(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkAuthTokenProtection: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-ID-10" {
		t.Errorf("ControlID = %q, want HITRUST-ID-10", r.ControlID)
	}

	compliant := `{"token_protection": true, "aes_256": true, "authentication": true}`
	r2, err := m.checkAuthTokenProtection(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkAuthTokenProtection compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckDataClassificationGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkDataClassification(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkDataClassification: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-01" {
		t.Errorf("ControlID = %q, want HITRUST-IP-01", r.ControlID)
	}

	compliant := `{"data_classification": true, "labeling": true, "enforcement": true}`
	r2, err := m.checkDataClassification(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkDataClassification compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckLoggingMonitoringGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkLoggingMonitoring(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkLoggingMonitoring: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-12" {
		t.Errorf("ControlID = %q, want HITRUST-IP-12", r.ControlID)
	}

	compliant := `{"logging_monitoring": true, "audit_log": true, "alerting": true}`
	r2, err := m.checkLoggingMonitoring(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkLoggingMonitoring compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckDataBoundaryGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkDataBoundary(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkDataBoundary: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-19" {
		t.Errorf("ControlID = %q, want HITRUST-IP-19", r.ControlID)
	}

	compliant := `{"data_boundary": true, "network_segmentation": true, "enforcement": true}`
	r2, err := m.checkDataBoundary(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkDataBoundary compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckDataRetentionDisposalGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkDataRetentionDisposal(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkDataRetentionDisposal: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-20" {
		t.Errorf("ControlID = %q, want HITRUST-IP-20", r.ControlID)
	}

	compliant := `{"data_retention": true, "disposal_policy": true, "enforcement": true}`
	r2, err := m.checkDataRetentionDisposal(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkDataRetentionDisposal compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckProtectedStorageGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkProtectedStorage(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkProtectedStorage: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-24" {
		t.Errorf("ControlID = %q, want HITRUST-IP-24", r.ControlID)
	}

	compliant := `{"protected_storage": true, "aes_256": true, "access_control": true}`
	r2, err := m.checkProtectedStorage(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkProtectedStorage compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckTransmissionGuardGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkTransmissionGuard(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkTransmissionGuard: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-25" {
		t.Errorf("ControlID = %q, want HITRUST-IP-25", r.ControlID)
	}

	compliant := `{"transmission_guard": true, "tls": true, "authentication": true}`
	r2, err := m.checkTransmissionGuard(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkTransmissionGuard compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckIncidentReportingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkIncidentReporting(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkIncidentReporting: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-05" {
		t.Errorf("ControlID = %q, want HITRUST-IR-05", r.ControlID)
	}

	compliant := `{"incident_reporting": true, "incident_response": true, "audit_log": true}`
	r2, err := m.checkIncidentReporting(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkIncidentReporting compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckIncidentInfoCollectionGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkIncidentInfoCollection(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkIncidentInfoCollection: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-08" {
		t.Errorf("ControlID = %q, want HITRUST-IR-08", r.ControlID)
	}

	compliant := `{"incident_collection": true, "incident_response": true, "audit_log": true}`
	r2, err := m.checkIncidentInfoCollection(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkIncidentInfoCollection compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckIncidentMitigationGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkIncidentMitigation(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkIncidentMitigation: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-12" {
		t.Errorf("ControlID = %q, want HITRUST-IR-12", r.ControlID)
	}

	compliant := `{"incident_mitigation": true, "incident_response": true, "audit_log": true}`
	r2, err := m.checkIncidentMitigation(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkIncidentMitigation compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckChangeMonitoringGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkChangeMonitoring(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkChangeMonitoring: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OP-04" {
		t.Errorf("ControlID = %q, want HITRUST-OP-04", r.ControlID)
	}

	compliant := `{"change_monitoring": true, "audit_log": true, "alerting": true}`
	r2, err := m.checkChangeMonitoring(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkChangeMonitoring compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckAutomatedChangeSupportGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkAutomatedChangeSupport(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkAutomatedChangeSupport: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OP-10" {
		t.Errorf("ControlID = %q, want HITRUST-OP-10", r.ControlID)
	}

	compliant := `{"automated_change": true, "audit_log": true, "change_control": true}`
	r2, err := m.checkAutomatedChangeSupport(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkAutomatedChangeSupport compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckCapacityPlanningGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkCapacityPlanning(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkCapacityPlanning: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OP-14" {
		t.Errorf("ControlID = %q, want HITRUST-OP-14", r.ControlID)
	}

	compliant := `{"capacity_planning": true, "monitoring": true, "threshold": true}`
	r2, err := m.checkCapacityPlanning(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkCapacityPlanning compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckSecurityCategorizationGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkSecurityCategorization(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkSecurityCategorization: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OR-02" {
		t.Errorf("ControlID = %q, want HITRUST-OR-02", r.ControlID)
	}

	compliant := `{"security_categorization": true, "categorization": true, "policy": true}`
	r2, err := m.checkSecurityCategorization(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkSecurityCategorization compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

func TestCheckRiskMonitoringGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkRiskMonitoring(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkRiskMonitoring: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OR-07" {
		t.Errorf("ControlID = %q, want HITRUST-OR-07", r.ControlID)
	}

	compliant := `{"risk_monitoring": true, "risk_assessment": true, "alerting": true}`
	r2, err := m.checkRiskMonitoring(ctx, []byte(compliant))
	if err != nil {
		t.Fatalf("checkRiskMonitoring compliant: %v", err)
	}
	if string(r2.Status) != "compliant" {
		t.Errorf("Status = %q, want compliant", r2.Status)
	}
}

// --- 80% functions: test non_compliant path (compliant path already covered by CheckAll) ---

func TestCheckHITRUSTAutomatedMarkingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAutomatedMarking(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAutomatedMarking: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-18" {
		t.Errorf("ControlID = %q, want HITRUST-AM-18", r.ControlID)
	}
}

func TestCheckHITRUSTSecurityFiltersGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTSecurityFilters(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTSecurityFilters: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-23" {
		t.Errorf("ControlID = %q, want HITRUST-AM-23", r.ControlID)
	}
}

func TestCheckHITRUSTWirelessAccessGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTWirelessAccess(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTWirelessAccess: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-11" {
		t.Errorf("ControlID = %q, want HITRUST-AM-11", r.ControlID)
	}
}

func TestCheckHITRUSTMobileCodeGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTMobileCode(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTMobileCode: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-14" {
		t.Errorf("ControlID = %q, want HITRUST-AM-14", r.ControlID)
	}
}

func TestCheckHITRUSTExternalSystemsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTExternalSystems(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTExternalSystems: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-15" {
		t.Errorf("ControlID = %q, want HITRUST-AM-15", r.ControlID)
	}
}

func TestCheckHITRUSTInfoSharingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTInfoSharing(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTInfoSharing: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AM-16" {
		t.Errorf("ControlID = %q, want HITRUST-AM-16", r.ControlID)
	}
}

func TestCheckHITRUSTSoftwareUsageGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTSoftwareUsage(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTSoftwareUsage: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-CA-10" {
		t.Errorf("ControlID = %q, want HITRUST-CA-10", r.ControlID)
	}
}

func TestCheckHITRUSTAlternateCommsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAlternateComms(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAlternateComms: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-08" {
		t.Errorf("ControlID = %q, want HITRUST-BC-08", r.ControlID)
	}
}

func TestCheckHITRUSTLongTermStorageGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTLongTermStorage(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTLongTermStorage: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-BC-10" {
		t.Errorf("ControlID = %q, want HITRUST-BC-10", r.ControlID)
	}
}

func TestCheckHITRUSTPOAMGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTPOAM(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTPOAM: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-RA-05" {
		t.Errorf("ControlID = %q, want HITRUST-RA-05", r.ControlID)
	}
}

func TestCheckHITRUSTDataMiningPreventionGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTDataMiningPrevention(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTDataMiningPrevention: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-16" {
		t.Errorf("ControlID = %q, want HITRUST-IP-16", r.ControlID)
	}
}

func TestCheckHITRUSTEndpointSecurityGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTEndpointSecurity(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTEndpointSecurity: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-PE-09" {
		t.Errorf("ControlID = %q, want HITRUST-PE-09", r.ControlID)
	}
}

func TestCheckHITRUSTDataPrivacyControlsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTDataPrivacyControls(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTDataPrivacyControls: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-PE-19" {
		t.Errorf("ControlID = %q, want HITRUST-PE-19", r.ControlID)
	}
}

func TestCheckHITRUSTInfoSpillageGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTInfoSpillage(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTInfoSpillage: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IP-15" {
		t.Errorf("ControlID = %q, want HITRUST-IP-15", r.ControlID)
	}
}

func TestCheckHITRUSTDisposalGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTDisposal(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTDisposal: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-PE-14" {
		t.Errorf("ControlID = %q, want HITRUST-PE-14", r.ControlID)
	}
}

func TestCheckHITRUSTAIModelGovernanceGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Non-compliant: no keywords
	r, err := m.checkHITRUSTAIModelGovernance(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIModelGovernance: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-03" {
		t.Errorf("ControlID = %q, want HITRUST-AI-03", r.ControlID)
	}

	// Partial: only governance keyword, no framework keyword
	partial := `{"ai_governance": true}`
	r2, err := m.checkHITRUSTAIModelGovernance(ctx, []byte(partial))
	if err != nil {
		t.Fatalf("checkHITRUSTAIModelGovernance partial: %v", err)
	}
	if string(r2.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (partial)", r2.Status)
	}
}

func TestCheckHITRUSTAIOutputValidationGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIOutputValidation(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIOutputValidation: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-04" {
		t.Errorf("ControlID = %q, want HITRUST-AI-04", r.ControlID)
	}
}

func TestCheckHITRUSTAITrainingDataGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAITrainingData(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAITrainingData: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-05" {
		t.Errorf("ControlID = %q, want HITRUST-AI-05", r.ControlID)
	}
}

func TestCheckHITRUSTAIModelInventoryGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIModelInventory(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIModelInventory: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-06" {
		t.Errorf("ControlID = %q, want HITRUST-AI-06", r.ControlID)
	}
}

func TestCheckHITRUSTAIBiasTestingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIBiasTesting(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIBiasTesting: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-07" {
		t.Errorf("ControlID = %q, want HITRUST-AI-07", r.ControlID)
	}
}

func TestCheckHITRUSTAIModelRetentionGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIModelRetention(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIModelRetention: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-08" {
		t.Errorf("ControlID = %q, want HITRUST-AI-08", r.ControlID)
	}
}

func TestCheckHITRUSTAIPrivacyImpactGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIPrivacyImpact(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIPrivacyImpact: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-09" {
		t.Errorf("ControlID = %q, want HITRUST-AI-09", r.ControlID)
	}
}

func TestCheckHITRUSTAIThirdPartyRiskGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTAIThirdPartyRisk(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTAIThirdPartyRisk: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-AI-10" {
		t.Errorf("ControlID = %q, want HITRUST-AI-10", r.ControlID)
	}
}

func TestCheckHITRUSTDevConfigMgmtGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTDevConfigMgmt(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTDevConfigMgmt: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-SD-06" {
		t.Errorf("ControlID = %q, want HITRUST-SD-06", r.ControlID)
	}
}

func TestCheckHITRUSTDevSecurityTestingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTDevSecurityTesting(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTDevSecurityTesting: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-SD-07" {
		t.Errorf("ControlID = %q, want HITRUST-SD-07", r.ControlID)
	}
}

func TestCheckHITRUSTIRPlanTestingGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTIRPlanTesting(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTIRPlanTesting: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-06" {
		t.Errorf("ControlID = %q, want HITRUST-IR-06", r.ControlID)
	}
}

func TestCheckHITRUSTEvidencePreservationGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTEvidencePreservation(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTEvidencePreservation: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-09" {
		t.Errorf("ControlID = %q, want HITRUST-IR-09", r.ControlID)
	}
}

func TestCheckHITRUSTIncidentCommsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTIncidentComms(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTIncidentComms: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-10" {
		t.Errorf("ControlID = %q, want HITRUST-IR-10", r.ControlID)
	}
}

func TestCheckHITRUSTForensicAnalysisGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTForensicAnalysis(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTForensicAnalysis: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-11" {
		t.Errorf("ControlID = %q, want HITRUST-IR-11", r.ControlID)
	}
}

func TestCheckHITRUSTRecoveryGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTRecovery(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTRecovery: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-13" {
		t.Errorf("ControlID = %q, want HITRUST-IR-13", r.ControlID)
	}
}

func TestCheckHITRUSTPostIncidentReviewGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTPostIncidentReview(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTPostIncidentReview: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-IR-14" {
		t.Errorf("ControlID = %q, want HITRUST-IR-14", r.ControlID)
	}
}

func TestCheckHITRUSTChangeAccessRestrictionsGap(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()
	r, err := m.checkHITRUSTChangeAccessRestrictions(ctx, []byte(gapNonCompliantInput))
	if err != nil {
		t.Fatalf("checkHITRUSTChangeAccessRestrictions: %v", err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
	if r.ControlID != "HITRUST-OP-05" {
		t.Errorf("ControlID = %q, want HITRUST-OP-05", r.ControlID)
	}
}
