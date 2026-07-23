// SPDX-License-Identifier: Apache-2.0
// CMMC Level 2 — Coverage Gap Tests
//
// Tests targeting uncovered/partially covered branches to reach 80%+ coverage.
// These exercises the non-compliant code paths and edge cases not hit by the
// existing test suite.

package cmmcl2

import (
	"context"
	"strings"
	"testing"
)

func TestDependencies(t *testing.T) {
	m := NewCMMCL2Module()
	deps := m.Dependencies()
	if len(deps) == 0 {
		t.Error("Dependencies() returned empty slice")
	}
	expected := []string{"soc2", "iso27001", "fedramp", "ioc", "trust"}
	for _, exp := range expected {
		found := false
		for _, d := range deps {
			if d == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Dependencies() missing %q", exp)
		}
	}
}

// --- AC Domain Coverage ---

func TestCheckLimitSystemAccess_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// No auth, no RBAC, no access control patterns — fully non-compliant
	r, err := m.checkLimitSystemAccess(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has auth but missing RBAC and access control
	r, err = m.checkLimitSystemAccess(ctx, []byte(`{"authentication": true, "auth_enabled": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for auth-only, got %s: %s", r.Status, r.Message)
	}

	// Has RBAC but missing auth
	r, err = m.checkLimitSystemAccess(ctx, []byte(`{"rbac": true, "roles": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for RBAC-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckTransactionFunctionControl_ABAC(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// Compliant with ABAC (instead of RBAC)
	r, err := m.checkTransactionFunctionControl(ctx, []byte(`{"abac": true, "attributes": true, "authentication": true, "access_policy": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant for ABAC path, got %s: %s", r.Status, r.Message)
	}

	// Non-compliant: missing all
	r, err = m.checkTransactionFunctionControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckRoleBasedAccessControl_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// Wildcard access — should be non-compliant
	r, err := m.checkRoleBasedAccessControl(ctx, []byte(`{"rbac": true, "roles": true, "admin": true, "wildcard": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant with wildcard, got %s: %s", r.Status, r.Message)
	}

	// permit_all — should be non-compliant
	r, err = m.checkRoleBasedAccessControl(ctx, []byte(`{"rbac": true, "roles": true, "viewer": true, "permit_all": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant with permit_all, got %s: %s", r.Status, r.Message)
	}

	// No RBAC at all — fully non-compliant
	r, err = m.checkRoleBasedAccessControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// RBAC + least_privilege (compliant via least_privilege path)
	r, err = m.checkRoleBasedAccessControl(ctx, []byte(`{"rbac": true, "least_privilege": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with rbac+least_privilege, got %s: %s", r.Status, r.Message)
	}
}

// --- AU Domain Coverage ---

func TestCheckAuditEvents_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// No audit log patterns at all — non-compliant
	r, err := m.checkAuditEvents(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has audit log but no integrity
	r, err = m.checkAuditEvents(ctx, []byte(`{"audit_log": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for audit-only, got %s: %s", r.Status, r.Message)
	}

	// Has hash_chain (which matches both audit pattern and integrity) — this is actually compliant
	// because hash_chain is both an audit pattern and an integrity indicator.
	// To test the "integrity only, no audit" branch, we need a string that has
	// integrity but does NOT match any audit pattern regex.
	r, err = m.checkAuditEvents(ctx, []byte(`{"integrity": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Note: "integrity" doesn't match audit patterns (audit_log, logging_enabled, etc.)
	// but it's also not "log_integrity" or "hash_chain" — so this tests the no-audit-log branch.
	// However, "integrity" alone without "log_integrity" or "hash_chain" means no integrity flag either.
	// This is a fully non-compliant case.
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for integrity-only (wrong keyword), got %s: %s", r.Status, r.Message)
	}
}

func TestCheckAuditRecordContent_PartialAndNonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// Only 1 field — non-compliant (< 2)
	r, err := m.checkAuditRecordContent(ctx, []byte(`{"event": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant with 1 field, got %s: %s", r.Status, r.Message)
	}

	// 2 fields — partial (2 <= fieldsFound < 4)
	r, err = m.checkAuditRecordContent(ctx, []byte(`{"event": true, "timestamp": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "partial" {
		t.Errorf("expected partial with 2 fields, got %s: %s", r.Status, r.Message)
	}

	// 3 fields — still partial
	r, err = m.checkAuditRecordContent(ctx, []byte(`{"event_type": true, "timestamp": true, "source": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "partial" {
		t.Errorf("expected partial with 3 fields, got %s: %s", r.Status, r.Message)
	}

	// 4+ fields — compliant
	r, err = m.checkAuditRecordContent(ctx, []byte(`{"event_type": true, "timestamp": true, "source": true, "user_id": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with 4 fields, got %s: %s", r.Status, r.Message)
	}
}

// --- CA Domain Coverage ---

func TestCheckSecurityAssessment_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// No compliance, no vuln, no audit — fully non-compliant
	r, err := m.checkSecurityAssessment(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has compliance but no vuln or audit — still needs one of them
	r, err = m.checkSecurityAssessment(ctx, []byte(`{"compliance": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for compliance-only, got %s: %s", r.Status, r.Message)
	}

	// Compliance + audit_log (satisfies second condition)
	r, err = m.checkSecurityAssessment(ctx, []byte(`{"compliance": true, "audit_log": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}

	// Compliance + vulnerability (satisfies second condition)
	r, err = m.checkSecurityAssessment(ctx, []byte(`{"compliance": true, "vulnerability": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckPlanOfAction_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkPlanOfAction(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has remediation but no tracking/audit
	r, err = m.checkPlanOfAction(ctx, []byte(`{"remediation": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for remediation-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckContinuousMonitoring_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkContinuousMonitoring(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has monitoring but no scan
	r, err = m.checkContinuousMonitoring(ctx, []byte(`{"monitoring": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for monitoring-only, got %s: %s", r.Status, r.Message)
	}

	// Has scan but no monitoring/ccm
	r, err = m.checkContinuousMonitoring(ctx, []byte(`{"scanner": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for scan-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckChangeControl_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkChangeControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has change_log but no review or version
	r, err = m.checkChangeControl(ctx, []byte(`{"change_log": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for changelog-only, got %s: %s", r.Status, r.Message)
	}
}

// --- IA/IR Domain Coverage ---

func TestCheckIdentifyAuthenticateUsers_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkIdentifyAuthenticateUsers(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has auth but no unique ID or device auth
	r, err = m.checkIdentifyAuthenticateUsers(ctx, []byte(`{"authentication": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for auth-only, got %s: %s", r.Status, r.Message)
	}

	// Auth + device auth (compliant via device path)
	r, err = m.checkIdentifyAuthenticateUsers(ctx, []byte(`{"authentication": true, "mtls": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with auth+mtls, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckMultiFactorAuth_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkMultiFactorAuth(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckAuthenticatorManagement_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkAuthenticatorManagement(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Password policy but no key rotation or credential management
	r, err = m.checkAuthenticatorManagement(ctx, []byte(`{"password_policy": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for password-only, got %s: %s", r.Status, r.Message)
	}

	// Password policy + credential (compliant via credMgmt)
	r, err = m.checkAuthenticatorManagement(ctx, []byte(`{"password_policy": true, "credential": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckAuthenticatorFeedback_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkAuthenticatorFeedback(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckIncidentHandling_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkIncidentHandling(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has IOC but no incident response pattern
	r, err = m.checkIncidentHandling(ctx, []byte(`{"indicator": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for ioc-only, got %s: %s", r.Status, r.Message)
	}

	// Has incident_response but no IOC keyword
	r, err = m.checkIncidentHandling(ctx, []byte(`{"incident_response": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for incidentresp-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckIncidentMonitoring_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkIncidentMonitoring(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Only monitoring, no tracking
	r, err = m.checkIncidentMonitoring(ctx, []byte(`{"monitoring": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for monitoring-only, got %s: %s", r.Status, r.Message)
	}
}

// --- MA/MP/PE Domain Coverage ---

func TestCheckControlledMaintenance_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkControlledMaintenance(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has maintenance but no authorized
	r, err = m.checkControlledMaintenance(ctx, []byte(`{"maintenance": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for maintenance-only, got %s: %s", r.Status, r.Message)
	}

	// Has authorized but no maintenance
	r, err = m.checkControlledMaintenance(ctx, []byte(`{"authorized": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for authorized-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckMediaSanitization_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkMediaSanitization(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Compliant via wipe keyword
	r, err = m.checkMediaSanitization(ctx, []byte(`{"wipe": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}

	// Compliant via disposal
	r, err = m.checkMediaSanitization(ctx, []byte(`{"media_disposal": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckMediaAccessControl_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkMediaAccessControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Has access but no logging
	r, err = m.checkMediaAccessControl(ctx, []byte(`{"media_access": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for access-only, got %s: %s", r.Status, r.Message)
	}

	// Has logging but no access
	r, err = m.checkMediaAccessControl(ctx, []byte(`{"audit": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for logging-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckPhysicalAccessControl_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkPhysicalAccessControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Compliant via surveillance
	r, err = m.checkPhysicalAccessControl(ctx, []byte(`{"surveillance": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

// --- AM Domain Coverage ---

func TestCheckIdentifyManageAssets_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkIdentifyManageAssets(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Inventory only, no labeling/tracking
	r, err = m.checkIdentifyManageAssets(ctx, []byte(`{"inventory": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for inventory-only, got %s: %s", r.Status, r.Message)
	}

	// Inventory + tracking (compliant via tracking)
	r, err = m.checkIdentifyManageAssets(ctx, []byte(`{"inventory": true, "tracking": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckAssetInventory_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkAssetInventory(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// SBOM only, no dependencies
	r, err = m.checkAssetInventory(ctx, []byte(`{"sbom": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for sbom-only, got %s: %s", r.Status, r.Message)
	}
}

// --- RA/SA/SC/SI Domain Coverage ---

func TestCheckVulnerabilityScanning_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkVulnerabilityScanning(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Vuln scan only, no remediation
	r, err = m.checkVulnerabilityScanning(ctx, []byte(`{"vulnerability": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for vuln-only, got %s: %s", r.Status, r.Message)
	}

	// Remediation only, no vuln scan
	r, err = m.checkVulnerabilityScanning(ctx, []byte(`{"remediation": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for remediation-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckThreatMonitoring_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkThreatMonitoring(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Threat intel only, no monitoring
	r, err = m.checkThreatMonitoring(ctx, []byte(`{"threat_intel": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for threat-only, got %s: %s", r.Status, r.Message)
	}

	// Monitoring only, no threat intel
	r, err = m.checkThreatMonitoring(ctx, []byte(`{"monitoring": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for monitoring-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckInsiderThreat_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkInsiderThreat(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Insider threat only, no monitoring
	r, err = m.checkInsiderThreat(ctx, []byte(`{"insider_threat": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for insider-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckThreatIntelligence_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkThreatIntelligence(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Compliant via ioc_store
	r, err = m.checkThreatIntelligence(ctx, []byte(`{"ioc_store": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckEncryptionInTransit_Compliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// Compliant via encryption pattern (encryption_at_rest)
	r, err := m.checkEncryptionInTransit(ctx, []byte(`{"encryption_at_rest": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant via encryption pattern, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckEncryptionInTransit_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkEncryptionInTransit(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckEncryptionAtRest_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkEncryptionAtRest(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckFlawRemediation_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkFlawRemediation(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Patching only, no vuln scan
	r, err = m.checkFlawRemediation(ctx, []byte(`{"patching": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for patching-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckMaliciousCodeProtection_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkMaliciousCodeProtection(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckSystemMonitoring_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkSystemMonitoring(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// Audit log only, no monitoring
	r, err = m.checkSystemMonitoring(ctx, []byte(`{"audit_log": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for audit-only, got %s: %s", r.Status, r.Message)
	}

	// Monitoring only, no audit log
	r, err = m.checkSystemMonitoring(ctx, []byte(`{"monitoring": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for monitoring-only, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckInformationIntegrity_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	r, err := m.checkInformationIntegrity(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}

// --- Remote Access Control additional coverage ---

func TestCheckRemoteAccessControl_NonCompliant(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// No MFA, no TLS, no monitoring — fully non-compliant
	r, err := m.checkRemoteAccessControl(ctx, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}

	// MFA but no TLS
	r, err = m.checkRemoteAccessControl(ctx, []byte(`{"mfa": true, "monitoring": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant for MFA+monitoring but no TLS, got %s: %s", r.Status, r.Message)
	}
}
