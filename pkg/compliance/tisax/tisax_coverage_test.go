// SPDX-License-Identifier: Apache-2.0
// TISAX AL2 — Coverage Gap Tests
//
// Tests targeting uncovered/partially covered branches to reach 80%+ coverage.
// Uses same-package access (no compliance import to avoid cycle).

package tisax

import (
	"context"
	"strings"
	"testing"
)

func newModule() *TISAXModule {
	return NewTISAXModule()
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

func TestDependencies(t *testing.T) {
	m := newModule()
	deps := m.Dependencies()
	if len(deps) == 0 {
		t.Error("Dependencies() returned empty slice")
	}
	expected := []string{"iso27001", "soc2", "fips", "ioc", "trust"}
	for i, dep := range expected {
		if i >= len(deps) {
			t.Errorf("Dependencies() missing %s", dep)
		} else if deps[i] != dep {
			t.Errorf("Dependencies()[%d] = %q, want %q", i, deps[i], dep)
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern helper negative branches
// ---------------------------------------------------------------------------

func TestHasEncryption_Negative(t *testing.T) {
	m := newModule()
	if m.hasEncryption("no encryption here at all") {
		t.Error("hasEncryption should return false for input without encryption keywords")
	}
}

func TestHasAudit_Negative(t *testing.T) {
	m := newModule()
	if m.hasAudit("nothing audit related whatsoever") {
		t.Error("hasAudit should return false for input without audit keywords")
	}
}

func TestHasAccessControl_Negative(t *testing.T) {
	m := newModule()
	if m.hasAccessControl("completely unrelated content") {
		t.Error("hasAccessControl should return false for input without access keywords")
	}
}

// ---------------------------------------------------------------------------
// DSC domain — checkDataProtection non-compliant branches
// ---------------------------------------------------------------------------

func TestCheckDataProtection_NonCompliant_NoEncryption(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataProtection(ctx, []byte(`{"access_control": "rbac", "audit_log": true}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
	if !strings.Contains(r.Message, "encryption") {
		t.Errorf("message should mention encryption: %s", r.Message)
	}
}

func TestCheckDataProtection_NonCompliant_NoAccess(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataProtection(ctx, []byte(`{"encryption": "aes_256", "audit_log": true}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
	if !strings.Contains(r.Message, "access") {
		t.Errorf("message should mention access: %s", r.Message)
	}
}

func TestCheckDataProtection_NonCompliant_NoAudit(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataProtection(ctx, []byte(`{"encryption": "aes_256", "rbac": true}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
	if !strings.Contains(r.Message, "audit") {
		t.Errorf("message should mention audit: %s", r.Message)
	}
}

func TestCheckDataProtection_NonCompliant_AllMissing(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataProtection(ctx, []byte(`{"nothing": "here"}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckDataProtection_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkDataProtection(ctx, []byte(`aes_256 encryption_at_rest rbac roles audit_log logging_enabled`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DSC domain — checkEndpointProtection
// ---------------------------------------------------------------------------

func TestCheckEndpointProtection_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointProtection(ctx, []byte(`malware scanner patching`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckEndpointProtection_Compliant_EDR(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointProtection(ctx, []byte(`edr patch_management`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckEndpointProtection_NonCompliant_NoMalware(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointProtection(ctx, []byte(`patching only`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckEndpointProtection_NonCompliant_NoPatching(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointProtection(ctx, []byte(`antivirus endpoint`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckEndpointProtection_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkEndpointProtection(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DSC domain — checkVulnerabilityManagement
// ---------------------------------------------------------------------------

func TestCheckVulnerabilityManagement_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`vulnerability cve remediation`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckVulnerabilityManagement_Compliant_Alt(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`vuln_scan patching`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckVulnerabilityManagement_NonCompliant_NoVulnScan(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`remediation fix`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
	if !strings.Contains(r.Message, "scanning") {
		t.Errorf("message should mention scanning: %s", r.Message)
	}
}

func TestCheckVulnerabilityManagement_NonCompliant_NoRemediation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`vulnerability cve`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckVulnerabilityManagement_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`nothing here`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DSC domain — checkLoggingMonitoring
// ---------------------------------------------------------------------------

func TestCheckLoggingMonitoring_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkLoggingMonitoring(ctx, []byte(`audit_log monitoring siem`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckLoggingMonitoring_Compliant_Alert(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkLoggingMonitoring(ctx, []byte(`audit_enabled alert`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckLoggingMonitoring_NonCompliant_NoAudit(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkLoggingMonitoring(ctx, []byte(`monitoring siem`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckLoggingMonitoring_NonCompliant_NoMonitoring(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkLoggingMonitoring(ctx, []byte(`audit_log logging_enabled`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckLoggingMonitoring_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkLoggingMonitoring(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// PP domain — checkSecurityAwareness
// ---------------------------------------------------------------------------

func TestCheckSecurityAwareness_Compliant_Training(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityAwareness(ctx, []byte(`training awareness`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecurityAwareness_Compliant_Policy(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityAwareness(ctx, []byte(`security_policy acceptable_use`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecurityAwareness_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecurityAwareness(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DP domain — checkSecureDevelopment
// ---------------------------------------------------------------------------

func TestCheckSecureDevelopment_Compliant_WithTesting(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureDevelopment(ctx, []byte(`secure_development code_review unit_test rbac`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecureDevelopment_Compliant_WithAccess(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureDevelopment(ctx, []byte(`sdlc rbac roles`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckSecureDevelopment_NonCompliant_NoSDLC(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureDevelopment(ctx, []byte(`testing unit_test`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckSecureDevelopment_NonCompliant_NoTestingNoAccess(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureDevelopment(ctx, []byte(`secure_development code_review`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckSecureDevelopment_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkSecureDevelopment(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DP domain — checkPrototypingSecurity
// ---------------------------------------------------------------------------

func TestCheckPrototypingSecurity_Compliant_TestEnv(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPrototypingSecurity(ctx, []byte(`test_environment rbac roles`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPrototypingSecurity_Compliant_Isolation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPrototypingSecurity(ctx, []byte(`isolation abac least_privilege`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckPrototypingSecurity_NonCompliant_NoAccess(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPrototypingSecurity(ctx, []byte(`test_environment staging`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckPrototypingSecurity_NonCompliant_NoEnvNoIsolation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPrototypingSecurity(ctx, []byte(`rbac roles`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckPrototypingSecurity_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkPrototypingSecurity(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DP domain — checkConfigurationManagement
// ---------------------------------------------------------------------------

func TestCheckConfigurationManagement_Compliant_VersionControl(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkConfigurationManagement(ctx, []byte(`version_control git`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckConfigurationManagement_Compliant_Baseline(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkConfigurationManagement(ctx, []byte(`baseline infrastructure_as_code`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckConfigurationManagement_NonCompliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkConfigurationManagement(ctx, []byte(`nothing here`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// DP domain — checkAuditReadiness
// ---------------------------------------------------------------------------

func TestCheckAuditReadiness_Compliant_WithEvidence(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAuditReadiness(ctx, []byte(`audit_log evidence trust_portal compliance report`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckAuditReadiness_Compliant_WithAssessment(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAuditReadiness(ctx, []byte(`audit_enabled assessment compliance`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckAuditReadiness_NonCompliant_NoAudit(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAuditReadiness(ctx, []byte(`evidence compliance`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckAuditReadiness_NonCompliant_NoEvidence(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAuditReadiness(ctx, []byte(`audit_log logging_enabled`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckAuditReadiness_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAuditReadiness(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// IS domain — checkInfoSecPolicy
// ---------------------------------------------------------------------------

func TestCheckInfoSecPolicy_Compliant_WithCommunication(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkInfoSecPolicy(ctx, []byte(`security_policy management_approved policy_communicated`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(r.Evidence))
	}
}

func TestCheckInfoSecPolicy_Compliant_NoCommunication(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkInfoSecPolicy(ctx, []byte(`infosec_policy approved`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckInfoSecPolicy_NonCompliant_NoPolicy(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkInfoSecPolicy(ctx, []byte(`management_approved governance`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckInfoSecPolicy_NonCompliant_NoApproval(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkInfoSecPolicy(ctx, []byte(`security_policy awareness`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckInfoSecPolicy_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkInfoSecPolicy(ctx, []byte(`nothing relevant`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// IS domain — checkAssetManagement
// ---------------------------------------------------------------------------

func TestCheckAssetManagement_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAssetManagement(ctx, []byte(`asset_inventory classification asset_owner`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckAssetManagement_NonCompliant_NoInventory(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAssetManagement(ctx, []byte(`classification owner`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckAssetManagement_NonCompliant_NoClassification(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAssetManagement(ctx, []byte(`inventory owner responsibility`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// hasInventory=true ("inventory"), hasClassification=false, hasOwner=true ("owner")
	// Missing classification => non-compliant
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckAssetManagement_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAssetManagement(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// IS domain — checkAccessControl
// ---------------------------------------------------------------------------

func TestCheckAccessControl_NonCompliant_NoRBAC(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	// authentication and minimize trigger hasAuth and hasLeastPrivilege,
	// but none of the access patterns (rbac, roles, abac, least_privilege) match
	r, err := m.checkAccessControl(ctx, []byte(`authentication minimize`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", r.Status)
	}
}

func TestCheckAccessControl_NonCompliant_NoAuth(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAccessControl(ctx, []byte(`rbac roles least_privilege`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// hasRBAC=true (rbac matches), hasAuth=false, hasLeastPrivilege=true (least_privilege matches pattern too, but also "roles" triggers hasRBAC)
	// Actually least_privilege is also in accessPatterns, so hasRBAC=true, hasAuth=false, hasLeastPrivilege=true
	// This should be noncompliant because hasAuth is false
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckAccessControl_NonCompliant_NoLeastPrivilege(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAccessControl(ctx, []byte(`rbac authentication`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckAccessControl_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkAccessControl(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// IS domain — checkCryptography
// ---------------------------------------------------------------------------

func TestCheckCryptography_Compliant_WithTLS(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCryptography(ctx, []byte(`aes_256 key_management tls https`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items (with TLS), got %d", len(r.Evidence))
	}
}

func TestCheckCryptography_Compliant_NoTLS(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCryptography(ctx, []byte(`encryption_at_rest key_rotation`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckCryptography_NonCompliant_NoEncryption(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCryptography(ctx, []byte(`key_management tls`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckCryptography_NonCompliant_NoKeyMgmt(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCryptography(ctx, []byte(`aes_256 fips_140`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckCryptography_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCryptography(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// IS domain — checkCommsSecurity
// ---------------------------------------------------------------------------

func TestCheckCommsSecurity_Compliant(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCommsSecurity(ctx, []byte(`tls https firewall monitoring audit_log`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckCommsSecurity_NonCompliant_NoTLS(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCommsSecurity(ctx, []byte(`firewall monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckCommsSecurity_NonCompliant_NoSegmentation(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCommsSecurity(ctx, []byte(`tls monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckCommsSecurity_NonCompliant_NoMonitoring(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCommsSecurity(ctx, []byte(`tls firewall segmentation`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckCommsSecurity_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkCommsSecurity(ctx, []byte(`nothing here`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// OR domain — checkRiskAssessment
// ---------------------------------------------------------------------------

func TestCheckRiskAssessment_Compliant_WithRegister(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`risk_assessment threat_model risk_register`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(r.Evidence))
	}
}

func TestCheckRiskAssessment_Compliant_NoRegister(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`risk_methodology threat`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckRiskAssessment_NonCompliant_NoMethodology(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`threat vulnerability`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckRiskAssessment_NonCompliant_NoThreatModel(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`risk_assessment risk_matrix`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckRiskAssessment_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkRiskAssessment(ctx, []byte(`nothing`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

// ---------------------------------------------------------------------------
// OR domain — checkIncidentMgmt
// ---------------------------------------------------------------------------

func TestCheckIncidentMgmt_Compliant_WithReporting(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentMgmt(ctx, []byte(`incident_response ioc detection reporting`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(r.Evidence))
	}
}

func TestCheckIncidentMgmt_Compliant_NoReporting(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentMgmt(ctx, []byte(`incident_procedure monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("status = %s, want compliant", r.Status)
	}
}

func TestCheckIncidentMgmt_NonCompliant_NoIncident(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentMgmt(ctx, []byte(`ioc detection monitoring`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckIncidentMgmt_NonCompliant_NoIOC(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentMgmt(ctx, []byte(`incident_response reporting`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}

func TestCheckIncidentMgmt_NonCompliant_Empty(t *testing.T) {
	m := newModule()
	ctx := context.Background()
	r, err := m.checkIncidentMgmt(ctx, []byte(`nothing here`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("status = %s, want noncompliant", r.Status)
	}
}
