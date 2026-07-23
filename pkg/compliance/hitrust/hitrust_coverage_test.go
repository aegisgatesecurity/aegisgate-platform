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
		wantContains string // substring expected in Message
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
			wantContains: "audit logging not configured",
		},
		{
			name:         "rbac + audit but no review",
			input:        `{"rbac": true, "audit_log": true}`,
			wantContains: "periodic access review not configured",
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

	tests := []struct {
		name         string
		input        string
		wantContains string
	}{
		{
			name:         "no session timeout no auth",
			input:        `{"nothing": true}`,
			wantContains: "session timeout not configured",
		},
		{
			name:         "session timeout only no auth",
			input:        `{"session_timeout": 1800}`,
			wantContains: "authentication not enabled",
		},
		{
			name:         "auth only no session timeout",
			input:        `{"authentication": true}`,
			wantContains: "session timeout not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkSessionManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSessionManagement: %v", err)
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

func TestCheckPrivilegedAccess_NonCompliant(t *testing.T) {
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
			name:         "only rbac",
			input:        `{"rbac": true}`,
			wantContains: "MFA not required",
		},
		{
			name:         "rbac + mfa no audit no pam",
			input:        `{"rbac": true, "mfa": true}`,
			wantContains: "audit logging not configured",
		},
		{
			name:         "rbac + mfa + audit no pam",
			input:        `{"rbac": true, "mfa": true, "audit_log": true}`,
			wantContains: "privileged access management not detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkPrivilegedAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPrivilegedAccess: %v", err)
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

// --- Non-compliant branch tests for ID family ---

func TestCheckIdentityVerification_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		wantContains string
	}{
		{
			name:         "no auth no unique id",
			input:        `{"nothing": true}`,
			wantContains: "authentication not configured",
		},
		{
			name:         "auth only no unique id",
			input:        `{"authentication": true}`,
			wantContains: "unique user identification not configured",
		},
		{
			name:         "unique_id only no auth",
			input:        `{"user_id": true}`,
			wantContains: "authentication not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkIdentityVerification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIdentityVerification: %v", err)
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

func TestCheckIdentityVerification_CompliantWithoutMFA(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant with auth + unique_id but no MFA (MFA is evidence in the compliant branch)
	r, err := m.checkIdentityVerification(ctx, []byte(`{"authentication": true, "unique_id": true}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckAuthenticatorManagement_NonCompliant(t *testing.T) {
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
			wantContains: "password policy not configured",
		},
		{
			name:         "password_policy only",
			input:        `{"password_policy": true}`,
			wantContains: "key management not configured",
		},
		{
			name:         "password_policy + key_management no mfa",
			input:        `{"password_policy": true, "key_management": true}`,
			wantContains: "MFA not enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkAuthenticatorManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuthenticatorManagement: %v", err)
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

func TestCheckCredentialManagement_NonCompliant(t *testing.T) {
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
			wantContains: "credential rotation not configured",
		},
		{
			name:         "rotation only no revocation",
			input:        `{"key_rotation": true}`,
			wantContains: "credential revocation not configured",
		},
		{
			name:         "revocation only no rotation",
			input:        `{"revocation": true}`,
			wantContains: "credential rotation not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkCredentialManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCredentialManagement: %v", err)
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

func TestCheckCredentialManagement_CompliantWithoutAudit(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant with rotation + revocation but no audit (audit is evidence-only)
	r, err := m.checkCredentialManagement(ctx, []byte(`{"key_rotation": true, "revocation": true}`))
	if err != nil {
		t.Fatalf("checkCredentialManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

// --- Non-compliant branch tests for IP family ---

func TestCheckKeyManagement_NonCompliant(t *testing.T) {
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
			wantContains: "key management not configured",
		},
		{
			name:         "key_management only no rotation",
			input:        `{"key_management": true}`,
			wantContains: "key rotation not configured",
		},
		{
			name:         "rotation only no key_management",
			input:        `{"key_rotation": true}`,
			wantContains: "key management not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkKeyManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkKeyManagement: %v", err)
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

func TestCheckKeyManagement_CompliantWithoutFIPS(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant with key_management + rotation but no FIPS (FIPS is evidence-only)
	r, err := m.checkKeyManagement(ctx, []byte(`{"key_management": true, "key_rotation": true}`))
	if err != nil {
		t.Fatalf("checkKeyManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckEndpointProtection_NonCompliant(t *testing.T) {
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
			wantContains: "anti-malware not configured",
		},
		{
			name:         "antimalware only no hardening no edr",
			input:        `{"antimalware": true}`,
			wantContains: "endpoint hardening or EDR not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkEndpointProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEndpointProtection: %v", err)
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

func TestCheckEndpointProtection_CompliantWithHardening(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: antimalware + hardening (no EDR)
	r, err := m.checkEndpointProtection(ctx, []byte(`{"antimalware": true, "hardening": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckEndpointProtection_CompliantWithEDR(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: antimalware + EDR (no hardening)
	r, err := m.checkEndpointProtection(ctx, []byte(`{"antimalware": true, "edr": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckNetworkProtection_NonCompliant(t *testing.T) {
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
			wantContains: "firewall/WAF not configured",
		},
		{
			name:         "firewall only no segmentation no egress",
			input:        `{"firewall": true}`,
			wantContains: "network segmentation or egress filtering not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkNetworkProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkNetworkProtection: %v", err)
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

func TestCheckNetworkProtection_CompliantWithEgress(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: firewall + egress filtering (no segmentation)
	r, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "egress_filter": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckMalwareProtection_NonCompliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMalwareProtection(ctx, []byte(`{"nothing": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %q", string(r.Status))
	}
}

func TestCheckMalwareProtection_CompliantWithUpdates(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: antimalware + signature updates (no scan points)
	r, err := m.checkMalwareProtection(ctx, []byte(`{"antimalware": true, "signature_update": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckVulnerabilityManagement_NonCompliant(t *testing.T) {
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
			wantContains: "vulnerability scanning not configured",
		},
		{
			name:         "vuln scan only no remediation",
			input:        `{"vulnerability_scan": true}`,
			wantContains: "patch remediation not configured",
		},
		{
			name:         "remediation only no vuln scan",
			input:        `{"patch": true}`,
			wantContains: "vulnerability scanning not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkVulnerabilityManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkVulnerabilityManagement: %v", err)
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

func TestCheckVulnerabilityManagement_CompliantWithRiskRating(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: vuln scan + remediation with risk rating (evidence)
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`{"vulnerability_scan": true, "patch": true, "cvss": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckVulnerabilityManagement_CompliantWithoutRiskRating(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: vuln scan + remediation without risk rating
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`{"vulnerability_scan": true, "remediation": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

func TestCheckBackupAndRecovery_NonCompliant(t *testing.T) {
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
			wantContains: "backup procedures not configured",
		},
		{
			name:         "backup only no recovery test",
			input:        `{"backup": true}`,
			wantContains: "recovery testing not configured",
		},
		{
			name:         "no backup no recovery",
			input:        `{"nothing": true}`,
			wantContains: "backup procedures not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkBackupAndRecovery(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkBackupAndRecovery: %v", err)
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

func TestCheckBackupAndRecovery_CompliantWithoutOffsite(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: backup + recovery test but no offsite (offsite is evidence-only)
	r, err := m.checkBackupAndRecovery(ctx, []byte(`{"backup": true, "recovery_test": true}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
}

// --- Additional pattern-matching coverage ---

func TestHasRBAC_PatternVariants(t *testing.T) {
	m := NewHITRUSTModule()

	tests := []struct {
		input  string
		expect bool
	}{
		{input: `{"role_based": true}`, expect: true},
		{input: `{"abac": true}`, expect: true},
		{input: `{"attribute_based": true}`, expect: true},
		{input: `{"roles": true}`, expect: true},
		{input: `{"nothing": true}`, expect: false},
	}

	for _, tt := range tests {
		got := m.hasRBAC(tt.input)
		if got != tt.expect {
			t.Errorf("hasRBAC(%q) = %v, want %v", tt.input, got, tt.expect)
		}
	}
}

func TestHasAudit_PatternVariants(t *testing.T) {
	m := NewHITRUSTModule()

	tests := []struct {
		input  string
		expect bool
	}{
		{input: `{"logging_enabled": true}`, expect: true},
		{input: `{"audit_enabled": true}`, expect: true},
		{input: `{"log_integrity": true}`, expect: true},
		{input: `{"hash_chain": true}`, expect: true},
		{input: `{"siem": true}`, expect: true},
		{input: `{"nothing": true}`, expect: false},
	}

	for _, tt := range tests {
		got := m.hasAudit(tt.input)
		if got != tt.expect {
			t.Errorf("hasAudit(%q) = %v, want %v", tt.input, got, tt.expect)
		}
	}
}

// --- Additional variant pattern tests for better coverage ---

func TestCheckLogicalAccess_CompliantWithVariants(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test with alternate patterns: auth_enabled + need_to_know + roles
	r, err := m.checkLogicalAccess(ctx, []byte(`{"roles": true, "auth_enabled": true, "need_to_know": true}`))
	if err != nil {
		t.Fatalf("checkLogicalAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with RBAC variants, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckAccessReview_CompliantWithVariants(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test with siem audit pattern + review keyword
	r, err := m.checkAccessReview(ctx, []byte(`{"rbac": true, "siem": true, "review": true}`))
	if err != nil {
		t.Fatalf("checkAccessReview: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with siem audit pattern, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckPrivilegedAccess_CompliantWithAdmin(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test "admin" as privileged access keyword
	r, err := m.checkPrivilegedAccess(ctx, []byte(`{"rbac": true, "mfa": true, "audit_log": true, "admin": true}`))
	if err != nil {
		t.Fatalf("checkPrivilegedAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with admin keyword, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckPrivilegedAccess_CompliantWithPAM(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test "pam" as privileged access keyword
	r, err := m.checkPrivilegedAccess(ctx, []byte(`{"rbac": true, "mfa": true, "siem": true, "pam": true}`))
	if err != nil {
		t.Fatalf("checkPrivilegedAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with pam keyword, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckEndpointProtection_CompliantWithAllEvidence(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Full evidence: antimalware + hardening + EDR
	r, err := m.checkEndpointProtection(ctx, []byte(`{"antimalware": true, "hardening": true, "edr": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(r.Evidence))
	}
}

func TestCheckNetworkProtection_CompliantWithSegmentation(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: firewall + segmentation
	r, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "network_segmentation": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckNetworkProtection_CompliantWithDMZ(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: firewall + DMZ
	r, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "dmz": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with DMZ, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckNetworkProtection_CompliantWithEgressFilteringKeyword(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: firewall + egress_filtering (alternate keyword)
	r, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "egress_filtering": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with egress_filtering, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckMalwareProtection_CompliantWithScanPoints(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant: antimalware + scan points
	r, err := m.checkMalwareProtection(ctx, []byte(`{"antimalware": true, "file_upload": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckMalwareProtection_CompliantWithAllEvidence(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Full evidence: antimalware + updates + scan points
	r, err := m.checkMalwareProtection(ctx, []byte(`{"antimalware": true, "signature_update": true, "scan_entry": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
	if len(r.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(r.Evidence))
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
		t.Errorf("expected non_compliant, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckMFA_CompliantWithRemoteAccess(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkMFA(ctx, []byte(`{"mfa": true, "remote_access": true}`))
	if err != nil {
		t.Fatalf("checkMFA: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
	if !strings.Contains(r.Message, "remote") {
		t.Errorf("expected message to mention remote, got %q", r.Message)
	}
}

func TestCheckUserAuthentication_NonCompliant(t *testing.T) {
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
			wantContains: "authentication not configured",
		},
		{
			name:         "auth only no unique_id no mfa",
			input:        `{"authentication": true}`,
			wantContains: "unique user identification not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkUserAuthentication(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkUserAuthentication: %v", err)
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

func TestCheckPasswordManagement_NonCompliant(t *testing.T) {
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
			wantContains: "password policy not configured",
		},
		{
			name:         "min_length only no policy",
			input:        `{"min_length": 12}`,
			wantContains: "password policy not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkPasswordManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPasswordManagement: %v", err)
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

// --- Firewall and vulnerability pattern variant tests ---

func TestCheckNetworkProtection_FirewallVariants(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test WAF pattern
	r, err := m.checkNetworkProtection(ctx, []byte(`{"waf": true, "network_segmentation": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with WAF, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckNetworkProtection_NetworkPolicyAsFirewall(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test network_policy as both firewall and egress
	r, err := m.checkNetworkProtection(ctx, []byte(`{"network_policy": true, "egress_filter": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with network_policy + egress_filter, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckVulnerabilityManagement_VulnPatternVariants(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name   string
		input  string
		status string
	}{
		{
			name:   "scanner + remediation",
			input:  `{"scanner": true, "remediation": true}`,
			status: "compliant",
		},
		{
			name:   "patch_management + remediation",
			input:  `{"patch_management": true, "patch": true}`,
			status: "compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := m.checkVulnerabilityManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkVulnerabilityManagement: %v", err)
			}
			if strings.ToLower(string(r.Status)) != tt.status {
				t.Errorf("expected %s, got %q: %q", tt.status, string(r.Status), r.Message)
			}
		})
	}
}

func TestCheckSessionManagement_CompliantWithIdleTimeout(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	r, err := m.checkSessionManagement(ctx, []byte(`{"idle_timeout": 900, "authentication": true}`))
	if err != nil {
		t.Fatalf("checkSessionManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with idle_timeout, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckLogicalAccess_CompliantWithAlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test minimize as least_privilege alternative
	r, err := m.checkLogicalAccess(ctx, []byte(`{"rbac": true, "authentication": true, "minimize": true}`))
	if err != nil {
		t.Fatalf("checkLogicalAccess: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with minimize keyword, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckIdentityVerification_CompliantWithAlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test identity keyword for unique_id
	r, err := m.checkIdentityVerification(ctx, []byte(`{"authentication": true, "identity": true}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with identity keyword, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckIdentityVerification_CompliantWithMFANoEvidence(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant with MFA - check evidence includes MFA mention
	r, err := m.checkIdentityVerification(ctx, []byte(`{"authentication": true, "user_id": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
	foundMFA := false
	for _, e := range r.Evidence {
		if strings.Contains(strings.ToLower(e), "mfa") {
			foundMFA = true
		}
	}
	if !foundMFA {
		t.Errorf("expected MFA in evidence when mfa=true, got %v", r.Evidence)
	}
}

func TestCheckAuthenticatorManagement_CompliantWithKeyRotation(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test key_rotation as alternate for key_management
	r, err := m.checkAuthenticatorManagement(ctx, []byte(`{"password_policy": true, "key_rotation": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckEncryptionAtRest_CompliantWithFIPS(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test fips_140 as trigger for hasEncryption
	r, err := m.checkEncryptionAtRest(ctx, []byte(`{"fips_140": true}`))
	if err != nil {
		t.Fatalf("checkEncryptionAtRest: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with FIPS, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckEncryptionInTransit_CompliantWithTLS13(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test TLS 1.3 specific detection
	r, err := m.checkEncryptionInTransit(ctx, []byte(`{"tls1.3": true}`))
	if err != nil {
		t.Fatalf("checkEncryptionInTransit: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with TLS 1.3, got %q: %q", string(r.Status), r.Message)
	}
	// Check that evidence mentions TLS 1.3
	foundTLS13 := false
	for _, e := range r.Evidence {
		if strings.Contains(e, "TLS 1.3") {
			foundTLS13 = true
		}
	}
	if !foundTLS13 {
		t.Errorf("expected TLS 1.3 in evidence, got %v", r.Evidence)
	}
}

func TestCheckEncryptionInTransit_CompliantWithEncryptionPattern(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test hasEncryption pattern detection (data_encrypted)
	r, err := m.checkEncryptionInTransit(ctx, []byte(`{"data_encrypted": true}`))
	if err != nil {
		t.Fatalf("checkEncryptionInTransit: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with data_encrypted, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckKeyManagement_CompliantWithFIPS(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Key management + rotation with FIPS evidence
	r, err := m.checkKeyManagement(ctx, []byte(`{"key_management_enabled": true, "rotation_policy": true, "fips_mode": true}`))
	if err != nil {
		t.Fatalf("checkKeyManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
	foundFIPS := false
	for _, e := range r.Evidence {
		if strings.Contains(e, "FIPS") {
			foundFIPS = true
		}
	}
	if !foundFIPS {
		t.Errorf("expected FIPS in evidence when fips_mode=true, got %v", r.Evidence)
	}
}

func TestCheckCredentialManagement_CompliantWithAuditEvidence(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Compliant with audit evidence
	r, err := m.checkCredentialManagement(ctx, []byte(`{"key_rotation": true, "revocation": true, "audit_log": true}`))
	if err != nil {
		t.Fatalf("checkCredentialManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
	foundAudit := false
	for _, e := range r.Evidence {
		if strings.Contains(strings.ToLower(e), "audit") {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Errorf("expected audit in evidence, got %v", r.Evidence)
	}
}

func TestCheckEncryptionAtRest_CompliantWithKeyMgmtEvidence(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Encryption at rest with key management evidence
	r, err := m.checkEncryptionAtRest(ctx, []byte(`{"encryption_at_rest": true, "key_management": true}`))
	if err != nil {
		t.Fatalf("checkEncryptionAtRest: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
	foundKeyMgmt := false
	for _, e := range r.Evidence {
		if strings.Contains(strings.ToLower(e), "key management") {
			foundKeyMgmt = true
		}
	}
	if !foundKeyMgmt {
		t.Errorf("expected key management in evidence, got %v", r.Evidence)
	}
}

func TestCheckBackupAndRecovery_CompliantWithOffsite(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Full backup with offsite evidence
	r, err := m.checkBackupAndRecovery(ctx, []byte(`{"backup": true, "recovery_test": true, "offsite": true}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q", string(r.Status))
	}
	foundOffsite := false
	for _, e := range r.Evidence {
		if strings.Contains(strings.ToLower(e), "off-site") {
			foundOffsite = true
		}
	}
	if !foundOffsite {
		t.Errorf("expected off-site in evidence, got %v", r.Evidence)
	}
}

func TestCheckBackupAndRecovery_AlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test alternate keywords: data_backup + disaster_recovery
	r, err := m.checkBackupAndRecovery(ctx, []byte(`{"data_backup": true, "disaster_recovery": true}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with alternate keywords, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckVulnerabilityManagement_CompliantWithCVSS(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test cvss (both a vulnPattern and risk rating)
	r, err := m.checkVulnerabilityManagement(ctx, []byte(`{"cvss": true, "patch": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with cvss + patch, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckEndpointProtection_AlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test anti_malware + secure_baseline
	r, err := m.checkEndpointProtection(ctx, []byte(`{"anti_malware": true, "secure_baseline": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with anti_malware + secure_baseline, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckEndpointProtection_HostIDS(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test endpoint_protection + host_ids
	r, err := m.checkEndpointProtection(ctx, []byte(`{"endpoint_protection": true, "host_ids": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with endpoint_protection + host_ids, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckNetworkProtection_ProxyAsFirewall(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test proxy as firewall pattern + egress
	r, err := m.checkNetworkProtection(ctx, []byte(`{"proxy": true, "egress_filter": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant with proxy + egress, got %q: %q", string(r.Status), r.Message)
	}
}

func TestCheckMalwareProtection_AlternateKeywords(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	// Test malware_protection keyword
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

	// Test auto_update + email_scan
	r, err := m.checkMalwareProtection(ctx, []byte(`{"anti_malware": true, "auto_update": true, "email_scan": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %q: %q", string(r.Status), r.Message)
	}
}
