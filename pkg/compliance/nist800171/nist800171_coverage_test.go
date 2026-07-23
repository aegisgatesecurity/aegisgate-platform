// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - NIST 800-171 Coverage Gap Tests
// =========================================================================
// Targets 14 check functions + Dependencies() to push coverage from 70.2% → 80%+.
// Each check function tests: compliant, partial, non_compliant paths.
// =========================================================================

package nist800171

import (
	"context"
	"testing"
)

func TestNIST800171_AccessEnforcement_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant RBAC path", input: `{"rbac": true, "authentication": true, "access_policy": true}`, wantStatus: "compliant"},
		{name: "compliant ABAC path", input: `{"abac": true, "attributes": true, "auth_enabled": true, "policy_enforcement": true}`, wantStatus: "compliant"},
		{name: "non_compliant RBAC-only no auth", input: `{"rbac": true, "roles": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty input", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant ABAC no enforcement", input: `{"abac": true, "attributes": true, "authentication": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccessEnforcement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccessEnforcement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_LeastPrivilege_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant with roles and least_privilege", input: `{"rbac": true, "roles": "admin,user,viewer", "least_privilege": true}`, wantStatus: "compliant"},
		{name: "compliant with role def admin and user", input: `{"rbac": true, "roles": "admin,user", "least_privilege": true}`, wantStatus: "compliant"},
		{name: "non_compliant wildcard access", input: `{"rbac": true, "roles": "admin", "wildcard": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant permit_all", input: `{"rbac": true, "permit_all": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant RBAC-only without role def", input: `{"rbac": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty input", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkLeastPrivilege(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkLeastPrivilege: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_PermittedActionsWithoutAuth_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant health check", input: `{"health_check": true}`, wantStatus: "compliant"},
		{name: "compliant public status", input: `{"public_status": true}`, wantStatus: "compliant"},
		{name: "compliant trust portal", input: `{"trust_portal": true}`, wantStatus: "compliant"},
		{name: "non_compliant unauth write", input: `{"unauth_write": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant anonymous write", input: `{"anonymous_write": true}`, wantStatus: "non_compliant"},
		{name: "partial empty input", input: `{}`, wantStatus: "partial"},
		{name: "partial health check with unauth write", input: `{"health_check": true, "unauth_write": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkPermittedActionsWithoutAuth(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPermittedActionsWithoutAuth: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_RemoteAccess_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant all three", input: `{"mfa": true, "tls": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "non_compliant no MFA", input: `{"tls": true, "monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no TLS", input: `{"mfa": true, "monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no monitoring", input: `{"mfa": true, "tls": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRemoteAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRemoteAccess: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AuditRecordContent_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant 5 fields", input: `{"event_type": true, "timestamp": true, "source": true, "user_id": true, "result": true}`, wantStatus: "compliant"},
		{name: "compliant 4 fields", input: `{"action": true, "timestamp": true, "endpoint": true, "actor": true}`, wantStatus: "compliant"},
		{name: "partial 3 fields", input: `{"event_type": true, "timestamp": true, "source": true}`, wantStatus: "partial"},
		{name: "partial 2 fields", input: `{"event_type": true, "timestamp": true}`, wantStatus: "partial"},
		{name: "non_compliant one field only", input: `{"event_type": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditRecordContent(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditRecordContent: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AuditReview_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant with anomaly detection", input: `{"audit_log": true, "anomaly_detection": true, "alert": true}`, wantStatus: "compliant"},
		{name: "compliant with SIEM and review", input: `{"audit_search": true, "siem": true, "review": true}`, wantStatus: "compliant"},
		{name: "non_compliant no SIEM no anomaly", input: `{"audit_log": true, "monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no audit", input: `{"anomaly_detection": true, "alert": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditReview(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditReview: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AuditProtection_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant hash chain + auth", input: `{"hash_chain": true, "rbac": true}`, wantStatus: "compliant"},
		{name: "compliant log integrity + auth", input: `{"log_integrity": true, "auth": true}`, wantStatus: "compliant"},
		{name: "partial hash chain only", input: `{"hash_chain": true}`, wantStatus: "partial"},
		{name: "partial log integrity only", input: `{"log_integrity": true}`, wantStatus: "partial"},
		{name: "non_compliant no hash chain", input: `{"rbac": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_BaselineConfig_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant all three", input: `{"sbom": true, "version": true, "dependencies": true}`, wantStatus: "compliant"},
		{name: "partial sbom + version no deps", input: `{"sbom": true, "version": true}`, wantStatus: "partial"},
		{name: "partial sbom only", input: `{"sbom": true}`, wantStatus: "partial"},
		{name: "partial version only", input: `{"version": true}`, wantStatus: "partial"},
		{name: "non_compliant no baseline", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant only deps", input: `{"dependencies": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkBaselineConfig(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkBaselineConfig: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_FlawRemediation_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant scanner + patch", input: `{"scanner": true, "patch": true}`, wantStatus: "compliant"},
		{name: "compliant vulnerability + remediation", input: `{"vulnerability": true, "remediation": true}`, wantStatus: "compliant"},
		{name: "compliant scanner + SBOM", input: `{"scanner": true, "sbom": true}`, wantStatus: "compliant"},
		{name: "non_compliant no patching", input: `{"scanner": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no scanner", input: `{"patch": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkFlawRemediation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkFlawRemediation: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_IncidentHandling_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant incident response + monitoring", input: `{"incident_response": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "compliant IOC + SIEM", input: `{"ioc": true, "siem": true}`, wantStatus: "compliant"},
		{name: "non_compliant no IR plan", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no monitoring", input: `{"incident_response": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentHandling(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentHandling: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_IncidentMonitoring_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant SIEM + tracking", input: `{"siem": true, "tracking": true}`, wantStatus: "compliant"},
		{name: "compliant monitoring + ticket", input: `{"monitoring": true, "ticket": true}`, wantStatus: "compliant"},
		{name: "non_compliant no SIEM", input: `{"tracking": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no tracking", input: `{"siem": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_VulnerabilityScanning_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant scanning + remediation", input: `{"vulnerability": true, "remediation": true}`, wantStatus: "compliant"},
		{name: "compliant vuln_scan + patching", input: `{"vuln_scan": true, "patching": true}`, wantStatus: "compliant"},
		{name: "compliant cve + fix", input: `{"cve": true, "fix": true}`, wantStatus: "compliant"},
		{name: "non_compliant no scanner", input: `{"remediation": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no remediation", input: `{"vulnerability": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkVulnerabilityScanning(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkVulnerabilityScanning: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_VulnerabilityMonitoring_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant monitoring + threat intel", input: `{"monitoring": true, "threat_intel": true}`, wantStatus: "compliant"},
		{name: "compliant SIEM + IOC", input: `{"siem": true, "ioc": true}`, wantStatus: "compliant"},
		{name: "non_compliant no monitoring", input: `{"threat_intel": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no threat intel", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkVulnerabilityMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkVulnerabilityMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_BoundaryProtection_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant firewall + monitoring", input: `{"firewall": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "compliant boundary + audit_log", input: `{"boundary": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant network_segmentation + logging", input: `{"network_segmentation": true, "logging": true}`, wantStatus: "compliant"},
		{name: "non_compliant no boundary", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no monitoring", input: `{"firewall": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkBoundaryProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkBoundaryProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AccountManagement_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant all three", input: `{"authentication": true, "rbac": true, "session_timeout": true}`, wantStatus: "compliant"},
		{name: "compliant auth_enabled variant", input: `{"auth_enabled": true, "roles": true, "idle_timeout": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing auth", input: `{"rbac": true, "session_timeout": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing rbac", input: `{"authentication": true, "session_timeout": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing session timeout", input: `{"authentication": true, "rbac": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccountManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccountManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_ConfigSettings_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant secure defaults + config audit", input: `{"secure_default": true, "config_audit": true}`, wantStatus: "compliant"},
		{name: "compliant secure defaults + enforcement", input: `{"secure_defaults": true, "policy_enforcement": true}`, wantStatus: "compliant"},
		{name: "compliant secure defaults + hardening", input: `{"secure_default": true, "hardening": true}`, wantStatus: "compliant"},
		{name: "non_compliant no secure defaults", input: `{"config_audit": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkConfigSettings(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkConfigSettings: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AccessRestrictionsForChange_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant all three", input: `{"rbac": true, "audit_log": true, "change_control": true}`, wantStatus: "compliant"},
		{name: "compliant with review", input: `{"rbac": true, "logging_enabled": true, "review": true}`, wantStatus: "compliant"},
		{name: "compliant with approval", input: `{"roles": true, "audit_enabled": true, "approval": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing rbac", input: `{"audit_log": true, "change_control": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccessRestrictionsForChange(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccessRestrictionsForChange: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_MaliciousCodeProtection_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant malware scan + IOC", input: `{"malware_scan": true, "ioc": true}`, wantStatus: "compliant"},
		{name: "compliant antivirus + indicators", input: `{"antivirus": true, "indicators": true}`, wantStatus: "compliant"},
		{name: "compliant scanner + prompt injection", input: `{"scanner": true, "prompt_injection": true}`, wantStatus: "compliant"},
		{name: "compliant scanner + input validation", input: `{"malware_scan": true, "input_validation": true}`, wantStatus: "compliant"},
		{name: "non_compliant no scanner", input: `{"ioc": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no IOC or injection", input: `{"scanner": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMaliciousCodeProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMaliciousCodeProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_UserIdentification_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant auth + MFA + user_id", input: `{"authentication": true, "mfa": true, "user_id": true}`, wantStatus: "compliant"},
		{name: "compliant auth_enabled + multi_factor + unique_id", input: `{"auth_enabled": true, "multi_factor": true, "unique_id": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing MFA", input: `{"authentication": true, "user_id": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing auth", input: `{"mfa": true, "user_id": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant missing user_id", input: `{"authentication": true, "mfa": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkUserIdentification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkUserIdentification: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AuthenticatorMgmt_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant password + key rotation", input: `{"password_policy": true, "key_rotation": true}`, wantStatus: "compliant"},
		{name: "compliant password + credential lifecycle", input: `{"password": true, "lifecycle": true}`, wantStatus: "compliant"},
		{name: "compliant authenticator + rotation", input: `{"authenticator": true, "rotation": true}`, wantStatus: "compliant"},
		{name: "compliant password_policy + secret_management", input: `{"password_policy": true, "secret_management": true}`, wantStatus: "compliant"},
		{name: "non_compliant no password policy", input: `{"key_rotation": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuthenticatorMgmt(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuthenticatorMgmt: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_NonOrgUserIdentification_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant SSO + auth", input: `{"sso": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant federation + auth_enabled", input: `{"federation": true, "auth_enabled": true}`, wantStatus: "compliant"},
		{name: "compliant OIDC + auth", input: `{"oidc": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant MFA + auth", input: `{"mfa": true, "auth_enabled": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant no auth", input: `{"sso": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no SSO or MFA", input: `{"authentication": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkNonOrgUserIdentification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkNonOrgUserIdentification: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_AuditEvents_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant audit log + integrity", input: `{"audit_log": true, "log_integrity": true}`, wantStatus: "compliant"},
		{name: "compliant audit_enabled + hash_chain", input: `{"audit_enabled": true, "hash_chain": true}`, wantStatus: "compliant"},
		{name: "partial audit log only", input: `{"audit_log": true}`, wantStatus: "partial"},
		{name: "partial logging_enabled only", input: `{"logging_enabled": true}`, wantStatus: "partial"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditEvents(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditEvents: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_IncidentReporting_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant reporting + audit log", input: `{"reporting": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant notification + logging_enabled", input: `{"notification": true, "logging_enabled": true}`, wantStatus: "compliant"},
		{name: "non_compliant no reporting", input: `{"audit_log": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant no audit", input: `{"reporting": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentReporting(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentReporting: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_TransmissionConfidentiality_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant TLS", input: `{"tls": true}`, wantStatus: "compliant"},
		{name: "compliant HTTPS", input: `{"https": true}`, wantStatus: "compliant"},
		{name: "compliant TLS 1.2", input: `{"tls_1_2": true}`, wantStatus: "compliant"},
		{name: "compliant encryption at rest", input: `{"encryption_at_rest": true}`, wantStatus: "compliant"},
		{name: "compliant data encrypted", input: `{"data_encrypted": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTransmissionConfidentiality(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTransmissionConfidentiality: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_CryptographicKeyManagement_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant key management", input: `{"key_management": true}`, wantStatus: "compliant"},
		{name: "compliant key rotation", input: `{"key_rotation": true}`, wantStatus: "compliant"},
		{name: "compliant KMS", input: `{"kms": true}`, wantStatus: "compliant"},
		{name: "partial FIPS only", input: `{"fips_140": true}`, wantStatus: "partial"},
		{name: "partial FIPS mode only", input: `{"fips_mode": true}`, wantStatus: "partial"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCryptographicKeyManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCryptographicKeyManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_CryptographicProtection_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant FIPS 140", input: `{"fips_140": true}`, wantStatus: "compliant"},
		{name: "compliant FIPS mode", input: `{"fips_mode": true}`, wantStatus: "compliant"},
		{name: "compliant CMVP", input: `{"cmvp": true}`, wantStatus: "compliant"},
		{name: "partial encryption at rest", input: `{"encryption_at_rest": true}`, wantStatus: "partial"},
		{name: "partial data encrypted", input: `{"data_encrypted": true}`, wantStatus: "partial"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCryptographicProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCryptographicProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_SystemBackup_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant backup with retention", input: `{"backup": true, "retention": true}`, wantStatus: "compliant"},
		{name: "compliant data_backup with backup_retention", input: `{"data_backup": true, "backup_retention": true}`, wantStatus: "compliant"},
		{name: "compliant backup only", input: `{"backup": true}`, wantStatus: "compliant"},
		{name: "compliant disaster_recovery", input: `{"disaster_recovery": true}`, wantStatus: "compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSystemBackup(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSystemBackup: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_ExternalSystemServices_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant boundary + monitoring", input: `{"boundary": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "compliant trust_boundary + audit_log", input: `{"trust_boundary": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant proxy + approval", input: `{"proxy": true, "approval": true}`, wantStatus: "compliant"},
		{name: "compliant boundary + authorized", input: `{"boundary": true, "authorized": true}`, wantStatus: "compliant"},
		{name: "non_compliant no boundary", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant empty", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkExternalSystemServices(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkExternalSystemServices: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("status = %q; want %q, msg=%s", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestNIST800171_Dependencies_Coverage(t *testing.T) {
	m := NewNIST800171Module()
	deps := m.Dependencies()
	if len(deps) == 0 {
		t.Error("Dependencies() returned empty list")
	}
	expectedDeps := []string{"soc2", "iso27001", "hipaa", "fips", "ioc", "trust"}
	for _, dep := range expectedDeps {
		found := false
		for _, d := range deps {
			if d == dep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Dependencies() missing expected dependency: %s", dep)
		}
	}
}
