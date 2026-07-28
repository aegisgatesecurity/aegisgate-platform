// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Promoted CheckFuncs v2 Tests
// =========================================================================
//
// Tests for the 38 controls promoted/added in v3.6.0 (T8):
//   Phase 1 (13 promoted from manual stubs):
//     AC-8, AC-20, IA-9, IA-11, SC-40, IR-2, IR-3, SA-8,
//     CP-3, CP-4, CP-6, CP-7, CP-8
//   Phase 2 (25 new controls):
//     AT-2, AT-3, CA-2, CA-5, CA-7, CM-10, CM-12, PE-1,
//     MP-1, SI-1, SI-11, SI-14, SR-1, AU-12(1), SC-7(5),
//     AC-2(1), AC-2(3), AC-17(1), IA-2(1), IA-2(2),
//     AU-6(1), RA-5(1), SC-7(8), SC-28(1), SI-4(2)
//
// =========================================================================

package fedramp

import (
	"context"
	"testing"
)

func TestCheckSystemUseNotification(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "banner and auth", input: "login_banner authentication", wantPass: true},
		{name: "notification and login", input: "notification login", wantPass: true},
		{name: "tos and auth", input: "tos auth_enabled", wantPass: true},
		{name: "banner only", input: "system_banner", wantPass: false},
		{name: "auth only", input: "authentication", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSystemUseNotification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckUseOfExternalSystems(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "trust framework and boundary", input: "trust_framework capability_contract deny_by_default", wantPass: true},
		{name: "trust only", input: "trust_framework capability_contract", wantPass: false},
		{name: "boundary only", input: "deny_by_default fail_closed", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkUseOfExternalSystems(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckNonOrganizationalUserAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "api_key and auth", input: "api_key authentication oauth", wantPass: true},
		{name: "token and auth", input: "token auth_enabled", wantPass: true},
		{name: "api_key only", input: "api_key", wantPass: false},
		{name: "auth only", input: "authentication", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkNonOrganizationalUserAuth(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckReAuthentication(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "MFA and privileged", input: "mfa privileged rbac", wantPass: true},
		{name: "multi_factor and admin", input: "multi_factor admin", wantPass: true},
		{name: "MFA only", input: "mfa enabled", wantPass: false},
		{name: "privileged only", input: "privileged rbac", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkReAuthentication(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckWirelessLinkProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "TLS enforced", input: "tls_1.2 enforced", wantPass: true},
		{name: "encryption required", input: "encryption required", wantPass: true},
		{name: "TLS not enforced", input: "tls", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkWirelessLinkProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckIRTraining(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "playbook and timeline", input: "playbook soc timeline", wantPass: true},
		{name: "incident and response", input: "incident response", wantPass: true},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIRTraining(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckIRTesting(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "benchmark and playbook", input: "adversarial benchmark playbook", wantPass: true},
		{name: "benchmark only", input: "adversarial benchmark scanning", wantPass: false},
		{name: "playbook only", input: "incident playbook test", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIRTesting(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckSecurityEngineeringPrinciples(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "fail-closed and threat model", input: "fail_closed stride threat_model", wantPass: true},
		{name: "deny and security by design", input: "deny_by_default security_by_design", wantPass: true},
		{name: "fail-closed only", input: "fail_closed", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSecurityEngineeringPrinciples(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckContingencyTraining(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "playbook and recovery", input: "playbook contingency recovery", wantPass: true},
		{name: "incident and backup", input: "incident backup", wantPass: true},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkContingencyTraining(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckAlternateStorageSite(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "replication and backup", input: "replication postgres backup", wantPass: true},
		{name: "persistence and evidence", input: "persistence evidence retention", wantPass: true},
		{name: "replication only", input: "postgres replication", wantPass: false},
		{name: "backup only", input: "backup retention", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAlternateStorageSite(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckAlternateProcessingSite(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "deploy and config", input: "deploy single_binary configuration", wantPass: true},
		{name: "container and platformconfig", input: "container platformconfig env", wantPass: true},
		{name: "deploy only", input: "deploy container", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAlternateProcessingSite(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckTelecomServices(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "endpoints and redundancy", input: "endpoint api failover ha", wantPass: true},
		{name: "multi_endpoint and redundancy", input: "multi_endpoint redundancy", wantPass: true},
		{name: "endpoints only", input: "endpoint api", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTelecomServices(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

// Phase 2: New controls tests

func TestCheckSecurityAwarenessTraining(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "training and RBAC", input: "training awareness rbac roles", wantPass: true},
		{name: "onboarding and permissions", input: "onboarding permissions", wantPass: true},
		{name: "training only", input: "training content", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSecurityAwarenessTraining(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckMFAForNetworkAccess(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "MFA and network", input: "mfa network access", wantPass: true},
		{name: "2fa and remote", input: "2fa remote", wantPass: true},
		{name: "MFA only", input: "mfa enabled", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMFAForNetworkAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckEncryptionAtRestVerification(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "encryption and key management", input: "encryption aes key_management", wantPass: true},
		{name: "encrypted and fips", input: "encrypted fips kms", wantPass: true},
		{name: "encryption only", input: "encryption at_rest", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEncryptionAtRestVerification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckSystemMonitoringAlerts(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "anomaly and alerting", input: "anomaly_detection alert siem", wantPass: true},
		{name: "ioc and monitoring", input: "ioc threat monitoring", wantPass: true},
		{name: "anomaly only", input: "anomaly_detection", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSystemMonitoringAlerts(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckSupplyChainRiskManagement(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "AIBOM and SBOM", input: "aibom provenance sbom dependency", wantPass: true},
		{name: "supply_chain and component", input: "supply_chain component", wantPass: true},
		{name: "aibom only", input: "aibom provenance", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSupplyChainRiskManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckContinuousMonitoringVerification(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "CCM and IOC", input: "ccm continuous monitoring ioc", wantPass: true},
		{name: "monitoring and threat", input: "monitoring threat_intelligence", wantPass: true},
		{name: "ccm only", input: "ccm", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkContinuousMonitoringVerification(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckAuditLogGeneration(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "audit ring and TSA", input: "audit_ring hash_chain timestamp tsa", wantPass: true},
		{name: "audit_log and time", input: "audit_log time", wantPass: true},
		{name: "audit only", input: "audit_log", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditLogGeneration(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckBoundaryProtectionRestricts(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "proxy and deny", input: "proxy deny restrict", wantPass: true},
		{name: "MCP and block", input: "mcp block", wantPass: true},
		{name: "proxy only", input: "proxy http", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkBoundaryProtectionRestricts(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}

func TestCheckNetworkIsolation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{name: "isolation and proxy", input: "isolation segment proxy", wantPass: true},
		{name: "boundary and MCP", input: "boundary mcp", wantPass: true},
		{name: "isolation only", input: "isolation", wantPass: false},
		{name: "empty", input: "", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkNetworkIsolation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPass && result.Status != "compliant" {
				t.Errorf("expected compliant, got %s: %s", result.Status, result.Message)
			}
			if !tt.wantPass && result.Status == "compliant" {
				t.Errorf("expected non-compliant, got compliant: %s", result.Message)
			}
		})
	}
}