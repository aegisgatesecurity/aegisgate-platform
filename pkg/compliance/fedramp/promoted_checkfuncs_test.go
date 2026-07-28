// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Promoted CheckFuncs Tests
// =========================================================================
//
// Tests for the 7 controls promoted from manual_stubs.go to automated
// CheckFuncs in v3.5.0 Phase 3:
//   - AC-10: Concurrent Session Control
//   - IA-10: Adversary Detection
//   - IR-10: Incident Response Integration
//   - SC-6:  Protection at System Boundaries
//   - SC-22: Fail-Safe Network
//   - CM-9:  Configuration Management Plan
//   - CM-11: Software Installation Restrictions
//
// =========================================================================

package fedramp

import (
	"context"
	"testing"
)

func TestCheckConcurrentSessionControl(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "session limits and RBAC",
			input:    "session_limit=5 max_sessions rbac roles",
			wantPass: true,
		},
		{
			name:     "concurrent and RBAC",
			input:    "concurrent_sessions rbac_enabled",
			wantPass: true,
		},
		{
			name:     "session limits only",
			input:    "session_limit configured session_timeout=30m",
			wantPass: false, // partial — needs RBAC
		},
		{
			name:     "RBAC only",
			input:    "rbac_enabled roles defined",
			wantPass: false, // partial — needs session limits
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkConcurrentSessionControl(ctx, []byte(tt.input))
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

func TestCheckAdversaryDetection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "anomaly detection and auth",
			input:    "anomaly_detection enabled authentication mfa_configured",
			wantPass: true,
		},
		{
			name:     "IOC and auth",
			input:    "ioc threat_intelligence auth_enabled",
			wantPass: true,
		},
		{
			name:     "anomaly only",
			input:    "anomaly_detection enabled",
			wantPass: false, // partial — needs auth
		},
		{
			name:     "auth only",
			input:    "authentication mfa_enabled",
			wantPass: false, // partial — needs anomaly detection
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAdversaryDetection(ctx, []byte(tt.input))
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

func TestCheckIRIntegration(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "SIEM and audit",
			input:    "siem_enabled splunk audit_log active",
			wantPass: true,
		},
		{
			name:     "SIEM and audit ring",
			input:    "siem elasticsearch audit_ring",
			wantPass: true,
		},
		{
			name:     "SIEM only",
			input:    "siem_enabled qradar",
			wantPass: false, // partial — needs audit
		},
		{
			name:     "audit only",
			input:    "audit_log active",
			wantPass: false, // partial — needs SIEM
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIRIntegration(ctx, []byte(tt.input))
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

func TestCheckBoundaryProtectionSC6(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "proxy and deny-by-default",
			input:    "proxy http deny_by_default",
			wantPass: true,
		},
		{
			name:     "MCP and fail-closed",
			input:    "mcp_server mcp fail_closed",
			wantPass: true,
		},
		{
			name:     "proxy only",
			input:    "proxy http enabled",
			wantPass: false, // partial — needs deny-by-default
		},
		{
			name:     "deny-by-default only",
			input:    "deny_by_default block",
			wantPass: false, // partial — needs protocol pillar
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkBoundaryProtectionSC6(ctx, []byte(tt.input))
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

func TestCheckFailSafeNetwork(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "deny-by-default",
			input:    "deny_by_default configured",
			wantPass: true,
		},
		{
			name:     "fail-closed with failover",
			input:    "fail_closed high_availability failover",
			wantPass: true,
		},
		{
			name:     "default deny",
			input:    "default_deny block_unknown",
			wantPass: true,
		},
		{
			name:     "failover only",
			input:    "failover ha redundancy",
			wantPass: false, // needs deny-by-default
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkFailSafeNetwork(ctx, []byte(tt.input))
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

func TestCheckConfigurationManagementPlan(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "config subsystem",
			input:    "configuration platformconfig version=3.4.3",
			wantPass: true,
		},
		{
			name:     "config with baseline",
			input:    "config cm_baseline change_management",
			wantPass: true,
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkConfigurationManagementPlan(ctx, []byte(tt.input))
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

func TestCheckSoftwareInstallationRestrictions(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantPass bool
	}{
		{
			name:     "admin-only and RBAC",
			input:    "admin_only install_restrictions rbac roles",
			wantPass: true,
		},
		{
			name:     "restricted and RBAC",
			input:    "restricted_permissions rbac_enabled",
			wantPass: true,
		},
		{
			name:     "admin-only only",
			input:    "admin_only install_restrictions",
			wantPass: false, // partial — needs RBAC
		},
		{
			name:     "RBAC only",
			input:    "rbac permissions roles",
			wantPass: false, // partial — needs admin restrictions
		},
		{
			name:     "empty input",
			input:    "",
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSoftwareInstallationRestrictions(ctx, []byte(tt.input))
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
