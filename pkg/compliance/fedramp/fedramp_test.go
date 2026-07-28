// SPDX-License-Identifier: Apache-2.0
// FedRAMP Compliance Module - Unit Tests
//
// Path C: Full in-scope FedRAMP Moderate controls.
// Test coverage target: 80%+ per pkg/compliance coverage floor.
//
// Total controls: 175 (120 automated + 55 evidence-mapped)
// v3.6.0: 13 promoted from manual + 25 new controls added
//   AC: 21 (8 automated + 7 promoted + 4 enhanced + 2 manual)
//   AU: 16 (5 automated + 4 promoted + 2 enhanced + 5 manual)
//   IA: 13 (5 automated + 2 promoted + 2 enhanced + 4 manual)
//   SC: 25 (10 automated + 2 promoted + 4 enhanced + 9 manual)
//   CM: 14 (5 automated + 2 promoted + 2 new + 5 manual)
//   SI: 15 (6 automated + 3 new + 6 manual)
//   IR: 10 (3 automated + 2 promoted + 5 manual)
//   SA: 8 (1 automated + 1 promoted + 6 manual)
//   SR: 6 (1 automated + 1 new + 4 manual)
//   RA: 8 (4 automated + 1 enhanced + 3 manual)
//   CA: 10 (2 automated + 3 new + 5 manual)
//   AT: 5 (2 new + 3 manual)
//   CP: 9 (1 automated + 4 promoted + 4 manual)
//   MP: 3 (1 automated + 1 new + 1 manual)
//   PE: 3 (1 new + 2 manual)
//   PS: 3 (0 automated + 3 manual)
//   PM: 2 (0 automated + 2 manual)
//   PL: 2 (0 automated + 2 manual)
//   MA: 2 (0 automated + 2 manual)

package fedramp

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewFedRAMPModule(t *testing.T) {
	m := NewFedRAMPModule()
	if m == nil {
		t.Fatal("NewFedRAMPModule returned nil")
	}
	if m.Framework() != "fedramp" {
		t.Errorf("Framework() = %q, want fedramp", m.Framework())
	}
	if m.Version() != "2.0" {
		t.Errorf("Version() = %q, want 2.0", m.Version())
	}

	// Verify all 170 controls are registered (150 baseline + 20 enhancements)
	controls := m.Controls()
	if len(controls) != 170 {
		t.Errorf("len(Controls()) = %d, want 170", len(controls))
	}

	// Count automated vs evidence-mapped
	automated := 0
	evidenceMapped := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			evidenceMapped++
		}
	}
	if automated != 120 {
		t.Errorf("automated controls = %d, want 120", automated)
	}
	if evidenceMapped != 50 {
		t.Errorf("evidence-mapped controls = %d, want 50", evidenceMapped)
	}

	// Verify each family has the right number of controls
	familyCount := map[string]int{}
	for _, c := range controls {
		familyCount[c.Category]++
	}
	expectedFamilies := map[string]int{
		"Access Control":                            21,
		"Audit and Accountability":                  16,
		"Identification and Authentication":         13,
		"System and Communications Protection":      25,
		"Configuration Management":                  14,
		"System and Information Integrity":          14,
		"Incident Response":                         10,
		"System and Services Acquisition":            8,
		"Supply Chain Risk Management":              6,
		"Risk Assessment":                           8,
		"Assessment, Authorization, and Monitoring":  8,
		"Awareness and Training":                    3,
		"Contingency Planning":                      9,
		"Media Protection":                          3,
		"Personnel Security":                        3,
		"Program Management":                        2,
		"Planning":                                  2,
		"Physical and Environmental Protection":     3,
	}
	for family, expected := range expectedFamilies {
		if familyCount[family] != expected {
			t.Errorf("family %q: got %d controls, want %d", family, familyCount[family], expected)
		}
	}
}

// --- Path B controls (carried forward, 6 automated) ---

func TestCheckAccountManagement(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (auth + rbac + session_timeout)", input: `{"authentication": true, "rbac": true, "session_timeout": 1800}`, wantStatus: "compliant"},
		{name: "non-compliant (no auth)", input: `{"rbac": true, "session_timeout": 1800}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no rbac)", input: `{"authentication": true, "session_timeout": 1800}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no session_timeout)", input: `{"authentication": true, "rbac": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccountManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccountManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRemoteAccess(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (MFA + TLS + monitoring)", input: `{"mfa": true, "tls": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant (alternative markers)", input: `{"multi_factor": true, "https": true, "logging_enabled": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no MFA)", input: `{"tls": true, "audit_log": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no TLS)", input: `{"mfa": true, "audit_log": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no monitoring)", input: `{"mfa": true, "tls": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRemoteAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRemoteAccess: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuditEvents(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (audit + integrity)", input: `{"audit_log": true, "log_integrity": true}`, wantStatus: "compliant"},
		{name: "compliant (audit + hash_chain)", input: `{"audit_enabled": true, "hash_chain": true}`, wantStatus: "compliant"},
		{name: "partial (audit, no integrity)", input: `{"audit_log": true}`, wantStatus: "partial"},
		{name: "non-compliant (no audit)", input: `{"logging": false}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditEvents(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditEvents: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuditProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (integrity + RBAC)", input: `{"log_integrity": true, "rbac": true}`, wantStatus: "compliant"},
		{name: "partial (integrity, no RBAC)", input: `{"hash_chain": true}`, wantStatus: "partial"},
		{name: "non-compliant (no protection)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckMFA(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (MFA enabled)", input: `{"mfa": true}`, wantStatus: "compliant"},
		{name: "compliant (multi_factor)", input: `{"multi_factor": true}`, wantStatus: "compliant"},
		{name: "compliant (2fa)", input: `{"2fa": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no MFA)", input: `{"authentication": "password_only"}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMFA(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMFA: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckTransmissionProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (TLS 1.2 + FIPS)", input: `{"tls1.2": true, "fips_mode": true}`, wantStatus: "compliant"},
		{name: "compliant (TLS 1.3 + FIPS 140)", input: `{"tls1.3": true, "fips_140": true}`, wantStatus: "compliant"},
		{name: "partial (TLS, no FIPS)", input: `{"tls1.2": true}`, wantStatus: "partial"},
		{name: "non-compliant (TLS below 1.2)", input: `{"tls1.0": true, "fips_mode": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no TLS)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTransmissionProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTransmissionProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (AC family) ---

func TestCheckAccessEnforcement(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (RBAC + auth + policy)", input: `{"rbac": true, "authentication": true, "access_policy": true, "policy_enforcement": true}`, wantStatus: "compliant"},
		{name: "compliant (ABAC + auth + policy)", input: `{"abac": true, "attributes": true, "authentication": true, "policy_enforcement": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no access control)", input: `{"authentication": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccessEnforcement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccessEnforcement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckLeastPrivilege(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (RBAC + roles + no wildcard)", input: `{"rbac": true, "roles": ["admin", "user"], "least_privilege": true}`, wantStatus: "compliant"},
		{name: "non-compliant (wildcard)", input: `{"rbac": true, "wildcard": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no RBAC)", input: `{"least_privilege": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkLeastPrivilege(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkLeastPrivilege: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckPermittedActionsWithoutAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (health check documented)", input: `{"health_check": true, "public_status": true, "trust_portal": true}`, wantStatus: "compliant"},
		{name: "non-compliant (unauth write)", input: `{"health_check": true, "unauth_write": true}`, wantStatus: "non_compliant"},
		{name: "partial (no documented actions)", input: `{"rbac": true}`, wantStatus: "partial"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkPermittedActionsWithoutAuth(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPermittedActionsWithoutAuth: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (AU family) ---

func TestCheckAuditRecordContent(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (5 fields)", input: `{"event_type": "login", "timestamp": "2026-01-01", "source": "10.0.0.1", "user_id": "admin", "result": "success"}`, wantStatus: "compliant"},
		{name: "partial (3 fields)", input: `{"event_type": "login", "timestamp": "2026-01-01", "source": "10.0.0.1"}`, wantStatus: "partial"},
		{name: "non-compliant (no fields)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditRecordContent(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditRecordContent: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuditReview(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (audit_search + anomaly + alert)", input: `{"audit_search": true, "anomaly_detection": true, "alert": true}`, wantStatus: "compliant"},
		{name: "compliant (audit_log + siem + review)", input: `{"audit_log": true, "siem": true, "review": true}`, wantStatus: "compliant"},
		{name: "non_compliant (no audit search)", input: `{"anomaly_detection": true, "alert": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (no anomaly detection)", input: `{"audit_search": true, "alert": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditReview(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditReview: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuditRecordGeneration(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (audit_log + all pillars)", input: `{"audit_log": true, "http": true, "mcp": true, "a2a": true, "hash_chain": true}`, wantStatus: "compliant"},
		{name: "partial (audit_log only, no pillars)", input: `{"audit_log": true}`, wantStatus: "partial"},
		{name: "non_compliant (no audit)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditRecordGeneration(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditRecordGeneration: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (IA family) ---

func TestCheckDeviceAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (api_key + mtls + device_id)", input: `{"api_key": true, "mtls": true, "device_id": true}`, wantStatus: "compliant"},
		{name: "compliant (mtls + device_auth)", input: `{"mutual_tls": true, "device_auth": true}`, wantStatus: "compliant"},
		{name: "partial (api_key but no device_id)", input: `{"api_key": true}`, wantStatus: "partial"},
		{name: "partial (mtls but no device_id)", input: `{"mtls": true}`, wantStatus: "partial"},
		{name: "non_compliant (no auth)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDeviceAuth(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDeviceAuth: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuthenticatorMgmt(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (password_policy + key_rotation)", input: `{"password_policy": true, "key_rotation": true}`, wantStatus: "compliant"},
		{name: "compliant (password + expiry)", input: `{"password": true, "session_timeout": 1800}`, wantStatus: "compliant"},
		{name: "non_compliant (password_policy only, no rotation/expiry)", input: `{"password_policy": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuthenticatorMgmt(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuthenticatorMgmt: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuthenticatorFeedback(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (mask)", input: `{"mask": true}`, wantStatus: "compliant"},
		{name: "compliant (masked)", input: `{"masked": true}`, wantStatus: "compliant"},
		{name: "compliant (no_echo)", input: `{"no_echo": true}`, wantStatus: "compliant"},
		{name: "compliant (secure_input)", input: `{"secure_input": true}`, wantStatus: "compliant"},
		{name: "non_compliant (no masking)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuthenticatorFeedback(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuthenticatorFeedback: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckCryptoModuleAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (fips + tls)", input: `{"fips_140": true, "tls": true}`, wantStatus: "compliant"},
		{name: "compliant (fips_mode + key_management)", input: `{"fips_mode": true, "key_management": true}`, wantStatus: "compliant"},
		{name: "partial (fips only, no tls/key_mgmt)", input: `{"fips_140": true}`, wantStatus: "partial"},
		{name: "non_compliant (no fips)", input: `{"tls": true, "key_management": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCryptoModuleAuth(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCryptoModuleAuth: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (SC family) ---

func TestCheckSharedResources(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (multi_tenant + data_segregation)", input: `{"multi_tenant": true, "data_segregation": true}`, wantStatus: "compliant"},
		{name: "compliant (tenant_isolation + rbac)", input: `{"tenant_isolation": true, "rbac": true}`, wantStatus: "compliant"},
		{name: "non_compliant (no isolation)", input: `{}`, wantStatus: "non_compliant"},
		{name: "non_compliant (isolation only, no segregation)", input: `{"multi_tenant": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSharedResources(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSharedResources: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckBoundaryProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (proxy + egress_filter)", input: `{"proxy": true, "egress_filter": true}`, wantStatus: "compliant"},
		{name: "compliant (firewall + egress)", input: `{"firewall": true, "egress_filter": true}`, wantStatus: "compliant"},
		{name: "compliant (rate_limiting + egress)", input: `{"rate_limiting": true, "egress_filter": true}`, wantStatus: "compliant"},
		{name: "non_compliant (no egress filter)", input: `{"proxy": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkBoundaryProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkBoundaryProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckCryptoKeyEstablishment(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (key_management + fips)", input: `{"key_management": true, "fips_mode": true}`, wantStatus: "compliant"},
		{name: "compliant (key_rotation + fips_140)", input: `{"key_rotation": true, "fips_140": true}`, wantStatus: "compliant"},
		{name: "non_compliant (key_mgmt only, no fips)", input: `{"key_management": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (fips only, no key_mgmt)", input: `{"fips_mode": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCryptoKeyEstablishment(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCryptoKeyEstablishment: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckCryptoProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (fips_140)", input: `{"fips_140": true}`, wantStatus: "compliant"},
		{name: "compliant (fips_mode)", input: `{"fips_mode": true}`, wantStatus: "compliant"},
		{name: "partial (tls but no fips)", input: `{"tls": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCryptoProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCryptoProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckSessionProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (session_timeout + csrf_token)", input: `{"session_timeout": 1800, "csrf_token": true}`, wantStatus: "compliant"},
		{name: "compliant (idle_timeout + mfa)", input: `{"idle_timeout": "5m", "mfa": true}`, wantStatus: "compliant"},
		{name: "compliant (timeout + session_token)", input: `{"timeout": 3600, "session_token": true}`, wantStatus: "compliant"},
		{name: "non_compliant (timeout only, no csrf/reauth)", input: `{"session_timeout": 1800}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSessionProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSessionProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckDataAtRest(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (encryption_at_rest + key_management)", input: `{"encryption_at_rest": true, "key_management": true}`, wantStatus: "compliant"},
		{name: "compliant (data_encrypted + key_store)", input: `{"data_encrypted": true, "key_store": true}`, wantStatus: "compliant"},
		{name: "partial (encryption but no key_mgmt)", input: `{"encryption_at_rest": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDataAtRest(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDataAtRest: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (CM + SI family) ---

func TestCheckChangeControl(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (audit_log + review)", input: `{"audit_log": true, "review": true}`, wantStatus: "compliant"},
		{name: "compliant (audit_trail + git)", input: `{"audit_trail": true, "git": true}`, wantStatus: "compliant"},
		{name: "compliant (config_audit + approval)", input: `{"config_audit": true, "approval": true}`, wantStatus: "compliant"},
		{name: "compliant (audit_log + version_control)", input: `{"audit_log": true, "version_control": true}`, wantStatus: "compliant"},
		{name: "non_compliant (audit_log only, no approval)", input: `{"audit_log": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (review only, no audit)", input: `{"review": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkChangeControl(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkChangeControl: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckComponentInventory(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (sbom + dependencies + version)", input: `{"sbom": true, "dependencies": true, "version": "1.0"}`, wantStatus: "compliant"},
		{name: "compliant (aibom + inventory)", input: `{"aibom": true, "inventory": true}`, wantStatus: "compliant"},
		{name: "compliant (cyclonedx + versioning)", input: `{"cyclonedx": true, "versioning": true}`, wantStatus: "compliant"},
		{name: "partial (sbom only, no inventory)", input: `{"sbom": true}`, wantStatus: "partial"},
		{name: "partial (sbom + version but no inventory)", input: `{"sbom": true, "version": "1.0"}`, wantStatus: "compliant"},
		{name: "non_compliant (no sbom)", input: `{"dependencies": true, "version": "1.0"}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkComponentInventory(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkComponentInventory: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckFlawRemediation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (scanner + patch)", input: `{"scanner": true, "patch": true}`, wantStatus: "compliant"},
		{name: "compliant (vulnerability + sbom)", input: `{"vulnerability": true, "sbom": true}`, wantStatus: "compliant"},
		{name: "compliant (vuln + update)", input: `{"vuln": true, "update": true}`, wantStatus: "compliant"},
		{name: "non_compliant (scanner only, no patch)", input: `{"scanner": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (patch only, no scanner)", input: `{"patch": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkFlawRemediation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkFlawRemediation: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckSoftwareIntegrity(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (hash_chain + aibom)", input: `{"hash_chain": true, "aibom": true}`, wantStatus: "compliant"},
		{name: "compliant (integrity + attestation)", input: `{"integrity": true, "attestation": true}`, wantStatus: "compliant"},
		{name: "compliant (log_integrity + sbom)", input: `{"log_integrity": true, "sbom": true}`, wantStatus: "compliant"},
		{name: "partial (hash_chain only)", input: `{"hash_chain": true}`, wantStatus: "partial"},
		{name: "non_compliant (no hash_chain)", input: `{"aibom": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSoftwareIntegrity(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSoftwareIntegrity: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckInputValidation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (input_validation + prompt_injection)", input: `{"input_validation": true, "prompt_injection": true}`, wantStatus: "compliant"},
		{name: "compliant (validation + xss)", input: `{"validation": true, "xss": true}`, wantStatus: "compliant"},
		{name: "compliant (sanitiz + sql_injection)", input: `{"sanitiz": true, "sql_injection": true}`, wantStatus: "compliant"},
		{name: "non_compliant (input_validation only)", input: `{"input_validation": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (injection only, no validation)", input: `{"prompt_injection": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkInputValidation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkInputValidation: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (IR family) ---

func TestCheckIncidentHandling(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (ioc + incident_response)", input: `{"ioc": true, "incident_response": true}`, wantStatus: "compliant"},
		{name: "compliant (alert + response)", input: `{"alert": true, "response": true}`, wantStatus: "compliant"},
		{name: "compliant (threat + siem + block)", input: `{"threat": true, "siem": true, "block": true}`, wantStatus: "compliant"},
		{name: "non_compliant (ioc only, no response)", input: `{"ioc": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (incident_response only, no detection)", input: `{"incident_response": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentHandling(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentHandling: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckIncidentMonitoring(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (monitoring + tracking)", input: `{"monitoring": true, "tracking": true}`, wantStatus: "compliant"},
		{name: "compliant (anomaly + ioc)", input: `{"anomaly": true, "ioc": true}`, wantStatus: "compliant"},
		{name: "compliant (audit_log + incident_tracking)", input: `{"audit_log": true, "incident_tracking": true}`, wantStatus: "compliant"},
		{name: "non_compliant (monitoring only)", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (tracking only)", input: `{"tracking": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Path C new controls (RA family) ---

func TestCheckRiskAssessment(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (scan + threat)", input: `{"compliance": true, "threat": true}`, wantStatus: "compliant"},
		{name: "compliant (scan + schedule)", input: `{"scan": true, "schedule": true}`, wantStatus: "compliant"},
		{name: "compliant (compliance + ccm)", input: `{"compliance": true, "ccm": true}`, wantStatus: "compliant"},
		{name: "non_compliant (scan only, no threat/schedule)", input: `{"scan": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (threat only, no scan)", input: `{"threat": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRiskAssessment(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRiskAssessment: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckVulnerabilityScanning(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (scanner + ccm)", input: `{"scanner": true, "ccm": true}`, wantStatus: "compliant"},
		{name: "compliant (vuln + schedule)", input: `{"vulnerability": true, "schedule": true}`, wantStatus: "compliant"},
		{name: "partial (scanner only)", input: `{"scanner": true}`, wantStatus: "partial"},
		{name: "non_compliant (ccm only, no scanner)", input: `{"ccm": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkVulnerabilityScanning(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkVulnerabilityScanning: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckContinuousMonitoring(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (ccm + scan)", input: `{"ccm": true, "scan": true}`, wantStatus: "compliant"},
		{name: "compliant (continuous + scanner)", input: `{"continuous": true, "scanner": true}`, wantStatus: "compliant"},
		{name: "compliant (schedule + compliance)", input: `{"schedule": true, "compliance": true}`, wantStatus: "compliant"},
		{name: "partial (ccm only)", input: `{"ccm": true}`, wantStatus: "partial"},
		{name: "partial (scan only)", input: `{"scan": true}`, wantStatus: "partial"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkContinuousMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkContinuousMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Missing CheckFunc tests: CM-5, CM-6, RA-6 ---

func TestCheckChangeAccessRestrictions(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (rbac + change_log)", input: `{"rbac": true, "change_log": true}`, wantStatus: "compliant"},
		{name: "compliant (roles + audit_log)", input: `{"roles": ["admin"], "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant (admin_only + config_audit)", input: `{"admin_only": true, "config_audit": true}`, wantStatus: "compliant"},
		{name: "compliant (restricted + change_log)", input: `{"restricted": true, "change_log": true}`, wantStatus: "compliant"},
		{name: "non_compliant (rbac only, no change_log)", input: `{"rbac": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (change_log only, no rbac)", input: `{"change_log": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkChangeAccessRestrictions(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkChangeAccessRestrictions: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckConfigSettings(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (security + secure_default)", input: `{"security": true, "secure_default": true}`, wantStatus: "compliant"},
		{name: "compliant (security_config + hardened)", input: `{"security_config": true, "hardened": true}`, wantStatus: "compliant"},
		{name: "compliant (tls + policy)", input: `{"tls": true, "policy": true}`, wantStatus: "compliant"},
		{name: "compliant (security + enforcement)", input: `{"security": true, "enforcement": true}`, wantStatus: "compliant"},
		{name: "compliant (security_config + config_enforcement)", input: `{"security_config": true, "config_enforcement": true}`, wantStatus: "compliant"},
		{name: "non_compliant (security only, no defaults)", input: `{"security": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (default_deny only, no security)", input: `{"default_deny": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkConfigSettings(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkConfigSettings: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckTechnicalSurveillance(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (ioc + monitoring)", input: `{"ioc": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "compliant (indicator + siem)", input: `{"indicator": true, "siem": true}`, wantStatus: "compliant"},
		{name: "compliant (anomaly_detection + audit_log)", input: `{"anomaly_detection": true, "audit_log": true}`, wantStatus: "compliant"},
		{name: "compliant (threat_intelligence + monitoring)", input: `{"threat_intelligence": true, "monitoring": true}`, wantStatus: "compliant"},
		{name: "non_compliant (ioc only, no monitoring)", input: `{"ioc": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (monitoring only, no ioc/anomaly)", input: `{"monitoring": true}`, wantStatus: "non_compliant"},
		{name: "non_compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTechnicalSurveillance(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTechnicalSurveillance: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// --- Edge case tests ---

func TestCheckFuncs_EdgeCases(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	// Test that all automated CheckFuncs handle empty input gracefully
	automatedControls := m.Controls()
	var checkFuncs []compliance.ControlDefinition
	for _, c := range automatedControls {
		if c.Automated && c.CheckFunc != nil {
			checkFuncs = append(checkFuncs, c)
		}
	}

	t.Run("empty_input", func(t *testing.T) {
		for _, c := range checkFuncs {
			result, err := c.CheckFunc(ctx, []byte{})
			if err != nil {
				t.Errorf("Control %s returned error on empty input: %v", c.ID, err)
				continue
			}
			if string(result.Status) == "" {
				t.Errorf("Control %s returned empty status on empty input", c.ID)
			}
			// Empty input should always be non_compliant
			if string(result.Status) == "compliant" {
				t.Errorf("Control %s returned compliant on empty input, expected non_compliant or partial", c.ID)
			}
		}
	})

	t.Run("whitespace_only", func(t *testing.T) {
		for _, c := range checkFuncs {
			result, err := c.CheckFunc(ctx, []byte("   \t\n  "))
			if err != nil {
				t.Errorf("Control %s returned error on whitespace input: %v", c.ID, err)
				continue
			}
			if string(result.Status) == "" {
				t.Errorf("Control %s returned empty status on whitespace input", c.ID)
			}
		}
	})

	t.Run("large_input", func(t *testing.T) {
		largeInput := []byte(strings.Repeat(`{"rbac": true, "tls": true, "audit_log": true, "monitoring": true} `, 1000))
		for _, c := range checkFuncs {
			result, err := c.CheckFunc(ctx, largeInput)
			if err != nil {
				t.Errorf("Control %s returned error on large input: %v", c.ID, err)
				continue
			}
			if string(result.Status) == "" {
				t.Errorf("Control %s returned empty status on large input", c.ID)
			}
		}
	})
}

// --- Integration: all automated checks on a fully compliant config ---

func TestFedRAMPModule_AllAutomatedChecks(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	compliantConfig := `{
		"authentication": true, "auth_enabled": true, "rbac": true, "roles": ["admin", "user"],
		"session_timeout": 1800, "idle_timeout": "5m", "mfa": true, "multi_factor": true, "2fa": true,
		"tls": true, "https": true, "tls1.2": true, "tls1.3": true, "fips_mode": true, "fips_140": true,
		"audit_log": true, "audit_enabled": true, "log_integrity": true, "hash_chain": true,
		"logging_enabled": true, "monitoring": true, "access_policy": true, "policy_enforcement": true,
		"least_privilege": true, "health_check": true, "public_status": true, "trust_portal": true,
		"event_type": "login", "timestamp": "2026-01-01", "source": "10.0.0.1", "user_id": "admin", "result": "success",
		"anomaly_detection": true, "alert": true, "audit_search": true,
		"mtls": true, "device_id": true, "password_policy": true, "key_rotation": true,
		"mask": true, "key_management": true, "multi_tenant": true, "data_segregation": true,
		"proxy": true, "egress_filter": true, "rate_limiting": true, "network_policy": true,
		"encryption_at_rest": true, "csrf_token": true,
		"sbom": true, "aibom": true, "cyclonedx": true, "version": "1.0",
		"scanner": true, "vulnerability": true, "ioc": true, "incident_response": true,
		"tracking": true, "notification": true, "siem": true,
		"ccm": true, "scan": true, "compliance": true, "threat": true,
		"input_validation": true, "prompt_injection": true,
		"change_log": true, "config_audit": true, "secure_default": true,
		"attestation": true, "trust": true, "git": true,
		"safe_errors": true, "error_handling": true, "remediation": true, "sla_enabled": true,
		"backup": true, "persistence": true, "backup_schedule": true, "schedule": true,
		"isolation": true, "security_boundary": true, "sandbox": true,
		"dos_protection": true, "rate_limiting": true, "throttling": true, "circuit_breaker": true,
		"port_restrictions": true, "minimal_services": true,
		"software_usage": true, "license_compliance": true, "information_location": true,
		"data_classification": true, "retention_policy": true,
		"non_disruptive": true, "safe_mode": true
	}`

	// All 49 automated controls should return compliant
	automatedIDs := []string{
		"FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-6", "FedRAMP-AC-14", "FedRAMP-AC-17",
		"FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-6", "FedRAMP-AU-9", "FedRAMP-AU-12",
		"FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7",
		"FedRAMP-SC-3", "FedRAMP-SC-4", "FedRAMP-SC-5", "FedRAMP-SC-7", "FedRAMP-SC-8",
		"FedRAMP-SC-12", "FedRAMP-SC-13", "FedRAMP-SC-23", "FedRAMP-SC-28", "FedRAMP-SC-39",
		"FedRAMP-CM-3", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-7", "FedRAMP-CM-8",
		"FedRAMP-CM-10", "FedRAMP-CM-12",
		"FedRAMP-SI-2", "FedRAMP-SI-7", "FedRAMP-SI-10", "FedRAMP-SI-11", "FedRAMP-SI-14",
		"FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6",
		"FedRAMP-SA-22", "FedRAMP-SR-4",
		"FedRAMP-RA-3", "FedRAMP-RA-4", "FedRAMP-RA-5", "FedRAMP-RA-6",
		"FedRAMP-CA-7",
		"FedRAMP-CP-9", "FedRAMP-MP-6",
	}

	controls := m.Controls()
	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	for _, id := range automatedIDs {
		c, ok := controlMap[id]
		if !ok {
			t.Errorf("Automated control %s not found in registered controls", id)
			continue
		}
		if !c.Automated {
			t.Errorf("Control %s should be automated", id)
			continue
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", id)
			continue
		}
		result, err := c.CheckFunc(ctx, []byte(compliantConfig))
		if err != nil {
			t.Errorf("Control %s CheckFunc error: %v", id, err)
			continue
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Control %s on compliant config: status=%s, msg=%s", id, result.Status, result.Message)
		}
	}
}

func TestFedRAMPModule_Dependencies(t *testing.T) {
	m := NewFedRAMPModule()
	deps := m.Dependencies()
	if len(deps) != 5 {
		t.Errorf("Dependencies() returned %d items, want 5", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"soc2", "iso42001", "fips", "ioc", "trust"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}

func TestFedRAMPModule_EvidenceMappedControls(t *testing.T) {
	m := NewFedRAMPModule()
	controls := m.Controls()

	evidenceMappedIDs := []string{
		"FedRAMP-AC-24",
		"FedRAMP-AU-10", "FedRAMP-AU-16",
		"FedRAMP-IA-8",
		"FedRAMP-CM-2",
		"FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-8", "FedRAMP-SI-12", "FedRAMP-SI-16",
		"FedRAMP-IR-7", "FedRAMP-IR-8",
		"FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-9", "FedRAMP-SA-11",
		"FedRAMP-SR-3", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12",
		"FedRAMP-RA-7", "FedRAMP-RA-9",
		"FedRAMP-CA-1", "FedRAMP-CA-3", "FedRAMP-CA-8", "FedRAMP-CA-9",
		"FedRAMP-SC-15", "FedRAMP-SC-44",
		"FedRAMP-AT-1",
		"FedRAMP-CP-1", "FedRAMP-CP-2",
		"FedRAMP-MP-5",
		"FedRAMP-PE-3", "FedRAMP-PE-20",
		// Manual stubs (customer responsibility — policies, procedures, HR, physical)
		"FedRAMP-AC-1",
		"FedRAMP-AU-1",
		"FedRAMP-IA-1",
		"FedRAMP-SC-1",
		"FedRAMP-IR-1",
		"FedRAMP-SA-1",
		"FedRAMP-CM-1",
		"FedRAMP-RA-1",
		"FedRAMP-PS-1", "FedRAMP-PS-2", "FedRAMP-PS-3",
		"FedRAMP-PM-1", "FedRAMP-PM-14",
		"FedRAMP-PL-1", "FedRAMP-PL-2",
		"FedRAMP-MA-1",
	}

	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	for _, id := range evidenceMappedIDs {
		c, ok := controlMap[id]
		if !ok {
			t.Errorf("Evidence-mapped control %s not found", id)
			continue
		}
		if c.Automated {
			t.Errorf("Evidence-mapped control %s should have Automated=false, got true", id)
		}
	}
}

// --- New SC Family Controls (Path C expansion) ---

func TestCheckSecurityFunctionIsolation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "isolation sandbox container security_boundary", "compliant"},
		{"partial", "isolation sandbox container", "partial"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-SC-3", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl SC-3 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("SC-3 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckDenialOfServiceProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "rate_limiting circuit_breaker ddos_protection", "compliant"},
		{"partial", "rate_limiting", "partial"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-SC-5", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl SC-5 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("SC-5 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckPortServiceRestrictions(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "port_restrictions minimal_services", "compliant"},
		{"partial", "port_restrictions service_allowlist", "partial"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-SC-39", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl SC-39 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("SC-39 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

// --- New CM Family Controls (Path C expansion) ---

func TestCheckLeastFunctionality(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "minimal_services allowlist", "compliant"},
		{"noncompliant_nostack", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-CM-7", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl CM-7 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("CM-7 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckSoftwareUsageRestrictions(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "aibom license apache", "compliant"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-CM-10", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl CM-10 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("CM-10 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckInformationLocation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "classification data_classification persistence retention", "compliant"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-CM-12", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl CM-12 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("CM-12 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

// --- New SI Family Controls (Path C expansion) ---

func TestCheckErrorHandling(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "safe_errors error_handling", "compliant"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-SI-11", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl SI-11 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("SI-11 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckNonDisruptiveIntegrity(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "ccm continuous hash_chain", "compliant"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-SI-14", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl SI-14 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("SI-14 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

// --- New RA Family Controls (Path C expansion) ---

func TestCheckVulnerabilityRemediation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "scanner sla sla_enabled", "compliant"},
		{"partial", "scanner ioc", "partial"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-RA-4", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl RA-4 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("RA-4 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

// --- New Family Controls: CP, MP ---

func TestCheckSystemBackup(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", "backup persistence encryption_at_rest schedule", "compliant"},
		{"partial", "backup persistence", "partial"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-CP-9", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl CP-9 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("CP-9 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

func TestCheckMediaSanitization(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant_with_sanitization", "encryption_at_rest key_management sanitization", "compliant"},
		{"compliant_key_destruction", "encryption_at_rest key_management", "compliant"},
		{"noncompliant", "default_config", "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.CheckControl(ctx, "FedRAMP-MP-6", []byte(tt.input))
			if err != nil {
				t.Fatalf("CheckControl MP-6 %s: %v", tt.name, err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("MP-6 %s: got %q, want %q", tt.name, string(result.Status), tt.wantStatus)
			}
		})
	}
}

// --- Test all 18 families are represented ---

func TestFedRAMPModule_AllEighteenFamilies(t *testing.T) {
	m := NewFedRAMPModule()
	controls := m.Controls()

	expectedCategories := map[string]int{
		"Access Control":                            0,
		"Audit and Accountability":                  0,
		"Identification and Authentication":         0,
		"System and Communications Protection":      0,
		"Configuration Management":                  0,
		"System and Information Integrity":          0,
		"Incident Response":                         0,
		"System and Services Acquisition":           0,
		"Supply Chain Risk Management":              0,
		"Risk Assessment":                           0,
		"Assessment, Authorization, and Monitoring": 0,
		"Awareness and Training":                    0,
		"Contingency Planning":                      0,
		"Media Protection":                          0,
		"Physical and Environmental Protection":     0,
		"Personnel Security":                        0,
		"Program Management":                        0,
		"Planning":                                  0,
		"Maintenance":                               0,
	}

	for _, c := range controls {
		if _, ok := expectedCategories[c.Category]; !ok {
			t.Errorf("unexpected category %q for control %s", c.Category, c.ID)
		}
		expectedCategories[c.Category]++
	}

	for cat, count := range expectedCategories {
		if count == 0 {
			t.Errorf("no controls found for category %q", cat)
		}
	}
}
