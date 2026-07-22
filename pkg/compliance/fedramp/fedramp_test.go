// SPDX-License-Identifier: Apache-2.0
// FedRAMP Compliance Module - Unit Tests
//
// Path C: Full in-scope FedRAMP Moderate controls.
// Test coverage target: 80%+ per pkg/compliance coverage floor.
//
// Total controls: 56 (31 automated + 25 evidence-mapped)
//   AC: 6 (5 automated + 1 evidence-mapped)
//   AU: 7 (5 automated + 2 evidence-mapped)
//   IA: 6 (5 automated + 1 evidence-mapped)
//   SC: 7 (7 automated + 0 evidence-mapped)
//   CM: 5 (4 automated + 1 evidence-mapped)
//   SI: 6 (4 automated + 2 evidence-mapped)
//   IR: 5 (3 automated + 2 evidence-mapped)
//   SA: 5 (1 automated + 4 evidence-mapped)
//   SR: 5 (1 automated + 4 evidence-mapped)
//   RA: 4 (3 automated + 1 evidence-mapped)
//   CA: 4 (1 automated + 3 evidence-mapped)

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

	// Verify all 56 controls are registered
	controls := m.Controls()
	if len(controls) != 60 {
		t.Errorf("len(Controls()) = %d, want 56", len(controls))
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
	if automated != 38 {
		t.Errorf("automated controls = %d, want 31", automated)
	}
	if evidenceMapped != 22 {
		t.Errorf("evidence-mapped controls = %d, want 25", evidenceMapped)
	}

	// Verify each family has the right number of controls
	familyCount := map[string]int{}
	for _, c := range controls {
		familyCount[c.Category]++
	}
	expectedFamilies := map[string]int{
		"Access Control":                            6,
		"Audit and Accountability":                  7,
		"Identification and Authentication":         6,
		"System and Communications Protection":      7,
		"Configuration Management":                  5,
		"System and Information Integrity":          6,
		"Incident Response":                         5,
		"System and Services Acquisition":           5,
		"Supply Chain Risk Management":              5,
		"Risk Assessment":                           4,
		"Assessment, Authorization, and Monitoring": 4,
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

	result, err := m.checkAuditReview(ctx, []byte(`{"audit_search": true, "anomaly_detection": true, "alert": true}`))
	if err != nil {
		t.Fatalf("checkAuditReview: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckAuditRecordGeneration(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkAuditRecordGeneration(ctx, []byte(`{"audit_log": true, "http": true, "mcp": true, "a2a": true, "hash_chain": true}`))
	if err != nil {
		t.Fatalf("checkAuditRecordGeneration: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

// --- Path C new controls (IA family) ---

func TestCheckDeviceAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkDeviceAuth(ctx, []byte(`{"api_key": true, "mtls": true, "device_id": true}`))
	if err != nil {
		t.Fatalf("checkDeviceAuth: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckAuthenticatorMgmt(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkAuthenticatorMgmt(ctx, []byte(`{"password_policy": true, "key_rotation": true}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorMgmt: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckAuthenticatorFeedback(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkAuthenticatorFeedback(ctx, []byte(`{"mask": true}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorFeedback: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckCryptoModuleAuth(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkCryptoModuleAuth(ctx, []byte(`{"fips_140": true, "tls": true}`))
	if err != nil {
		t.Fatalf("checkCryptoModuleAuth: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

// --- Path C new controls (SC family) ---

func TestCheckSharedResources(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkSharedResources(ctx, []byte(`{"multi_tenant": true, "data_segregation": true}`))
	if err != nil {
		t.Fatalf("checkSharedResources: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckBoundaryProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkBoundaryProtection(ctx, []byte(`{"proxy": true, "egress_filter": true}`))
	if err != nil {
		t.Fatalf("checkBoundaryProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckCryptoKeyEstablishment(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkCryptoKeyEstablishment(ctx, []byte(`{"key_management": true, "fips_mode": true}`))
	if err != nil {
		t.Fatalf("checkCryptoKeyEstablishment: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckCryptoProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkCryptoProtection(ctx, []byte(`{"fips_140": true}`))
	if err != nil {
		t.Fatalf("checkCryptoProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckSessionProtection(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkSessionProtection(ctx, []byte(`{"session_timeout": 1800, "csrf_token": true}`))
	if err != nil {
		t.Fatalf("checkSessionProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckDataAtRest(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkDataAtRest(ctx, []byte(`{"encryption_at_rest": true, "key_management": true}`))
	if err != nil {
		t.Fatalf("checkDataAtRest: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

// --- Path C new controls (CM + SI family) ---

func TestCheckChangeControl(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkChangeControl(ctx, []byte(`{"audit_log": true, "review": true}`))
	if err != nil {
		t.Fatalf("checkChangeControl: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckComponentInventory(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkComponentInventory(ctx, []byte(`{"sbom": true, "dependencies": true, "version": "1.0"}`))
	if err != nil {
		t.Fatalf("checkComponentInventory: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckFlawRemediation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkFlawRemediation(ctx, []byte(`{"scanner": true, "patch": true}`))
	if err != nil {
		t.Fatalf("checkFlawRemediation: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckSoftwareIntegrity(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkSoftwareIntegrity(ctx, []byte(`{"hash_chain": true, "aibom": true}`))
	if err != nil {
		t.Fatalf("checkSoftwareIntegrity: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckInputValidation(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkInputValidation(ctx, []byte(`{"input_validation": true, "prompt_injection": true}`))
	if err != nil {
		t.Fatalf("checkInputValidation: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

// --- Path C new controls (IR family) ---

func TestCheckIncidentHandling(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkIncidentHandling(ctx, []byte(`{"ioc": true, "incident_response": true}`))
	if err != nil {
		t.Fatalf("checkIncidentHandling: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckIncidentMonitoring(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkIncidentMonitoring(ctx, []byte(`{"monitoring": true, "tracking": true}`))
	if err != nil {
		t.Fatalf("checkIncidentMonitoring: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

// --- Path C new controls (RA family) ---

func TestCheckRiskAssessment(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkRiskAssessment(ctx, []byte(`{"compliance": true, "threat": true}`))
	if err != nil {
		t.Fatalf("checkRiskAssessment: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckVulnerabilityScanning(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkVulnerabilityScanning(ctx, []byte(`{"scanner": true, "ccm": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityScanning: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestCheckContinuousMonitoring(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	result, err := m.checkContinuousMonitoring(ctx, []byte(`{"ccm": true, "scan": true}`))
	if err != nil {
		t.Fatalf("checkContinuousMonitoring: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
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
		"attestation": true, "trust": true, "git": true
	}`

	// All 31 automated controls should return compliant
	automatedIDs := []string{
		"FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-6", "FedRAMP-AC-14", "FedRAMP-AC-17",
		"FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-6", "FedRAMP-AU-9", "FedRAMP-AU-12",
		"FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7",
		"FedRAMP-SC-4", "FedRAMP-SC-7", "FedRAMP-SC-8", "FedRAMP-SC-12", "FedRAMP-SC-13",
		"FedRAMP-SC-23", "FedRAMP-SC-28",
		"FedRAMP-CM-3", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-8",
		"FedRAMP-SI-2", "FedRAMP-SI-7", "FedRAMP-SI-10",
		"FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6",
		"FedRAMP-SA-22", "FedRAMP-SR-4",
		"FedRAMP-RA-3", "FedRAMP-RA-5", "FedRAMP-RA-6",
		"FedRAMP-CA-7",
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
		"FedRAMP-CM-2", "FedRAMP-SI-3", "FedRAMP-SI-4", "FedRAMP-SI-8",
		"FedRAMP-IR-7", "FedRAMP-IR-8",
		"FedRAMP-SA-4", "FedRAMP-SA-5", "FedRAMP-SA-9", "FedRAMP-SA-11",
		"FedRAMP-SR-3", "FedRAMP-SR-6", "FedRAMP-SR-8", "FedRAMP-SR-12",
		"FedRAMP-RA-7",
		"FedRAMP-CA-2", "FedRAMP-CA-8", "FedRAMP-CA-9",
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
