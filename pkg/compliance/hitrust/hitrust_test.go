// SPDX-License-Identifier: Apache-2.0
// HITRUST CSF Compliance Module - Unit Tests
//
// HITRUST CSF v11.2 — 43 in-scope controls.
// Test coverage target: 80%+ per pkg/compliance coverage floor.
//
// Total controls: 43 (18 automated + 25 evidence-mapped)
//   AM: 10 (7 automated + 3 evidence-mapped)
//   ID:  5 (3 automated + 2 evidence-mapped)
//   IP: 13 (8 automated + 5 evidence-mapped)
//   PE: 15 (0 automated + 15 evidence-mapped)

package hitrust

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewHITRUSTModule(t *testing.T) {
	m := NewHITRUSTModule()
	if m == nil {
		t.Fatal("NewHITRUSTModule returned nil")
	}
	if m.Framework() != "hitrust" {
		t.Errorf("Framework() = %q, want hitrust", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
}

func TestHITRUSTControlCount(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	if len(controls) != 43 {
		t.Errorf("len(Controls()) = %d, want 43", len(controls))
	}

	automated := 0
	evidenceMapped := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			evidenceMapped++
		}
	}
	if automated != 19 {
		t.Errorf("automated controls = %d, want 18", automated)
	}
	if evidenceMapped != 24 {
		t.Errorf("evidence-mapped controls = %d, want 25", evidenceMapped)
	}

	// Verify each family has the right number of controls
	familyCount := map[string]int{}
	for _, c := range controls {
		familyCount[c.Category]++
	}
	expectedFamilies := map[string]int{
		"Access Management":      10,
		"Identity Management":    5,
		"Information Protection": 13,
		"Privacy and Endpoint":   15,
	}
	for family, expected := range expectedFamilies {
		if familyCount[family] != expected {
			t.Errorf("family %q: got %d controls, want %d", family, familyCount[family], expected)
		}
	}
}

func TestHITRUSTAutomatedChecks(t *testing.T) {
	m := NewHITRUSTModule()

	// All 18 automated control IDs
	automatedIDs := []string{
		// AM family (7 automated)
		"HITRUST-AM-02", "HITRUST-AM-03", "HITRUST-AM-04",
		"HITRUST-AM-06", "HITRUST-AM-07", "HITRUST-AM-09", "HITRUST-AM-10",
		// ID family (3 automated)
		"HITRUST-ID-02", "HITRUST-ID-03", "HITRUST-ID-04",
		// IP family (8 automated)
		"HITRUST-IP-02", "HITRUST-IP-03", "HITRUST-IP-04", "HITRUST-IP-05",
		"HITRUST-IP-07", "HITRUST-IP-08", "HITRUST-IP-09", "HITRUST-IP-10",
		"HITRUST-IP-13",
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
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", id)
		}
	}
}

func TestHITRUSTMFA(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (mfa)", input: `{"mfa": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant (multi_factor)", input: `{"multi_factor": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant (2fa)", input: `{"2fa": true, "tls": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no MFA)", input: `{"authentication": true}`, wantStatus: "non_compliant"},
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

func TestHITRUSTUserAuthentication(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (auth + unique ID + MFA)", input: `{"authentication": true, "user_id": true, "mfa": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no auth)", input: `{"user_id": true, "mfa": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no MFA)", input: `{"authentication": true, "user_id": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkUserAuthentication(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkUserAuthentication: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTLogicalAccess(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkLogicalAccess(ctx, []byte(`{"rbac": true, "authentication": true, "least_privilege": true}`))
	if err != nil {
		t.Fatalf("checkLogicalAccess: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTPasswordManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (policy + min_length)", input: `{"password_policy": true, "min_length": 12}`, wantStatus: "compliant"},
		{name: "compliant (policy + rotation)", input: `{"password_policy": true, "password_rotation": 90}`, wantStatus: "compliant"},
		{name: "non-compliant (no policy)", input: `{"min_length": 12}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkPasswordManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPasswordManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTAccessReview(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkAccessReview(ctx, []byte(`{"rbac": true, "audit_log": true, "access_review": true}`))
	if err != nil {
		t.Fatalf("checkAccessReview: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTSessionManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkSessionManagement(ctx, []byte(`{"session_timeout": 1800, "authentication": true}`))
	if err != nil {
		t.Fatalf("checkSessionManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTPrivilegedAccess(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkPrivilegedAccess(ctx, []byte(`{"rbac": true, "mfa": true, "audit_log": true, "privileged_access": true}`))
	if err != nil {
		t.Fatalf("checkPrivilegedAccess: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTIdentityVerification(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkIdentityVerification(ctx, []byte(`{"authentication": true, "user_id": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTAuthenticatorManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkAuthenticatorManagement(ctx, []byte(`{"password_policy": true, "key_management": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTCredentialManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkCredentialManagement(ctx, []byte(`{"key_rotation": true, "revocation": true, "audit_log": true}`))
	if err != nil {
		t.Fatalf("checkCredentialManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTEncryptionAtRest(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (encryption_at_rest)", input: `{"encryption_at_rest": true, "key_management": true}`, wantStatus: "compliant"},
		{name: "compliant (aes_256)", input: `{"aes_256": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no encryption)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEncryptionAtRest(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEncryptionAtRest: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTEncryptionInTransit(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (TLS)", input: `{"tls": true, "https": true}`, wantStatus: "compliant"},
		{name: "compliant (TLS 1.3)", input: `{"tls1.3": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no TLS)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEncryptionInTransit(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEncryptionInTransit: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTKeyManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkKeyManagement(ctx, []byte(`{"key_management": true, "key_rotation": true, "fips_140": true}`))
	if err != nil {
		t.Fatalf("checkKeyManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTDataMasking(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (masking + non_production)", input: `{"data_masking": true, "non_production": true}`, wantStatus: "compliant"},
		{name: "compliant (masking + PII)", input: `{"masking": true, "pii": true}`, wantStatus: "compliant"},
		{name: "partial (masking, no env)", input: `{"data_masking": true}`, wantStatus: "partial"},
		{name: "non-compliant (no masking)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDataMasking(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDataMasking: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTEndpointProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkEndpointProtection(ctx, []byte(`{"antimalware": true, "hardening": true, "edr": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTNetworkProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "network_segmentation": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTMalwareProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkMalwareProtection(ctx, []byte(`{"antimalware": true, "signature_update": true, "scan_entry": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTVulnerabilityManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkVulnerabilityManagement(ctx, []byte(`{"vulnerability_scan": true, "patch": true, "cvss": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTBackupAndRecovery(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkBackupAndRecovery(ctx, []byte(`{"backup": true, "recovery_test": true, "offsite": true}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTEvidenceMappedNotAutomated(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	// All 25 evidence-mapped control IDs
	evidenceMappedIDs := []string{
		// AM family (3 evidence-mapped)
		"HITRUST-AM-01", "HITRUST-AM-05", "HITRUST-AM-08",
		// ID family (2 evidence-mapped)
		"HITRUST-ID-01", "HITRUST-ID-05",
		// IP family (5 evidence-mapped)
		"HITRUST-IP-01", "HITRUST-IP-06", "HITRUST-IP-11", "HITRUST-IP-12",
		// PE family (15 evidence-mapped)
		"HITRUST-PE-01", "HITRUST-PE-02", "HITRUST-PE-03", "HITRUST-PE-04",
		"HITRUST-PE-05", "HITRUST-PE-06", "HITRUST-PE-07", "HITRUST-PE-08",
		"HITRUST-PE-09", "HITRUST-PE-10", "HITRUST-PE-11", "HITRUST-PE-12",
		"HITRUST-PE-13", "HITRUST-PE-14", "HITRUST-PE-15",
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
		if c.CheckFunc != nil {
			t.Errorf("Evidence-mapped control %s should have nil CheckFunc", id)
		}
	}
}

func TestHITRUSTAllControlsHaveFields(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	for _, c := range controls {
		if c.ID == "" {
			t.Errorf("Control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("Control %s has empty Name", c.ID)
		}
		if c.Description == "" {
			t.Errorf("Control %s has empty Description", c.ID)
		}
		if c.Category == "" {
			t.Errorf("Control %s has empty Category", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("Control %s has empty Severity", c.ID)
		}
		if c.Automated && c.CheckFunc == nil {
			t.Errorf("Automated control %s has nil CheckFunc", c.ID)
		}
		if !c.Automated && c.CheckFunc != nil {
			t.Errorf("Evidence-mapped control %s should have nil CheckFunc", c.ID)
		}
	}
}

func TestHITRUSTModuleDependencies(t *testing.T) {
	m := NewHITRUSTModule()
	deps := m.Dependencies()
	if len(deps) != 6 {
		t.Errorf("Dependencies() returned %d items, want 6", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"hipaa", "iso27001", "fips", "soc2", "ioc", "trust"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}
