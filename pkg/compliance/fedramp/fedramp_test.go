// SPDX-License-Identifier: Apache-2.0
// FedRAMP Compliance Module - Unit Tests
//
// Test coverage target: 80%+ per pkg/compliance coverage floor.

package fedramp

import (
	"context"
	"testing"
)

func TestNewFedRAMPModule(t *testing.T) {
	m := NewFedRAMPModule()
	if m == nil {
		t.Fatal("NewFedRAMPModule returned nil")
	}
	if m.Framework() != "fedramp" {
		t.Errorf("Framework() = %q, want fedramp", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}

	// Verify all 8 controls are registered
	controls := m.Controls()
	if len(controls) != 8 {
		t.Errorf("len(Controls()) = %d, want 8", len(controls))
	}

	// Verify the 5 automated control IDs are present
	automated := map[string]bool{
		"FedRAMP-AC-2":  false,
		"FedRAMP-AC-17": false,
		"FedRAMP-AU-2":  false,
		"FedRAMP-AU-9":  false,
		"FedRAMP-IA-2":  false,
		"FedRAMP-SC-8":  false,
	}
	for _, c := range controls {
		if _, ok := automated[c.ID]; ok {
			automated[c.ID] = true
			if !c.Automated {
				t.Errorf("Control %s should be automated", c.ID)
			}
			if c.CheckFunc == nil {
				t.Errorf("Control %s has nil CheckFunc", c.ID)
			}
		}
	}
	for id, found := range automated {
		if !found {
			t.Errorf("Automated control %s not registered", id)
		}
	}

	// Verify the 2 evidence-mapped control IDs are present
	evidenceMapped := map[string]bool{
		"FedRAMP-CM-2": false,
		"FedRAMP-SI-4": false,
	}
	for _, c := range controls {
		if _, ok := evidenceMapped[c.ID]; ok {
			evidenceMapped[c.ID] = true
			if c.Automated {
				t.Errorf("Control %s should be evidence-mapped (not automated)", c.ID)
			}
		}
	}
	for id, found := range evidenceMapped {
		if !found {
			t.Errorf("Evidence-mapped control %s not registered", id)
		}
	}
}

func TestCheckAccountManagement(t *testing.T) {
	m := NewFedRAMPModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (auth + rbac + session_timeout)",
			input:      `{"authentication": true, "rbac": true, "session_timeout": 1800}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no auth)",
			input:      `{"rbac": true, "session_timeout": 1800}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no rbac)",
			input:      `{"authentication": true, "session_timeout": 1800}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no session_timeout)",
			input:      `{"authentication": true, "rbac": true}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccountManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccountManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
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
		{
			name:       "compliant (MFA + TLS + monitoring)",
			input:      `{"mfa": true, "tls": true, "audit_log": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (alternative markers)",
			input:      `{"multi_factor": true, "https": true, "logging_enabled": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no MFA)",
			input:      `{"tls": true, "audit_log": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no TLS)",
			input:      `{"mfa": true, "audit_log": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no monitoring)",
			input:      `{"mfa": true, "tls": true}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRemoteAccess(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRemoteAccess: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
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
		{
			name:       "compliant (audit + integrity)",
			input:      `{"audit_log": true, "log_integrity": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (audit + hash_chain)",
			input:      `{"audit_enabled": true, "hash_chain": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (audit, no integrity)",
			input:      `{"audit_log": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no audit)",
			input:      `{"logging": false}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditEvents(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditEvents: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
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
		{
			name:       "compliant (integrity + RBAC)",
			input:      `{"log_integrity": true, "rbac": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (integrity, no RBAC)",
			input:      `{"hash_chain": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no protection)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
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
		{
			name:       "compliant (MFA enabled)",
			input:      `{"mfa": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (multi_factor)",
			input:      `{"multi_factor": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (2fa)",
			input:      `{"2fa": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no MFA)",
			input:      `{"authentication": "password_only"}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMFA(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMFA: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
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
		{
			name:       "compliant (TLS 1.2 + FIPS)",
			input:      `{"tls1.2": true, "fips_mode": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (TLS 1.3 + FIPS 140)",
			input:      `{"tls1.3": true, "fips_140": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (TLS, no FIPS)",
			input:      `{"tls1.2": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (TLS below 1.2)",
			input:      `{"tls1.0": true, "fips_mode": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no TLS)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTransmissionProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTransmissionProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestFedRAMPModule_AllAutomatedChecks(t *testing.T) {
	// Integration-style: all 6 automated checks on a fully compliant config.
	m := NewFedRAMPModule()
	ctx := context.Background()

	compliantConfig := `{
		"authentication": true,
		"auth_enabled": true,
		"rbac": true,
		"roles": ["admin", "user"],
		"session_timeout": 1800,
		"idle_timeout": "5m",
		"mfa": true,
		"multi_factor": true,
		"2fa": true,
		"tls": true,
		"https": true,
		"tls1.2": true,
		"tls1.3": true,
		"fips_mode": true,
		"fips_140": true,
		"audit_log": true,
		"audit_enabled": true,
		"log_integrity": true,
		"hash_chain": true,
		"logging_enabled": true,
		"monitoring": true
	}`

	checkFns := map[string]func(context.Context, []byte) (string, string){
		"FedRAMP-AC-2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccountManagement(c, b)
			return string(r.Status), r.Message
		},
		"FedRAMP-AC-17": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRemoteAccess(c, b)
			return string(r.Status), r.Message
		},
		"FedRAMP-AU-2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuditEvents(c, b)
			return string(r.Status), r.Message
		},
		"FedRAMP-AU-9": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuditProtection(c, b)
			return string(r.Status), r.Message
		},
		"FedRAMP-IA-2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMFA(c, b)
			return string(r.Status), r.Message
		},
		"FedRAMP-SC-8": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkTransmissionProtection(c, b)
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checkFns {
		t.Run(controlID, func(t *testing.T) {
			status, msg := checkFn(ctx, []byte(compliantConfig))
			if status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, status, msg)
			}
		})
	}
}

func TestFedRAMPModule_Dependencies(t *testing.T) {
	m := NewFedRAMPModule()
	deps := m.Dependencies()
	if len(deps) != 5 {
		t.Errorf("Dependencies() returned %d items, want 5", len(deps))
	}
	depsStr := ""
	for _, d := range deps {
		depsStr += d + ","
	}
	for _, expected := range []string{"soc2", "iso42001", "fips", "ioc", "trust"} {
		if !contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
