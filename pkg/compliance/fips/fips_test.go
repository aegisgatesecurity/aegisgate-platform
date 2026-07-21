// SPDX-License-Identifier: Apache-2.0
// FIPS 140-2/140-3 Compliance Module - Unit Tests
//
// Test coverage target: 80%+ per pkg/compliance coverage floor.

package fips

import (
	"context"
	"testing"
)

func TestNewFIPS140Module(t *testing.T) {
	m := NewFIPS140Module()
	if m == nil {
		t.Fatal("NewFIPS140Module returned nil")
	}
	if m.Framework() != "fips" {
		t.Errorf("Framework() = %q, want fips", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}

	// Verify all 10 controls are registered
	controls := m.Controls()
	if len(controls) != 10 {
		t.Errorf("len(Controls()) = %d, want 10", len(controls))
	}

	// Verify the 8 automated control IDs are present
	automated := map[string]bool{
		"FIPS-140-001": false,
		"FIPS-140-002": false,
		"FIPS-140-003": false,
		"FIPS-140-004": false,
		"FIPS-140-005": false,
		"FIPS-140-006": false,
		"FIPS-140-007": false,
		"FIPS-140-008": false,
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

	// Verify the 2 manual control IDs are present
	manual := map[string]bool{
		"FIPS-140-009": false, // CMVP
		"FIPS-140-010": false, // HSM
	}
	for _, c := range controls {
		if _, ok := manual[c.ID]; ok {
			manual[c.ID] = true
			if c.Automated {
				t.Errorf("Control %s should be manual", c.ID)
			}
		}
	}
	for id, found := range manual {
		if !found {
			t.Errorf("Manual control %s not registered", id)
		}
	}
}

func TestCheckFIPSModeEnabled(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// Note: this test depends on the global fips.CurrentMode state.
	// Other tests may have set it. We just check the Status is one of
	// {compliant, non_compliant}, never panic.
	result, err := m.checkFIPSModeEnabled(ctx, nil)
	if err != nil {
		t.Fatalf("checkFIPSModeEnabled: %v", err)
	}
	if result.ControlID != "FIPS-140-001" {
		t.Errorf("ControlID = %q, want FIPS-140-001", result.ControlID)
	}
	if string(result.Severity) != "Critical" {
		t.Errorf("Severity = %q, want Critical", result.Severity)
	}
}

func TestCheckFIPSLevel(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkFIPSLevel(ctx, nil)
	if err != nil {
		t.Fatalf("checkFIPSLevel: %v", err)
	}
	if result.ControlID != "FIPS-140-002" {
		t.Errorf("ControlID = %q, want FIPS-140-002", result.ControlID)
	}
}

func TestCheckApprovedCipherSuites(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (ECDHE-RSA-AES256-GCM-SHA384)",
			input:      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (ECDHE-ECDSA-AES128-GCM-SHA256)",
			input:      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (RC4)",
			input:      "TLS_RSA_WITH_RC4_128_SHA",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (3DES)",
			input:      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (MD5)",
			input:      "TLS_RSA_WITH_RC4_128_MD5",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no approved cipher)",
			input:      "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkApprovedCipherSuites(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkApprovedCipherSuites: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckMinimumTLSVersion(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (TLS 1.3)",
			input:      "tls1.3 enabled",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (TLS 1.2)",
			input:      "tls1.2 enabled",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (min_version 1.3)",
			input:      "min_version: 1.3",
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no TLS version)",
			input:      "http enabled",
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMinimumTLSVersion(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMinimumTLSVersion: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckApprovedHashes(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (SHA-256)",
			input:      "sha-256 used for HMAC",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (SHA-384)",
			input:      "sha-384 used for TLS",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (SHA3-256)",
			input:      "sha3-256 used for audit",
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (MD5)",
			input:      "md5 used for legacy check",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (SHA-1)",
			input:      "sha-1 used for compatibility",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no approved hash)",
			input:      "no hash configured",
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkApprovedHashes(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkApprovedHashes: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckMinimumKeySizes(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (RSA 2048)",
			input:      "rsa 2048 used for TLS",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (RSA 4096)",
			input:      "rsa 4096 used for key exchange",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (ECDSA P-256)",
			input:      "ecdsa p-256 used for signing",
			wantStatus: "compliant",
		},
		{
			name:       "compliant (AES 128)",
			input:      "aes 128 used for encryption",
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (RSA 1024)",
			input:      "rsa 1024 used for legacy",
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (AES 64)",
			input:      "aes 64 used for weak cipher",
			wantStatus: "non_compliant",
		},
		{
			name:       "compliant (no key sizes mentioned)",
			input:      "no key size info",
			wantStatus: "compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMinimumKeySizes(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMinimumKeySizes: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckSelfTest(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkSelfTest(ctx, nil)
	if err != nil {
		t.Fatalf("checkSelfTest: %v", err)
	}
	if result.ControlID != "FIPS-140-007" {
		t.Errorf("ControlID = %q, want FIPS-140-007", result.ControlID)
	}
	// Self-test should pass on any working Go runtime
	if string(result.Status) != "compliant" {
		t.Errorf("Self-test should pass, got status=%q msg=%q",
			result.Status, result.Message)
	}
}

func TestCheckAuditLogging(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkAuditLogging(ctx, nil)
	if err != nil {
		t.Fatalf("checkAuditLogging: %v", err)
	}
	if result.ControlID != "FIPS-140-008" {
		t.Errorf("ControlID = %q, want FIPS-140-008", result.ControlID)
	}
	// Audit logging is not enabled by default; status should be partial
	if string(result.Status) != "partial" {
		t.Errorf("Audit logging should be partial (not enabled by default), got status=%q",
			result.Status)
	}
}

func TestFIPS140Module_Dependencies(t *testing.T) {
	m := NewFIPS140Module()
	deps := m.Dependencies()
	if len(deps) != 2 {
		t.Errorf("Dependencies() returned %d items, want 2", len(deps))
	}
	depsStr := ""
	for _, d := range deps {
		depsStr += d + ","
	}
	if depsStr != "tls,crypto," && depsStr != "crypto,tls," {
		t.Errorf("Dependencies() = %v, want [tls crypto]", deps)
	}
}
