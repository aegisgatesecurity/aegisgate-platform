// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - FIPS 140 Coverage Gap Tests
// =========================================================================
// Targets uncovered functions to push FIPS from 78.0% → 80%+:
// - checkFIPSModeEnabled (0%)
// - checkMinimumTLSVersion (52.9%)
// - checkApprovedHashes (63.2%)
// - checkSelfTest (66.7%)
// - checkApprovedCipherSuites (73.7%)
// - checkMinimumKeySizes (70.4%)
// - checkCMVPValidation (70%)
// - checkHSMIntegration (70%)
// - intToStr (80%)
// =========================================================================

package fips

import (
	"context"
	"strings"
	"testing"
)

// =====================================================================
// checkFIPSModeEnabled (0% → 100%)
// =====================================================================

func TestCheckFIPSModeEnabled(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// Note: FIPS mode may or may not be enabled in test environment,
	// so we test that the function runs and returns a valid result.
	result, err := m.checkFIPSModeEnabled(ctx, nil)
	if err != nil {
		t.Fatalf("checkFIPSModeEnabled: %v", err)
	}
	if result.ControlID != "FIPS-140-001" {
		t.Errorf("ControlID = %q; want FIPS-140-001", result.ControlID)
	}
	if result.Status != "compliant" && result.Status != "non_compliant" {
		t.Errorf("Status = %q; want compliant or non_compliant", result.Status)
	}
	if result.Message == "" {
		t.Error("Message should not be empty")
	}
}

// =====================================================================
// checkMinimumTLSVersion (52.9% → higher)
// =====================================================================

func TestCheckMinimumTLSVersion_TLS13(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// TLS 1.3 config
	input := []byte(`{"tls": {"min_version": "1.3"}, "tls1.3": true}`)
	result, err := m.checkMinimumTLSVersion(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	if result.Status != "compliant" {
		t.Errorf("TLS 1.3 config: status=%s, msg=%s", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "1.3") {
		t.Errorf("Expected message to mention TLS 1.3, got: %s", result.Message)
	}
}

func TestCheckMinimumTLSVersion_TLS12Only(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// TLS 1.2 only (no 1.3)
	input := []byte(`{"tls": {"min_version": "1.2"}, "tls1.2": true}`)
	result, err := m.checkMinimumTLSVersion(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	if result.Status != "compliant" {
		t.Errorf("TLS 1.2 config: status=%s, msg=%s", result.Status, result.Message)
	}
}

func TestCheckMinimumTLSVersion_NoTLS(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// No TLS version info at all
	input := []byte(`{"other": "config"}`)
	result, err := m.checkMinimumTLSVersion(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("No TLS config: status=%s, want non_compliant", result.Status)
	}
	if result.Remediation == "" {
		t.Error("Expected remediation for non-compliant TLS version")
	}
}

func TestCheckMinimumTLSVersion_MinVersionPattern(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// min_version 1.3 pattern — needs to match the regex `min[-_ ]?version[: _-]*1[._-]3`
	input := []byte(`{"min_version:1.3": true}`)
	result, err := m.checkMinimumTLSVersion(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	// This hits the pattern[2] path which checks for "1.3" in the input
	if result.Status != "compliant" {
		t.Errorf("min_version 1.3: status=%s, msg=%s", result.Status, result.Message)
	}
}

// =====================================================================
// checkApprovedHashes (63.2% → higher)
// =====================================================================

func TestCheckApprovedHashes_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"sha-256": true, "sha-384": true, "sha-512": true, "sha3-256": true}`)
	result, err := m.checkApprovedHashes(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedHashes: %v", err)
	}
	if result.Status != "compliant" {
		t.Errorf("Approved hashes config: status=%s, msg=%s", result.Status, result.Message)
	}
}

func TestCheckApprovedHashes_DisallowedMD5(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// MD5 only, no approved hashes — should be non_compliant
	input := []byte(`{"md5": true, "hash": "MD5 checksum"}`)
	result, err := m.checkApprovedHashes(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedHashes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("MD5 only: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "MD5") {
		t.Errorf("Expected message to mention MD5, got: %s", result.Message)
	}
}

func TestCheckApprovedHashes_DisallowedSHA1(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"sha-256": true, "SHA-1": true}`)
	result, err := m.checkApprovedHashes(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedHashes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("SHA-1 present: status=%s, want non_compliant", result.Status)
	}
}

func TestCheckApprovedHashes_NoApprovedNoDisallowed(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"other": "config"}`)
	result, err := m.checkApprovedHashes(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedHashes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("No hashes at all: status=%s, want non_compliant", result.Status)
	}
	if !strings.Contains(result.Message, "no FIPS-approved hashes") {
		t.Errorf("Expected message about no approved hashes, got: %s", result.Message)
	}
}

// =====================================================================
// checkMinimumKeySizes (70.4% → higher)
// =====================================================================

func TestCheckMinimumKeySizes_WeakRSA(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"rsa_1024": true, "ecdsa_p256": true, "aes_256": true}`)
	result, err := m.checkMinimumKeySizes(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumKeySizes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("Weak RSA: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "RSA") {
		t.Errorf("Expected message about RSA key size, got: %s", result.Message)
	}
}

func TestCheckMinimumKeySizes_WeakECDSA(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"ecdsa_p128": true, "rsa_2048": true, "aes_256": true}`)
	result, err := m.checkMinimumKeySizes(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumKeySizes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("Weak ECDSA: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
}

func TestCheckMinimumKeySizes_WeakAES(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"rsa_2048": true, "ecdsa_p256": true, "aes_64": true}`)
	result, err := m.checkMinimumKeySizes(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumKeySizes: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("Weak AES: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
}

func TestCheckMinimumKeySizes_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"rsa_2048": true, "ecdsa_p256": true, "aes_256": true}`)
	result, err := m.checkMinimumKeySizes(ctx, input)
	if err != nil {
		t.Fatalf("checkMinimumKeySizes: %v", err)
	}
	if result.Status != "compliant" {
		t.Errorf("Valid key sizes: status=%s, msg=%s", result.Status, result.Message)
	}
}

// =====================================================================
// checkSelfTest (66.7% → higher)
// =====================================================================

func TestCheckSelfTest(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkSelfTest(ctx, nil)
	if err != nil {
		t.Fatalf("checkSelfTest: %v", err)
	}
	if result.ControlID != "FIPS-140-007" {
		t.Errorf("ControlID = %q; want FIPS-140-007", result.ControlID)
	}
	// Self-test passes or fails depending on runtime state
	if result.Status != "compliant" && result.Status != "non_compliant" {
		t.Errorf("Status = %q; want compliant or non_compliant", result.Status)
	}
}

// =====================================================================
// checkAuditLogging (75% → higher)
// =====================================================================

func TestCheckAuditLogging(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkAuditLogging(ctx, nil)
	if err != nil {
		t.Fatalf("checkAuditLogging: %v", err)
	}
	if result.ControlID != "FIPS-140-008" {
		t.Errorf("ControlID = %q; want FIPS-140-008", result.ControlID)
	}
	// Audit logging may or may not be enabled
	if result.Status != "compliant" && result.Status != "partial" {
		t.Errorf("Status = %q; want compliant or partial", result.Status)
	}
}

// =====================================================================
// checkApprovedCipherSuites — additional paths (73.7% → higher)
// =====================================================================

func TestCheckApprovedCipherSuites_DisallowedCiphers(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"ciphers": "RC4-SHA, DES-CBC, TLS_RSA_WITH_AES_128_GCM_SHA256"}`)
	result, err := m.checkApprovedCipherSuites(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedCipherSuites: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("Disallowed ciphers: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
}

func TestCheckApprovedCipherSuites_NoApprovedNoDisallowed(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"other": "config"}`)
	result, err := m.checkApprovedCipherSuites(ctx, input)
	if err != nil {
		t.Fatalf("checkApprovedCipherSuites: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("No ciphers at all: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "no FIPS-approved ciphers") {
		t.Errorf("Expected message about no approved ciphers, got: %s", result.Message)
	}
}

// =====================================================================
// checkCMVPValidation — partial path (70% → higher)
// =====================================================================

func TestCheckCMVPValidation_Partial(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// Only CMVP number, no cert or module flag
	input := []byte(`{"cmvp": "AES-C-1234"}`)
	result, err := m.checkCMVPValidation(ctx, input)
	if err != nil {
		t.Fatalf("checkCMVPValidation: %v", err)
	}
	if result.Status != "partial" {
		t.Errorf("Partial CMVP: status=%s, want partial, msg=%s", result.Status, result.Message)
	}
}

func TestCheckCMVPValidation_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"other": "config"}`)
	result, err := m.checkCMVPValidation(ctx, input)
	if err != nil {
		t.Fatalf("checkCMVPValidation: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("No CMVP: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
}

// =====================================================================
// checkHSMIntegration — partial path (70% → higher)
// =====================================================================

func TestCheckHSMIntegration_Partial(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	// Only HSM, no PKCS11 or endpoint
	input := []byte(`{"hsm": true}`)
	result, err := m.checkHSMIntegration(ctx, input)
	if err != nil {
		t.Fatalf("checkHSMIntegration: %v", err)
	}
	if result.Status != "partial" {
		t.Errorf("Partial HSM: status=%s, want partial, msg=%s", result.Status, result.Message)
	}
}

func TestCheckHSMIntegration_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	input := []byte(`{"other": "config"}`)
	result, err := m.checkHSMIntegration(ctx, input)
	if err != nil {
		t.Fatalf("checkHSMIntegration: %v", err)
	}
	if result.Status != "non_compliant" {
		t.Errorf("No HSM: status=%s, want non_compliant, msg=%s", result.Status, result.Message)
	}
}

// =====================================================================
// intToStr (80% → 100%)
// =====================================================================

func TestIntToStr(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{2, "2"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
	}
	for _, tt := range tests {
		got := intToStr(tt.input)
		if got != tt.want {
			t.Errorf("intToStr(%d) = %q; want %q", tt.input, got, tt.want)
		}
	}
}

// =====================================================================
// checkFIPSLevel (75% → higher)
// =====================================================================

func TestCheckFIPSLevel(t *testing.T) {
	m := NewFIPS140Module()
	ctx := context.Background()

	result, err := m.checkFIPSLevel(ctx, nil)
	if err != nil {
		t.Fatalf("checkFIPSLevel: %v", err)
	}
	if result.ControlID != "FIPS-140-002" {
		t.Errorf("ControlID = %q; want FIPS-140-002", result.ControlID)
	}
	// FIPS level may or may not be configured
	if result.Status != "compliant" && result.Status != "non_compliant" {
		t.Errorf("Status = %q; want compliant or non_compliant", result.Status)
	}
}