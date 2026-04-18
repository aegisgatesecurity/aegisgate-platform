// Copyright 2024 AegisGate
// FIPS Module Tests

package fips

import (
	"crypto/tls"
	"testing"
)

func TestFIPSModeConfiguration(t *testing.T) {
	// Test default mode
	mode := GetMode()
	if mode.Enabled != false {
		t.Error("Expected FIPS mode to be disabled by default")
	}

	// Test configuring FIPS 140-2
	err := Configure(Level140_2)
	if err != nil {
		t.Fatalf("Failed to configure FIPS mode: %v", err)
	}

	// Verify mode is enabled
	mode = GetMode()
	if !mode.Enabled {
		t.Error("Expected FIPS mode to be enabled")
	}
	if mode.Level != Level140_2 {
		t.Errorf("Expected FIPS 140-2, got %s", mode.Level)
	}

	// Test configuring FIPS 140-3
	err = Configure(Level140_3, WithAudit(true))
	if err != nil {
		t.Fatalf("Failed to configure FIPS 140-3: %v", err)
	}

	mode = GetMode()
	if mode.Level != Level140_3 {
		t.Errorf("Expected FIPS 140-3, got %s", mode.Level)
	}
	if !mode.AuditEnabled {
		t.Error("Expected audit to be enabled")
	}
}

func TestApprovedAlgorithms(t *testing.T) {
	// Test hash algorithms
	hashes := ApprovedHashAlgorithms()
	if len(hashes) == 0 {
		t.Error("Expected hash algorithms to be available")
	}

	// Verify SHA-256 is available (required)
	if _, ok := hashes["SHA-256"]; !ok {
		t.Error("SHA-256 should be available")
	}

	// Test cipher suites
	ciphers := ApprovedCipherSuites()
	if len(ciphers) == 0 {
		t.Error("Expected cipher suites to be available")
	}

	// Test minimum key sizes
	mins := MinimumKeySizes()
	if mins["RSA"] < 2048 {
		t.Error("RSA minimum should be at least 2048 bits")
	}
}

func TestComplianceCheck(t *testing.T) {
	report := Check(Level140_2)

	if report == nil {
		t.Fatal("Expected compliance report")
	}

	if report.FIPSLevel != Level140_2 {
		t.Errorf("Expected Level140_2, got %v", report.FIPSLevel)
	}

	// Should have at least some checks
	if len(report.Checks) == 0 {
		t.Error("Expected compliance checks to be performed")
	}

	t.Logf("Compliance Report:\n%s", report.String())
}

func TestKeyValidation(t *testing.T) {
	tests := []struct {
		algorithm string
		size      int
		wantErr   bool
	}{
		{"RSA", 2048, false},
		{"RSA", 4096, false},
		{"RSA", 1024, true}, // Too small
		{"ECDSA", 256, false},
		{"ECDSA", 384, false},
		{"AES", 128, false},
		{"AES", 256, false},
	}

	for _, tt := range tests {
		err := ValidateKeySize(tt.algorithm, tt.size)
		if tt.wantErr && err == nil {
			t.Errorf("Expected error for %s %d", tt.algorithm, tt.size)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("Unexpected error for %s %d: %v", tt.algorithm, tt.size, err)
		}
	}
}

func TestHashValidation(t *testing.T) {
	// Valid hash algorithms
	valid := []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256"}
	for _, h := range valid {
		if err := ValidateHashAlgorithm(h); err != nil {
			t.Errorf("Expected %s to be valid: %v", h, err)
		}
	}

	// Invalid hash algorithm
	if err := ValidateHashAlgorithm("MD5"); err == nil {
		t.Error("Expected MD5 to be invalid")
	}
}

func TestSelfTest(t *testing.T) {
	// Enable FIPS mode temporarily
	oldMode := *CurrentMode
	CurrentMode.AuditEnabled = true
	CurrentMode.Enabled = true
	defer func() { *CurrentMode = oldMode }()

	err := SelfTest()
	if err != nil {
		t.Fatalf("Self-test failed: %v", err)
	}

	// Check audit log
	log := GetAuditLog()
	if len(log) == 0 {
		t.Error("Expected audit log entries")
	}
}

func TestTLSConfig(t *testing.T) {
	config := GetTLSConfig(tls.VersionTLS12)

	if config.MinVersion < tls.VersionTLS12 {
		t.Error("Expected minimum TLS 1.2")
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelNone, "None"},
		{Level140_2, "FIPS 140-2"},
		{Level140_3, "FIPS 140-3"},
		{Level(99), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("Level.String() = %q, want %q", got, tt.want)
		}
	}
}
