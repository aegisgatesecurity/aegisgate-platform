// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - CertInit Coverage Tests
// =========================================================================
// Targeted tests for uncovered branches in certinit.go (80% → target 95%)
// Covers: checkExistingCerts edge cases, parseKeyFile formats, ValidateCerts paths
// =========================================================================

package certinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckExistingCerts_AllValidFiles tests the happy path where all cert files exist and are valid.
func TestCheckExistingCerts_AllValidFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true

	// Generate certs first
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	existing, warnings := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if !existing {
		t.Error("checkExistingCerts() = false, want true for valid generated certs")
	}
	if len(warnings) > 0 {
		t.Logf("warnings (acceptable): %v", warnings)
	}
}

// TestCheckExistingCerts_InvalidServerCertPEM tests when server cert file contains invalid PEM.
func TestCheckExistingCerts_InvalidServerCertPEM(t *testing.T) {
	dir := t.TempDir()

	// Generate valid CA + server key, but invalid server cert
	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Overwrite server cert with garbage
	os.WriteFile(result.ServerCertPath, []byte("NOT A CERT"), 0644)

	existing, warnings := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if existing {
		t.Error("checkExistingCerts() = true, want false for invalid server cert PEM")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid server cert, got none")
	}
}

// TestCheckExistingCerts_InvalidCACertPEM tests when CA cert file contains invalid PEM.
func TestCheckExistingCerts_InvalidCACertPEM(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Overwrite CA cert with garbage
	os.WriteFile(result.CACertPath, []byte("NOT A CA CERT"), 0644)

	existing, warnings := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if existing {
		t.Error("checkExistingCerts() = true, want false for invalid CA cert PEM")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid CA cert, got none")
	}
}

// TestCheckExistingCerts_InvalidServerKey tests when server key file contains invalid key.
func TestCheckExistingCerts_InvalidServerKey(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Overwrite server key with garbage PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")})
	os.WriteFile(result.ServerKeyPath, keyPEM, 0600)

	existing, warnings := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if existing {
		t.Error("checkExistingCerts() = true, want false for invalid server key")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid server key, got none")
	}
}

// TestCheckExistingCerts_InvalidCAKey tests when CA key file contains invalid key.
func TestCheckExistingCerts_InvalidCAKey(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Overwrite CA key with garbage PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
	os.WriteFile(result.CAKeyPath, keyPEM, 0600)

	existing, warnings := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if existing {
		t.Error("checkExistingCerts() = true, want false for invalid CA key")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid CA key, got none")
	}
}

// TestCheckExistingCerts_MissingServerCert tests when server cert file doesn't exist.
// checkExistingCerts returns false with no warnings for missing files (it's a binary check).
func TestCheckExistingCerts_MissingServerCert(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Delete server cert
	os.Remove(result.ServerCertPath)

	existing, _ := checkExistingCerts(
		result.ServerCertPath, result.ServerKeyPath,
		result.CACertPath, result.CAKeyPath,
	)

	if existing {
		t.Error("checkExistingCerts() = true, want false for missing server cert")
	}
}

// TestParseKeyFile_PKCS1RSAKey tests parsing a PKCS1 RSA private key.
func TestParseKeyFile_PKCS1RSAKey(t *testing.T) {
	dir := t.TempDir()

	// Generate RSA key and write as PKCS1
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, keyPEM, 0600)

	parsed, err := parseKeyFile(keyPath)
	if err != nil {
		t.Errorf("parseKeyFile(PKCS1 RSA) error: %v", err)
	}
	if parsed == nil {
		t.Error("parseKeyFile(PKCS1 RSA) returned nil key")
	}
}

// TestParseKeyFile_PKCS8Key tests parsing a PKCS8 private key.
func TestParseKeyFile_PKCS8Key(t *testing.T) {
	dir := t.TempDir()

	// Generate ECDSA key and write as PKCS8
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, keyPEM, 0600)

	parsed, err := parseKeyFile(keyPath)
	if err != nil {
		t.Errorf("parseKeyFile(PKCS8) error: %v", err)
	}
	if parsed == nil {
		t.Error("parseKeyFile(PKCS8) returned nil key")
	}
}

// TestParseKeyFile_PKCS8RSAKey tests parsing a PKCS8 RSA private key.
func TestParseKeyFile_PKCS8RSAKey(t *testing.T) {
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, keyPEM, 0600)

	parsed, err := parseKeyFile(keyPath)
	if err != nil {
		t.Errorf("parseKeyFile(PKCS8 RSA) error: %v", err)
	}
	if parsed == nil {
		t.Error("parseKeyFile(PKCS8 RSA) returned nil key")
	}
}

// TestParseKeyFile_FileReadError tests when the key file doesn't exist.
func TestParseKeyFile_FileReadError(t *testing.T) {
	_, err := parseKeyFile("/nonexistent/path/server.key")
	if err == nil {
		t.Error("parseKeyFile(nonexistent) expected error, got nil")
	}
}

// TestParseKeyFile_UnsupportedPEMBlock tests when PEM block has wrong type.
func TestParseKeyFile_UnsupportedPEMBlock(t *testing.T) {
	dir := t.TempDir()

	// Write a PEM block with wrong type
	invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a private key")})
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, invalidPEM, 0600)

	_, err := parseKeyFile(keyPath)
	if err == nil {
		t.Error("parseKeyFile(wrong PEM type) expected error, got nil")
	}
}

// TestParseKeyFile_NoPEMData tests when file contains no PEM data.
func TestParseKeyFile_NoPEMData(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, []byte("this is not PEM data at all"), 0600)

	_, err := parseKeyFile(keyPath)
	if err == nil {
		t.Error("parseKeyFile(no PEM data) expected error, got nil")
	}
}

// TestValidateCerts_InvalidServerKey tests ValidateCerts when server key is invalid.
func TestValidateCerts_InvalidServerKey(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Corrupt server key
	os.WriteFile(result.ServerKeyPath, []byte("INVALID KEY DATA"), 0600)

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts() error: %v", err)
	}
	if validation.ServerKeyValid {
		t.Error("ServerKeyValid = true, want false for corrupted key")
	}
	if validation.Valid {
		t.Error("Valid = true, want false when server key is invalid")
	}
}

// TestValidateCerts_InvalidCAKey tests ValidateCerts when CA key is invalid.
func TestValidateCerts_InvalidCAKey(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	// Corrupt CA key
	os.WriteFile(result.CAKeyPath, []byte("INVALID CA KEY DATA"), 0600)

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts() error: %v", err)
	}
	if validation.CAKeyValid {
		t.Error("CAKeyValid = true, want false for corrupted CA key")
	}
}

// TestValidateCerts_MissingCertDir tests ValidateCerts when cert directory doesn't exist.
func TestValidateCerts_MissingCertDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CertDir = "/nonexistent/cert/dir"

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts() error: %v", err)
	}
	if validation.Valid {
		t.Error("Valid = true, want false for missing cert dir")
	}
}

// TestValidateCerts_CustomHostnames tests that the primary hostname is in SANs.
// Note: GenerateProxyCertificate only uses the primary hostname for the cert's
// DNSNames/SANs — additional hostnames are not currently included. This test
// validates the actual behavior (primary hostname only in SANs).
func TestValidateCerts_CustomHostnames(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	cfg.Hostnames = []string{"myhost.local", "test.example.com"}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}
	if result.Generated != true {
		t.Error("Generated = false, want true for new certs")
	}

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts() error: %v", err)
	}

	// Primary hostname (cfg.Hostnames[0]) must appear in SANs
	if len(validation.ServerSANs) == 0 {
		t.Fatal("ServerSANs is empty")
	}
	foundPrimary := false
	for _, san := range validation.ServerSANs {
		if san == "myhost.local" {
			foundPrimary = true
			break
		}
	}
	if !foundPrimary {
		t.Errorf("primary hostname %q not found in ServerSANs: %v", "myhost.local", validation.ServerSANs)
	}

	// Validate CN matches primary hostname
	if validation.ServerCN != "myhost.local" {
		t.Errorf("ServerCN = %q, want %q", validation.ServerCN, "myhost.local")
	}
}

// TestEnsureCerts_AutoGenerateFalse_NoExisting tests auto_generate=false with no existing certs.
func TestEnsureCerts_AutoGenerateFalse_NoExisting(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = false

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts(AutoGenerate=false) error: %v", err)
	}
	if result.Generated {
		t.Error("Generated = true, want false when AutoGenerate=false")
	}
	if result.Existing {
		t.Error("Existing = true, want false when no certs exist and AutoGenerate=false")
	}
}

// TestEnsureCerts_AutoGenerateFalse_WithExisting tests that auto_generate=false returns
// early without checking whether certs exist on disk. The current implementation
// short-circuits — it does not look for existing certs when auto-generate is off.
func TestEnsureCerts_AutoGenerateFalse_WithExisting(t *testing.T) {
	dir := t.TempDir()

	// First: generate certs with AutoGenerate=true
	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true
	result1, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("first EnsureCerts() error: %v", err)
	}
	if !result1.Generated {
		t.Fatal("first run should generate certs")
	}

	// Second: with AutoGenerate=false — EnsureCerts returns early without checking existing
	cfg.AutoGenerate = false
	result2, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("second EnsureCerts() error: %v", err)
	}
	if result2.Generated {
		t.Error("Generated = true, want false when AutoGenerate=false")
	}
	// Existing is false because AutoGenerate=false skips the existing-certs check
	if result2.Existing {
		t.Error("Existing = true for AutoGenerate=false, implementation returns early without checking")
	}
	// Should have a warning about auto_generate being disabled
	if len(result2.Warnings) == 0 {
		t.Error("expected at least one warning about auto_generate being disabled")
	}
}

// TestParseCertificateFile_InvalidData tests parseCertificateFile with garbage data.
func TestParseCertificateFile_InvalidData(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	os.WriteFile(certPath, []byte("NOT A CERTIFICATE"), 0644)

	_, err := parseCertificateFile(certPath)
	if err == nil {
		t.Error("parseCertificateFile(invalid data) expected error, got nil")
	}
}

// TestParseCertificateFile_MissingFile tests parseCertificateFile with nonexistent file.
func TestParseCertificateFile_MissingFile(t *testing.T) {
	_, err := parseCertificateFile("/nonexistent/cert.crt")
	if err == nil {
		t.Error("parseCertificateFile(missing file) expected error, got nil")
	}
}

// TestEnsureCerts_ExpirySet tests that generated results have future expiry dates.
func TestEnsureCerts_ExpirySet(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.CertDir = dir
	cfg.AutoGenerate = true

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts() error: %v", err)
	}

	now := time.Now()
	if result.CAExpiry.Before(now) {
		t.Errorf("CAExpiry %v is before now %v", result.CAExpiry, now)
	}
	if result.ServerExpiry.Before(now) {
		t.Errorf("ServerExpiry %v is before now %v", result.ServerExpiry, now)
	}
}
