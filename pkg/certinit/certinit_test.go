// SPDX-License-Identifier: MIT
package certinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CertDir != "./certs" {
		t.Errorf("expected CertDir ./certs, got %s", cfg.CertDir)
	}
	if !cfg.AutoGenerate {
		t.Error("expected AutoGenerate true")
	}
	if len(cfg.Hostnames) != 1 || cfg.Hostnames[0] != "localhost" {
		t.Errorf("expected Hostnames [localhost], got %v", cfg.Hostnames)
	}
	if cfg.CertFile != "server.crt" {
		t.Errorf("expected CertFile server.crt, got %s", cfg.CertFile)
	}
	if cfg.KeyFile != "server.key" {
		t.Errorf("expected KeyFile server.key, got %s", cfg.KeyFile)
	}
	if cfg.CACertFile != "ca.crt" {
		t.Errorf("expected CACertFile ca.crt, got %s", cfg.CACertFile)
	}
	if cfg.CAKeyFile != "ca.key" {
		t.Errorf("expected CAKeyFile ca.key, got %s", cfg.CAKeyFile)
	}
}

func TestEnsureCerts_Disabled(t *testing.T) {
	cfg := Config{CertDir: t.TempDir(), AutoGenerate: false}
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Generated {
		t.Error("should not generate when disabled")
	}
	if result.Existing {
		t.Error("should not find existing when disabled")
	}
}

func TestEnsureCerts_GeneratesNew(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Generated {
		t.Error("expected certificates to be generated")
	}
	if result.Existing {
		t.Error("should not report existing for new certs")
	}

	// Verify files exist
	if _, err := os.Stat(result.ServerCertPath); err != nil {
		t.Errorf("server cert not created: %v", err)
	}
	if _, err := os.Stat(result.ServerKeyPath); err != nil {
		t.Errorf("server key not created: %v", err)
	}
	if _, err := os.Stat(result.CACertPath); err != nil {
		t.Errorf("CA cert not created: %v", err)
	}
	if _, err := os.Stat(result.CAKeyPath); err != nil {
		t.Errorf("CA key not created: %v", err)
	}
}

func TestEnsureCerts_Idempotent(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// First run — generates
	result1, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("first run error: %v", err)
	}
	if !result1.Generated {
		t.Error("first run should generate")
	}

	// Second run — detects existing
	result2, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}
	if result2.Generated {
		t.Error("second run should NOT regenerate")
	}
	if !result2.Existing {
		t.Error("second run should find existing")
	}
}

func TestEnsureCerts_CreatesCertDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "certs")
	cfg := Config{
		CertDir:      dir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Generated {
		t.Error("expected generation")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("cert directory not created: %v", err)
	}
}

func TestEnsureCerts_GeneratedCertIsValid(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CA cert should be valid for ~10 years
	if result.CAExpiry.Before(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Errorf("CA cert expiry too soon: %v", result.CAExpiry)
	}

	// Server cert should be valid for ~1 year
	if result.ServerExpiry.Before(time.Now().Add(350 * 24 * time.Hour)) {
		t.Errorf("server cert expiry too soon: %v", result.ServerExpiry)
	}
	if result.ServerExpiry.After(time.Now().Add(366 * 24 * time.Hour)) {
		t.Errorf("server cert expiry too far: %v", result.ServerExpiry)
	}

	// Certs should not be expired
	if result.CAExpiry.Before(time.Now()) {
		t.Error("CA cert is already expired")
	}
	if result.ServerExpiry.Before(time.Now()) {
		t.Error("server cert is already expired")
	}
}

func TestValidateCerts_WithGenerated(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// Generate first
	_, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}

	// Validate
	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("validate error: %v", err)
	}
	if !v.Valid {
		t.Errorf("expected valid, got issues: %v", v.Issues)
	}
	if !v.ServerCertValid {
		t.Error("server cert should be valid")
	}
	if !v.ServerKeyValid {
		t.Error("server key should be valid")
	}
	if !v.CACertValid {
		t.Error("CA cert should be valid")
	}
	if !v.CAKeyValid {
		t.Error("CA key should be valid")
	}
	if v.CACN != "AegisGate CA" {
		t.Errorf("expected CA CN 'AegisGate CA', got %s", v.CACN)
	}
	if !v.CAIsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if v.ServerCN != "localhost" {
		t.Errorf("expected server CN 'localhost', got %s", v.ServerCN)
	}
}

func TestValidateCerts_NoFiles(t *testing.T) {
	cfg := Config{
		CertDir:    t.TempDir(),
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("validate error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with no files")
	}
	if len(v.Issues) == 0 {
		t.Error("expected issues for missing files")
	}
}

func TestParseCertificateFile_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crt")
	os.WriteFile(path, []byte("not a pem file"), 0644)

	_, err := parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParseKeyFile_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	os.WriteFile(path, []byte("not a key file"), 0644)

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestCheckExistingCerts_PartialFiles(t *testing.T) {
	dir := t.TempDir()
	// Create only CA cert, not server cert
	caPath := filepath.Join(dir, "ca.crt")
	os.WriteFile(caPath, []byte("placeholder"), 0644)

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		caPath,
		filepath.Join(dir, "ca.key"),
	)
	if existing {
		t.Error("should not find existing with partial files")
	}
	_ = warnings // warnings OK for partial
}
