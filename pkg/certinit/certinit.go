// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Certificate Initialization
// =========================================================================
//
// First-run certificate initializer for the AegisGate platform.
// Generates self-signed CA + server certificates on startup when
// auto_generate is enabled and no certificates exist.
//
// This enables zero-config TLS for Community tier deployments:
//   - First startup: generates CA cert + server cert in cert_dir
//   - Subsequent startups: detects existing certs, skips generation
//   - Idempotent: safe to call repeatedly (won't overwrite existing certs)
//
// Uses the upstream certificate.Manager from aegisgate-source for
// actual certificate generation (ECDSA P-256, 10-year CA, 1-year server).
// =========================================================================

package certinit

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/certificate"
)

// Config holds certificate initialization settings.
// These are typically loaded from the platformconfig TLS section.
type Config struct {
	// CertDir is the directory where certificates are stored.
	// Defaults to "./certs" or "/data/certs" in Docker.
	CertDir string `yaml:"cert_dir"`

	// AutoGenerate enables automatic self-signed certificate generation
	// when no existing certificates are found. Community tier default: true.
	AutoGenerate bool `yaml:"auto_generate"`

	// Hostnames is the list of hostnames to include in the server
	// certificate's Subject Alternative Names (SAN).
	// Defaults to ["localhost"] for Community tier.
	Hostnames []string `yaml:"hostnames"`

	// CertFile is the filename for the server certificate PEM.
	// Defaults to "server.crt".
	CertFile string `yaml:"cert_file"`

	// KeyFile is the filename for the server private key PEM.
	// Defaults to "server.key".
	KeyFile string `yaml:"key_file"`

	// CACertFile is the filename for the CA certificate PEM.
	// Defaults to "ca.crt".
	CACertFile string `yaml:"ca_cert_file"`

	// CAKeyFile is the filename for the CA private key PEM.
	// Defaults to "ca.key".
	CAKeyFile string `yaml:"ca_key_file"`
}

// DefaultConfig returns the default certificate initialization configuration.
func DefaultConfig() Config {
	return Config{
		CertDir:      "./certs",
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
}

// Result contains information about the certificate initialization process.
type Result struct {
	// Generated is true if new certificates were generated during this run.
	Generated bool

	// Existing is true if valid certificates already existed and were reused.
	Existing bool

	// CACertPath is the full path to the CA certificate file.
	CACertPath string

	// CAKeyPath is the full path to the CA private key file.
	CAKeyPath string

	// ServerCertPath is the full path to the server certificate file.
	ServerCertPath string

	// ServerKeyPath is the full path to the server private key file.
	ServerKeyPath string

	// CAExpiry is the NotAfter date of the CA certificate.
	CAExpiry time.Time

	// ServerExpiry is the NotAfter date of the server certificate.
	ServerExpiry time.Time

	// Warnings contains any non-fatal issues detected during initialization.
	Warnings []string
}

// EnsureCerts is the primary entry point. It checks for existing certificates
// and generates new ones if auto_generate is enabled and none exist.
//
// This function is idempotent — it will NOT overwrite existing certificates.
// If certificates exist but are invalid/expired, it logs a warning but
// does NOT regenerate (to preserve manual certificate deployments).
//
// Returns a Result describing what was found or generated.
func EnsureCerts(cfg Config) (*Result, error) {
	if !cfg.AutoGenerate {
		return &Result{
			Generated: false,
			Existing:  false,
			Warnings:  []string{"auto_generate disabled — skipping certificate initialization"},
		}, nil
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory %s: %w", cfg.CertDir, err)
	}

	result := &Result{
		CACertPath:     filepath.Join(cfg.CertDir, cfg.CACertFile),
		CAKeyPath:      filepath.Join(cfg.CertDir, cfg.CAKeyFile),
		ServerCertPath: filepath.Join(cfg.CertDir, cfg.CertFile),
		ServerKeyPath:  filepath.Join(cfg.CertDir, cfg.KeyFile),
	}

	// Check if server cert + key already exist and are valid
	existing, warnings := checkExistingCerts(result.ServerCertPath, result.ServerKeyPath, result.CACertPath, result.CAKeyPath)
	if existing {
		result.Existing = true
		result.Warnings = warnings
		return result, nil
	}

	// Generate new certificates
	mgr := certificate.NewManager()

	// Generate CA certificate
	caCert, err := mgr.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Save CA cert + key
	if err := mgr.Save(caCert, result.CACertPath, result.CAKeyPath); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	result.CAExpiry = caCert.Certificate.NotAfter

	// Generate server certificate for each hostname
	// For Community tier, we generate one server cert with all SANs
	primaryHostname := "localhost"
	if len(cfg.Hostnames) > 0 {
		primaryHostname = cfg.Hostnames[0]
	}

	serverCert, err := mgr.GenerateProxyCertificate(primaryHostname)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Save server cert + key
	if err := mgr.Save(serverCert, result.ServerCertPath, result.ServerKeyPath); err != nil {
		return nil, fmt.Errorf("failed to save server certificate: %w", err)
	}

	result.ServerExpiry = serverCert.Certificate.NotAfter
	result.Generated = true
	result.Warnings = warnings

	return result, nil
}

// checkExistingCerts checks whether valid certificates already exist on disk.
// Returns (true, warnings) if all required files exist and are parseable.
// Returns (false, warnings) if any file is missing or invalid.
func checkExistingCerts(serverCertPath, serverKeyPath, caCertPath, caKeyPath string) (bool, []string) {
	var warnings []string

	// Check all required files exist
	files := map[string]string{
		"server cert": serverCertPath,
		"server key":  serverKeyPath,
		"CA cert":     caCertPath,
		"CA key":      caKeyPath,
	}

	for _, path := range files {
		if _, err := os.Stat(path); err != nil {
			// File doesn't exist — need to generate
			return false, warnings
		}
	}

	// All files exist — validate them
	serverCert, err := parseCertificateFile(serverCertPath)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("existing server cert invalid: %v", err))
		return false, warnings
	}

	caCert, err := parseCertificateFile(caCertPath)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("existing CA cert invalid: %v", err))
		return false, warnings
	}

	// Check for expiry warnings
	now := time.Now()
	if serverCert.NotAfter.Before(now) {
		warnings = append(warnings, fmt.Sprintf("server certificate expired on %s", serverCert.NotAfter.Format(time.RFC3339)))
		return false, warnings
	} else if serverCert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		warnings = append(warnings, fmt.Sprintf("server certificate expires soon: %s", serverCert.NotAfter.Format(time.RFC3339)))
	}

	if caCert.NotAfter.Before(now) {
		warnings = append(warnings, fmt.Sprintf("CA certificate expired on %s", caCert.NotAfter.Format(time.RFC3339)))
		return false, warnings
	} else if caCert.NotAfter.Before(now.Add(90 * 24 * time.Hour)) {
		warnings = append(warnings, fmt.Sprintf("CA certificate expires soon: %s", caCert.NotAfter.Format(time.RFC3339)))
	}

	// Validate key files are parseable
	if _, err := parseKeyFile(serverKeyPath); err != nil {
		warnings = append(warnings, fmt.Sprintf("existing server key invalid: %v", err))
		return false, warnings
	}

	if _, err := parseKeyFile(caKeyPath); err != nil {
		warnings = append(warnings, fmt.Sprintf("existing CA key invalid: %v", err))
		return false, warnings
	}

	return true, warnings
}

// parseCertificateFile reads and parses a PEM certificate file.
func parseCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Cert path from config, not user input
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	return cert, nil
}

// parseKeyFile reads and attempts to parse a PEM private key file.
func parseKeyFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Key path from config, not user input
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try ECDSA first (AegisGate generates ECDSA P-256)
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported key format in %s", path)
}

// ValidateCerts performs a full validation of existing certificates.
// Returns the certificate details and any issues found.
// This is intended for the /api/v1/certs dashboard endpoint.
func ValidateCerts(cfg Config) (*CertValidation, error) {
	v := &CertValidation{
		CACertPath:     filepath.Join(cfg.CertDir, cfg.CACertFile),
		CAKeyPath:      filepath.Join(cfg.CertDir, cfg.CAKeyFile),
		ServerCertPath: filepath.Join(cfg.CertDir, cfg.CertFile),
		ServerKeyPath:  filepath.Join(cfg.CertDir, cfg.KeyFile),
	}

	// Check server cert
	cert, err := parseCertificateFile(v.ServerCertPath)
	if err != nil {
		v.ServerCertValid = false
		v.Issues = append(v.Issues, fmt.Sprintf("server cert: %v", err))
	} else {
		v.ServerCertValid = true
		v.ServerExpiry = cert.NotAfter
		v.ServerCN = cert.Subject.CommonName
		v.ServerSANs = cert.DNSNames

		if cert.NotAfter.Before(time.Now()) {
			v.Issues = append(v.Issues, "server certificate is EXPIRED")
		} else if cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			v.Issues = append(v.Issues, "server certificate expires within 30 days")
		}
	}

	// Check CA cert
	caCert, err := parseCertificateFile(v.CACertPath)
	if err != nil {
		v.CACertValid = false
		v.Issues = append(v.Issues, fmt.Sprintf("CA cert: %v", err))
	} else {
		v.CACertValid = true
		v.CAExpiry = caCert.NotAfter
		v.CACN = caCert.Subject.CommonName
		v.CAIsCA = caCert.IsCA

		if caCert.NotAfter.Before(time.Now()) {
			v.Issues = append(v.Issues, "CA certificate is EXPIRED")
		}
	}

	// Check key files
	if _, err := parseKeyFile(v.ServerKeyPath); err != nil {
		v.ServerKeyValid = false
		v.Issues = append(v.Issues, fmt.Sprintf("server key: %v", err))
	} else {
		v.ServerKeyValid = true
	}

	if _, err := parseKeyFile(v.CAKeyPath); err != nil {
		v.CAKeyValid = false
		v.Issues = append(v.Issues, fmt.Sprintf("CA key: %v", err))
	} else {
		v.CAKeyValid = true
	}

	v.Valid = len(v.Issues) == 0
	return v, nil
}

// CertValidation holds the result of a certificate validation check.
type CertValidation struct {
	Valid           bool      `json:"valid"`
	ServerCertValid bool      `json:"server_cert_valid"`
	ServerKeyValid  bool      `json:"server_key_valid"`
	ServerCN        string    `json:"server_cn"`
	ServerSANs      []string  `json:"server_sans"`
	ServerExpiry    time.Time `json:"server_expiry"`
	CACertValid     bool      `json:"ca_cert_valid"`
	CAKeyValid      bool      `json:"ca_key_valid"`
	CACN            string    `json:"ca_cn"`
	CAIsCA          bool      `json:"ca_is_ca"`
	CAExpiry        time.Time `json:"ca_expiry"`
	CACertPath      string    `json:"ca_cert_path"`
	CAKeyPath       string    `json:"ca_key_path"`
	ServerCertPath  string    `json:"server_cert_path"`
	ServerKeyPath   string    `json:"server_key_path"`
	Issues          []string  `json:"issues"`
}
