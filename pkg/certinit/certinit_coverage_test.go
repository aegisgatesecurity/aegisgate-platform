// SPDX-License-Identifier: Apache-2.0
//go:build !race

package certinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pemEncodeCert writes a PEM-encoded certificate to a file
func pemEncodeCert(path string, certDER []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// pemEncodeKey writes a PEM-encoded RSA private key to a file
func pemEncodeKey(path string, key *rsa.PrivateKey) error {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// =========================================================================
// EnsureCerts error paths
// =========================================================================

func TestEnsureCerts_MkdirAllError(t *testing.T) {
	// Test os.MkdirAll error path - use invalid absolute path
	cfg := Config{
		CertDir:      "/proc/fake_dir_that_cannot_exist_xyz123",
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	_, err := EnsureCerts(cfg)
	if err == nil {
		t.Error("expected error for mkdir failure")
	}
}

func TestEnsureCerts_PermissionDenied(t *testing.T) {
	// Create a directory that exists but is not writable
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Skip("cannot change permissions on this system")
	}

	cfg := Config{
		CertDir:      dir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	_, err := EnsureCerts(cfg)

	// Restore permissions for cleanup
	os.Chmod(dir, 0755)

	if err == nil {
		t.Error("expected error for permission denied")
	}
}

// =========================================================================
// checkExistingCerts error paths
// =========================================================================

func TestCheckExistingCerts_ServerCertParseError(t *testing.T) {
	dir := t.TempDir()

	// Create valid CA cert and key first
	caCertDER, caKey := generateTestCert(t, "Test CA", true, time.Now().Add(365*24*time.Hour))
	serverKey := generateTestKey(t)

	// Write valid CA cert and key
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	serverKeyPath := filepath.Join(dir, "server.key")

	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)
	pemEncodeKey(serverKeyPath, serverKey)

	// Write INVALID server cert (corrupt PEM)
	invalidCertPath := filepath.Join(dir, "server.crt")
	os.WriteFile(invalidCertPath, []byte("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"), 0644)

	existing, warnings := checkExistingCerts(
		invalidCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with corrupt server cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for invalid server cert")
	}
}

func TestCheckExistingCerts_CACertParseError(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caKey := generateTestKey(t)

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeKey(caKeyPath, caKey)

	// Write INVALID CA cert
	os.WriteFile(caCertPath, []byte("-----BEGIN CERTIFICATE-----\nINVALIDCA\n-----END CERTIFICATE-----"), 0644)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with corrupt CA cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for invalid CA cert")
	}
}

func TestCheckExistingCerts_ServerKeyParseError(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, _ := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)

	// Write INVALID server key
	os.WriteFile(serverKeyPath, []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALIDKEY\n-----END RSA PRIVATE KEY-----"), 0600)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with corrupt server key")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for invalid server key")
	}
}

func TestCheckExistingCerts_CAKeyParseError(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caCertDER, _ := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeCert(caCertPath, caCertDER)

	// Write key in PKCS8 format wrapped in wrong type to test unsupported format
	os.WriteFile(caKeyPath, []byte("-----BEGIN PRIVATE KEY-----\nINVALIDKEYDATA==\n-----END PRIVATE KEY-----"), 0600)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with unsupported CA key format")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for invalid CA key")
	}
}

func TestCheckExistingCerts_ExpiredServerCert(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(-24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with expired server cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for expired server cert")
	}
}

func TestCheckExistingCerts_ExpiredCACert(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(-24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	if existing {
		t.Error("should not find existing with expired CA cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for expired CA cert")
	}
}

func TestCheckExistingCerts_ServerCertExpiringSoon(t *testing.T) {
	dir := t.TempDir()

	// Server cert expires in 20 days (within 30 day warning threshold)
	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(20*24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	// Should still find existing (just warn), but warn about expiry
	if !existing {
		t.Error("should find existing with cert expiring soon")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for cert expiring soon")
	}
}

func TestCheckExistingCerts_CACertExpiringSoon(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	// CA cert expires in 60 days (within 90 day warning threshold)
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(60*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(serverKeyPath, serverKey)
	pemEncodeCert(caCertPath, caCertDER)
	pemEncodeKey(caKeyPath, caKey)

	existing, warnings := checkExistingCerts(
		serverCertPath,
		serverKeyPath,
		caCertPath,
		caKeyPath,
	)

	// Should still find existing (just warn), but warn about expiry
	if !existing {
		t.Error("should find existing with CA cert expiring soon")
	}
	if len(warnings) == 0 {
		t.Error("expected warning for CA cert expiring soon")
	}
}

// =========================================================================
// parseCertificateFile error paths
// =========================================================================

func TestParseCertificateFile_ReadError(t *testing.T) {
	// Test os.ReadFile error path - file that doesn't exist
	_, err := parseCertificateFile("/nonexistent/path/to/cert.pem")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParseCertificateFile_NoCertPEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nocert.pem")

	// Write PEM block that is NOT a certificate
	os.WriteFile(path, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"), 0644)

	_, err := parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for non-certificate PEM block")
	}
}

func TestParseCertificateFile_InvalidASN1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalidasn1.pem")

	// Write a PEM block with garbage DER data
	os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA_HERE\n-----END CERTIFICATE-----"), 0644)

	_, err := parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for invalid ASN.1 data")
	}
}

// =========================================================================
// ValidateCerts error paths
// =========================================================================

func TestValidateCerts_ExpiredServerCert(t *testing.T) {
	dir := t.TempDir()

	// Generate expired server cert - NotAfter in the past
	notAfter := time.Now().Add(-24 * time.Hour)
	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, notAfter)
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	serverCertPath := filepath.Join(dir, "server.crt")
	pemEncodeCert(serverCertPath, serverCertDER)
	pemEncodeKey(filepath.Join(dir, "server.key"), serverKey)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	pemEncodeKey(filepath.Join(dir, "ca.key"), caKey)

	// Debug: verify the cert was written correctly by parsing it back
	parsedCert, parseErr := parseCertificateFile(serverCertPath)
	if parseErr != nil {
		t.Fatalf("debug: failed to parse written cert: %v", parseErr)
	}
	if !parsedCert.NotAfter.Before(time.Now()) {
		t.Fatalf("debug: test setup failed - cert NotAfter (%v) should be in the past", parsedCert.NotAfter)
	}

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with expired server cert")
	}
	// Note: ServerCertValid is true since the cert parsed successfully
	// but it has expired, which is recorded in Issues

	foundExpired := false
	for _, issue := range v.Issues {
		if issue == "server certificate is EXPIRED" {
			foundExpired = true
			break
		}
	}
	if !foundExpired {
		t.Errorf("expected EXPIRED issue, got: %v", v.Issues)
	}
}

func TestValidateCerts_ExpiredCACert(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	// Generate expired CA cert - NotAfter in the past
	notAfter := time.Now().Add(-24 * time.Hour)
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, notAfter)

	pemEncodeCert(filepath.Join(dir, "server.crt"), serverCertDER)
	pemEncodeKey(filepath.Join(dir, "server.key"), serverKey)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	pemEncodeKey(filepath.Join(dir, "ca.key"), caKey)

	// Debug: verify the CA cert was written correctly by parsing it back
	parsedCert, parseErr := parseCertificateFile(filepath.Join(dir, "ca.crt"))
	if parseErr != nil {
		t.Fatalf("debug: failed to parse written CA cert: %v", parseErr)
	}
	if !parsedCert.NotAfter.Before(time.Now()) {
		t.Fatalf("debug: test setup failed - CA cert NotAfter (%v) should be in the past", parsedCert.NotAfter)
	}

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with expired CA cert")
	}
	// Note: CACertValid is true since the cert parsed successfully
	// but it has expired, which is recorded in Issues

	foundExpired := false
	for _, issue := range v.Issues {
		if issue == "CA certificate is EXPIRED" {
			foundExpired = true
			break
		}
	}
	if !foundExpired {
		t.Errorf("expected CA EXPIRED issue, got: %v", v.Issues)
	}
}

func TestValidateCerts_ServerCertExpiringSoon(t *testing.T) {
	dir := t.TempDir()

	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(20*24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	pemEncodeCert(filepath.Join(dir, "server.crt"), serverCertDER)
	pemEncodeKey(filepath.Join(dir, "server.key"), serverKey)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	pemEncodeKey(filepath.Join(dir, "ca.key"), caKey)

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with server cert expiring soon")
	}

	foundExpiring := false
	for _, issue := range v.Issues {
		if issue == "server certificate expires within 30 days" {
			foundExpiring = true
			break
		}
	}
	if !foundExpiring {
		t.Errorf("expected 'expires within 30 days' issue, got: %v", v.Issues)
	}
}

func TestValidateCerts_InvalidServerCert(t *testing.T) {
	dir := t.TempDir()
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	// Write invalid cert data
	os.WriteFile(filepath.Join(dir, "server.crt"), []byte("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"), 0644)
	pemEncodeKey(filepath.Join(dir, "server.key"), caKey)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	pemEncodeKey(filepath.Join(dir, "ca.key"), caKey)

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with invalid server cert")
	}
	if v.ServerCertValid {
		t.Error("server cert should not be valid")
	}
}

func TestValidateCerts_InvalidServerKey(t *testing.T) {
	dir := t.TempDir()
	serverCertDER, _ := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caCertDER, caKey := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	pemEncodeCert(filepath.Join(dir, "server.crt"), serverCertDER)
	os.WriteFile(filepath.Join(dir, "server.key"), []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----"), 0600)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	pemEncodeKey(filepath.Join(dir, "ca.key"), caKey)

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with invalid server key")
	}
	if v.ServerKeyValid {
		t.Error("server key should not be valid")
	}
}

func TestValidateCerts_InvalidCAKey(t *testing.T) {
	dir := t.TempDir()
	serverCertDER, serverKey := generateTestCertPair(t, "localhost", false, time.Now().Add(365*24*time.Hour))
	caCertDER, _ := generateTestCertPair(t, "Test CA", true, time.Now().Add(365*24*time.Hour))

	pemEncodeCert(filepath.Join(dir, "server.crt"), serverCertDER)
	pemEncodeKey(filepath.Join(dir, "server.key"), serverKey)
	pemEncodeCert(filepath.Join(dir, "ca.crt"), caCertDER)
	os.WriteFile(filepath.Join(dir, "ca.key"), []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----"), 0600)

	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with invalid CA key")
	}
	if v.CAKeyValid {
		t.Error("CA key should not be valid")
	}
}

// =========================================================================
// parseKeyFile error paths
// =========================================================================

func TestParseKeyFile_UnsupportedKeyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsupported.key")

	// Write PEM with unknown key format
	os.WriteFile(path, []byte("-----BEGIN OTHER KEY TYPE-----\nSOMEDATA\n-----END OTHER KEY TYPE-----"), 0600)

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for unsupported key format")
	}
}

func TestParseKeyFile_ReadError(t *testing.T) {
	_, err := parseKeyFile("/nonexistent/path/to/key.pem")
	if err == nil {
		t.Error("expected error for non-existent key file")
	}
}

func TestParseKeyFile_NoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nopem.key")

	// Write PEM with no block
	os.WriteFile(path, []byte("not a pem file at all"), 0600)

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for no PEM block")
	}
}

// =========================================================================
// Helper functions
// =========================================================================

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

// generateTestCert generates a test certificate and returns its DER encoding
func generateTestCert(t *testing.T, cn string, isCA bool, notAfter time.Time) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key := generateTestKey(t)

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Sub(big.NewInt(1<<62), big.NewInt(1)))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return certDER, key
}

// generateTestCertPair generates a test certificate and returns its DER encoding
func generateTestCertPair(t *testing.T, cn string, isCA bool, notAfter time.Time) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	return generateTestCert(t, cn, isCA, notAfter)
}
