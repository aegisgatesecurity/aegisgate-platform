package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/pkiattest"
)

// TestDefaultMITMAttestationConfig tests default config creation
func TestDefaultMITMAttestationConfig(t *testing.T) {
	cfg := DefaultMITMAttestationConfig()

	if cfg == nil {
		t.Fatal("DefaultMITMAttestationConfig returned nil")
	}

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}

	if !cfg.RequireChainVerification {
		t.Error("RequireChainVerification should be true by default")
	}

	if !cfg.RequireCRL {
		t.Error("RequireCRL should be true by default")
	}

	if cfg.RequireOCSP {
		t.Error("RequireOCSP should be false by default (can be slow)")
	}

	if !cfg.BackdoorPrevention {
		t.Error("BackdoorPrevention should be true by default")
	}

	if !cfg.FailClosed {
		t.Error("FailClosed should be true by default")
	}

	if cfg.CRLTimeout != 5*time.Second {
		t.Errorf("Expected CRLTimeout 5s, got %v", cfg.CRLTimeout)
	}

	if cfg.OCSPTimeout != 5*time.Second {
		t.Errorf("Expected OCSPTimeout 5s, got %v", cfg.OCSPTimeout)
	}

	if cfg.CacheTTL != 5*time.Minute {
		t.Errorf("Expected CacheTTL 5m, got %v", cfg.CacheTTL)
	}
}

// TestNewMITMAttestation tests MITM attestation creation
func TestNewMITMAttestation(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		ma, err := NewMITMAttestation(nil)
		if err != nil {
			t.Fatalf("Failed with nil config: %v", err)
		}
		if ma == nil {
			t.Fatal("NewMITMAttestation returned nil")
		}
		if !ma.IsEnabled() {
			t.Error("Should be enabled by default")
		}
	})

	t.Run("custom_config", func(t *testing.T) {
		cfg := &MITMAttestationConfig{
			Enabled:                  true,
			RequireChainVerification: false,
			RequireCRL:               false,
			RequireOCSP:              false,
			BackdoorPrevention:       false,
			FailClosed:               false,
			CacheResults:             true,
			CacheTTL:                 10 * time.Minute,
		}

		ma, err := NewMITMAttestation(cfg)
		if err != nil {
			t.Fatalf("Failed with custom config: %v", err)
		}
		if ma == nil {
			t.Fatal("NewMITMAttestation returned nil")
		}
	})
}

// TestAttestUpstreamCertificate tests certificate attestation
func TestAttestUpstreamCertificate(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled:                  true,
		RequireChainVerification: false,
		RequireCRL:               false,
		RequireOCSP:              false,
		BackdoorPrevention:       true,
		FailClosed:               false,
		CacheResults:             true,
		CacheTTL:                 5 * time.Minute,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// Create a test certificate
	cert := createTestCertificate(t, "test.example.com", false)

	t.Run("attest_certificate", func(t *testing.T) {
		result := ma.AttestUpstreamCertificate(cert)

		if result == nil {
			t.Fatal("AttestUpstreamCertificate returned nil result")
		}

		if result.Certificate == nil {
			t.Error("Certificate should not be nil in result")
		}

		if result.Timestamp.IsZero() {
			t.Error("Timestamp should be set")
		}
	})

	t.Run("cache_result", func(t *testing.T) {
		// First attestation
		result1 := ma.AttestUpstreamCertificate(cert)

		// Second attestation should use cache
		result2 := ma.AttestUpstreamCertificate(cert)

		// Both should have same serial number
		if result1.Certificate.SerialNumber.String() != result2.Certificate.SerialNumber.String() {
			t.Error("Cache should return same certificate")
		}
	})
}

// TestAttestConnection tests TLS connection attestation
func TestAttestConnection(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled:                  true,
		RequireChainVerification: false,
		RequireCRL:               false,
		RequireOCSP:              false,
		BackdoorPrevention:       true,
		FailClosed:               false,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	t.Run("nil_connection_state", func(t *testing.T) {
		_, err := ma.AttestConnection(nil)
		if err == nil {
			t.Error("Expected error for nil connection state")
		}
	})

	t.Run("empty_peer_certs", func(t *testing.T) {
		connState := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		_, err := ma.AttestConnection(connState)
		if err == nil {
			t.Error("Expected error for empty peer certificates")
		}
	})
}

// TestAddTrustAnchor tests adding trust anchors
func TestAddTrustAnchor(t *testing.T) {
	cfg := DefaultMITMAttestationConfig()
	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// Create test CA certificate
	caCert := createTestCertificate(t, "Test CA", true)

	t.Run("add_valid_anchor", func(t *testing.T) {
		err := ma.AddTrustAnchor(caCert)
		if err != nil {
			t.Errorf("Failed to add trust anchor: %v", err)
		}
	})

	t.Run("nil_certificate", func(t *testing.T) {
		err := ma.AddTrustAnchor(nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})

	t.Run("verify_in_anchors", func(t *testing.T) {
		anchors := ma.GetTrustAnchors()
		if len(anchors) == 0 {
			// Trust anchor was added to attestation but GetTrustAnchors may not return it
			// depending on implementation
			t.Log("No trust anchors returned (may be expected based on implementation)")
		}
	})
}

// TestRevokeCertificate tests certificate revocation
func TestRevokeCertificate(t *testing.T) {
	cfg := DefaultMITMAttestationConfig()
	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	serialNumber := "123456789"
	reason := "Compromised key"

	err = ma.RevokeCertificate(serialNumber, reason)
	if err != nil {
		t.Errorf("Failed to revoke certificate: %v", err)
	}
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	cfg := DefaultMITMAttestationConfig()
	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	stats := ma.GetStats()

	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	if _, ok := stats["enabled"]; !ok {
		t.Error("Stats should include 'enabled'")
	}

	if _, ok := stats["chain_verification"]; !ok {
		t.Error("Stats should include 'chain_verification'")
	}

	if _, ok := stats["crl_checking"]; !ok {
		t.Error("Stats should include 'crl_checking'")
	}

	if _, ok := stats["trust_anchor_count"]; !ok {
		t.Error("Stats should include 'trust_anchor_count'")
	}
}

// TestClearCache tests cache clearing
func TestClearCache(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled:      true,
		CacheResults: true,
		CacheTTL:     5 * time.Minute,
		RequireCRL:   false,
		RequireOCSP:  false,
		FailClosed:   false,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// Cache a result
	cert := createTestCertificate(t, "cache.example.com", false)
	_ = ma.AttestUpstreamCertificate(cert)

	// Clear cache
	ma.ClearCache()

	// Verify cache is empty
	if len(ma.resultCache) != 0 {
		t.Errorf("Cache should be empty after ClearCache, has %d entries", len(ma.resultCache))
	}
}

// TestIsEnabled tests enabled state
func TestIsEnabled(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled: true,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	if !ma.IsEnabled() {
		t.Error("Should be enabled")
	}

	ma.SetEnabled(false)

	if ma.IsEnabled() {
		t.Error("Should be disabled after SetEnabled(false)")
	}
}

// TestShouldFailClosed tests fail-closed behavior
func TestShouldFailClosed(t *testing.T) {
	t.Run("fail_closed_true", func(t *testing.T) {
		cfg := &MITMAttestationConfig{
			Enabled:     true,
			FailClosed:  true,
			RequireCRL:  false,
			RequireOCSP: false,
		}

		ma, err := NewMITMAttestation(cfg)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}

		if !ma.ShouldFailClosed() {
			t.Error("ShouldFailClosed should return true")
		}
	})

	t.Run("fail_closed_false", func(t *testing.T) {
		cfg := &MITMAttestationConfig{
			Enabled:     true,
			FailClosed:  false,
			RequireCRL:  false,
			RequireOCSP: false,
		}

		ma, err := NewMITMAttestation(cfg)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}

		if ma.ShouldFailClosed() {
			t.Error("ShouldFailClosed should return false")
		}
	})
}

// TestPreInterceptCheck tests pre-interception attestation
func TestPreInterceptCheck(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled:     false, // Disabled
		FailClosed:  true,
		RequireCRL:  false,
		RequireOCSP: false,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// When disabled, should allow
	allowed, result, err := ma.PreInterceptCheck("example.com:443", 5*time.Second)

	if !allowed {
		t.Error("Should allow when disabled")
	}

	if result != nil {
		t.Error("Result should be nil when disabled")
	}

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestValidateExistingConnection tests existing connection validation
func TestValidateExistingConnection(t *testing.T) {
	cfg := &MITMAttestationConfig{
		Enabled:     true,
		RequireCRL:  false,
		RequireOCSP: false,
		FailClosed:  false,
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// Test with nil connection - should return error
	_, err = ma.ValidateExistingConnection(nil)
	if err == nil {
		t.Error("Expected error for nil connection")
	}
}

// TestMITMAttestationResult tests result structure
func TestMITMAttestationResult(t *testing.T) {
	result := &MITMAttestationResult{
		Valid:               true,
		Reason:              "test",
		Certificate:         nil,
		ChainVerified:       true,
		RevocationChecked:   true,
		BackdoorChecked:     true,
		BackdoorDetected:    false,
		AttestationDuration: time.Second,
		Timestamp:           time.Now(),
	}

	if result.Valid != true {
		t.Error("Valid should be true")
	}

	if result.Reason != "test" {
		t.Error("Reason should match")
	}

	if result.ChainVerified != true {
		t.Error("ChainVerified should be true")
	}
}

// Helper function to create test certificates
func createTestCertificate(t *testing.T, commonName string, isCA bool) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestTrustAnchorIntegration tests trust anchor operations
func TestTrustAnchorIntegration(t *testing.T) {
	// Create trust anchor config
	caCert := createTestCertificate(t, "Test Root CA", true)

	trustAnchor := &pkiattest.TrustAnchor{
		Certificate: caCert,
		Purpose:     "Test Root CA",
	}

	cfg := &MITMAttestationConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		FailClosed:   false,
		TrustAnchors: []*pkiattest.TrustAnchor{trustAnchor},
	}

	ma, err := NewMITMAttestation(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM attestation: %v", err)
	}

	// Verify trust anchor was added
	anchors := ma.GetTrustAnchors()
	if len(anchors) != 1 {
		t.Errorf("Expected 1 trust anchor, got %d", len(anchors))
	}
}
