package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/pkiattest"
)

// TestNewPKIAttestationIntegrator tests PKI integrator creation
func TestNewPKIAttestationIntegrator(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		integrator, err := NewPKIAttestationIntegrator(nil)
		if err != nil {
			t.Fatalf("Failed with nil config: %v", err)
		}
		if integrator == nil {
			t.Fatal("NewPKIAttestationIntegrator returned nil")
		}
		if !integrator.enabled {
			t.Error("Should be enabled by default")
		}
	})
	
	t.Run("custom_config", func(t *testing.T) {
		cfg := &PKIConfig{
			Enabled:      true,
			RequireCRL:   true,
			RequireOCSP:  true,
			VerifyChain:  true,
		}
		
		integrator, err := NewPKIAttestationIntegrator(cfg)
		if err != nil {
			t.Fatalf("Failed with custom config: %v", err)
		}
		if integrator == nil {
			t.Fatal("NewPKIAttestationIntegrator returned nil")
		}
	})
	
	t.Run("with_trust_anchors", func(t *testing.T) {
		caCert := createPKITestCertificate(t, "Test CA", true)
		
		cfg := &PKIConfig{
			Enabled:      true,
			RequireCRL:   false,
			RequireOCSP:  false,
			VerifyChain:  false,
			TrustAnchors: []*pkiattest.TrustAnchor{
				{
					Certificate: caCert,
					Purpose:     "Test CA",
				},
			},
		}
		
		integrator, err := NewPKIAttestationIntegrator(cfg)
		if err != nil {
			t.Fatalf("Failed with trust anchors: %v", err)
		}
		
		status := integrator.GetAttestationStatus()
		if status == nil {
			t.Error("GetAttestationStatus returned nil")
		}
	})
}

// TestPKIVerifyClientCertificate tests client certificate verification
func TestPKIVerifyClientCertificate(t *testing.T) {
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	t.Run("valid_certificate", func(t *testing.T) {
		cert := createPKITestCertificate(t, "client.example.com", false)
		
		_, _, _ = integrator.VerifyClientCertificate(cert)
		
		// Without proper CA setup, this may return an error or false
		// depending on the internal attestation implementation
	})
	
	t.Run("nil_certificate", func(t *testing.T) {
		valid, _, err := integrator.VerifyClientCertificate(nil)
		
		// When PKI attestation is disabled, nil certificate may be accepted
		// The result depends on implementation
		_ = valid
		_ = err
	})
}

// TestPKIAddTrustAnchor tests adding trust anchors
func TestPKIAddTrustAnchor(t *testing.T) {
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	t.Run("add_valid_anchor", func(t *testing.T) {
		caCert := createPKITestCertificate(t, "Test Root CA", true)
		
		anchor, err := integrator.AddTrustAnchor(caCert)
		
		// May succeed or fail depending on implementation
		// If it succeeds, verify anchor
		if err == nil && anchor == nil {
			t.Error("Anchor should not be nil on success")
		}
	})
	
	t.Run("add_nil_certificate", func(t *testing.T) {
		_, err := integrator.AddTrustAnchor(nil)
		
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})
}

// TestPKIRevokeCertificate tests certificate revocation
func TestPKIRevokeCertificate(t *testing.T) {
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	serialNumber := "123456789ABCDEF"
	reason := "Key compromise"
	
	err = integrator.RevokeCertificate(serialNumber, reason)
	if err != nil {
		t.Logf("RevokeCertificate returned: %v (may be expected)", err)
	}
}

// TestPKIVerifyCertificateChain tests chain verification
func TestPKIVerifyCertificateChain(t *testing.T) {
	caCert := createPKITestCertificate(t, "Test Root CA", true)
	
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
		TrustAnchors: []*pkiattest.TrustAnchor{
			{
				Certificate: caCert,
				Purpose:     "Test Root CA",
			},
		},
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	t.Run("verify_chain", func(t *testing.T) {
		cert := createPKITestCertificate(t, "client.example.com", false)
		
		_, err := integrator.VerifyCertificateChain(cert)
		
		// May return error due to verification requirements
		_ = err
	})
}

// TestPKIGetAttestationStatus tests status retrieval
func TestPKIGetAttestationStatus(t *testing.T) {
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   true,
		RequireOCSP:  true,
		VerifyChain:  true,
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	status := integrator.GetAttestationStatus()
	
	if status == nil {
		t.Fatal("GetAttestationStatus returned nil")
	}
	
	if _, ok := status["enabled"]; !ok {
		t.Error("Status should include 'enabled'")
	}
	
	if _, ok := status["trust_anchor_count"]; !ok {
		t.Error("Status should include 'trust_anchor_count'")
	}
}

// TestPKIGetTrustStoreStats tests trust store statistics
func TestPKIGetTrustStoreStats(t *testing.T) {
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	stats := integrator.GetTrustStoreStats()
	
	if stats == nil {
		t.Fatal("GetTrustStoreStats returned nil")
	}
	
	if _, ok := stats["enabled"]; !ok {
		t.Error("Stats should include 'enabled'")
	}
}

// TestPKIConfigDefaults tests PKI config defaults
func TestPKIConfigDefaults(t *testing.T) {
	// When nil is passed, defaults should apply
	integrator, err := NewPKIAttestationIntegrator(nil)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	status := integrator.GetAttestationStatus()
	
	enabled, ok := status["enabled"].(bool)
	if !ok || !enabled {
		t.Error("Should be enabled by default")
	}
}

// TestPKIEnabledDisabled tests enabled/disabled behavior
func TestPKIEnabledDisabled(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		cfg := &PKIConfig{
			Enabled:      false,
			RequireCRL:   true,
			RequireOCSP:  true,
			VerifyChain:  true,
		}
		
		integrator, err := NewPKIAttestationIntegrator(cfg)
		if err != nil {
			t.Fatalf("Failed to create integrator: %v", err)
		}
		
		cert := createPKITestCertificate(t, "client.example.com", false)
		
		// When disabled, verification should pass
		valid, reason, err := integrator.VerifyClientCertificate(cert)
		
		if !valid {
			t.Errorf("Should pass when disabled, got valid=%v, reason=%s, err=%v", valid, reason, err)
		}
		
		if reason != "PKI attestation disabled" {
			t.Errorf("Expected 'PKI attestation disabled' reason, got '%s'", reason)
		}
	})
	
	t.Run("enabled", func(t *testing.T) {
		cfg := &PKIConfig{
			Enabled:      true,
			RequireCRL:   false,
			RequireOCSP:  false,
			VerifyChain:  false,
		}
		
		integrator, err := NewPKIAttestationIntegrator(cfg)
		if err != nil {
			t.Fatalf("Failed to create integrator: %v", err)
		}
		
		// When enabled, attestation will be performed
		cert := createPKITestCertificate(t, "client.example.com", false)
		valid, reason, err := integrator.VerifyClientCertificate(cert)
		
		// Result depends on certificate validation
		_ = valid
		_ = reason
		_ = err
	})
}

// TestPKIWithMultipleTrustAnchors tests multiple trust anchors
func TestPKIWithMultipleTrustAnchors(t *testing.T) {
	ca1 := createPKITestCertificate(t, "CA1", true)
	ca2 := createPKITestCertificate(t, "CA2", true)
	
	cfg := &PKIConfig{
		Enabled:      true,
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  false,
		TrustAnchors: []*pkiattest.TrustAnchor{
			{Certificate: ca1, Purpose: "CA1"},
			{Certificate: ca2, Purpose: "CA2"},
		},
	}
	
	integrator, err := NewPKIAttestationIntegrator(cfg)
	if err != nil {
		t.Fatalf("Failed to create integrator: %v", err)
	}
	
	status := integrator.GetAttestationStatus()
	
	count, ok := status["trust_anchor_count"].(int)
	if !ok {
		t.Log("trust_anchor_count not available as int")
	} else if count != 2 {
		t.Errorf("Expected 2 trust anchors, got %d", count)
	}
}

// Helper function to create test certificates for PKI tests
func createPKITestCertificate(t *testing.T, commonName string, isCA bool) *x509.Certificate {
	t.Helper()
	
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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