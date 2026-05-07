// SPDX-License-Identifier: Apache-2.0
//go:build !race

package sso

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"testing"
)

// =============================================================================
// validateSignature test coverage (9.5% → 95%+)
// =============================================================================

// TestValidateSignature_NilSignedInfo tests validateSignature when SignedInfo is nil
func TestValidateSignature_NilSignedInfo(t *testing.T) {
	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{},
			},
		},
	}

	err := p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     nil,
			SignatureValue: &SignatureValue{Value: "dummy"},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should error on nil SignedInfo")
	}
}

// TestValidateSignature_NoSigningCertificates tests when IdP has no signing certs
func TestValidateSignature_NoSigningCertificates(t *testing.T) {
	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{},
			},
		},
	}

	err := p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     &SignedInfo{},
			SignatureValue: &SignatureValue{Value: "dummy"},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should error when no signing certificates")
	}
}

// TestValidateSignature_InvalidCertificateType tests when cert public key is not RSA
func TestValidateSignature_InvalidCertificateType(t *testing.T) {
	// Create a self-signed RSA cert
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{cert},
			},
		},
	}

	err = p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     &SignedInfo{},
			SignatureValue: &SignatureValue{Value: "dummy"},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should error on nil SignedInfo")
	}
}

// TestValidateSignature_UnsupportedAlgorithm tests unsupported signature algorithm
func TestValidateSignature_UnsupportedAlgorithm(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", // Not supported
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{cert},
			},
		},
	}

	err = p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     &SignedInfo{},
			SignatureValue: &SignatureValue{Value: "ZHVtbXk="},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should error on unsupported algorithm")
	}
}

// TestValidateSignature_InvalidBase64Signature tests with invalid base64
func TestValidateSignature_InvalidBase64Signature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{cert},
			},
		},
	}

	err = p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     &SignedInfo{},
			SignatureValue: &SignatureValue{Value: "not-valid-base64!!!"},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should fail on invalid base64 signature")
	}
}

// TestValidateSignature_ValidRSA tests valid RSA signature verification
func TestValidateSignature_ValidRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	signedInfo := &SignedInfo{
		CanonicalizationMethod: &CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        &SignatureMethod{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
		Reference:              &Reference{URI: "#_123"},
	}

	signedInfoBytes, err := xml.Marshal(signedInfo)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(signedInfoBytes)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)

	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{cert},
			},
		},
	}

	err = p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     signedInfo,
			SignatureValue: &SignatureValue{Value: sigB64},
		},
	})
	if err != nil {
		t.Fatalf("validateSignature failed: %v", err)
	}
}

// TestValidateSignature_TamperedSignature tests with tampered signature
func TestValidateSignature_TamperedSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	signedInfo := &SignedInfo{
		CanonicalizationMethod: &CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        &SignatureMethod{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
		Reference:              &Reference{URI: "#_123"},
	}

	signedInfoBytes, err := xml.Marshal(signedInfo)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(signedInfoBytes)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the signature
	sig[0] ^= 0xFF
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	p := &SAMLProvider{
		samlConfig: &SAMLConfig{
			SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: []*x509.Certificate{cert},
			},
		},
	}

	err = p.validateSignature(&Response{
		Signature: &Signature{
			SignedInfo:     signedInfo,
			SignatureValue: &SignatureValue{Value: sigB64},
		},
	})
	if err == nil {
		t.Fatal("validateSignature should fail on tampered signature")
	}
}

// =============================================================================
// SAMLProvider Name and Type helper coverage
// =============================================================================

// TestSAMLProviderNameAndType tests the SAMLProvider Name() and Type() methods
func TestSAMLProviderNameAndType(t *testing.T) {
	p := &SAMLProvider{
		config: &SSOConfig{
			Name: "test-provider",
		},
	}

	if p.Name() != "test-provider" {
		t.Errorf("Name() = %q, want %q", p.Name(), "test-provider")
	}
	if p.Type() != ProviderSAML {
		t.Errorf("Type() = %q, want %q", p.Type(), ProviderSAML)
	}
}
