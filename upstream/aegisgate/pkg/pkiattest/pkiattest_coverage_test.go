// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate PKI Attestation - Comprehensive Test Coverage
//
// =========================================================================

package pkiattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// ============================================================
// ATTESTATION CONFIG TESTS
// ============================================================

func TestNewAttestationNilConfig(t *testing.T) {
	att, err := NewAttestation(nil)
	if err != nil {
		t.Errorf("NewAttestation(nil) returned error: %v", err)
	}
	if att == nil {
		t.Fatal("NewAttestation(nil) returned nil")
	}
	if att.config == nil {
		t.Error("config should not be nil after initialization")
	}
	if !att.config.RequireCRL {
		t.Error("RequireCRL should default to true")
	}
	if !att.config.RequireOCSP {
		t.Error("RequireOCSP should default to true")
	}
	if att.config.CRLCheckTimeout != 5*time.Second {
		t.Errorf("CRLCheckTimeout should be 5s, got %v", att.config.CRLCheckTimeout)
	}
	if !att.config.VerifyChain {
		t.Error("VerifyChain should default to true")
	}
}

func TestNewAttestationWithConfig(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	anchor, _ := NewTrustAnchor(caCert, "test")

	config := &AttestationConfig{
		TrustAnchors:     []*TrustAnchor{anchor},
		RequireCRL:       false,
		RequireOCSP:      false,
		CRLCheckTimeout:  10 * time.Second,
		OCSPCheckTimeout: 10 * time.Second,
		AllowExpired:     true,
		VerifyChain:      false,
	}

	att, err := NewAttestation(config)
	if err != nil {
		t.Fatalf("NewAttestation returned error: %v", err)
	}
	if att == nil {
		t.Fatal("Attestation should not be nil")
	}
	if len(att.config.TrustAnchors) != 1 {
		t.Errorf("Expected 1 trust anchor, got %d", len(att.config.TrustAnchors))
	}
}

func TestAttestCertificateNil(t *testing.T) {
	att, _ := NewAttestation(nil)
	result, err := att.AttestCertificate(nil)
	if err != nil {
		t.Errorf("AttestCertificate(nil) should not return error: %v", err)
	}
	if result.Valid {
		t.Error("Result should not be valid for nil certificate")
	}
	if result.Reason != "certificate is nil" {
		t.Errorf("Expected 'certificate is nil', got %s", result.Reason)
	}
}

func TestAttestCertificateSuccess(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	anchor, _ := NewTrustAnchor(caCert, "test")

	config := &AttestationConfig{
		TrustAnchors: []*TrustAnchor{anchor},
		RequireCRL:   false,
		RequireOCSP:  false,
		VerifyChain:  true,
	}
	att, _ := NewAttestation(config)

	result, err := att.AttestCertificate(caCert)
	if err != nil {
		t.Fatalf("AttestCertificate returned error: %v", err)
	}
	if !result.Valid {
		t.Errorf("Expected valid result, got: %s", result.Reason)
	}
}

func TestAddTrustAnchor(t *testing.T) {
	att, _ := NewAttestation(nil)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)

	anchor, err := att.AddTrustAnchor(caCert)
	if err != nil {
		t.Fatalf("AddTrustAnchor returned error: %v", err)
	}
	if anchor == nil {
		t.Fatal("Trust anchor should not be nil")
	}
	if anchor.Certificate != caCert {
		t.Error("Certificate should match")
	}
	if anchor.CertificateID == "" {
		t.Error("CertificateID should not be empty")
	}
	if anchor.Revoked {
		t.Error("Revoked should be false by default")
	}
	if len(att.config.TrustAnchors) != 1 {
		t.Errorf("Expected 1 trust anchor, got %d", len(att.config.TrustAnchors))
	}
}

func TestAddTrustAnchorNil(t *testing.T) {
	att, _ := NewAttestation(nil)
	_, err := att.AddTrustAnchor(nil)
	if err == nil {
		t.Error("AddTrustAnchor(nil) should return error")
	}
}

func TestAddTrustAnchorNonCA(t *testing.T) {
	att, _ := NewAttestation(nil)
	leafCert := createTestLeafCertificate(t)
	_, err := att.AddTrustAnchor(leafCert)
	if err == nil {
		t.Error("AddTrustAnchor with non-CA cert should return error")
	}
}

func TestRevokeTrustAnchor(t *testing.T) {
	att, _ := NewAttestation(nil)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	anchor, _ := att.AddTrustAnchor(caCert)

	err := att.RevokeTrustAnchor(anchor.CertificateID)
	if err != nil {
		t.Fatalf("RevokeTrustAnchor returned error: %v", err)
	}

	// Check anchor is revoked
	anchors := att.GetTrustAnchors()
	if len(anchors) != 1 {
		t.Fatal("Expected 1 anchor")
	}
	if !anchors[0].Revoked {
		t.Error("Trust anchor should be revoked")
	}
}

func TestRevokeTrustAnchorNotFound(t *testing.T) {
	att, _ := NewAttestation(nil)
	err := att.RevokeTrustAnchor("nonexistent")
	if err == nil {
		t.Error("RevokeTrustAnchor with nonexistent ID should return error")
	}
}

func TestGetTrustAnchors(t *testing.T) {
	att, _ := NewAttestation(nil)
	anchors := att.GetTrustAnchors()
	if anchors == nil {
		t.Error("GetTrustAnchors should not return nil")
	}

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	att.AddTrustAnchor(caCert)

	anchors = att.GetTrustAnchors()
	if len(anchors) != 1 {
		t.Errorf("Expected 1 anchor, got %d", len(anchors))
	}
}

// ============================================================
// CRL MANAGER TESTS
// ============================================================

func TestNewCRLManager(t *testing.T) {
	cm := NewCRLManager(0, 0)
	if cm == nil {
		t.Fatal("NewCRLManager returned nil")
	}
	if cm.maxAge != 7*24*time.Hour {
		t.Errorf("Default maxAge should be 7 days, got %v", cm.maxAge)
	}
	if cm.refreshDelay != 1*time.Hour {
		t.Errorf("Default refreshDelay should be 1 hour, got %v", cm.refreshDelay)
	}
}

func TestNewCRLManagerCustom(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 30*time.Minute)
	if cm == nil {
		t.Fatal("NewCRLManager returned nil")
	}
	if cm.maxAge != 24*time.Hour {
		t.Errorf("Expected maxAge 24h, got %v", cm.maxAge)
	}
	if cm.refreshDelay != 30*time.Minute {
		t.Errorf("Expected refreshDelay 30m, got %v", cm.refreshDelay)
	}
}

func TestCRLManagerAddCRL(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	crl := &CRL{
		Issuer:     "Test CA",
		LastUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	err := cm.AddCRL(crl)
	if err != nil {
		t.Errorf("AddCRL returned error: %v", err)
	}

	retrieved, err := cm.GetCRL("Test CA")
	if err != nil {
		t.Errorf("GetCRL returned error: %v", err)
	}
	if retrieved.Issuer != "Test CA" {
		t.Errorf("Expected issuer 'Test CA', got %s", retrieved.Issuer)
	}
}

func TestCRLManagerAddCRLNil(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	err := cm.AddCRL(nil)
	if err == nil {
		t.Error("AddCRL(nil) should return error")
	}
}

func TestCRLManagerGetCRLNotFound(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	_, err := cm.GetCRL("Nonexistent")
	if err == nil {
		t.Error("GetCRL with nonexistent issuer should return error")
	}
}

func TestCRLManagerGetCRLExpired(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	crl := &CRL{
		Issuer:     "Expired CA",
		LastUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-1 * time.Hour),
	}
	cm.AddCRL(crl)

	_, err := cm.GetCRL("Expired CA")
	if err == nil {
		t.Error("GetCRL with expired CRL should return error")
	}
}

func TestCRLManagerIsRevokedInCRL(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	crl := &CRL{
		Issuer:     "Test CA",
		LastUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCerts: []*CRLEntry{
			{SerialNumber: "12345", RevokedAt: time.Now(), Reason: "keyCompromise"},
		},
	}
	cm.AddCRL(crl)

	revoked, err := cm.IsRevokedInCRL("Test CA", "12345")
	if err != nil {
		t.Errorf("IsRevokedInCRL returned error: %v", err)
	}
	if !revoked {
		t.Error("Certificate should be revoked")
	}

	revoked, err = cm.IsRevokedInCRL("Test CA", "67890")
	if err != nil {
		t.Errorf("IsRevokedInCRL returned error: %v", err)
	}
	if revoked {
		t.Error("Certificate should not be revoked")
	}
}

func TestCRLManagerHasExpiredCRL(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)

	crl1 := &CRL{
		Issuer:     "Fresh CA",
		LastUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	cm.AddCRL(crl1)

	hasExpired, expiredList := cm.HasExpiredCRL()
	if hasExpired {
		t.Error("Should not have expired CRLs")
	}
	if len(expiredList) != 0 {
		t.Errorf("Expected no expired CRLs, got %d", len(expiredList))
	}

	crl2 := &CRL{
		Issuer:     "Expired CA",
		LastUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-1 * time.Hour),
	}
	cm.AddCRL(crl2)

	hasExpired, expiredList = cm.HasExpiredCRL()
	if !hasExpired {
		t.Error("Should have expired CRLs")
	}
	if len(expiredList) != 1 {
		t.Errorf("Expected 1 expired CRL, got %d", len(expiredList))
	}
}

func TestCRLManagerCRLForCA(t *testing.T) {
	cm := NewCRLManager(24*time.Hour, 1*time.Hour)
	caCert := createTestCACertificate(t, nil)

	crl := cm.CRLForCA(caCert)
	if crl == nil {
		t.Fatal("CRLForCA returned nil")
	}
	if crl.Issuer != caCert.Subject.CommonName {
		t.Errorf("Expected issuer %s, got %s", caCert.Subject.CommonName, crl.Issuer)
	}
	if len(crl.RevokedCerts) != 0 {
		t.Error("New CRL should have no revoked certs")
	}
}

// ============================================================
// OCSP MANAGER TESTS
// ============================================================

func TestNewOCSPManager(t *testing.T) {
	om := NewOCSPManager(0, 0)
	if om == nil {
		t.Fatal("NewOCSPManager returned nil")
	}
	if om.cacheTTL != 5*time.Minute {
		t.Errorf("Default cacheTTL should be 5m, got %v", om.cacheTTL)
	}
	if om.timeout != 5*time.Second {
		t.Errorf("Default timeout should be 5s, got %v", om.timeout)
	}
}

func TestNewOCSPManagerCustom(t *testing.T) {
	om := NewOCSPManager(10*time.Minute, 3*time.Second)
	if om == nil {
		t.Fatal("NewOCSPManager returned nil")
	}
	if om.cacheTTL != 10*time.Minute {
		t.Errorf("Expected cacheTTL 10m, got %v", om.cacheTTL)
	}
	if om.timeout != 3*time.Second {
		t.Errorf("Expected timeout 3s, got %v", om.timeout)
	}
}

func TestOCSPManagerAddOCSPResponse(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	resp := &OCSPResponse{
		CertificateID: "test-cert-123",
		Status:        OCSPStatusGood,
		ProducedAt:    time.Now(),
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(5 * time.Minute),
	}

	err := om.AddOCSPResponse("test-cert-123", resp)
	if err != nil {
		t.Errorf("AddOCSPResponse returned error: %v", err)
	}
}

func TestOCSPManagerAddOCSPResponseNil(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	err := om.AddOCSPResponse("test", nil)
	if err == nil {
		t.Error("AddOCSPResponse(nil) should return error")
	}
}

func TestOCSPManagerGetOCSPResponse(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	// Use NextUpdate far enough in the future to avoid "stale" check
	// The staleness check compares Now().After(NextUpdate - cacheTTL)
	// So we need NextUpdate - 5min > Now(), meaning NextUpdate should be > 5min from now
	resp := &OCSPResponse{
		CertificateID: "cert-1",
		Status:        OCSPStatusGood,
		ProducedAt:    time.Now(),
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(10 * time.Minute), // 10min to avoid stale check with 5min cacheTTL
	}
	om.AddOCSPResponse("cert-1", resp)

	retrieved, err := om.GetOCSPResponse("cert-1")
	if err != nil {
		t.Fatalf("GetOCSPResponse returned error: %v", err)
	}
	if retrieved.Status != OCSPStatusGood {
		t.Errorf("Expected status Good, got %d", retrieved.Status)
	}
}

func TestOCSPManagerGetOCSPResponseNotFound(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	_, err := om.GetOCSPResponse("nonexistent")
	if err == nil {
		t.Error("GetOCSPResponse with nonexistent ID should return error")
	}
}

func TestOCSPManagerGetOCSPResponseExpired(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	resp := &OCSPResponse{
		CertificateID: "expired-cert",
		Status:        OCSPStatusGood,
		ProducedAt:    time.Now().Add(-10 * time.Minute),
		ThisUpdate:    time.Now().Add(-10 * time.Minute),
		NextUpdate:    time.Now().Add(-5 * time.Minute),
	}
	om.AddOCSPResponse("expired-cert", resp)

	_, err := om.GetOCSPResponse("expired-cert")
	if err == nil {
		t.Error("GetOCSPResponse with expired response should return error")
	}
}

func TestOCSPStatusString(t *testing.T) {
	tests := []struct {
		status   OCSPStatus
		expected string
	}{
		{OCSPStatusGood, "good"},
		{OCSPStatusRevoked, "revoked"},
		{OCSPStatusUnknown, "unknown"},
		{OCSPStatus(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("OCSPStatus(%d).String() = %s, expected %s", tt.status, result, tt.expected)
		}
	}
}

func TestOCSPManagerCheckCertificateStatus(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	leaf := createTestLeafCertificate(t)

	certID := caCert.Subject.CommonName + "-" + leaf.SerialNumber.String()
	// Use NextUpdate far enough in the future to avoid "stale" check
	resp := &OCSPResponse{
		CertificateID: certID,
		Status:        OCSPStatusGood,
		ProducedAt:    time.Now(),
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(10 * time.Minute),
	}
	om.AddOCSPResponse(certID, resp)

	status, err := om.CheckCertificateStatus(leaf, caCert)
	if err != nil {
		t.Fatalf("CheckCertificateStatus returned error: %v", err)
	}
	if status != OCSPStatusGood {
		t.Errorf("Expected Good status, got %d", status)
	}
}

func TestOCSPManagerIsRevokedViaOCSP(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	leaf := createTestLeafCertificate(t)

	certID := caCert.Subject.CommonName + "-" + leaf.SerialNumber.String()

	// Use NextUpdate far enough in the future to avoid "stale" check
	resp := &OCSPResponse{
		CertificateID: certID,
		Status:        OCSPStatusGood,
		ProducedAt:    time.Now(),
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(10 * time.Minute),
	}
	om.AddOCSPResponse(certID, resp)

	revoked, err := om.IsRevokedViaOCSP(leaf, caCert)
	if err != nil {
		t.Fatalf("IsRevokedViaOCSP returned error: %v", err)
	}
	if revoked {
		t.Error("Certificate should not be revoked")
	}

	respRevoked := &OCSPResponse{
		CertificateID: certID,
		Status:        OCSPStatusRevoked,
		ProducedAt:    time.Now(),
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(10 * time.Minute),
	}
	om.AddOCSPResponse(certID, respRevoked)

	revoked, err = om.IsRevokedViaOCSP(leaf, caCert)
	if err != nil {
		t.Fatalf("IsRevokedViaOCSP returned error: %v", err)
	}
	if !revoked {
		t.Error("Certificate should be revoked")
	}
}

func TestOCSPManagerCreateOCSPResponse(t *testing.T) {
	om := NewOCSPManager(5*time.Minute, 5*time.Second)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	leaf := createTestLeafCertificate(t)

	resp := om.CreateOCSPResponse(leaf, caCert, OCSPStatusGood)
	if resp == nil {
		t.Fatal("CreateOCSPResponse returned nil")
	}
	if resp.Status != OCSPStatusGood {
		t.Errorf("Expected Good status, got %d", resp.Status)
	}
	if resp.CertificateID == "" {
		t.Error("CertificateID should not be empty")
	}
}

// ============================================================
// BACKDOOR PREVENTION TESTS
// ============================================================

func TestNewBackdoorPrevention(t *testing.T) {
	bp := NewBackdoorPrevention()
	if bp == nil {
		t.Fatal("NewBackdoorPrevention returned nil")
	}
}

func TestBackdoorPreventionSetAttestation(t *testing.T) {
	bp := NewBackdoorPrevention()
	att, _ := NewAttestation(nil)

	bp.SetAttestation(att)
	if bp.attestation == nil {
		t.Error("Attestation should be set")
	}
}

func TestBackdoorPreventionDetectBackdoorNil(t *testing.T) {
	bp := NewBackdoorPrevention()
	detected, reason, err := bp.DetectBackdoor(nil)
	if err != nil {
		t.Errorf("DetectBackdoor(nil) should not return error: %v", err)
	}
	if !detected {
		t.Error("Should detect backdoor for nil certificate")
	}
	if reason != "certificate is nil" {
		t.Errorf("Expected 'certificate is nil', got %s", reason)
	}
}

func TestBackdoorPreventionDetectBackdoorZeroSerial(t *testing.T) {
	bp := NewBackdoorPrevention()

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Zero Serial"},
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	detected, reason, err := bp.DetectBackdoor(cert)
	if err != nil {
		t.Errorf("DetectBackdoor returned error: %v", err)
	}
	if !detected {
		t.Error("Should detect backdoor for zero serial")
	}
	if reason == "" {
		t.Error("Reason should not be empty")
	}
}

func TestBackdoorPreventionDetectBackdoorValid(t *testing.T) {
	bp := NewBackdoorPrevention()
	cert := createTestCACertificate(t, nil)

	detected, reason, err := bp.DetectBackdoor(cert)
	if err != nil {
		t.Errorf("DetectBackdoor returned error: %v", err)
	}
	if detected {
		t.Errorf("Valid certificate should not be flagged as backdoor: %s", reason)
	}
}

// ============================================================
// SIGNATURE VERIFICATION TESTS
// ============================================================

func TestNewSignatureVerification(t *testing.T) {
	sv := NewSignatureVerification(nil)
	if sv == nil {
		t.Fatal("NewSignatureVerification returned nil")
	}
}

func TestSignatureVerificationNilCertificate(t *testing.T) {
	sv := NewSignatureVerification([]*TrustAnchor{})
	_, err := sv.VerifyCertificateSignature(nil)
	if err == nil {
		t.Error("VerifyCertificateSignature(nil) should return error")
	}
}

func TestSignatureVerificationNoSignature(t *testing.T) {
	sv := NewSignatureVerification([]*TrustAnchor{})
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "No Sig"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Raw:          []byte{},
		Signature:    []byte{},
	}

	_, err := sv.VerifyCertificateSignature(cert)
	if err == nil {
		t.Error("VerifyCertificateSignature with no signature should return error")
	}
}

// ============================================================
// TRUST STORE TESTS
// ============================================================

func TestNewTrustStore(t *testing.T) {
	ts := NewTrustStore()
	if ts == nil {
		t.Fatal("NewTrustStore returned nil")
	}
}

func TestTrustStoreAddTrustAnchor(t *testing.T) {
	ts := NewTrustStore()
	caCert := createTestCACertificate(t, nil)

	anchor, err := ts.AddTrustAnchor(caCert)
	if err != nil {
		t.Fatalf("AddTrustAnchor returned error: %v", err)
	}
	if anchor == nil {
		t.Fatal("Anchor should not be nil")
	}
	if anchor.CertificateID == "" {
		t.Error("CertificateID should not be empty")
	}
}

func TestTrustStoreAddTrustAnchorNil(t *testing.T) {
	ts := NewTrustStore()
	_, err := ts.AddTrustAnchor(nil)
	if err == nil {
		t.Error("AddTrustAnchor(nil) should return error")
	}
}

func TestTrustStoreAddTrustAnchorNonCA(t *testing.T) {
	ts := NewTrustStore()
	leaf := createTestLeafCertificate(t)
	_, err := ts.AddTrustAnchor(leaf)
	if err == nil {
		t.Error("AddTrustAnchor with non-CA cert should return error")
	}
}

func TestTrustStoreGetTrustAnchors(t *testing.T) {
	ts := NewTrustStore()
	anchors := ts.GetTrustAnchors()
	if anchors == nil {
		t.Error("GetTrustAnchors should not return nil")
	}

	caCert := createTestCACertificate(t, nil)
	ts.AddTrustAnchor(caCert)

	anchors = ts.GetTrustAnchors()
	if len(anchors) != 1 {
		t.Errorf("Expected 1 anchor, got %d", len(anchors))
	}
}

func TestTrustStoreGetTrustAnchorByID(t *testing.T) {
	ts := NewTrustStore()
	caCert := createTestCACertificate(t, nil)
	anchor, _ := ts.AddTrustAnchor(caCert)

	retrieved, err := ts.GetTrustAnchorByID(anchor.CertificateID)
	if err != nil {
		t.Errorf("GetTrustAnchorByID returned error: %v", err)
	}
	if retrieved.CertificateID != anchor.CertificateID {
		t.Error("Retrieved anchor should match")
	}
}

func TestTrustStoreGetTrustAnchorByIDNotFound(t *testing.T) {
	ts := NewTrustStore()
	_, err := ts.GetTrustAnchorByID("nonexistent")
	if err == nil {
		t.Error("GetTrustAnchorByID with nonexistent ID should return error")
	}
}

func TestTrustStoreRevokeTrustAnchor(t *testing.T) {
	ts := NewTrustStore()
	caCert := createTestCACertificate(t, nil)
	anchor, _ := ts.AddTrustAnchor(caCert)

	err := ts.RevokeTrustAnchor(anchor.CertificateID)
	if err != nil {
		t.Errorf("RevokeTrustAnchor returned error: %v", err)
	}

	retrieved, _ := ts.GetTrustAnchorByID(anchor.CertificateID)
	if !retrieved.Revoked {
		t.Error("Trust anchor should be revoked")
	}
}

func TestTrustStoreRevokeTrustAnchorNotFound(t *testing.T) {
	ts := NewTrustStore()
	err := ts.RevokeTrustAnchor("nonexistent")
	if err == nil {
		t.Error("RevokeTrustAnchor with nonexistent ID should return error")
	}
}

func TestTrustStoreAddRevokedCertificate(t *testing.T) {
	ts := NewTrustStore()
	err := ts.AddRevokedCertificate("serial-123", "cert-456", "keyCompromise")
	if err != nil {
		t.Errorf("AddRevokedCertificate returned error: %v", err)
	}

	revoked, reason, err := ts.IsRevoked("serial-123")
	if err != nil {
		t.Errorf("IsRevoked returned error: %v", err)
	}
	if !revoked {
		t.Error("Certificate should be revoked")
	}
	if reason != "keyCompromise" {
		t.Errorf("Expected reason 'keyCompromise', got %s", reason)
	}
}

func TestTrustStoreIsRevokedFalse(t *testing.T) {
	ts := NewTrustStore()
	revoked, reason, err := ts.IsRevoked("nonexistent")
	if err != nil {
		t.Errorf("IsRevoked returned error: %v", err)
	}
	if revoked {
		t.Error("Certificate should not be revoked")
	}
	if reason == "" {
		t.Error("Reason should not be empty")
	}
}

func TestTrustStoreClearRevocationCache(t *testing.T) {
	ts := NewTrustStore()
	ts.AddRevokedCertificate("serial-123", "cert-456", "test")
	ts.ClearRevocationCache()
}

func TestTrustStoreNewRevocationResult(t *testing.T) {
	ts := NewTrustStore()
	result := ts.NewRevocationResult(true, "test")
	if result == nil {
		t.Fatal("NewRevocationResult returned nil")
	}
	if !result.Valid {
		t.Error("Valid should be true")
	}
	if result.Reason != "test" {
		t.Errorf("Expected reason 'test', got %s", result.Reason)
	}
}

// ============================================================
// ENCODING HELPER TESTS
// ============================================================

func TestBase64EncodeCertificate(t *testing.T) {
	cert := createTestCACertificate(t, nil)
	encoded, err := Base64EncodeCertificate(cert)
	if err != nil {
		t.Errorf("Base64EncodeCertificate returned error: %v", err)
	}
	if encoded == "" {
		t.Error("Encoded certificate should not be empty")
	}
}

func TestBase64DecodeCertificate(t *testing.T) {
	cert := createTestCACertificate(t, nil)
	encoded, _ := Base64EncodeCertificate(cert)

	decoded, err := Base64DecodeCertificate(encoded)
	if err != nil {
		t.Errorf("Base64DecodeCertificate returned error: %v", err)
	}
	if decoded == nil {
		t.Fatal("Decoded certificate should not be nil")
	}
	if decoded.SerialNumber.String() != cert.SerialNumber.String() {
		t.Error("Serial numbers should match")
	}
}

func TestBase64DecodeCertificateInvalid(t *testing.T) {
	_, err := Base64DecodeCertificate("invalid-base64!!!")
	if err == nil {
		t.Error("Base64DecodeCertificate with invalid input should return error")
	}
}

func TestPEMEncodeCertificate(t *testing.T) {
	cert := createTestCACertificate(t, nil)
	pem := PEMEncodeCertificate(cert)
	if pem == "" {
		t.Error("PEM should not be empty")
	}
}

func TestPEMDecodeCertificate(t *testing.T) {
	cert := createTestCACertificate(t, nil)
	pem := PEMEncodeCertificate(cert)

	decoded, err := PEMDecodeCertificate(pem)
	if err != nil {
		t.Errorf("PEMDecodeCertificate returned error: %v", err)
	}
	if decoded == nil {
		t.Fatal("Decoded certificate should not be nil")
	}
	if decoded.SerialNumber.String() != cert.SerialNumber.String() {
		t.Error("Serial numbers should match")
	}
}

func TestPEMDecodeCertificateInvalid(t *testing.T) {
	_, err := PEMDecodeCertificate("not a pem")
	if err == nil {
		t.Error("PEMDecodeCertificate with invalid input should return error")
	}
}

// ============================================================
// VERIFY CERTIFICATE CHAIN TEST
// ============================================================

func TestVerifyCertificateChainNil(t *testing.T) {
	_, err := VerifyCertificateChain(nil, []*TrustAnchor{})
	if err == nil {
		t.Error("VerifyCertificateChain(nil) should return error")
	}
}

func TestVerifyCertificateChainBasic(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)
	anchor, _ := NewTrustAnchor(caCert, "test")

	chain, err := VerifyCertificateChain(caCert, []*TrustAnchor{anchor})
	if err != nil {
		t.Errorf("VerifyCertificateChain returned error: %v", err)
	}
	if len(chain) == 0 {
		t.Error("Chain should not be empty")
	}
}

// ============================================================
// NEW TRUST ANCHOR TESTS
// ============================================================

func TestNewTrustAnchorNil(t *testing.T) {
	_, err := NewTrustAnchor(nil, "test")
	if err == nil {
		t.Error("NewTrustAnchor(nil) should return error")
	}
}

func TestNewTrustAnchorNonCA(t *testing.T) {
	leaf := createTestLeafCertificate(t)
	_, err := NewTrustAnchor(leaf, "test")
	if err == nil {
		t.Error("NewTrustAnchor with non-CA cert should return error")
	}
}

func TestNewTrustAnchorSuccess(t *testing.T) {
	caCert := createTestCACertificate(t, nil)
	anchor, err := NewTrustAnchor(caCert, "testing")
	if err != nil {
		t.Errorf("NewTrustAnchor returned error: %v", err)
	}
	if anchor == nil {
		t.Fatal("Anchor should not be nil")
	}
	if anchor.Purpose != "testing" {
		t.Errorf("Expected purpose 'testing', got %s", anchor.Purpose)
	}
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

func createTestCACertificate(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	var err error
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
	}

	// Use a serial number that's guaranteed to be at least 8 digits (minimum 10000000)
	// Generate a random number in range [0, maxInt64) then add minimum
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000000))
	serialNumber = serialNumber.Add(serialNumber, big.NewInt(10000000))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	return cert
}

func createTestLeafCertificate(t *testing.T) *x509.Certificate {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert := createTestCACertificate(t, caKey)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Use a serial number that's guaranteed to be at least 8 digits
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000000))
	serialNumber = serialNumber.Add(serialNumber, big.NewInt(10000000))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf cert: %v", err)
	}

	return cert
}
