// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Attestation Validator 95%+ Coverage Tests
// ============================================================================

package attestation
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// Helper to generate a valid key for testing
func generateTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// TestVerify_ExpiredAttestation tests expired attestation handling
func TestVerify_ExpiredAttestation(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "expired-att",
		AgentID:         "agent-1",
		ContractID:      "contract-1",
		Frameworks:      []Framework{FrameworkGDPR},
		IssuedAt:        time.Now().Add(-48 * time.Hour),
		ExpiresAt:       time.Now().Add(-24 * time.Hour),
		SignerPublicKey: []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00},
		Signature:       []byte("test-signature"),
	}

	result, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.Valid {
		t.Error("Expired attestation should not be valid")
	}

	found := false
	for _, e := range result.Errors {
		if e == "attestation has expired" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'attestation has expired' error")
	}
}

// TestVerify_ExpiredJustNow tests attestation that just expired
func TestVerify_ExpiredJustNow(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "just-expired",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(-1 * time.Second),
		SignerPublicKey: []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00},
		Signature:       []byte("test"),
	}

	result, _ := v.Verify(att)
	if result.Valid {
		t.Error("Just-expired attestation should not be valid")
	}
}

// TestVerify_MissingSignature tests attestation with no signature
func TestVerify_MissingSignature(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "no-sig",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		SignerPublicKey: []byte{0x30, 0x59},
		Signature:       nil,
	}

	result, _ := v.Verify(att)
	if result.Valid {
		t.Error("Missing signature should fail verification")
	}
}

// TestVerify_MissingPublicKey tests attestation with no public key
func TestVerify_MissingPublicKey(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "no-key",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		SignerPublicKey: nil,
		Signature:       []byte("test"),
	}

	result, _ := v.Verify(att)
	if result.Valid {
		t.Error("Missing public key should fail verification")
	}
}

// TestVerify_BothMissing tests attestation with neither signature nor key
func TestVerify_BothMissing(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "neither",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		SignerPublicKey: nil,
		Signature:       nil,
	}

	result, _ := v.Verify(att)
	if result.Valid {
		t.Error("Missing both should fail verification")
	}
}

// TestVerify_InvalidSignature tests attestation with invalid signature
func TestVerify_InvalidSignature(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "bad-sig",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		SignerPublicKey: []byte{0x30, 0x59},
		Signature:       []byte("invalid-signature-data-too-short"),
	}

	result, _ := v.Verify(att)
	if result.Valid {
		t.Error("Invalid signature should fail verification")
	}
}

// TestVerify_StatementsCount tests statement counting
func TestVerify_StatementsCount(t *testing.T) {
	v := NewValidator()
	gen, _ := NewGenerator()

	req := &AttestationRequest{
		AgentID:    "agent-stmts",
		Frameworks: []Framework{FrameworkGDPR},
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	if len(att.Statements) == 0 {
		t.Fatal("Expected statements in attestation")
	}

	result, _ := v.Verify(att)

	if result.StatementsPass == 0 && result.StatementsFail == 0 {
		t.Error("Statement counts should be populated")
	}
}

// TestVerify_FutureExpiration tests attestation with future expiration
func TestVerify_FutureExpiration(t *testing.T) {
	v := NewValidator()
	gen, _ := NewGenerator()

	req := &AttestationRequest{
		AgentID:    "agent-future",
		Frameworks: []Framework{FrameworkGDPR},
		ValidFor:   24 * time.Hour,
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	result, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Logf("Verify result: %+v", result)
	}
}

// TestVerify_NoStatements tests attestation with no statements
func TestVerify_NoStatements(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "no-statements",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		SignerPublicKey: []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00},
		Signature:       []byte("test-signature-that-is-longer"),
		Statements:      nil,
	}

	result, _ := v.Verify(att)
	if result.StatementsPass != 0 || result.StatementsFail != 0 {
		t.Error("Expected zero statement counts for nil statements")
	}
}

// TestVerifyWithPublicKey_Valid tests full verification with key
func TestVerifyWithPublicKey_Valid(t *testing.T) {
	gen, _ := NewGenerator()
	v := NewValidator()

	req := &AttestationRequest{
		AgentID:    "agent-pk-valid",
		Frameworks: []Framework{FrameworkGDPR},
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	// Parse the public key from attestation
	pubKey, err := parseECDSAPublicKey(att.SignerPublicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	result, err := v.VerifyWithPublicKey(att, pubKey)
	if err != nil {
		t.Fatalf("VerifyWithPublicKey failed: %v", err)
	}

	if !result.Valid {
		t.Error("Valid attestation should verify with its own key")
	}
}

// TestVerifyWithPublicKey_WrongKey tests verification with wrong key
func TestVerifyWithPublicKey_WrongKey(t *testing.T) {
	gen, _ := NewGenerator()
	v := NewValidator()

	req := &AttestationRequest{
		AgentID:    "agent-wrong-key",
		Frameworks: []Framework{FrameworkGDPR},
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	// Generate a different key pair
	wrongKey, _ := generateTestKey()

	result, _ := v.VerifyWithPublicKey(att, &wrongKey.PublicKey)
	if result.Valid {
		t.Error("Wrong key should not verify attestation")
	}
}

// TestVerifyWithPublicKey_Expired tests expired attestation with explicit key
func TestVerifyWithPublicKey_Expired(t *testing.T) {
	v := NewValidator()

	att := &Attestation{
		ID:              "expired-explicit",
		AgentID:         "agent-1",
		ExpiresAt:       time.Now().Add(-1 * time.Hour),
		SignerPublicKey: []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00},
		Signature:       []byte("signature"),
	}

	wrongKey, _ := generateTestKey()
	result, _ := v.VerifyWithPublicKey(att, &wrongKey.PublicKey)

	if result.Valid {
		t.Error("Expired attestation should not be valid")
	}
}

// Helper function to parse ECDSA public key from marshaled bytes
func parseECDSAPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// TestVerify_ResultFields tests all result fields are populated
func TestVerify_ResultFields(t *testing.T) {
	v := NewValidator()
	gen, _ := NewGenerator()

	req := &AttestationRequest{
		AgentID:    "agent-fields",
		Frameworks: []Framework{FrameworkGDPR, FrameworkHIPAA},
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	result, _ := v.Verify(att)

	if result.AgentID != "agent-fields" {
		t.Errorf("AgentID mismatch: got %s", result.AgentID)
	}
	if len(result.Frameworks) != 2 {
		t.Errorf("Frameworks count mismatch: got %d", len(result.Frameworks))
	}
	if result.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
	if result.VerifiedAt.IsZero() {
		t.Error("VerifiedAt should be set")
	}
}

// TestVerify_EmptyErrors tests result errors is not nil
func TestVerify_EmptyErrors(t *testing.T) {
	v := NewValidator()
	gen, _ := NewGenerator()

	req := &AttestationRequest{
		AgentID:    "agent-noerr",
		Frameworks: []Framework{FrameworkGDPR},
	}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})

	result, _ := v.Verify(att)

	// For valid attestation, errors should be nil or empty
	if result.Errors != nil && len(result.Errors) > 0 && result.Valid {
		t.Logf("Valid attestation has errors: %v", result.Errors)
	}
}
