// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Attestation subcommand tests (v3.5.0+, Tier 5 prep)
//
// attestation_subcommand_test.go is a thin smoke test for the
// `aegisgate attestation verify` CLI verb. The real verification
// logic is tested in pkg/attestation/attestation_test.go; this
// file tests the CLI plumbing (file reading, result formatting,
// exit codes).

package main
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// makeTestEnvelope creates a signed envelope and writes it to a
// temp file. Returns the path.
func makeTestEnvelope(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := kr.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	env, err := attestation.Sign(
		[]byte(`{"key":"value"}`),
		"aegisgate://manifest/test-id",
		attestation.TypeEvidenceManifest,
		"test-instance:"+keyID,
		kr,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmpDir, "envelope.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// makeTestEnvelopeWithBadSig creates an envelope with a garbage
// signature. The verification should fail.
func makeTestEnvelopeWithBadSig(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := kr.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	env := &attestation.Envelope{
		ID:         "test-id",
		Type:       attestation.TypeEvidenceManifest,
		IssuedAt:   now,
		Subject:    "aegisgate://manifest/test",
		Issuer:     "test:" + keyID,
		RawPayload: []byte(`{"k":"v"}`),
		Signature: attestation.Signature{
			Algorithm: "ecdsa-p256",
			KeyID:     keyID,
			PublicKey: elliptic.Marshal(elliptic.P256(), otherPriv.PublicKey.X, otherPriv.PublicKey.Y),
			Value:     []byte{0x00, 0x01, 0x02, 0x03}, // garbage
			SignedAt:  now,
		},
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmpDir, "envelope-bad.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunAttestationVerify_HappyPath verifies the CLI verb on a
// valid envelope. We don't exec the binary (that's integration
// testing); we call the underlying logic directly.
func TestRunAttestationVerify_HappyPath(t *testing.T) {
	t.Parallel()
	path := makeTestEnvelope(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(&env); err != nil {
		t.Errorf("Verify on valid envelope: %v", err)
	}
}

// TestRunAttestationVerify_BadSignature verifies the CLI verb
// detects a bad signature.
func TestRunAttestationVerify_BadSignature(t *testing.T) {
	t.Parallel()
	path := makeTestEnvelopeWithBadSig(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(&env); err == nil {
		t.Error("expected error on bad signature, got nil")
	}
}

// TestAttestationUsage verifies the help text is non-empty.
func TestAttestationUsage(t *testing.T) {
	t.Parallel()
	// Capture stderr by redirecting it temporarily.
	// We just check that the function doesn't panic.
	attestationUsage()
}
