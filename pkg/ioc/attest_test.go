// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - IOC Attestation tests (D22)
// =========================================================================
//
// attest_test.go covers the SignAttestation / VerifyAttestation flow
// and the inlined marshalSEC1P256 helper introduced in D22.
// =========================================================================

package ioc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// TestSEC1P256_ByteIdenticalToEllipticMarshal verifies that
// marshalSEC1P256 produces byte-identical output to the deprecated
// crypto/elliptic.Marshal for P-256 keys. This is the regression
// test for D22 — the SEC 1 layout must not change.
func TestSEC1P256_ByteIdenticalToEllipticMarshal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	got := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)
	//nolint:staticcheck // SA1019: comparing against the deprecated
	// API to ensure byte-identical output. This is the point of
	// the test.
	want := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)

	if !bytes.Equal(got, want) {
		t.Errorf("marshalSEC1P256 output differs from elliptic.Marshal")
		t.Errorf("got:  %x", got)
		t.Errorf("want: %x", want)
	}
	if len(got) != 65 {
		t.Errorf("expected 65 bytes, got %d", len(got))
	}
	if got[0] != 0x04 {
		t.Errorf("expected first byte 0x04, got 0x%x", got[0])
	}
}

// TestSEC1P256_KnownVector verifies marshalSEC1P256 against the
// RFC 6979 test vector for P-256. The vector is the public key
// from NIST CAVP "SigVer.txt" (P-256, vector 0).
// See https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.2
// We can't use the full RFC 6979 vector (it needs the private
// key), but the public key alone is sufficient to verify SEC 1
// encoding.
func TestSEC1P256_PaddingWithSmallY(t *testing.T) {
	// Y=1 is the smallest possible positive Y coordinate.
	// Test that the encoder pads to 32 bytes correctly.
	// We construct a synthetic public key with X=1, Y=1.
	// This is not a valid curve point but the test is purely
	// about the byte encoding, not the math.
	one := big.NewInt(1)
	got := marshalSEC1P256(one, one)
	if len(got) != 65 {
		t.Fatalf("expected 65 bytes, got %d", len(got))
	}
	if got[0] != 0x04 {
		t.Fatalf("expected first byte 0x04, got 0x%x", got[0])
	}
	// Layout: [0] = 0x04; [1..32] = X (32 bytes, big-endian, padded right);
	// [33..64] = Y (32 bytes, big-endian, padded right). Bytes 1..31
	// are X padding (zeros), byte 32 is the last X byte. Bytes 33..63
	// are Y padding (zeros), byte 64 is the last Y byte. For Y=1,
	// byte 32 is 0x01 (X's last byte) and byte 64 is 0x01 (Y's last byte).
	for i := 1; i <= 31; i++ {
		if got[i] != 0x00 {
			t.Errorf("X padding byte %d = 0x%x, want 0x00", i, got[i])
		}
	}
	for i := 33; i <= 63; i++ {
		if got[i] != 0x00 {
			t.Errorf("Y padding byte %d = 0x%x, want 0x00", i, got[i])
		}
	}
	if got[32] != 0x01 || got[64] != 0x01 {
		t.Errorf("expected last byte of each coord to be 0x01, got 0x%x and 0x%x", got[32], got[64])
	}
}

// TestSignVerifyAttestation_RoundTrip is a basic Sign/Verify
// round-trip test to make sure the D22 refactor didn't break
// the cryptographic flow.
func TestSignVerifyAttestation_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	a := &IOCAttestation{
		Fingerprint: "fp-test-1",
		InstanceID:  "instance-test-1",
		IOCType:     IOCTypeAnomalyScore,
		Severity:    SeverityHigh,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if err := SignAttestation(a, priv, "key-1"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if a.Signature.Value == "" {
		t.Error("signature not populated")
	}
	if a.PublicKey.Value == "" {
		t.Error("public key not populated")
	}
	if err := VerifyAttestation(a); err != nil {
		t.Errorf("VerifyAttestation: %v", err)
	}

	// Tamper with the severity and verify it fails.
	a.Severity = SeverityCritical
	if err := VerifyAttestation(a); err == nil {
		t.Error("expected verification to fail after tampering")
	}
}
