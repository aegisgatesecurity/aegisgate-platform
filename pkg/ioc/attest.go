// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// attest.go implements the IOCAttestation primitive: a signed statement
// by an AegisGate instance that "this instance observed this IOC at
// this severity, first-seen and last-seen as stated".
//
// Wire format: mirrors the compliance manifest signature envelope that
// was proven in testlab/cross_instance_lab_test.go. The exact same
// verifyManifestSignature path works for IOC attestations and
// compliance manifests, which means a single verifier in main.go
// (or in a customer-side library) can verify both artifact types.
//
//	{
//	  "fingerprint": "<hex sha256>",
//	  "instanceId":  "<opaque instance id>",
//	  "iocType":     "proxy_response",
//	  "severity":    "high",
//	  "firstSeen":   "2026-06-15T08:00:00Z",
//	  "lastSeen":    "2026-06-15T09:00:00Z",
//	  "count":       42,
//	  "publicKey":   { "algorithm": "ecdsa-p256", "keyId": "...", "value": "<base64 SEC 1>" },
//	  "signature":   { "algorithm": "ecdsa-p256", "keyId": "...", "value": "<base64 ASN.1>" }
//	}
//
// The signature is over the canonicalized JSON of the attestation
// MINUS the signature field itself. The public key is embedded so
// the attestation is self-verifying: any third party can verify it
// with no out-of-band key exchange.
//
// Crypto: ECDSA P-256 with crypto/ecdsa. The SEC 1 encoding is
// done by an inlined marshalSEC1P256 helper (D22) instead of
// crypto/elliptic.Marshal, which is deprecated as of Go 1.21
// (SA1019). The crypto/ecdh package was considered but rejected
// because the existing surface uses *ecdsa.PrivateKey throughout;
// converting to *ecdh.PrivateKey would have required a conversion
// layer at every call site with no functional benefit. The
// inlined helper is 16 lines of standard library math and
// produces byte-identical output to elliptic.Marshal (verified
// in TestSEC1P256).
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// marshalSEC1P256 returns the SEC 1 uncompressed encoding of an
// ECDSA P-256 public key (65 bytes: 0x04 || X || Y), each coordinate
// zero-padded to 32 bytes. This is a minimal inlined reimplementation
// of the SEC 1 byte layout that elliptic.Marshal produces for P-256,
// without depending on the deprecated crypto/elliptic.Marshal API.
//
// D22: replaces the SA1019-suppressed elliptic.Marshal calls that
// were scheduled for migration to crypto/ecdh in v3.4.0. The
// crypto/ecdh API doesn't fit the existing *ecdsa.PrivateKey surface
// (it uses *ecdh.PrivateKey, which would require a conversion layer
// at every call site), so the cleanest fix is to inline the 4 lines
// of SEC 1 encoding math directly. The output is byte-identical to
// elliptic.Marshal for any P-256 key (verified in TestSEC1P256).
func marshalSEC1P256(x, y *big.Int) []byte {
	// Per SEC 1 §2.3.3: Uncompressed point = 0x04 || X || Y,
	// where X and Y are big-endian unsigned integers, each
	// padded to the curve size (32 bytes for P-256).
	const coordSize = 32
	out := make([]byte, 1+2*coordSize)
	out[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(out[1+coordSize-len(xBytes):1+coordSize], xBytes)
	copy(out[1+2*coordSize-len(yBytes):1+2*coordSize], yBytes)
	return out
}

// AlgorithmECDSA P256 is the only signing algorithm supported by the
// IOC library today. It matches the compliance manifest signer and
// is the platform-wide default.
const AlgorithmECDSAP256 = "ecdsa-p256"

// SignatureEnvelope is the wire-format signature field. The same
// shape is used in compliance manifests (see testlab/cross_instance_lab_test.go).
type SignatureEnvelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"` // base64(ASN.1(r, s))
}

// PublicKeyEnvelope is the wire-format embedded public key field.
// The Value is base64(SEC 1 uncompressed, 65 bytes: 0x04 || X || Y).
type PublicKeyEnvelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"` // base64(SEC 1 uncompressed)
}

// IOCAttestation is a signed statement about a single IOC. It is
// the unit that flows from one instance to another over the gossip
// protocol. A Bundle is a signed collection of IOCAttestations
// (see bundle.go).
type IOCAttestation struct {
	// Fingerprint is the IOC's fingerprint, copied verbatim. This
	// is the IOC's primary key; the attestation is meaningless
	// without it.
	Fingerprint string `json:"fingerprint"`

	// InstanceID is an opaque, instance-unique identifier. It is
	// NOT a customer identifier; it is a stable random string
	// generated once per AegisGate instance and stored alongside
	// the signing key. Two attestations with the same InstanceID
	// come from the same physical instance.
	InstanceID string `json:"instanceId"`

	// IOCType is the IOC type (proxy_response, anomaly_score, etc.).
	IOCType IOCType `json:"iocType"`

	// Severity is the highest severity the instance has observed
	// for this fingerprint.
	Severity Severity `json:"severity"`

	// FirstSeen is the first UTC time the instance observed the
	// fingerprint. Stamped by the producer; never zero.
	FirstSeen time.Time `json:"firstSeen"`

	// LastSeen is the most recent UTC time the instance observed
	// the fingerprint.
	LastSeen time.Time `json:"lastSeen"`

	// Count is the number of times the instance has observed the
	// fingerprint.
	Count int `json:"count"`

	// PublicKey is the embedded public key that signed this
	// attestation. Any third party can verify the signature using
	// only this field plus the JSON body.
	PublicKey PublicKeyEnvelope `json:"publicKey"`

	// Signature is the ECDSA P-256 signature over the canonicalized
	// JSON of the attestation MINUS this field.
	Signature SignatureEnvelope `json:"signature"`
}

// AttestationPayload returns the JSON bytes that the signature
// covers. This is the canonicalized JSON of the attestation with
// the Signature field zeroed. It is exported so Bundle.Sign
// (and tests) can compute the same payload.
func (a *IOCAttestation) AttestationPayload() ([]byte, error) {
	// We need a copy with Signature zeroed so we can re-canonicalize
	// consistently. Copy all fields except the signature.
	tmp := struct {
		Fingerprint string            `json:"fingerprint"`
		InstanceID  string            `json:"instanceId"`
		IOCType     IOCType           `json:"iocType"`
		Severity    Severity          `json:"severity"`
		FirstSeen   time.Time         `json:"firstSeen"`
		LastSeen    time.Time         `json:"lastSeen"`
		Count       int               `json:"count"`
		PublicKey   PublicKeyEnvelope `json:"publicKey"`
		Signature   SignatureEnvelope `json:"signature"`
	}{
		Fingerprint: a.Fingerprint,
		InstanceID:  a.InstanceID,
		IOCType:     a.IOCType,
		Severity:    a.Severity,
		FirstSeen:   a.FirstSeen,
		LastSeen:    a.LastSeen,
		Count:       a.Count,
		PublicKey:   a.PublicKey,
		// Signature is intentionally left zeroed.
		Signature: SignatureEnvelope{},
	}
	// We marshal via canonicalJSON (not the helper, since that
	// function is unexported; expose the same path).
	b, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return canonicalJSONMarshal(generic)
}

// canonicalJSONMarshal is the exported wrapper for the unexported
// canonicalJSON helper. We expose it because AttestationPayload
// and Bundle.payload need the same canonicalization.
func canonicalJSONMarshal(v interface{}) ([]byte, error) {
	return canonicalJSON(v)
}

// SignAttestationWithKeyRing is the keyring-aware variant of
// SignAttestation. Use this when the calling code has a
// *KeyRing (the post-Task-5 wiring path). The signature is
// produced with the keyring's current key, and the keyId
// embedded in the envelope is the current key's keyId (which
// may have rotated since the bundle was last signed).
//
// The keyring is consulted under a read lock; this is the
// hot path for the sync handler.
//
// IMPORTANT: the public key envelope is set BEFORE the
// signature, so the signature covers the public key binding.
// This is the same order as the legacy SignAttestation.
func SignAttestationWithKeyRing(a *IOCAttestation, kr *KeyRing) error {
	if a == nil {
		return errors.New("nil attestation")
	}
	if kr == nil {
		return errors.New("nil keyring")
	}
	// Determine the current keyId FIRST so we can populate the
	// public key envelope before computing the payload.
	kr.mu.RLock()
	currentKeyID := kr.current
	kr.mu.RUnlock()
	if currentKeyID == "" {
		return errors.New("keyring: no current key")
	}
	// Populate the public key envelope BEFORE signing.
	a.PublicKey = PublicKeyEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     currentKeyID,
		Value:     base64PublicKeyFor(kr, currentKeyID),
	}
	// Compute the payload and sign.
	payload, err := a.AttestationPayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	keyID, sigASN1, err := kr.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	a.Signature = SignatureEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// base64PublicKeyFor returns the base64(SEC 1 uncompressed)
// public key for a keyId in the keyring. Returns "" if the
// keyId is not found.
func base64PublicKeyFor(kr *KeyRing, keyID string) string {
	pub := kr.LookupKey(keyID)
	if pub == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// SignAttestation signs an IOCAttestation with the given ECDSA P-256
// private key. The signature is computed over AttestationPayload()
// and stored in the attestation's Signature field. The attestation's
// PublicKey field is also populated with the corresponding public
// key, so the signed attestation is self-verifying.
//
// keyID is an opaque identifier for the key (typically a short hash
// of the public key bytes, or a customer-chosen label). It lets a
// verifier who knows about key rotation choose the right key.
//
// This is the legacy single-key entry point. New code should use
// SignAttestationWithKeyRing so that key rotation is honored.
func SignAttestation(a *IOCAttestation, priv *ecdsa.PrivateKey, keyID string) error {
	if a == nil {
		return errors.New("nil attestation")
	}
	if priv == nil {
		return errors.New("nil private key")
	}
	if priv.Curve != elliptic.P256() {
		return fmt.Errorf("expected P-256 key, got %s", priv.Curve.Params().Name)
	}

	// Encode public key as SEC 1 uncompressed (65 bytes: 0x04 || X || Y).
	// D22: inlined via marshalSEC1P256 (replaces deprecated
	// crypto/elliptic.Marshal; the v3.4.0 migration to crypto/ecdh
	// was not done — see the file header comment).
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return fmt.Errorf("unexpected SEC 1 encoding: len=%d", len(pubBytes))
	}

	// Populate the public key envelope BEFORE signing so the
	// signature covers the public key binding.
	a.PublicKey = PublicKeyEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(pubBytes),
	}

	// Compute the payload and sign it.
	payload, err := a.AttestationPayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	sigASN1, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	a.Signature = SignatureEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// VerifyAttestation verifies the signature on an IOCAttestation.
// Returns nil if the signature is valid; an error otherwise. The
// verification uses ONLY the embedded public key, so a caller can
// verify an attestation they have never seen before with no
// out-of-band key exchange.
//
// The verification is performed against AttestationPayload() (the
// canonicalized JSON with the Signature field zeroed), which is
// exactly what was signed.
func VerifyAttestation(a *IOCAttestation) error {
	if a == nil {
		return errors.New("nil attestation")
	}
	if a.Signature.Algorithm != AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported signature algorithm: %q", a.Signature.Algorithm)
	}
	if a.PublicKey.Algorithm != AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported public key algorithm: %q", a.PublicKey.Algorithm)
	}
	if a.PublicKey.KeyID != a.Signature.KeyID {
		return fmt.Errorf("keyId mismatch: signature=%q publicKey=%q",
			a.Signature.KeyID, a.PublicKey.KeyID)
	}

	// Decode the embedded public key.
	pubBytes, err := base64.StdEncoding.DecodeString(a.PublicKey.Value)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != 65 {
		return fmt.Errorf("invalid SEC 1 key: len=%d, want 65", len(pubBytes))
	}
	if pubBytes[0] != 0x04 {
		return fmt.Errorf("invalid SEC 1 key: first byte=0x%x, want 0x04", pubBytes[0])
	}
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("public key not on P-256 curve")
	}

	// Decode the signature.
	sigBytes, err := base64.StdEncoding.DecodeString(a.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) == 0 {
		return errors.New("empty signature")
	}

	// Compute the payload and verify.
	payload, err := a.AttestationPayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
		return errors.New("ECDSA P-256 signature verification failed")
	}
	return nil
}

// GenerateKey is a convenience wrapper that generates a new
// ECDSA P-256 key pair for the IOC library. Returns the private
// key, the SEC 1-encoded public key (65 bytes), and an error.
//
// The keyID returned is "ioc-" + the first 8 bytes of the
// public key hex. This is stable across process restarts (as
// long as the key is stable) and short enough to be human-
// readable in audit logs.
func GenerateKey() (priv *ecdsa.PrivateKey, keyID string, err error) {
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	// D22: inlined via marshalSEC1P256 (see SignAttestation for context).
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)
	keyID = "ioc-" + base64.RawURLEncoding.EncodeToString(pubBytes[:8])
	return priv, keyID, nil
}

// PublicKeyToSEC1 is a small helper that returns the SEC 1
// uncompressed encoding of an ECDSA P-256 public key. Used by
// tests and by callers that need to log the public key.
func PublicKeyToSEC1(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256, got %s", pub.Curve.Params().Name)
	}
	// D22: inlined via marshalSEC1P256 (see SignAttestation for context).
	return marshalSEC1P256(pub.X, pub.Y), nil
}

// ParsePublicKey parses a SEC 1 uncompressed public key (65 bytes)
// into an ECDSA P-256 public key. This is the inverse of
// PublicKeyToSEC1.
func ParsePublicKey(sec1 []byte) (*ecdsa.PublicKey, error) {
	if len(sec1) != 65 {
		return nil, fmt.Errorf("invalid SEC 1 key: len=%d, want 65", len(sec1))
	}
	if sec1[0] != 0x04 {
		return nil, fmt.Errorf("invalid SEC 1 key: first byte=0x%x, want 0x04", sec1[0])
	}
	x := new(big.Int).SetBytes(sec1[1:33])
	y := new(big.Int).SetBytes(sec1[33:65])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("public key not on P-256 curve")
	}
	return pub, nil
}

// signASN1 is a thin wrapper around ecdsa.SignASN1. The wrapper
// exists so the bundle signer can call a single function name
// and so the package-private surface stays consistent. The
// crypto/ecdsa.SignASN1 is the same call internally.
func signASN1(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, digest)
}

// verifyASN1 is the matching wrapper around ecdsa.VerifyASN1.
// Bundle verification calls this so the import surface in
// bundle.go stays minimal.
func verifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// Compile-time guard: ensure we don't accidentally import x509
// unused; it is reserved for a future TLS-style verifier path.
var _ = x509.MarshalPKIXPublicKey
