// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// bundle.go implements the Bundle primitive: a signed collection of
// IOCAttestations exchanged between AegisGate instances over the
// pull-based HTTP gossip protocol.
//
// Wire format:
//
//	{
//	  "bundleId":     "<uuid>",
//	  "instanceId":   "<opaque instance id>",
//	  "issuedAt":     "2026-06-15T08:00:00Z",
//	  "count":        42,
//	  "attestations": [ <IOCAttestation>, ... ],
//	  "publicKey":    { "algorithm": "ecdsa-p256", "keyId": "...", "value": "<base64 SEC 1>" },
//	  "signature":    { "algorithm": "ecdsa-p256", "keyId": "...", "value": "<base64 ASN.1>" }
//	}
//
// The signature is over the canonicalized JSON of the bundle MINUS
// the signature field (same pattern as IOCAttestation). The bundle's
// PublicKey is embedded so the bundle is self-verifying.
//
// Delta queries: when a peer asks for IOCs since a timestamp, the
// server returns a bundle containing only attestations with
// LastSeen >= since. The bundle is otherwise structurally identical
// to a full bundle; the count and the issuedAt tell the client how
// much they received.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Bundle is a signed collection of IOCAttestations. It is the unit
// that flows over the gossip HTTP endpoint (GET /api/v1/ioc/manifest).
// A bundle is the natural unit of gossip: it has a single signature
// covering many IOCs, so the cost of signature verification is
// amortized over a large batch.
type Bundle struct {
	// BundleID is a unique identifier for this bundle (UUIDv4).
	// Two bundles with the same BundleID from the same instance
	// are bit-identical; a peer can dedupe on BundleID.
	BundleID string `json:"bundleId"`

	// InstanceID identifies the instance that produced this bundle.
	// Copied into every IOCAttestation in Attestations for cross-
	// reference, but also kept on the bundle for convenience.
	InstanceID string `json:"instanceId"`

	// IssuedAt is the UTC time the bundle was signed. Used by
	// the gossip client to bound "stale bundle" rejection.
	IssuedAt time.Time `json:"issuedAt"`

	// Count is the number of attestations in the bundle. Redundant
	// with len(Attestations) but kept for wire-format symmetry
	// with the compliance manifest and to make the count visible
	// in the envelope before deserializing the full body.
	Count int `json:"count"`

	// Attestations is the signed collection. Each IOCAttestation
	// carries its own signature; the bundle's signature is in
	// addition, covering the entire collection.
	Attestations []IOCAttestation `json:"attestations"`

	// PublicKey is the embedded public key that signed this bundle.
	// Any third party can verify the bundle using only this field.
	PublicKey PublicKeyEnvelope `json:"publicKey"`

	// Signature is the ECDSA P-256 signature over the canonicalized
	// JSON of the bundle MINUS this field.
	Signature SignatureEnvelope `json:"signature"`
}

// NewBundle creates an empty Bundle with a fresh BundleID and the
// current UTC time. Attestations are added by the producer; the
// bundle is signed with Sign() once all attestations are in.
func NewBundle(instanceID string) *Bundle {
	return &Bundle{
		BundleID:     uuid.NewString(),
		InstanceID:   instanceID,
		IssuedAt:     time.Now().UTC(),
		Attestations: []IOCAttestation{},
	}
}

// Add appends an attestation to the bundle. Does NOT sign; call
// Sign() once all attestations are added. The Count field is
// updated as a convenience.
func (b *Bundle) Add(a IOCAttestation) {
	b.Attestations = append(b.Attestations, a)
	b.Count = len(b.Attestations)
}

// bundlePayload returns the JSON bytes that the bundle's signature
// covers. It is the canonicalized JSON of the bundle with the
// Signature field zeroed.
func (b *Bundle) bundlePayload() ([]byte, error) {
	// Marshal-then-unmarshal-into-generic-then-canonicalize is
	// the same path as IOCAttestation.AttestationPayload. We do
	// it inline here so the field-with-zero-signature copy is
	// obvious.
	tmp := struct {
		BundleID     string            `json:"bundleId"`
		InstanceID   string            `json:"instanceId"`
		IssuedAt     time.Time         `json:"issuedAt"`
		Count        int               `json:"count"`
		Attestations []IOCAttestation  `json:"attestations"`
		PublicKey    PublicKeyEnvelope `json:"publicKey"`
		Signature    SignatureEnvelope `json:"signature"`
	}{
		BundleID:     b.BundleID,
		InstanceID:   b.InstanceID,
		IssuedAt:     b.IssuedAt,
		Count:        b.Count,
		Attestations: b.Attestations,
		PublicKey:    b.PublicKey,
		// Signature intentionally left zeroed.
		Signature: SignatureEnvelope{},
	}
	raw, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return canonicalJSONMarshal(generic)
}

// SignWithKeyRing is the keyring-aware variant of Sign. The
// signature is produced with the keyring's current key.
//
// The keyring is consulted under a read lock; this is the
// hot path for the sync handler.
//
// IMPORTANT: the public key envelope is set BEFORE the
// signature, so the signature covers the public key binding.
// This is the same order as the legacy Sign.
func (b *Bundle) SignWithKeyRing(kr *KeyRing) error {
	if b == nil {
		return errors.New("nil bundle")
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
	b.PublicKey = PublicKeyEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     currentKeyID,
		Value:     base64PublicKeyFor(kr, currentKeyID),
	}
	// Compute payload and sign.
	payload, err := b.bundlePayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	keyID, sigASN1, err := kr.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}
	b.Signature = SignatureEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// Sign signs the bundle with the given ECDSA P-256 private key.
// The signature covers bundlePayload() (i.e., the canonicalized
// JSON with the Signature field zeroed). The PublicKey envelope
// is populated as a side effect so the signed bundle is self-
// verifying.
//
// Individual IOCAttestations in the bundle MUST already be
// signed (call SignAttestation on each before adding). This
// function does NOT sign them; it only signs the bundle envelope.
// A bundle envelope signature over a list of unsigned attestations
// is still useful (it binds the list together with a single key
// and a timestamp), but the attestations themselves are then
// trivially forgeable. Producers should always sign attestations
// before bundling.
//
// This is the legacy single-key entry point. New code should use
// SignWithKeyRing so that key rotation is honored.
func (b *Bundle) Sign(priv *ecdsa.PrivateKey, keyID string) error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if priv == nil {
		return errors.New("nil private key")
	}

	// Encode the public key as SEC 1 uncompressed.
	//nolint:staticcheck // SA1019: see SignAttestation.
	pubBytes, err := PublicKeyToSEC1(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}

	// Populate the public key envelope BEFORE signing.
	b.PublicKey = PublicKeyEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(pubBytes),
	}

	// Compute payload and sign.
	payload, err := b.bundlePayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	sigASN1, err := signASN1(priv, digest[:])
	if err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}
	b.Signature = SignatureEnvelope{
		Algorithm: AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// VerifyBundleSignature verifies the bundle's own signature. It
// does NOT verify the signatures on individual IOCAttestations
// inside the bundle; callers that need attestation-level
// verification should call VerifyAttestation on each.
//
// Returns nil on success, an error otherwise.
func VerifyBundleSignature(b *Bundle) error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if b.Signature.Algorithm != AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported signature algorithm: %q", b.Signature.Algorithm)
	}
	if b.PublicKey.Algorithm != AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported public key algorithm: %q", b.PublicKey.Algorithm)
	}
	if b.PublicKey.KeyID != b.Signature.KeyID {
		return fmt.Errorf("keyId mismatch: signature=%q publicKey=%q",
			b.Signature.KeyID, b.PublicKey.KeyID)
	}

	// Decode the embedded public key.
	pub, err := ParsePublicKey(mustBase64Decode(b.PublicKey.Value))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	// Decode the signature.
	sigBytes, err := mustBase64DecodeErr(b.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) == 0 {
		return errors.New("empty signature")
	}

	// Compute the payload and verify.
	payload, err := b.bundlePayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !verifyASN1(pub, digest[:], sigBytes) {
		return errors.New("ECDSA P-256 bundle signature verification failed")
	}
	return nil
}

// VerifyAll verifies the bundle's signature AND the signature on
// every IOCAttestation inside it. Returns the first error
// encountered, or nil if everything is valid.
//
// Use this when accepting a bundle from a peer: a valid bundle
// signature does not prove the attestations inside are also
// valid (they could be unsigned or have been tampered with after
// bundling).
func (b *Bundle) VerifyAll() error {
	if err := VerifyBundleSignature(b); err != nil {
		return err
	}
	for i := range b.Attestations {
		if err := VerifyAttestation(&b.Attestations[i]); err != nil {
			return fmt.Errorf("attestation[%d]: %w", i, err)
		}
	}
	return nil
}

// mustBase64Decode is a small helper for the common case of
// decoding a non-empty base64 string. Returns nil on empty input.
func mustBase64Decode(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// mustBase64DecodeErr is the version that returns an error
// (used for signature decoding where an error is meaningful).
func mustBase64DecodeErr(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base64 string")
	}
	return base64.StdEncoding.DecodeString(s)
}
