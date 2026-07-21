// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// verify.go provides independent verification of a signed
// Manifest. The verifier does NOT need access to the Builder,
// the Scanner, or the License Manager - it works from the
// Manifest bytes alone, which is the auditor workflow.
//
// v3.3.0+ Track 2.

package evidence

//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// ErrSignatureInvalid is returned when the manifest signature fails
// to verify against the embedded public key.
var ErrSignatureInvalid = errors.New("evidence: signature invalid")

// ErrSignatureMissing is returned when the manifest has no signature.
// A manifest with no signature is treated as invalid by default -
// auditors must opt in to trusting unsigned manifests.
var ErrSignatureMissing = errors.New("evidence: signature missing")

// ErrKeyIDMismatch is returned when the manifest KeyID does not
// match the expected key. This is how key rotation is handled:
// the auditor can pass the current key ID and refuse to verify
// against an older key.
var ErrKeyIDMismatch = errors.New("evidence: key id mismatch")

// Verify checks that the manifest signature is valid against the
// embedded public key. It re-canonicalizes the manifest (zeroing
// the Signature field), hashes with SHA-256, and calls
// ecdsa.VerifyASN1. Returns nil if the signature is valid.
//
// Use VerifyWithKey if you have a known-good public key and want
// to refuse manifests that were signed by a different key.
func Verify(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("evidence: nil manifest")
	}
	if len(m.Signature.Value) == 0 {
		return ErrSignatureMissing
	}
	if len(m.Signature.PublicKey) == 0 {
		return fmt.Errorf("evidence: signature has no public key (auditor must use VerifyWithKey)")
	}
	pub, err := publicKeyFromSEC1(m.Signature.PublicKey)
	if err != nil {
		return fmt.Errorf("evidence: decode public key: %w", err)
	}
	return verifyWithKey(m, pub)
}

// VerifyWithKey checks the manifest signature against a specific
// public key. Use this when you have a canonical public key from
// the platform (e.g., /.well-known/aegisgate-evidence-pubkey.pem)
// and want to refuse manifests that were signed by a different key.
//
// If expectedKeyID is non-empty, it must match manifest.Signature.KeyID
// (case-insensitive). This is the key-rotation guard.
func VerifyWithKey(m *Manifest, pub *ecdsa.PublicKey, expectedKeyID string) error {
	if m == nil {
		return fmt.Errorf("evidence: nil manifest")
	}
	if len(m.Signature.Value) == 0 {
		return ErrSignatureMissing
	}
	if expectedKeyID != "" && m.Signature.KeyID != expectedKeyID {
		return fmt.Errorf("%w: have %q, want %q",
			ErrKeyIDMismatch, m.Signature.KeyID, expectedKeyID)
	}
	return verifyWithKey(m, pub)
}

// verifyWithKey is the shared verification path.
func verifyWithKey(m *Manifest, pub *ecdsa.PublicKey) error {
	// Make a shallow copy so we can zero the signature without
	// mutating the caller's manifest.
	copy := *m
	copy.Signature = Signature{}

	canonical, err := canonicalJSON(&copy)
	if err != nil {
		return fmt.Errorf("evidence: canonicalize: %w", err)
	}
	hash := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, hash[:], m.Signature.Value) {
		return ErrSignatureInvalid
	}
	return nil
}

// publicKeyFromSEC1 decodes an SEC 1 encoded ECDSA public key (the
// format produced by elliptic.Marshal). Returns the *ecdsa.PublicKey
// or an error if the bytes are malformed or the curve does not match.
func publicKeyFromSEC1(sec1 []byte) (*ecdsa.PublicKey, error) {
	//nolint:staticcheck // SA1019: elliptic.Unmarshal is deprecated as of Go 1.21
	// in favor of crypto/ecdh. We keep SEC 1 for backward compatibility
	// with the existing trust attestation scheme (see builder.go for
	// the migration plan).
	x, y := elliptic.Unmarshal(elliptic.P256(), sec1)
	if x == nil {
		return nil, fmt.Errorf("invalid SEC 1 bytes for P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// VerifyResult is a structured verification outcome, useful for
// the HTTP /verify endpoint and the CLI `evidence verify` command.
type VerifyResult struct {
	// Verified is true iff the signature is valid.
	Verified bool `json:"verified"`
	// Reason is populated when Verified is false.
	Reason string `json:"reason,omitempty"`
	// ManifestID is echoed back for the caller's audit trail.
	ManifestID string `json:"manifest_id"`
	// KeyID is the key the manifest was signed with.
	KeyID string `json:"key_id"`
	// SignedAt is when the manifest was signed.
	SignedAt string `json:"signed_at,omitempty"`
}

// VerifyDetailed wraps Verify with a structured result. It is the
// API the HTTP /verify endpoint and CLI use, so callers do not
// need to inspect error types.
func VerifyDetailed(m *Manifest) VerifyResult {
	res := VerifyResult{
		ManifestID: m.ManifestID,
		KeyID:      m.Signature.KeyID,
		SignedAt:   m.Signature.SignedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if err := Verify(m); err != nil {
		res.Verified = false
		res.Reason = err.Error()
		return res
	}
	res.Verified = true
	return res
}

// VerifyEnvelope checks the manifest's attestation envelope (the
// v3.5.0+ signature path). If the manifest has an envelope, this
// delegates to attestation.Verify, which validates the envelope's
// signature, type, subject, validity window, and algorithm.
//
// If the manifest has no envelope, VerifyEnvelope returns an
// error (the legacy Verify path should be used instead).
//
// Tier 5 prep. See plans/ENVELOPE-DESIGN-v1.1-FROZEN.md §5.3.
func VerifyEnvelope(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("evidence: nil manifest")
	}
	if m.Attestation == nil {
		return fmt.Errorf("evidence: VerifyEnvelope: no envelope (use Verify for the legacy c3 path)")
	}
	return attestation.Verify(m.Attestation)
}

// VerifyEnvelopeWithKey checks the manifest's envelope against
// the provided public key (auditor scenario). If the manifest
// has no envelope, returns an error.
func VerifyEnvelopeWithKey(m *Manifest, pub *ecdsa.PublicKey, expectedKeyID string) error {
	if m == nil {
		return fmt.Errorf("evidence: nil manifest")
	}
	if m.Attestation == nil {
		return fmt.Errorf("evidence: VerifyEnvelopeWithKey: no envelope")
	}
	return attestation.VerifyWithKey(m.Attestation, pub, expectedKeyID)
}
