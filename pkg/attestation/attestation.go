// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Signed Attestation Envelope (v3.5.0+, Tier 5 prep)
//
// attestation.go defines the Envelope and Signature structs
// and the 4 lifecycle operations (Sign, Verify, VerifyWithKey,
// VerifyOnline). The envelope is the AegisGate signed-attestation
// primitive used by c3 (migrated), TODO-301 AR-EaaS, TODO-302
// AIBOM, TODO-303 Agent Intent, TODO-304 Prompt Cache, and
// TODO-305 CVE-for-AI.
//
// Tier 5 prep. Frozen 2026-06-15d (Council of Mine 8/8
// unanimous Devil's Advocate on the design).

package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// algorithmECDSAP256 is the only supported algorithm in v3.5.0+.
const algorithmECDSAP256 = "ecdsa-p256"

// domainSeparationPrefix is prepended (in a SHA-256 hash) to
// the canonical bytes before signing. Bumping the v1 to v2 is
// a wire-incompatible change.
const domainSeparationPrefix = "aegisgate-attestation-v1"

// Envelope is the AegisGate signed-attestation envelope. It
// wraps any domain-specific payload (c3 evidence manifest,
// AR-EaaS eval result, AIBOM, Agent Intent, Prompt Cache
// attestation, CVE entry) with the cryptographic binding that
// makes the claim tamper-evident and third-party-verifiable.
//
// The envelope is the SOLE place where AegisGate signatures
// live. Features MUST NOT add their own signature fields; they
// define their payload and let pkg/attestation sign the whole
// thing.
type Envelope struct {
	// ID is a UUIDv4 uniquely identifying this envelope.
	// Two envelopes with the same ID are bit-identical.
	ID string `json:"id"`

	// Type identifies the payload schema. Format:
	//   "<domain>.<schema-name>.v<major>"
	// Must be registered in the type registry (see types.go).
	Type Type `json:"type"`

	// IssuedAt is the UTC time the envelope was signed.
	IssuedAt time.Time `json:"issued_at"`

	// ValidUntil is when the envelope expires. Zero value
	// means "does not expire." Use sparingly; most envelopes
	// should have a validity window.
	ValidUntil time.Time `json:"valid_until,omitempty"`

	// Subject identifies WHAT this envelope is about. Format:
	//   "aegisgate://<kind>/<id>"
	Subject string `json:"subject"`

	// Issuer identifies WHO signed this envelope. Format:
	//   "<instance-id>:<key-id>"
	Issuer string `json:"issuer"`

	// RawPayload is the JSON-encoded feature-specific payload.
	// Stored as json.RawMessage so the envelope can be marshaled
	// without re-encoding the payload.
	RawPayload json.RawMessage `json:"payload"`

	// Signature is the cryptographic binding.
	Signature Signature `json:"signature"`
}

// Signature is the ECDSA P-256 binding. Re-uses the same shape
// as pkg/evidence.Signature for consistency with c3.
type Signature struct {
	// Algorithm is the signing algorithm identifier.
	// Always "ecdsa-p256" in v3.5.0+. Forward-compatible.
	Algorithm string `json:"algorithm"`

	// KeyID is the rotating key identifier.
	KeyID string `json:"key_id"`

	// PublicKey is the SEC 1 encoded public key. Embedded so
	// an offline verifier (auditor on a plane) can verify
	// without contacting AegisGate.
	PublicKey []byte `json:"public_key"`

	// Value is the ECDSA signature in ASN.1 DER encoding.
	Value []byte `json:"value"`

	// SignedAt is the UTC time the signature was produced.
	// SHOULD match Envelope.IssuedAt; duplicated here so the
	// signature is self-describing.
	SignedAt time.Time `json:"signed_at"`
}

// --------------------------------------------------------------------
// The 9-reason error taxonomy
// --------------------------------------------------------------------

// VerificationError is the error type returned by Verify,
// VerifyWithKey, and VerifyOnline. Callers use errors.As to
// inspect the failure mode and decide whether to retry, log,
// or reject.
type VerificationError struct {
	Reason  VerificationReason
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("attestation: verify: %s (cause: %v)", e.Message, e.Cause)
	}
	return fmt.Sprintf("attestation: verify: %s", e.Message)
}

// Unwrap returns the underlying cause for use with errors.Is/As.
func (e *VerificationError) Unwrap() error { return e.Cause }

// VerificationReason is the failure taxonomy. Each value
// implies a specific remediation.
type VerificationReason int

const (
	ReasonUnknown              VerificationReason = iota
	ReasonMalformed                               // envelope is not well-formed JSON or missing required fields
	ReasonUnknownType                             // Type is not in the registry
	ReasonInvalidSubject                          // Subject fails validation
	ReasonSignatureInvalid                        // CRITICAL: signature does not verify
	ReasonKeyMismatch                             // KeyID doesn't match expected
	ReasonExpired                                 // past ValidUntil
	ReasonNotYetValid                             // IssuedAt in the future (clock skew or backdating)
	ReasonPublicKeyFetch                          // VerifyOnline: /.well-known/ fetch failed
	ReasonAlgorithmUnsupported                    // Signature uses an unsupported algorithm
)

// String returns a human-readable name for the reason.
func (r VerificationReason) String() string {
	switch r {
	case ReasonUnknown:
		return "unknown"
	case ReasonMalformed:
		return "malformed"
	case ReasonUnknownType:
		return "unknown_type"
	case ReasonInvalidSubject:
		return "invalid_subject"
	case ReasonSignatureInvalid:
		return "signature_invalid"
	case ReasonKeyMismatch:
		return "key_mismatch"
	case ReasonExpired:
		return "expired"
	case ReasonNotYetValid:
		return "not_yet_valid"
	case ReasonPublicKeyFetch:
		return "public_key_fetch"
	case ReasonAlgorithmUnsupported:
		return "algorithm_unsupported"
	}
	return fmt.Sprintf("reason_%d", int(r))
}

// --------------------------------------------------------------------
// Sign: produce a signed Envelope
// --------------------------------------------------------------------

// Sign produces a signed Envelope wrapping the given payload.
//
// Parameters:
//   - payload:         the JSON-marshaled feature-specific data
//     (must be valid JSON; will be stored as-is
//     in RawPayload)
//   - subject:         the Subject field (must validate as
//     aegisgate://<kind>/<id>)
//   - attestationType: the Type field (must be in the registry)
//   - issuer:          the Issuer field (format: <instance>:<key>)
//   - kr:              the keyring (provides the signing key
//     and the public key binding)
//   - ttl:             how long the envelope is valid (zero = no
//     expiration)
//
// Returns the signed Envelope, or an error if:
//   - payload is not valid JSON
//   - subject fails validation
//   - attestationType is not in the registry
//   - issuer is malformed
//   - kr has no current signing key
func Sign(
	payload []byte,
	subject string,
	attestationType Type,
	issuer string,
	kr *ioc.KeyRing,
	ttl time.Duration,
) (*Envelope, error) {
	// Validate inputs.
	if len(payload) == 0 {
		return nil, fmt.Errorf("attestation: Sign: empty payload")
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("attestation: Sign: payload is not valid JSON")
	}
	if err := ValidateType(attestationType); err != nil {
		return nil, err
	}
	if _, _, err := validateSubject(subject); err != nil {
		return nil, err
	}
	if err := validateIssuer(issuer); err != nil {
		return nil, err
	}
	if kr == nil {
		return nil, fmt.Errorf("attestation: Sign: nil keyring")
	}

	// Get the current signing key from the keyring.
	keyID, priv, err := kr.CurrentKey()
	if err != nil {
		return nil, fmt.Errorf("attestation: Sign: get current key: %w", err)
	}

	// Build the envelope (signature populated below).
	now := time.Now().UTC()
	env := &Envelope{
		ID:         generateUUID(),
		Type:       attestationType,
		IssuedAt:   now,
		Subject:    subject,
		Issuer:     issuer,
		RawPayload: payload,
	}
	if ttl > 0 {
		env.ValidUntil = now.Add(ttl)
	}

	// Encode the public key as SEC 1 for embedding.
	pubSEC1, err := ioc.PublicKeyToSEC1(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("attestation: Sign: encode public key: %w", err)
	}

	// Build the to-be-signed form: the envelope with the
	// Signature struct re-populated with {Algorithm, KeyID,
	// PublicKey} only (no Value, no SignedAt).
	toSign := *env
	toSign.Signature = Signature{
		Algorithm: algorithmECDSAP256,
		KeyID:     keyID,
		PublicKey: pubSEC1,
	}

	// Canonicalize the to-be-signed form.
	canonical, err := canonicalMarshal(toSign)
	if err != nil {
		return nil, fmt.Errorf("attestation: Sign: canonicalize: %w", err)
	}

	// Hash with domain-separation prefix.
	h := sha256.New()
	h.Write([]byte(domainSeparationPrefix))
	h.Write(canonical)
	digest := h.Sum(nil)

	// ECDSA P-256 sign the hash (ASN.1 DER output).
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, fmt.Errorf("attestation: Sign: ecdsa sign: %w", err)
	}

	// Populate the envelope's Signature struct.
	env.Signature = Signature{
		Algorithm: algorithmECDSAP256,
		KeyID:     keyID,
		PublicKey: pubSEC1,
		Value:     sig,
		SignedAt:  now,
	}
	return env, nil
}

// --------------------------------------------------------------------
// Verify (offline, embedded public key)
// --------------------------------------------------------------------

// Verify checks the envelope's signature and validity. It does
// NOT fetch the public key from /.well-known/; it uses the
// embedded PublicKey. For online verification, use VerifyOnline.
//
// Returns nil if the envelope is valid. Returns an error of
// type *VerificationError on failure (callers use errors.As
// to inspect the failure mode).
func Verify(env *Envelope) error {
	if env == nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "nil envelope"}
	}
	// Parse the embedded public key.
	pub, err := parsePublicKey(env.Signature.PublicKey)
	if err != nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "embedded public key is invalid", Cause: err}
	}
	return verifyInternal(env, pub, "")
}

// VerifyWithKey is the offline-friendly variant: the caller
// provides the public key directly (e.g., from an out-of-band
// channel). Used by auditors who cannot reach the /.well-known/
// endpoint.
//
// expectedKeyID is optional; pass "" to skip the KeyID check.
func VerifyWithKey(env *Envelope, pub *ecdsa.PublicKey, expectedKeyID string) error {
	if env == nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "nil envelope"}
	}
	if pub == nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "nil public key"}
	}
	return verifyInternal(env, pub, expectedKeyID)
}

// VerifyOnline is the production path: it fetches the public
// key from the issuer's /.well-known/aegisgate-attestation-
// pubkeys.json endpoint, then verifies. Subject to network
// availability; for offline, use VerifyWithKey.
func VerifyOnline(ctx context.Context, env *Envelope) error {
	if env == nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "nil envelope"}
	}
	// Parse the issuer to get the instance-id and key-id.
	instanceID, keyID, err := parseIssuer(env.Issuer)
	if err != nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "invalid issuer", Cause: err}
	}
	// Fetch the public key from the well-known endpoint.
	pub, err := fetchPublicKey(ctx, instanceID, keyID)
	if err != nil {
		return &VerificationError{Reason: ReasonPublicKeyFetch, Message: fmt.Sprintf("fetch public key for instance %s", instanceID), Cause: err}
	}
	return verifyInternal(env, pub, keyID)
}

// --------------------------------------------------------------------
// Internal: the shared verification logic
// --------------------------------------------------------------------

// verifyInternal is the shared verification path. It is called
// by Verify, VerifyWithKey, and VerifyOnline after the public
// key has been obtained.
func verifyInternal(env *Envelope, pub *ecdsa.PublicKey, expectedKeyID string) error {
	// 1. Validate the Type.
	if err := ValidateType(env.Type); err != nil {
		return &VerificationError{Reason: ReasonUnknownType, Message: err.Error()}
	}
	// 2. Validate the Subject.
	if _, _, err := validateSubject(env.Subject); err != nil {
		return &VerificationError{Reason: ReasonInvalidSubject, Message: err.Error()}
	}
	// 3. Validate the Issuer.
	if _, _, err := parseIssuer(env.Issuer); err != nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "invalid issuer", Cause: err}
	}
	// 4. Check the algorithm.
	if env.Signature.Algorithm != algorithmECDSAP256 {
		return &VerificationError{Reason: ReasonAlgorithmUnsupported, Message: fmt.Sprintf("algorithm %q not supported", env.Signature.Algorithm)}
	}
	// 5. Check the KeyID if expectedKeyID is provided.
	if expectedKeyID != "" && env.Signature.KeyID != expectedKeyID {
		return &VerificationError{Reason: ReasonKeyMismatch, Message: fmt.Sprintf("KeyID %q does not match expected %q", env.Signature.KeyID, expectedKeyID)}
	}
	// 6. Check the validity window.
	now := time.Now().UTC()
	if !env.ValidUntil.IsZero() && now.After(env.ValidUntil) {
		return &VerificationError{Reason: ReasonExpired, Message: fmt.Sprintf("envelope expired at %s (now %s)", env.ValidUntil, now)}
	}
	// 7. Check that IssuedAt is not in the future (with a
	// 1-minute clock-skew tolerance).
	skew := 1 * time.Minute
	if env.IssuedAt.After(now.Add(skew)) {
		return &VerificationError{Reason: ReasonNotYetValid, Message: fmt.Sprintf("IssuedAt %s is in the future (now %s, skew %s)", env.IssuedAt, now, skew)}
	}
	// 8. Reconstruct the to-be-signed form and verify the
	// signature. The to-be-signed form is the envelope with
	// the Signature struct re-populated with {Algorithm,
	// KeyID, PublicKey} only (no Value, no SignedAt).
	toSign := *env
	toSign.Signature = Signature{
		Algorithm: env.Signature.Algorithm,
		KeyID:     env.Signature.KeyID,
		PublicKey: env.Signature.PublicKey,
	}
	canonical, err := canonicalMarshal(toSign)
	if err != nil {
		return &VerificationError{Reason: ReasonMalformed, Message: "canonicalize failed", Cause: err}
	}
	h := sha256.New()
	h.Write([]byte(domainSeparationPrefix))
	h.Write(canonical)
	digest := h.Sum(nil)
	// 9. Verify the signature.
	if !ecdsa.VerifyASN1(pub, digest, env.Signature.Value) {
		return &VerificationError{Reason: ReasonSignatureInvalid, Message: "ECDSA signature does not verify (tampering or wrong key)"}
	}
	return nil
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// validateIssuer checks that the issuer is in the form
// "<instance-id>:<key-id>" with both parts non-empty and
// ASCII-only.
func validateIssuer(issuer string) error {
	_, _, err := parseIssuer(issuer)
	return err
}

// parseIssuer splits an issuer into (instance-id, key-id).
func parseIssuer(issuer string) (instanceID, keyID string, err error) {
	if issuer == "" {
		return "", "", fmt.Errorf("attestation: empty issuer")
	}
	idx := strings.Index(issuer, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("attestation: issuer %q missing %q separator", issuer, ":")
	}
	instanceID = issuer[:idx]
	keyID = issuer[idx+1:]
	if instanceID == "" {
		return "", "", fmt.Errorf("attestation: empty instance-id in issuer")
	}
	if keyID == "" {
		return "", "", fmt.Errorf("attestation: empty key-id in issuer")
	}
	if !isASCII(instanceID) {
		return "", "", fmt.Errorf("attestation: non-ASCII instance-id")
	}
	if !isASCII(keyID) {
		return "", "", fmt.Errorf("attestation: non-ASCII key-id")
	}
	return instanceID, keyID, nil
}

// parsePublicKey parses a SEC 1 encoded public key.
func parsePublicKey(sec1 []byte) (*ecdsa.PublicKey, error) {
	if len(sec1) == 0 {
		return nil, fmt.Errorf("empty SEC 1 bytes")
	}
	return ioc.ParsePublicKey(sec1)
}

// generateUUID generates a UUIDv4 using the IOC library's
// existing NewBundle helper (which generates a UUIDv4).
// This avoids adding a second import of google/uuid.
func generateUUID() string {
	b := ioc.NewBundle("attestation-id-gen")
	return b.BundleID
}

// fetchPublicKey fetches the evidence-signing public key from the
// canonical well-known URL of the issuing AegisGate instance.
//
// The Issuer field of an envelope is "<instance-id>:<key-id>". We
// interpret <instance-id> as the host (or host:port) of the
// instance and fetch
//
//	GET https://<instance-id>/.well-known/aegisgate-evidence-pubkey.pem
//
// The endpoint serves a standard PEM "PUBLIC KEY" block (PKIX format).
// We parse it with x509.ParsePKIXPublicKey and verify the algorithm
// is ECDSA P-256 (the only algorithm supported in v3.5.0+).
//
// This implements the c3 verifiable compliance workflow: an auditor
// can verify an attestation by fetching the issuer's public key
// from the canonical well-known URL, with no out-of-band key exchange.
//
// D22: replaces the v0.1 placeholder that always returned an error.
// 5-second HTTP timeout, context-aware. Errors are wrapped
// so callers can use errors.As to inspect the failure mode.
// isPrivateOrReservedHost returns true if the hostname is a private, reserved,
// or internal network address that should not be used for outbound HTTP requests.
// This prevents SSRF by rejecting hostnames like "169.254.169.254",
// "10.0.0.1", "192.168.1.1", "[::1]", etc.
// Loopback addresses (localhost, 127.0.0.1, ::1) are NOT rejected here
// because they are explicitly allowed for development (the caller checks them).
func isPrivateOrReservedHost(host string) bool {
	// Strip port if present (e.g., "127.0.0.1:8080" → "127.0.0.1").
	// The port is not relevant to the SSRF check.
	h := host
	if idx := strings.LastIndex(h, ":"); idx > 0 {
		h = h[:idx]
	}
	// Reject obvious private/internal patterns without DNS resolution.
	// This covers the most common SSRF targets.
	for _, prefix := range []string{
		"169.254.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "fc", "fd", "fe80::", "::ffff:",
		"0.",
	} {
		if strings.HasPrefix(h, prefix) {
			return true
		}
	}
	// Allow 127.0.0.1 and localhost (handled by caller for HTTP scheme).
	// Reject all other 127.x.x.x addresses.
	if strings.HasPrefix(h, "127.") && h != "127.0.0.1" {
		return true
	}
	return false
}

func fetchPublicKey(ctx context.Context, instanceID, keyID string) (*ecdsa.PublicKey, error) {
	// Sanitize instanceID. parseIssuer already validated that
	// it's ASCII, but we also reject path-traversal characters,
	// ".." segments, and internal/private network addresses to
	// prevent SSRF.
	if instanceID == "" || strings.ContainsAny(instanceID, "/\\?#") || strings.Contains(instanceID, "..") {
		return nil, fmt.Errorf("attestation: fetchPublicKey: invalid instance-id %q", instanceID)
	}
	// Reject internal/private network addresses to prevent SSRF.
	// Only allowloopback (localhost/127.0.0.1/::1) for development
	// and public hostnames for production.
	if isPrivateOrReservedHost(instanceID) {
		return nil, fmt.Errorf("attestation: fetchPublicKey: private/reserved instance-id rejected %q", instanceID)
	}
	// Build the well-known URL. Use HTTPS by default; fall back to
	// HTTP if the instance is on localhost / 127.0.0.1 (development).
	scheme := "https"
	if strings.HasPrefix(instanceID, "localhost") || strings.HasPrefix(instanceID, "127.0.0.1") || strings.HasPrefix(instanceID, "::1") {
		scheme = "http"
	}
	url := scheme + "://" + instanceID + "/.well-known/aegisgate-evidence-pubkey.pem"

	// HTTP GET with a 5-second timeout. The context is checked
	// first so callers can cancel earlier.
	// #nosec G107 -- url is constructed from validated instanceID (path traversal + SSRF rejected above)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("attestation: fetchPublicKey: build request: %w", err)
	}
	req.Header.Set("Accept", "application/x-pem-file")
	req.Header.Set("User-Agent", "aegisgate-attestation-verify/3.5.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestation: fetchPublicKey: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation: fetchPublicKey: GET %s: HTTP %d", url, resp.StatusCode)
	}

	// Read up to 1 MiB of PEM (public keys are ~400 bytes;
	// 1 MiB is generous against accidental big responses).
	const maxPEMSize = 1 << 20
	body := make([]byte, maxPEMSize)
	n, err := io.ReadFull(resp.Body, body)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("attestation: fetchPublicKey: read body: %w", err)
	}
	body = body[:n]

	// Parse the PEM block. The well-known endpoint serves the
	// same PKIX format as pkg/evidence/pubkey.go.
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("attestation: fetchPublicKey: no PEM block found in response from %s", url)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("attestation: fetchPublicKey: unexpected PEM block type %q (want %q)", block.Type, "PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attestation: fetchPublicKey: parse PKIX public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attestation: fetchPublicKey: not an ECDSA public key (got %T)", pub)
	}
	if ecPub.Curve != nil && ecPub.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("attestation: fetchPublicKey: not a P-256 key (got %s)", ecPub.Curve.Params().Name)
	}
	// keyID is currently informational; the envelope's Signature.KeyID
	// is the authoritative identifier. We don't fail on mismatch
	// because key rotation is allowed mid-flight.
	_ = keyID
	return ecPub, nil
}

// _ is a compile-time reference to keep the errors import.
var _ = errors.New
