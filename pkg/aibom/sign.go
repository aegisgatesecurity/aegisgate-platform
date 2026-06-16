// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM signer (TODO-302)
//
// sign.go wraps a CycloneDX BOM in the attestation envelope
// primitive. The BOM is the signed payload (after JCS
// canonicalization inside attestation.Sign).
//
// # Why this lives in its own file
//
// The AIBOM type, the BOM type, and the envelope type are
// all distinct concerns. sign.go is the glue: it converts
// the BOM to JSON, picks the envelope subject, picks the
// issuer, and calls attestation.Sign.
//
// The sign/verify split mirrors the c3 evidence manifest
// (pkg/evidence) and the AR-EaaS result (pkg/evaluator).
// All three features share the same envelope primitive;
// the per-feature glue is the only code that differs.

package aibom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// DefaultSubjectKind is the URI scheme component for AIBOM
// subjects. The full subject is:
//
//	aegisgate://<SubjectKind>/<deployment-id>
//
// Per the frozen envelope design (ENVELOPE-DESIGN-v1.1-FROZEN.md),
// the kind "deployment" is one of the 8 registered kinds.
const DefaultSubjectKind = "deployment"

// SignerOption configures a single Sign call. Functional-
// options pattern (per TODO-301 C1 lesson).
type SignerOption func(*signerOptions)

// signerOptions holds the per-call options.
type signerOptions struct {
	subjectKind string
	issuer      string
	keyID       string
	ttl         time.Duration
	notes       string
}

// WithSubjectKind overrides the URI kind component of the
// envelope subject. Default: "deployment".
func WithSubjectKind(k string) SignerOption {
	return func(o *signerOptions) { o.subjectKind = k }
}

// WithIssuer overrides the issuer string in the envelope.
// Default: derived from the deployment id + key id.
func WithIssuer(s string) SignerOption {
	return func(o *signerOptions) { o.issuer = s }
}

// WithKeyID overrides the key id in the issuer. Default:
// the current keyring's key id.
func WithKeyID(s string) SignerOption {
	return func(o *signerOptions) { o.keyID = s }
}

// WithTTL sets the envelope's ValidUntil = now + ttl. A
// zero or negative value means "no expiration" (the signed
// AIBOM is long-lived, like the c3 manifest). The AIBOM
// itself is point-in-time, but the signature should be
// permanent (an AIBOM from 2024 is just as valid in 2025).
func WithTTL(d time.Duration) SignerOption {
	return func(o *signerOptions) { o.ttl = d }
}

// WithNotes adds a free-form note to the issuer string.
// Used by the CLI/HTTP to record operator notes.
func WithNotes(s string) SignerOption {
	return func(o *signerOptions) { o.notes = s }
}

// Sign wraps a BOM in an attestation envelope. The BOM
// is JSON-encoded (JCS-canonicalized inside attestation.Sign),
// the subject is "aegisgate://deployment/<serial-number>".
//
// Returns the signed envelope.
func Sign(bom *BOM, keyRing *ioc.KeyRing, opts ...SignerOption) (*attestation.Envelope, error) {
	if bom == nil {
		return nil, fmt.Errorf("aibom: BOM is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("aibom: keyRing is required")
	}
	o := applySignerOptions(opts)
	if o.subjectKind == "" {
		o.subjectKind = DefaultSubjectKind
	}

	// Serialize the BOM to JSON. The envelope's JCS
	// canonicalizer will sort keys at every level before
	// signing, so this Go-native encoding is the input,
	// not the signed form.
	payloadBytes, err := json.Marshal(bom)
	if err != nil {
		return nil, fmt.Errorf("aibom: marshal BOM: %w", err)
	}

	// Build the subject: aegisgate://deployment/<deployment-id>.
	// The deployment id is the BOM's serial number (minus
	// the "urn:uuid:" prefix; the envelope subject is
	// supposed to be a URI, but the kind/id grammar is
	// aegisgate://<kind>/<id>, not a URN).
	subject := buildSubject(o.subjectKind, bom)
	if subject == "" {
		return nil, fmt.Errorf("aibom: cannot build subject (no deployment id in BOM)")
	}

	// Build the issuer. Default format:
	//   aibom:shortfp:<16-hex>:<key-id>[:<notes>]
	// The shortfp is the first 16 hex of the SHA-256 of
	// the BOM's deployment id. Same pattern as TODO-301
	// C2 fix (16 hex = 64 bits of entropy, plenty for
	// an identifier).
	//
	// C1 fix (TODO-302 review): the previous implementation
	// dropped WithKeyID when WithIssuer was also supplied
	// (the keyID was only consumed in the auto-issuer
	// branch). Now: if the caller supplies BOTH a custom
	// issuer AND a custom keyID, the keyID is appended to
	// the custom issuer with a colon separator. This makes
	// the WithKeyID/WithIssuer interaction explicit and
	// observable (no silent drops).
	issuer := o.issuer
	if issuer == "" {
		// Auto-generated issuer: buildIssuer() already
		// includes the keyID. We pass the keyID explicitly
		// so the caller can override it via WithKeyID.
		keyID := o.keyID
		if keyID == "" {
			keyID = keyRing.CurrentKeyID()
		}
		issuer = buildIssuer(bom, keyID)
	} else if o.keyID != "" {
		// Custom issuer: append the keyID for correlation.
		// If the caller supplied a custom issuer WITHOUT
		// a keyID, the custom issuer stands as-is (the
		// caller takes responsibility for the format).
		issuer = issuer + ":" + o.keyID
	}
	if o.notes != "" {
		issuer = issuer + ":" + sanitizeNotes(o.notes)
	}

	env, err := attestation.Sign(
		payloadBytes,
		subject,
		attestation.TypeAIBOM,
		issuer,
		keyRing,
		o.ttl,
	)
	if err != nil {
		return nil, fmt.Errorf("aibom: attestation.Sign: %w", err)
	}
	return env, nil
}

// buildSubject returns "aegisgate://<kind>/<deployment-id>".
// The deployment id is extracted from the BOM's SerialNumber
// (with the "urn:uuid:" prefix stripped). For v0.1, the
// SerialNumber is always "urn:uuid:<deployment-id>".
func buildSubject(kind string, bom *BOM) string {
	id := deploymentIDFromBOM(bom)
	if id == "" {
		return ""
	}
	return "aegisgate://" + kind + "/" + id
}

// deploymentIDFromBOM extracts the deployment id from the
// BOM. For v0.1, this is the SerialNumber minus the
// "urn:uuid:" prefix. Returns "" if the SerialNumber is
// missing or doesn't follow the expected format.
func deploymentIDFromBOM(bom *BOM) string {
	if bom.SerialNumber == "" {
		return ""
	}
	const prefix = "urn:uuid:"
	if !strings.HasPrefix(bom.SerialNumber, prefix) {
		return ""
	}
	return strings.TrimPrefix(bom.SerialNumber, prefix)
}

// buildIssuer returns the default issuer string. The format
// is "aibom:shortfp:<16-hex>:<key-id>" where <16-hex> is
// the first 16 hex chars of SHA-256(SerialNumber).
func buildIssuer(bom *BOM, keyID string) string {
	id := deploymentIDFromBOM(bom)
	if id == "" {
		return "aibom:unknown:" + keyID
	}
	// 16 hex chars = 64 bits of entropy (TODO-301 C2 fix
	// pattern). hashSHA256Hex returns the full 64-char hex
	// digest; we take the first 16.
	short := hashSHA256Hex([]byte(id))[:16]
	return "aibom:shortfp:" + short + ":" + keyID
}

// sanitizeNotes cleans the operator notes for inclusion in
// the issuer string. The issuer is a flat string with no
// escaping, so we replace problematic characters (colons,
// newlines) with underscores. The notes are NOT part of
// the signed payload (the signed payload is the BOM JSON);
// this is just a hint in the issuer field.
func sanitizeNotes(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Truncate to keep the issuer under 128 chars total.
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

// applySignerOptions returns the effective options.
func applySignerOptions(opts []SignerOption) signerOptions {
	o := signerOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
