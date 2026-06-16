// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection sign/verify (TODO-304)
//
// cache.go wraps a PromptAttestation in the attestation
// envelope. The sign/verify split mirrors pkg/agentintentsign
// (the most up-to-date pattern; TODO-303 m1 introduced the
// Clock interface).
//
// All Tier 5 features share the same envelope primitive; the
// per-feature glue is the only code that differs.

package promptcache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// AttestorOption (functional options, per TODO-301 C1 lesson)
// =====================================================================

// AttestorOption configures a single Attest call. Functional
// options (per TODO-301 C1, TODO-302 C2, TODO-303) are the
// only way to override defaults; the attestor holds no
// mutable per-call state.
type AttestorOption func(*attestorOptions)

// attestorOptions holds the per-call options. The zero
// value is the default for every field.
type attestorOptions struct {
	// subjectKind overrides the URI kind component of
	// the envelope subject. Default: "prompt".
	subjectKind string
	// issuer overrides the issuer string. Default:
	// derived from the attestor_id + key id (shortfp
	// format consistent with TODO-301/302/303).
	issuer string
	// keyID overrides the key id in the issuer. Default:
	// the current keyring's key id.
	keyID string
	// ttl overrides the attestation's ValidUntil =
	// attested_at + ttl. Default: DefaultPromptCacheTTL
	// (1 hour). A non-positive value restores the default.
	// Values above MaxPromptCacheTTL are clamped down.
	ttl time.Duration
	// attestedAt overrides the AttestedAt timestamp.
	// Default: now() in UTC.
	attestedAt time.Time
}

// WithSubjectKind overrides the URI kind component of
// the envelope subject. Default: "prompt".
func WithSubjectKind(k string) AttestorOption {
	return func(o *attestorOptions) { o.subjectKind = k }
}

// WithIssuer overrides the issuer string in the envelope.
// Default: derived from the attestor_id + key id (shortfp
// format consistent with TODO-301/302/303).
func WithIssuer(s string) AttestorOption {
	return func(o *attestorOptions) { o.issuer = s }
}

// WithKeyID overrides the key id in the issuer. Default:
// the current keyring's key id.
func WithKeyID(s string) AttestorOption {
	return func(o *attestorOptions) { o.keyID = s }
}

// WithTTL sets the attestation's ValidUntil = attested_at
// + ttl. A non-positive value restores the default. Values
// above MaxPromptCacheTTL are clamped down.
//
// Note: the attestation's TTL is independent of the
// envelope's ValidUntil. The attestation is the user-facing
// expiry ("this attestation covers prompts until..."),
// while the envelope's ValidUntil is the cryptographic one
// ("the signature is valid until..."). For prompt-cache
// attestations, the two are the same: the attestation
// expires when the signature expires. We set them both to
// the same value.
func WithTTL(d time.Duration) AttestorOption {
	return func(o *attestorOptions) { o.ttl = d }
}

// WithAttestedAt overrides the AttestedAt timestamp.
// Default: now() in UTC. Used by tests; v0.1 callers
// should NOT supply this.
func WithAttestedAt(t time.Time) AttestorOption {
	return func(o *attestorOptions) { o.attestedAt = t }
}

// applyAttestorOptions returns the effective options.
func applyAttestorOptions(opts []AttestorOption) attestorOptions {
	o := attestorOptions{ttl: DefaultPromptCacheTTL}
	for _, opt := range opts {
		opt(&o)
	}
	// Clamp TTL to [0, MaxPromptCacheTTL]. A non-positive
	// value means "use default" (we re-apply the default).
	if o.ttl <= 0 {
		o.ttl = DefaultPromptCacheTTL
	} else if o.ttl > MaxPromptCacheTTL {
		o.ttl = MaxPromptCacheTTL
	}
	return o
}

// =====================================================================
// Attest (sign)
// =====================================================================

// Attest wraps a PromptAttestation in the attestation
// envelope. The attestation is validated, JSON-encoded, and
// signed. The envelope's subject is "aegisgate://prompt/
// <prompt_hash>".
//
// Returns the signed envelope.
//
// Design notes (from the TODO-301/302/303 reviews):
//
//   - We copy the caller's PromptAttestation to a local
//     variable (the C3 fix) before applying defaults. We
//     never mutate the caller's struct.
//   - The default issuer is built from attestor_id + key
//     id (shortfp format, the C2 fix from TODO-301).
//   - The TTL is clamped to [0, MaxPromptCacheTTL]
//     (the TTL clamping pattern from all 3 prior
//     features).
func Attest(att *PromptAttestation, keyRing *ioc.KeyRing, opts ...AttestorOption) (*attestation.Envelope, error) {
	if att == nil {
		return nil, fmt.Errorf("promptcache: PromptAttestation is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("promptcache: keyRing is required")
	}
	o := applyAttestorOptions(opts)

	// 1. Apply defaults to a local copy. We do NOT
	// mutate the caller's struct (lesson from TODO-301
	// C3 / TODO-303 C1). The PromptAttestation has
	// string and time fields; the struct itself is a
	// shallow copy.
	t := *att
	if t.AttestedAt.IsZero() {
		if !o.attestedAt.IsZero() {
			t.AttestedAt = o.attestedAt
		} else {
			t.AttestedAt = time.Now().UTC()
		}
	}
	if t.ValidUntil.IsZero() {
		t.ValidUntil = t.AttestedAt.Add(o.ttl)
	}

	// 2. Compute the prompt hash if not already set.
	// We do this AFTER applying AttestedAt/ValidUntil
	// defaults so Validate sees a complete struct.
	// (Note: the caller is expected to compute
	// PromptHash with HashPrompt BEFORE calling Attest;
	// if they don't, Validate will reject the empty
	// PromptHash.)
	//
	// We do NOT auto-compute PromptHash here because
	// that would require the caller to pass the raw
	// prompt text into Attest, which is a privacy
	// concern (the raw prompt may be sensitive; we
	// want the caller to hash locally and pass only
	// the hash). This is also consistent with how
	// AIBOM handles prompt fingerprints (the caller
	// computes them; the signer doesn't see the raw
	// prompt).

	// 3. Validate the attestation. Defaults are
	// applied first so that a caller-supplied
	// attestation with missing fields (which we just
	// filled in) passes validation.
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("promptcache: validate: %w", err)
	}
	// Also check that ValidUntil > now (so we never
	// sign an already-expired attestation).
	if !t.ValidUntil.After(time.Now().UTC()) {
		return nil, fmt.Errorf("promptcache: valid_until is in the past or now (must be in the future)")
	}

	// 4. Serialize. The envelope's JCS canonicalizer
	// will sort keys at every level before signing, so
	// this Go-native encoding is the input, not the
	// signed form.
	payloadBytes, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("promptcache: marshal attestation: %w", err)
	}

	// 5. Build the subject. The subject is the prompt
	// hash (the verify path extracts this and
	// compares it to PromptAttestation.PromptHash as
	// defense in depth).
	kind := o.subjectKind
	if kind == "" {
		kind = DefaultSubjectKind
	}
	subject := "aegisgate://" + kind + "/" + t.PromptHash

	// 6. Build the issuer. Pass the LOCAL copy `t` to
	// buildIssuer (TODO-303 C1 fix). In v0.1 the
	// AttestorID is required (so `t.AttestorID` and
	// `att.AttestorID` are always equal), but passing
	// `t` makes the function consistent and prevents
	// future bugs if we add more auto-fillable fields.
	issuer := o.issuer
	if issuer == "" {
		keyID := o.keyID
		if keyID == "" {
			keyID = keyRing.CurrentKeyID()
		}
		issuer = buildIssuer(&t, keyID)
	} else if o.keyID != "" {
		// TODO-302 C1 fix: WithKeyID in the custom-
		// issuer path appends the key id to the
		// custom issuer with a colon separator. Never
		// silently drop an option.
		issuer = issuer + ":" + o.keyID
	}

	// 7. The envelope's ValidUntil is set to the
	// attestation's ValidUntil (they are the same).
	// The envelope's TTL is the duration from now
	// until the attestation's ValidUntil.
	envelopeTTL := time.Until(t.ValidUntil)
	if envelopeTTL <= 0 {
		// Should never happen (we checked above), but
		// defense in depth.
		return nil, fmt.Errorf("promptcache: envelope TTL is non-positive")
	}

	// 8. Sign.
	env, err := attestation.Sign(
		payloadBytes,
		subject,
		attestation.TypePromptCacheAttestation,
		issuer,
		keyRing,
		envelopeTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("promptcache: attestation.Sign: %w", err)
	}
	return env, nil
}

// buildIssuer returns the default issuer string. The format
// is "promptcache:shortfp:<16-hex>:<key-id>:<attestor-id>".
// The full attestor_id is appended (sanitized to replace
// colons with underscores). The attestor_id is at the END
// of the issuer, so the verify path can use HasSuffix to
// extract it without ambiguity from the colons in the
// attestor_id itself.
//
// We don't truncate the attestor_id (the MaxAttestorIDLen
// is enforced at validate time; the issuer just inlines
// whatever the operator supplied).
func buildIssuer(att *PromptAttestation, keyID string) string {
	short := shortFingerprint(att.AttestorID)
	return "promptcache:shortfp:" + short + ":" + keyID + ":" + sanitizeForIssuer(att.AttestorID)
}

// shortFingerprint returns the first 16 hex chars of
// SHA-256(s). 16 hex = 64 bits of entropy, consistent with
// the TODO-301 C2 / TODO-302 / TODO-303 issuer pattern.
func shortFingerprint(s string) string {
	return hashSHA256Hex([]byte(s))[:16]
}

// sanitizeForIssuer replaces characters that would break
// the issuer format (colons, newlines) with underscores.
// The issuer is a flat string with no escaping.
func sanitizeForIssuer(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// =====================================================================
// Clock (for testable time checks)
// =====================================================================

// Clock is the time source for the verify path. The
// default implementation uses time.Now() UTC. Tests can
// pass a custom clock to deterministically test
// expiry/not-yet-valid checks without sleeping.
//
// Pattern: per TODO-303 m1 fix. The verify-side expiry and
// not-yet-valid checks use this interface, making them
// deterministic under -race tests.
type Clock interface {
	Now() time.Time
}

// SystemClock is the default Clock implementation. It
// returns time.Now() in UTC.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// defaultClock is the clock used by Verify when no
// custom clock is provided. Initialized to SystemClock.
var defaultClock Clock = SystemClock{}

// SetDefaultClock replaces the default clock. Used by
// tests; production code should NOT call this (the
// SystemClock is the only safe production choice).
func SetDefaultClock(c Clock) {
	if c != nil {
		defaultClock = c
	}
}

// =====================================================================
// Verify
// =====================================================================

// VerifyResult is the structured output of Verify.
// It bundles the envelope, the decoded PromptAttestation,
// and a pass/fail decision.
//
// `Valid` is true only if:
//   - The envelope signature verifies.
//   - The payload is a valid PromptAttestation with all
//     required fields.
//   - The envelope's Type is
//     attestation.TypePromptCacheAttestation.
//   - The envelope's Subject is aegisgate://prompt/<hash>
//     and the hash matches the attestation's PromptHash.
//   - The attestation's ValidUntil > now (not expired).
//   - The attestation's AttestedAt <= now (not in the
//     future).
//   - The issuer's attestor_id tail matches the
//     attestation's attestor_id (cross-attestor replay
//     protection).
type VerifyResult struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty
	// when Valid is true.
	Reason string `json:"reason,omitempty"`
	// Attestation is the decoded PromptAttestation.
	// nil only if the payload was not valid JSON.
	Attestation *PromptAttestation `json:"attestation,omitempty"`
	// Envelope is the raw envelope as supplied.
	Envelope *attestation.Envelope `json:"envelope"`
}

// Verify verifies a signed prompt-cache attestation
// envelope. The flow:
//  1. attestation.Verify the envelope (signature, type,
//     etc.).
//  2. Type check.
//  3. Subject kind check (aegisgate://prompt/<hash>).
//  4. Decode the payload as a PromptAttestation.
//  5. Sanity-check the attestation fields (validate).
//  6. Expiry check (ValidUntil > now).
//  7. Not-yet-valid check (AttestedAt <= now).
//  8. Prompt-hash check (envelope subject hash == attestation
//     PromptHash).
//  9. Cross-attestor replay check (issuer's attestor_id
//     tail matches the attestation's attestor_id).
//
// Returns a VerifyResult describing the outcome. Never
// returns an error directly; all error modes are folded
// into the VerifyResult.Reason field.
//
// Uses defaultClock for time checks. For testable time,
// use VerifyWithClock.
func Verify(ctx context.Context, env *attestation.Envelope) *VerifyResult {
	return VerifyWithClock(ctx, env, defaultClock)
}

// VerifyWithClock is the testable variant of Verify.
// It takes a Clock parameter that supplies the "now"
// for the expiry and not-yet-valid checks. Tests can
// pass a frozen clock to deterministically test these
// paths without sleeping (per m1 fix, TODO-303 review,
// applied here to TODO-304 from the start).
func VerifyWithClock(ctx context.Context, env *attestation.Envelope, clock Clock) *VerifyResult {
	out := &VerifyResult{Envelope: env}
	if env == nil {
		out.Reason = "envelope is nil"
		return out
	}
	// Defensive: a nil clock falls back to SystemClock
	// (so tests that pass nil don't panic).
	if clock == nil {
		clock = SystemClock{}
	}
	// 1. Signature + envelope well-formedness.
	if err := attestation.Verify(env); err != nil {
		out.Reason = err.Error()
		return out
	}
	// 2. Type check.
	if env.Type != attestation.TypePromptCacheAttestation {
		out.Reason = fmt.Sprintf("envelope type is %q, want %q",
			env.Type, attestation.TypePromptCacheAttestation)
		return out
	}
	// 3. Subject kind check (defense in depth, per TODO-301 M1).
	if !strings.HasPrefix(env.Subject, "aegisgate://prompt/") {
		out.Reason = ErrInvalidSubject.Error() + ": " + env.Subject
		return out
	}
	// 4. Decode the payload.
	att, err := ParseAttestation([]byte(env.RawPayload))
	if err != nil {
		out.Reason = fmt.Sprintf("decode PromptAttestation: %v", err)
		return out
	}
	// 5. Sanity-check the attestation fields.
	if err := att.Validate(); err != nil {
		out.Reason = fmt.Sprintf("invalid PromptAttestation: %v", err)
		return out
	}
	// 6. Expiry check.
	now := clock.Now()
	if !att.ValidUntil.After(now) {
		out.Reason = ErrAttestationExpired.Error() + " (valid_until=" + att.ValidUntil.Format(time.RFC3339Nano) + ", now=" + now.Format(time.RFC3339Nano) + ")"
		return out
	}
	// 7. Not-yet-valid check.
	if att.AttestedAt.After(now) {
		out.Reason = ErrAttestationNotYetValid.Error() + " (attested_at=" + att.AttestedAt.Format(time.RFC3339Nano) + ", now=" + now.Format(time.RFC3339Nano) + ")"
		return out
	}
	// 8. Prompt-hash check. Extract the hash from the
	// envelope subject and compare it to the
	// attestation's PromptHash. The subject is
	// "aegisgate://prompt/<hash>" so we strip the
	// prefix and compare.
	subjectHash := strings.TrimPrefix(env.Subject, "aegisgate://prompt/")
	if subjectHash != att.PromptHash {
		out.Reason = ErrPromptHashMismatch.Error() + " (subject=" + subjectHash + ", attestation=" + att.PromptHash + ")"
		return out
	}
	// 9. Cross-attestor replay check. The issuer's
	// tail must match the attestation's attestor_id
	// (after sanitization). If they don't match, the
	// attestation was re-signed by a different key
	// with a different attestor_id (a replay attempt).
	if !issuerMatchesAttestor(env.Issuer, att.AttestorID) {
		out.Reason = ErrAttestorMismatch.Error() + " (issuer=" + env.Issuer + ", attestor_id=" + att.AttestorID + ")"
		return out
	}
	out.Attestation = att
	out.Valid = true
	return out
}

// ParseAttestation decodes a PromptAttestation from JSON
// bytes. Used by the verify path and by callers that want
// to inspect a signed attestation without re-decoding the
// envelope's RawPayload.
func ParseAttestation(payload []byte) (*PromptAttestation, error) {
	var att PromptAttestation
	if err := json.Unmarshal(payload, &att); err != nil {
		return nil, fmt.Errorf("promptcache: parse PromptAttestation: %w", err)
	}
	return &att, nil
}

// VerifyJSON verifies a JSON-encoded envelope. Convenience
// for callers that receive the envelope as bytes.
func VerifyJSON(ctx context.Context, payload []byte) (*VerifyResult, error) {
	var env attestation.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("promptcache: parse envelope: %w", err)
	}
	return Verify(ctx, &env), nil
}

// issuerMatchesAttestor returns true if the issuer ends
// with the sanitized attestor_id. The issuer format is
// "promptcache:shortfp:<16-hex>:<key-id>:<attestor-id>"
// (the attestor_id is the last colon-delimited component,
// but it may itself contain colons, so we use HasSuffix
// rather than splitting on colons).
//
// The full sanitized attestor_id must match the tail of
// the issuer. We do NOT truncate the attestor_id (the
// issuer has the full form, so the match is exact).
//
// C2 fix (TODO-304 review): the prefix check validates
// that parts[2] is hex (not just length 16) and that
// parts[3] (the key_id) is non-empty. The previous
// length-only validation would accept
// `parts[2] = "aaaaaaaaaaaaaaaa"` (16 a's, not hex).
func issuerMatchesAttestor(issuer, attestorID string) bool {
	sanitized := sanitizeForIssuer(attestorID)
	// Tail match: the issuer must end with ":" + sanitized
	// (so we don't false-positive on a longer attestor_id
	// that happens to have the same suffix as a shorter
	// one).
	if !strings.HasSuffix(issuer, ":"+sanitized) {
		return false
	}
	// The prefix "promptcache:shortfp:16hex:keyid:" must
	// be present. We extract it by trimming the suffix.
	prefix := strings.TrimSuffix(issuer, ":"+sanitized)
	parts := strings.Split(prefix, ":")
	if len(parts) != 4 {
		return false
	}
	// Validate parts[0..3] are well-formed.
	if parts[0] != "promptcache" {
		return false
	}
	if parts[1] != "shortfp" {
		return false
	}
	// C2 fix: validate parts[2] is 16 hex chars (not
	// just any 16 characters).
	if !isHexString(parts[2]) || len(parts[2]) != 16 {
		return false
	}
	// C2 fix: validate parts[3] (the key_id) is
	// non-empty. We don't validate its format (the
	// keyring knows what its key ids look like), but
	// an empty key_id is never valid.
	if parts[3] == "" {
		return false
	}
	return true
}

// isHexString returns true if s is non-empty and contains
// only hex characters (0-9, a-f, A-F). Used by
// issuerMatchesAttestor to validate the shortfp component.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
