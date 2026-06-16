// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing sign/verify (TODO-303)
//
// sign.go wraps an IntentTuple in the attestation envelope.
// verify.go verifies the envelope and decodes the tuple.
//
// The sign/verify split mirrors pkg/evaluator and pkg/aibom.
// All three packages share the same envelope primitive;
// the per-feature glue is the only code that differs.

package agentintentsign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// SignerOption (functional options, per TODO-301 C1 lesson)
// =====================================================================

// SignerOption configures a single Sign call. Functional
// options (per TODO-301 C1, TODO-302 C2) are the only
// way to override defaults; the signer holds no mutable
// per-call state.
type SignerOption func(*signerOptions)

// signerOptions holds the per-call options. The zero
// value is the default for every field.
type signerOptions struct {
	// subjectKind overrides the URI kind component of
	// the envelope subject. Default: "intent".
	subjectKind string
	// issuer overrides the issuer string. Default:
	// derived from the agent_id + key id.
	issuer string
	// keyID overrides the key id in the issuer. Default:
	// the current keyring's key id.
	keyID string
	// ttl overrides the intent's ValidUntil = now + ttl.
	// Default: DefaultIntentTTL (1 hour).
	ttl time.Duration
	// context is an optional free-form context blob
	// (e.g., session id, request id). Default: empty.
	context string
	// intentID overrides the generated UUIDv4.
	// Default: a new UUIDv4.
	intentID string
	// issuedAt overrides the IssuedAt timestamp. Default:
	// now() in UTC.
	issuedAt time.Time
}

// WithSubjectKind overrides the URI kind component of
// the envelope subject. Default: "intent".
func WithSubjectKind(k string) SignerOption {
	return func(o *signerOptions) { o.subjectKind = k }
}

// WithIssuer overrides the issuer string in the envelope.
// Default: derived from the agent_id + key id (shortfp
// format consistent with TODO-301/302).
func WithIssuer(s string) SignerOption {
	return func(o *signerOptions) { o.issuer = s }
}

// WithKeyID overrides the key id in the issuer. Default:
// the current keyring's key id.
func WithKeyID(s string) SignerOption {
	return func(o *signerOptions) { o.keyID = s }
}

// WithTTL sets the intent's ValidUntil = now + ttl. A
// non-positive value restores the default. Values above
// MaxIntentTTL are clamped down.
//
// Note: the intent's TTL is independent of the envelope's
// ValidUntil. The intent is the user-facing expiry
// ("this declaration is valid until..."), while the
// envelope's ValidUntil is the cryptographic one ("the
// signature is valid until..."). For A2A intents, the
// two are usually the same: the intent expires when the
// signature expires. We set them both to the same value.
func WithTTL(d time.Duration) SignerOption {
	return func(o *signerOptions) { o.ttl = d }
}

// WithContext adds a free-form context blob to the
// IntentTuple.
func WithContext(s string) SignerOption {
	return func(o *signerOptions) { o.context = s }
}

// WithIntentID overrides the auto-generated UUIDv4. Used
// by tests for deterministic comparisons; v0.1 callers
// should NOT supply this (let the signer generate one).
func WithIntentID(s string) SignerOption {
	return func(o *signerOptions) { o.intentID = s }
}

// WithIssuedAt overrides the IssuedAt timestamp. Default:
// now() in UTC. Used by tests; v0.1 callers should NOT
// supply this.
func WithIssuedAt(t time.Time) SignerOption {
	return func(o *signerOptions) { o.issuedAt = t }
}

// applySignerOptions returns the effective options.
func applySignerOptions(opts []SignerOption) signerOptions {
	o := signerOptions{ttl: DefaultIntentTTL}
	for _, opt := range opts {
		opt(&o)
	}
	// Clamp TTL to [0, MaxIntentTTL]. A non-positive value
	// means "use default" (we re-apply the default).
	if o.ttl <= 0 {
		o.ttl = DefaultIntentTTL
	} else if o.ttl > MaxIntentTTL {
		o.ttl = MaxIntentTTL
	}
	return o
}

// =====================================================================
// Sign
// =====================================================================

// Sign wraps an IntentTuple in the attestation envelope.
// The tuple is validated, JSON-encoded, and signed. The
// envelope's subject is "aegisgate://intent/<intent-id>".
//
// Returns the signed envelope.
func Sign(tuple *IntentTuple, keyRing *ioc.KeyRing, opts ...SignerOption) (*attestation.Envelope, error) {
	if tuple == nil {
		return nil, fmt.Errorf("agentintentsign: IntentTuple is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("agentintentsign: keyRing is required")
	}
	o := applySignerOptions(opts)

	// 1. Apply defaults to a local copy. We do NOT
	// mutate the caller's struct (lesson from TODO-301
	// C3). The IntentTuple has slice and string fields
	// that share the underlying array/bytes with the
	// caller's struct, but the struct itself is a copy.
	t := *tuple
	if t.IntentID == "" {
		if o.intentID != "" {
			t.IntentID = o.intentID
		} else {
			t.IntentID = uuid.NewString()
		}
	}
	if t.IssuedAt.IsZero() {
		if !o.issuedAt.IsZero() {
			t.IssuedAt = o.issuedAt
		} else {
			t.IssuedAt = time.Now().UTC()
		}
	}
	if t.ValidUntil.IsZero() {
		t.ValidUntil = t.IssuedAt.Add(o.ttl)
	}
	if o.context != "" && t.Context == "" {
		t.Context = o.context
	}

	// 2. Validate the tuple. Defaults are applied first
	// so that a caller-supplied tuple with missing fields
	// (which we just filled in) passes validation.
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("agentintentsign: validate: %w", err)
	}
	// Also check that ValidUntil > now (so we never
	// sign an already-expired intent).
	if !t.ValidUntil.After(time.Now().UTC()) {
		return nil, fmt.Errorf("agentintentsign: valid_until is in the past or now (must be in the future)")
	}

	// 4. Serialize. The envelope's JCS canonicalizer
	// will sort keys at every level before signing, so
	// this Go-native encoding is the input, not the
	// signed form.
	payloadBytes, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("agentintentsign: marshal tuple: %w", err)
	}

	// 5. Build the subject.
	kind := o.subjectKind
	if kind == "" {
		kind = DefaultSubjectKind
	}
	subject := "aegisgate://" + kind + "/" + t.IntentID

	// 6. Build the issuer. C1 fix (TODO-303 review): pass
	// the LOCAL copy `t` to buildIssuer, not the original
	// `tuple` parameter. The local copy is what we
	// actually sign (the marshaled payload is from `t`),
	// so the issuer must be built from the same data.
	// In v0.1 the AgentID is required (so `t.AgentID`
	// and `tuple.AgentID` are always equal), but passing
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
		issuer = issuer + ":" + o.keyID
	}

	// 7. The envelope's ValidUntil is set to the
	// intent's ValidUntil (they are the same). The
	// envelope's TTL is the duration from now until
	// the intent's ValidUntil.
	envelopeTTL := time.Until(t.ValidUntil)
	if envelopeTTL <= 0 {
		// Should never happen (we checked above), but
		// defense in depth.
		return nil, fmt.Errorf("agentintentsign: envelope TTL is non-positive")
	}

	// 8. Sign.
	env, err := attestation.Sign(
		payloadBytes,
		subject,
		attestation.TypeAgentIntent,
		issuer,
		keyRing,
		envelopeTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("agentintentsign: attestation.Sign: %w", err)
	}
	return env, nil
}

// buildIssuer returns the default issuer string. The format
// is "a2a-intent:shortfp:<16-hex>:<key-id>:<agent-id>".
// The full agent_id is appended (sanitized to replace
// colons with underscores). The agent_id is at the END
// of the issuer, so the verify path can use HasSuffix to
// extract it without ambiguity from the colons in the
// agent_id itself.
//
// We don't truncate the agent_id (the MaxAgentIDLen is
// enforced at validate time; the issuer just inlines
// whatever the operator supplied).
func buildIssuer(tuple *IntentTuple, keyID string) string {
	short := shortFingerprint(tuple.AgentID)
	return "a2a-intent:shortfp:" + short + ":" + keyID + ":" + sanitizeForIssuer(tuple.AgentID)
}

// shortFingerprint returns the first 16 hex chars of
// SHA-256(s). 16 hex = 64 bits of entropy, consistent with
// the TODO-301 C2 / TODO-302 issuer pattern.
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
// m1 fix (TODO-303 review): the verify-side expiry and
// not-yet-valid checks previously used time.Now() directly,
// making them racy under -race tests. The Clock interface
// allows the verify path to accept an injected clock.
//
// The default clock (SystemClock) is used by the public
// Verify function. Tests use VerifyWithClock.
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
// It bundles the envelope, the decoded IntentTuple, and
// a pass/fail decision.
//
// `Valid` is true only if:
//   - The envelope signature verifies.
//   - The payload is a valid IntentTuple with all required fields.
//   - The envelope's Type is attestation.TypeAgentIntent.
//   - The envelope's Subject is aegisgate://intent/<id>.
//   - The intent's ValidUntil > now (not expired).
//   - The intent's IssuedAt <= now (not in the future).
//   - The issuer's agent_id prefix matches the tuple's
//     agent_id (cross-agent replay protection).
type VerifyResult struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty when
	// Valid is true.
	Reason string `json:"reason,omitempty"`
	// Tuple is the decoded IntentTuple. nil only if the
	// payload was not valid JSON.
	Tuple *IntentTuple `json:"tuple,omitempty"`
	// Envelope is the raw envelope as supplied.
	Envelope *attestation.Envelope `json:"envelope"`
}

// Verify verifies a signed A2A intent envelope. The flow:
//  1. attestation.Verify the envelope (signature, type, etc.).
//  2. Subject kind check (aegisgate://intent/<id>).
//  3. Decode the payload as an IntentTuple.
//  4. Sanity-check the tuple fields (validate).
//  5. Expiry check (ValidUntil > now).
//  6. Not-yet-valid check (IssuedAt <= now).
//  7. Cross-agent replay check (issuer's agent prefix
//     matches the tuple's agent_id).
//
// Returns a VerifyResult describing the outcome. Never
// returns an error directly; all error modes are folded
// into the VerifyResult.Reason field. Sentinel errors
// (ErrIntentExpired, ErrIntentNotYetValid, etc.) are
// wrapped in Reason so callers can use errors.Is if
// they parse Reason (we keep the error string human-
// readable, not just the sentinel).
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
// paths without sleeping (per m1 fix, TODO-303 review).
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
	if env.Type != attestation.TypeAgentIntent {
		out.Reason = fmt.Sprintf("envelope type is %q, want %q",
			env.Type, attestation.TypeAgentIntent)
		return out
	}
	// 3. Subject kind check (defense in depth, per TODO-301 M1).
	if !strings.HasPrefix(env.Subject, "aegisgate://intent/") {
		out.Reason = ErrInvalidSubject.Error() + ": " + env.Subject
		return out
	}
	// 4. Decode the payload.
	tuple, err := ParseTuple([]byte(env.RawPayload))
	if err != nil {
		out.Reason = fmt.Sprintf("decode IntentTuple: %v", err)
		return out
	}
	// 5. Sanity-check the tuple fields.
	if err := tuple.Validate(); err != nil {
		out.Reason = fmt.Sprintf("invalid IntentTuple: %v", err)
		return out
	}
	// 6. Expiry check.
	now := clock.Now()
	if !tuple.ValidUntil.After(now) {
		out.Reason = ErrIntentExpired.Error() + " (valid_until=" + tuple.ValidUntil.Format(time.RFC3339Nano) + ", now=" + now.Format(time.RFC3339Nano) + ")"
		return out
	}
	// 7. Not-yet-valid check.
	if tuple.IssuedAt.After(now) {
		out.Reason = ErrIntentNotYetValid.Error() + " (issued_at=" + tuple.IssuedAt.Format(time.RFC3339Nano) + ", now=" + now.Format(time.RFC3339Nano) + ")"
		return out
	}
	// 8. Cross-agent replay check. M2 fix (TODO-303
	// review): the previous comment said "last 32 chars
	// of the issuer", but the actual implementation
	// uses the FULL agent_id (via tail-match). The
	// 32-char prefix was an early design that was
	// changed to use the full agent_id to avoid
	// ambiguity. The comment now reflects the
	// implementation.
	//
	// The issuer's tail must match the tuple's agent_id
	// (after sanitization). If they don't match, the
	// intent was re-signed by a different key with a
	// different agent_id (a replay attempt).
	if !issuerMatchesAgent(env.Issuer, tuple.AgentID) {
		out.Reason = ErrCrossAgentReplay.Error() + " (issuer=" + env.Issuer + ", agent_id=" + tuple.AgentID + ")"
		return out
	}
	out.Tuple = tuple
	out.Valid = true
	return out
}

// ParseTuple decodes an IntentTuple from JSON bytes.
// Used by the verify path and by callers that want to
// inspect a signed intent without re-decoding the
// envelope's RawPayload.
func ParseTuple(payload []byte) (*IntentTuple, error) {
	var tuple IntentTuple
	if err := json.Unmarshal(payload, &tuple); err != nil {
		return nil, fmt.Errorf("agentintentsign: parse IntentTuple: %w", err)
	}
	return &tuple, nil
}

// VerifyJSON verifies a JSON-encoded envelope. Convenience
// for callers that receive the envelope as bytes.
func VerifyJSON(ctx context.Context, payload []byte) (*VerifyResult, error) {
	var env attestation.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("agentintentsign: parse envelope: %w", err)
	}
	return Verify(ctx, &env), nil
}

// issuerMatchesAgent returns true if the issuer ends with
// the sanitized agent_id. The issuer format is
// "a2a-intent:shortfp:<16-hex>:<key-id>:<agent-id>"
// (the agent_id is the last colon-delimited component,
// but it may itself contain colons, so we use HasSuffix
// rather than splitting on colons).
//
// The full sanitized agent_id must match the tail of
// the issuer. We do NOT truncate the agent_id (the
// issuer has the full form, so the match is exact).
//
// C2 fix (TODO-303 review): the prefix check now
// validates that parts[2] is hex (not just length 16)
// and that parts[3] (the key_id) is non-empty. The
// previous check was a length-only validation, which
// would accept `parts[2] = "aaaaaaaaaaaaaaaa"` (16 a's,
// not hex).
func issuerMatchesAgent(issuer, agentID string) bool {
	sanitized := sanitizeForIssuer(agentID)
	// Tail match: the issuer must end with ":" + sanitized
	// (so we don't false-positive on a longer agent_id
	// that happens to have the same suffix as a shorter one).
	if !strings.HasSuffix(issuer, ":"+sanitized) {
		return false
	}
	// The prefix "a2a-intent:shortfp:16hex:keyid:" must
	// be present. We extract it by trimming the suffix.
	prefix := strings.TrimSuffix(issuer, ":"+sanitized)
	parts := strings.Split(prefix, ":")
	if len(parts) != 4 {
		return false
	}
	// Validate parts[0..3] are well-formed.
	if parts[0] != "a2a-intent" {
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
	// C2 fix: validate parts[3] (the key_id) is non-empty.
	// We don't validate its format (the keyring knows
	// what its key ids look like), but an empty key_id
	// is never valid.
	if parts[3] == "" {
		return false
	}
	return true
}

// isHexString returns true if s is non-empty and contains
// only hex characters (0-9, a-f, A-F). Used by
// issuerMatchesAgent to validate the shortfp component.
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

// crypto.go is in a separate file (hashSHA256Hex).
// We use that helper for shortFingerprint.
