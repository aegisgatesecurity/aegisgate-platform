// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry sign/verify (TODO-305)
//
// entry.go wraps a CVEEntry in the attestation envelope.
// The sign/verify split mirrors pkg/agentintentsign
// (the most up-to-date pattern; TODO-303 m1 introduced
// the Clock interface). All Tier 5 features share the
// same envelope primitive; the per-feature glue is the
// only code that differs.
//
// v0.1 deviations from the TODO-301/302/303/304 pattern:
//   - TTL = 0 means "no expiration" (CVE entries are
//     immutable). This is enforced by the verify path
//     (no ReasonExpired check for TTL = 0).
//   - Issuer is 3-component: "cve:shortfp:<16-hex>:
//     <key-id>". No tail-embedded field (CVE entries
//     are single-issuer publications; there's no
//     "attestor" beyond the publisher).

package cve

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
// SignerOption (functional options, per TODO-301 C1 lesson)
// =====================================================================

// SignerOption configures a single Publish call.
// Functional options (per TODO-301 C1, TODO-302 C2,
// TODO-303, TODO-304) are the only way to override
// defaults; the publisher holds no mutable per-call
// state.
type SignerOption func(*signerOptions)

// signerOptions holds the per-call options.
type signerOptions struct {
	// subjectKind overrides the URI kind component of
	// the envelope subject. Default: "cve".
	subjectKind string
	// issuer overrides the issuer string. Default:
	// derived from the publisher's name + key id
	// (shortfp format consistent with TODO-301/302/
	// 303/304).
	issuer string
	// keyID overrides the key id in the issuer.
	// Default: the current keyring's key id.
	keyID string
	// publishedAt overrides the PublishedAt timestamp.
	// Default: now() in UTC.
	publishedAt time.Time
	// nowFn is the time source. Default: time.Now UTC.
	// Used by tests (gotcha 57).
	nowFn func() time.Time
}

// WithSubjectKind overrides the URI kind component of
// the envelope subject. Default: "cve".
func WithSubjectKind(k string) SignerOption {
	return func(o *signerOptions) { o.subjectKind = k }
}

// WithIssuer overrides the issuer string in the
// envelope. Default: derived from the publisher's name
// + key id (shortfp format).
func WithIssuer(s string) SignerOption {
	return func(o *signerOptions) { o.issuer = s }
}

// WithKeyID overrides the key id in the issuer.
// Default: the current keyring's key id.
func WithKeyID(s string) SignerOption {
	return func(o *signerOptions) { o.keyID = s }
}

// WithPublishedAt overrides the PublishedAt timestamp.
// Default: now() in UTC. Used by tests; v0.1 callers
// should NOT supply this (let the publisher stamp it).
func WithPublishedAt(t time.Time) SignerOption {
	return func(o *signerOptions) { o.publishedAt = t }
}

// withNowFn is a test-only option that overrides the
// time source. Not exported; used by the test suite to
// avoid time.Sleep (gotcha 57).
func withNowFn(fn func() time.Time) SignerOption {
	return func(o *signerOptions) { o.nowFn = fn }
}

// applySignerOptions returns the effective options.
func applySignerOptions(opts []SignerOption) signerOptions {
	o := signerOptions{
		nowFn: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// =====================================================================
// Publish (sign)
// =====================================================================

// Publish wraps a CVEEntry in the attestation envelope.
// The envelope's subject is "aegisgate://cve/<cve-id>".
//
// The TTL parameter controls the envelope's ValidUntil.
// CVE entries are immutable, so pass 0 for no
// expiration (the default for CVE entries).
//
// Returns the signed envelope.
//
// Design notes (from the TODO-301/302/303/304 reviews):
//
//   - We copy the caller's CVEEntry to a local variable
//     (the C3 fix) before applying defaults. We never
//     mutate the caller's struct.
//   - The default issuer is built from the publisher's
//     name + key id (shortfp format, the C2 fix from
//     TODO-301).
//   - WithKeyID in the custom-issuer path appends the
//     key id with a colon separator (the C1 fix from
//     TODO-302).
//   - TTL = 0 means no expiration (CVE-specific; this
//     deviates from the TODO-301/302/303/304 "always
//     clamp TTL" pattern, justified by CVE semantics).
func Publish(entry *CVEEntry, keyRing *ioc.KeyRing, ttl time.Duration, opts ...SignerOption) (*attestation.Envelope, error) {
	if entry == nil {
		return nil, fmt.Errorf("cve: CVEEntry is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("cve: keyRing is required")
	}
	o := applySignerOptions(opts)

	// 1. Apply defaults to a local copy (no caller
	// mutation, per TODO-301 C3). The CVEEntry has
	// string and time fields; the struct itself is a
	// shallow copy.
	t := *entry
	if t.PublishedAt.IsZero() {
		if !o.publishedAt.IsZero() {
			t.PublishedAt = o.publishedAt
		} else {
			t.PublishedAt = o.nowFn()
		}
	}

	// 2. Validate the entry. Defaults are applied
	// first so a caller-supplied entry with missing
	// fields (which we just filled in) passes
	// validation.
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("cve: validate: %w", err)
	}

	// 3. Serialize. The envelope's JCS canonicalizer
	// will sort keys at every level before signing, so
	// this Go-native encoding is the input, not the
	// signed form.
	payloadBytes, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("cve: marshal entry: %w", err)
	}

	// 4. Build the subject. The subject is the CVE-ID
	// (the verify path extracts this and compares it
	// to CVEEntry.ID as defense in depth).
	kind := o.subjectKind
	if kind == "" {
		kind = SubjectKind
	}
	subject := "aegisgate://" + kind + "/" + t.ID

	// 5. Build the issuer. Pass the LOCAL copy `t` to
	// buildIssuer (TODO-303 C1 fix). In v0.1 the
	// DiscoveredBy is required, so `t.DiscoveredBy`
	// and `entry.DiscoveredBy` are always equal, but
	// passing `t` makes the function consistent and
	// prevents future bugs if we add more auto-
	// fillable fields.
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

	// 6. Sign. The TTL is passed through as-is
	// (CVE-specific: TTL=0 means no expiration,
	// unlike the other 4 Tier 5 features which
	// always clamp).
	env, err := attestation.Sign(
		payloadBytes,
		subject,
		attestation.TypeCVEEntry,
		issuer,
		keyRing,
		ttl,
	)
	if err != nil {
		return nil, fmt.Errorf("cve: attestation.Sign: %w", err)
	}
	return env, nil
}

// buildIssuer returns the default issuer string. The
// format is "cve:shortfp:<16-hex>:<key-id>". 3
// components: feature + shortfp + key-id. No tail-
// embedded field (CVE entries are single-issuer
// publications).
func buildIssuer(entry *CVEEntry, keyID string) string {
	short := shortFingerprint(entry.DiscoveredBy)
	return "cve:shortfp:" + short + ":" + keyID
}

// shortFingerprint returns the first 16 hex chars of
// SHA-256(s). 16 hex = 64 bits of entropy, consistent
// with the TODO-301/302/303/304 issuer pattern.
func shortFingerprint(s string) string {
	return hashSHA256Hex([]byte(s))[:16]
}

// hashSHA256Hex returns the hex-encoded SHA-256 of b.
// We implement this here (not in pkg/ioc) to keep
// pkg/cve's dependency surface minimal. The
// implementation is a one-liner with crypto/sha256.
func hashSHA256Hex(b []byte) string {
	// Imported inline to keep the imports list clean.
	// (See crypto.go for the actual import.)
	return _hashSHA256Hex(b)
}

// =====================================================================
// Clock (for testable time checks)
// =====================================================================

// Clock is the time source for the verify path. The
// default implementation uses time.Now() UTC. Tests can
// pass a custom clock to deterministically test
// expiry/not-yet-valid checks without sleeping.
//
// Pattern: per TODO-303 m1 fix, applied to TODO-304 and
// now TODO-305.
type Clock interface {
	Now() time.Time
}

// SystemClock is the default Clock implementation.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// defaultClock is the clock used by Verify when no
// custom clock is provided. Initialized to SystemClock.
var defaultClock Clock = SystemClock{}

// SetDefaultClock replaces the default clock. Used by
// tests; production code should NOT call this.
func SetDefaultClock(c Clock) {
	if c != nil {
		defaultClock = c
	}
}

// =====================================================================
// Verify
// =====================================================================

// VerifyResult is the structured output of Verify.
type VerifyResult struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty
	// when Valid is true.
	Reason string `json:"reason,omitempty"`
	// Entry is the decoded CVEEntry.
	// nil only if the payload was not valid JSON.
	Entry *CVEEntry `json:"entry,omitempty"`
	// Envelope is the raw envelope as supplied.
	Envelope *attestation.Envelope `json:"envelope"`
	// IsWithdrawal is true if the entry has
	// WithdrawnAt set.
	IsWithdrawal bool `json:"is_withdrawal,omitempty"`
}

// Verify verifies a signed CVE entry envelope. The
// flow:
//  1. attestation.Verify the envelope.
//  2. Type check (must be attestation.TypeCVEEntry).
//  3. Subject kind check (aegisgate://cve/<id>).
//  4. Issuer prefix check (cve:shortfp:...).
//  5. Decode the payload as a CVEEntry.
//  6. Sanity-check the entry (Validate).
//  7. Subject/ID check (envelope subject == entry ID).
//  8. Expiry check (only if envelope has ValidUntil).
//  9. Not-yet-valid check (PublishedAt <= now).
//
// Returns a VerifyResult. Never returns an error
// directly; all error modes are folded into
// VerifyResult.Reason.
//
// Uses defaultClock for time checks. For testable time,
// use VerifyWithClock.
func Verify(ctx context.Context, env *attestation.Envelope) *VerifyResult {
	return VerifyWithClock(ctx, env, defaultClock)
}

// VerifyWithClock is the testable variant of Verify.
// It takes a Clock parameter that supplies the "now"
// for the expiry and not-yet-valid checks.
func VerifyWithClock(ctx context.Context, env *attestation.Envelope, clock Clock) *VerifyResult {
	out := &VerifyResult{Envelope: env}
	if env == nil {
		out.Reason = "envelope is nil"
		return out
	}
	if clock == nil {
		clock = SystemClock{}
	}
	// 1. Signature + envelope well-formedness.
	if err := attestation.Verify(env); err != nil {
		out.Reason = err.Error()
		return out
	}
	// 2. Type check.
	if env.Type != attestation.TypeCVEEntry {
		out.Reason = fmt.Sprintf("envelope type is %q, want %q",
			env.Type, attestation.TypeCVEEntry)
		return out
	}
	// 3. Subject kind check (defense in depth, per
	// TODO-301 M1).
	if !strings.HasPrefix(env.Subject, "aegisgate://cve/") {
		out.Reason = "envelope subject is not aegisgate://cve/<id>: " + env.Subject
		return out
	}
	// 4. Issuer prefix check. CVE entries are
	// published by AegisGate (or a delegated
	// publisher); the issuer must start with
	// "cve:shortfp:". This is a coarse check: the
	// downstream consumer may want to verify the
	// specific publisher identity, but for v0.1 we
	// just check the prefix.
	if !strings.HasPrefix(env.Issuer, "cve:shortfp:") {
		out.Reason = ErrCVEIssuerMismatch.Error() + ": " + env.Issuer
		return out
	}
	// 5. Decode the payload.
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		out.Reason = fmt.Sprintf("decode CVEEntry: %v", err)
		return out
	}
	// 6. Sanity-check the entry.
	if err := entry.Validate(); err != nil {
		out.Reason = fmt.Sprintf("invalid CVEEntry: %v", err)
		return out
	}
	// 7. Subject/ID check.
	cveIDFromSubject := extractCVEIDFromSubject(env.Subject)
	if cveIDFromSubject != entry.ID {
		out.Reason = ErrCVEIDMismatch.Error() + fmt.Sprintf(" (subject=%q, entry=%q)", cveIDFromSubject, entry.ID)
		return out
	}
	// 8. Expiry check. CVE entries typically have no
	// ValidUntil (TTL=0). Only check if ValidUntil is
	// set.
	now := clock.Now()
	if !env.ValidUntil.IsZero() && !env.ValidUntil.After(now) {
		out.Reason = ErrCVEExpired.Error() + " (valid_until=" + env.ValidUntil.Format(time.RFC3339Nano) + ", now=" + now.Format(time.RFC3339Nano) + ")"
		return out
	}
	// 9. Not-yet-valid check. PublishedAt is optional
	// in the schema (withdrawals can have zero
	// PublishedAt if they were never published), so
	// only check if it's set.
	if !entry.PublishedAt.IsZero() && entry.PublishedAt.After(now) {
		out.Reason = fmt.Sprintf("CVE entry is not yet valid (published_at=%s, now=%s)",
			entry.PublishedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		return out
	}
	out.Entry = entry
	out.IsWithdrawal = entry.IsWithdrawal()
	out.Valid = true
	return out
}

// ParseEntry decodes a CVEEntry from JSON bytes. Used
// by the verify path and by callers that want to inspect
// a signed entry without re-decoding the envelope.
func ParseEntry(payload []byte) (*CVEEntry, error) {
	var entry CVEEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		return nil, fmt.Errorf("cve: parse CVEEntry: %w", err)
	}
	return &entry, nil
}

// VerifyJSON verifies a JSON-encoded envelope.
func VerifyJSON(ctx context.Context, payload []byte) (*VerifyResult, error) {
	var env attestation.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("cve: parse envelope: %w", err)
	}
	return Verify(ctx, &env), nil
}
