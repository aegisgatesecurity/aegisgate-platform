// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry tests (TODO-305)
//
// entry_test.go covers the sign/verify lifecycle, the
// feed operations, the severity bands, the validation
// rules, and all sentinel error paths.
//
// The test density mirrors pkg/agentintentsign (53
// tests) and pkg/promptcache (74 tests); we aim for
// similar coverage here.

package cve

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// Test helpers
// =====================================================================

// makeTestKeyRing creates an in-memory keyring for tests.
func makeTestKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	return kr
}

// makeTestEntry returns a valid CVEEntry for a prompt-
// injection example. The shape is based on a realistic
// AI/ML vulnerability disclosure.
func makeTestEntry(t *testing.T) *CVEEntry {
	t.Helper()
	return &CVEEntry{
		ID:           "AEGIS-2026-0001",
		Title:        "[EXAMPLE] Prompt injection via Markdown image alt-text",
		Description:  "EXAMPLE entry. An attacker can inject instructions into a model prompt by including carefully crafted Markdown image alt-text that is rendered as part of the model's context window. This is a test fixture; not a real disclosure.",
		Affected:     []string{"anthropic/claude-3-5-sonnet@<20241022"},
		Fixed:        []string{"anthropic/claude-3-5-sonnet@20241022"},
		Score:        7.5,
		Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
		References:   []string{"https://example.com/advisory/AEGIS-2026-0001"},
		Mitigations:  []string{"Sanitize Markdown before including in prompts."},
		DiscoveredBy: "AegisGate Research",
		DisclosedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	}
}

// frozenClock is a Clock that returns a fixed time.
type frozenClock struct {
	t time.Time
}

func (f frozenClock) Now() time.Time { return f.t }

// =====================================================================
// SeverityFromScore
// =====================================================================

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  SeverityBand
	}{
		{-1, SeverityNone},
		{0, SeverityNone},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}
	for _, tc := range cases {
		got := SeverityFromScore(tc.score)
		if got != tc.want {
			t.Errorf("SeverityFromScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// =====================================================================
// Validate
// =====================================================================

func TestValidate_HappyPath(t *testing.T) {
	e := makeTestEntry(t)
	if err := e.Validate(); err != nil {
		t.Errorf("Validate on valid entry: %v", err)
	}
	// Band should be auto-derived from score (7.5 -> HIGH).
	if e.Band != string(SeverityHigh) {
		t.Errorf("Band = %q, want %q (auto-derived)", e.Band, SeverityHigh)
	}
}

func TestValidate_Nil(t *testing.T) {
	var e *CVEEntry
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on nil should fail")
	}
}

func TestValidate_MissingID(t *testing.T) {
	e := makeTestEntry(t)
	e.ID = ""
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on missing id should fail")
	}
}

func TestValidate_IDTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.ID = "AEGIS-2026-" + strings.Repeat("1", 100)
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized id should fail")
	}
}

func TestValidate_BadIDFormat(t *testing.T) {
	cases := []string{
		"NOT-AEGIS-2026-0001",
		"AEGIS-26-0001",    // year not 4 digits
		"AEGIS-2026-1",     // sequence not 4 digits
		"AEGIS-2026-0001X", // trailing chars
		"XEGIS-2026-0001",  // wrong prefix
		"AEGIS-ABCD-0001",  // non-digit year
		"AEGIS-2026-abcd",  // non-digit sequence
		"aegis-2026-0001",  // lowercase
	}
	for _, c := range cases {
		e := makeTestEntry(t)
		e.ID = c
		if err := e.Validate(); err == nil {
			t.Errorf("Validate on bad id %q should fail", c)
		}
	}
}

func TestValidate_GoodIDFormat(t *testing.T) {
	cases := []string{
		"AEGIS-2026-0001",
		"AEGIS-2026-0001",
		"AEGIS-2026-9999",
		"AEGIS-2026-10000",   // 5-digit sequence
		"AEGIS-2026-9999999", // 7-digit sequence
	}
	for _, c := range cases {
		e := makeTestEntry(t)
		e.ID = c
		if err := e.Validate(); err != nil {
			t.Errorf("Validate on good id %q: %v", c, err)
		}
	}
}

func TestValidate_MissingTitle(t *testing.T) {
	e := makeTestEntry(t)
	e.Title = ""
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on missing title should fail")
	}
}

func TestValidate_TitleTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.Title = strings.Repeat("a", MaxTitleLen+1)
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized title should fail")
	}
}

func TestValidate_MissingDescription(t *testing.T) {
	e := makeTestEntry(t)
	e.Description = ""
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on missing description should fail")
	}
}

func TestValidate_DescriptionTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.Description = strings.Repeat("a", MaxDescriptionLen+1)
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized description should fail")
	}
}

func TestValidate_ScoreOutOfRange(t *testing.T) {
	cases := []float64{-1, -0.1, 10.1, 11, 100}
	for _, s := range cases {
		e := makeTestEntry(t)
		e.Score = s
		if err := e.Validate(); err == nil {
			t.Errorf("Validate on score %v should fail", s)
		}
	}
}

func TestValidate_ScoreValid(t *testing.T) {
	cases := []float64{0, 0.1, 4.0, 7.5, 9.0, 10.0}
	for _, s := range cases {
		e := makeTestEntry(t)
		e.Score = s
		if err := e.Validate(); err != nil {
			t.Errorf("Validate on score %v: %v", s, err)
		}
	}
}

func TestValidate_VectorRequiredWithScore(t *testing.T) {
	e := makeTestEntry(t)
	e.Score = 7.5
	e.Vector = ""
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on score without vector should fail")
	}
}

func TestValidate_BadReference(t *testing.T) {
	cases := []string{
		"not-a-url",
		"ftp://example.com",
		"javascript:alert(1)",
		"file:///etc/passwd",
	}
	for _, r := range cases {
		e := makeTestEntry(t)
		e.References = []string{r}
		if err := e.Validate(); err == nil {
			t.Errorf("Validate on bad reference %q should fail", r)
		}
	}
}

func TestValidate_GoodReference(t *testing.T) {
	cases := []string{
		"http://example.com",
		"https://example.com",
		"https://example.com/path?query=1",
	}
	for _, r := range cases {
		e := makeTestEntry(t)
		e.References = []string{r}
		if err := e.Validate(); err != nil {
			t.Errorf("Validate on good reference %q: %v", r, err)
		}
	}
}

func TestValidate_MissingDiscoveredBy(t *testing.T) {
	e := makeTestEntry(t)
	e.DiscoveredBy = ""
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on missing discovered_by should fail")
	}
}

func TestValidate_MissingDisclosedAt(t *testing.T) {
	e := makeTestEntry(t)
	e.DisclosedAt = time.Time{}
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on missing disclosed_at should fail")
	}
}

func TestValidate_WithdrawalBeforeDisclosure(t *testing.T) {
	e := makeTestEntry(t)
	e.DisclosedAt = time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	e.WithdrawnAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // before
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on withdrawal before disclosure should fail")
	}
}

func TestValidate_ValidWithdrawal(t *testing.T) {
	e := makeTestEntry(t)
	e.DisclosedAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	e.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC) // after
	if err := e.Validate(); err != nil {
		t.Errorf("Validate on valid withdrawal: %v", err)
	}
}

func TestIsWithdrawal(t *testing.T) {
	var e *CVEEntry
	if e.IsWithdrawal() {
		t.Errorf("nil entry should not be a withdrawal")
	}
	e = makeTestEntry(t)
	if e.IsWithdrawal() {
		t.Errorf("entry without WithdrawnAt should not be a withdrawal")
	}
	e.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	if !e.IsWithdrawal() {
		t.Errorf("entry with WithdrawnAt should be a withdrawal")
	}
}

func TestIsPublished(t *testing.T) {
	var e *CVEEntry
	if e.IsPublished() {
		t.Errorf("nil entry should not be published")
	}
	e = makeTestEntry(t)
	if e.IsPublished() {
		t.Errorf("entry without PublishedAt should not be published")
	}
	e.PublishedAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	if !e.IsPublished() {
		t.Errorf("entry with PublishedAt should be published")
	}
}

// =====================================================================
// Publish (Sign)
// =====================================================================

func TestPublish_NilEntry(t *testing.T) {
	kr := makeTestKeyRing(t)
	if _, err := Publish(nil, kr, 0); err == nil {
		t.Errorf("Publish on nil should fail")
	}
}

func TestPublish_NilKeyRing(t *testing.T) {
	e := makeTestEntry(t)
	if _, err := Publish(e, nil, 0); err == nil {
		t.Errorf("Publish on nil keyring should fail")
	}
}

func TestPublish_HappyPath(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0) // TTL = 0 = no expiration
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Subject: aegisgate://cve/AEGIS-2026-0001
	wantSubject := "aegisgate://cve/AEGIS-2026-0001"
	if env.Subject != wantSubject {
		t.Errorf("Subject = %q, want %q", env.Subject, wantSubject)
	}
	// Type: TypeCVEEntry
	if env.Type != attestation.TypeCVEEntry {
		t.Errorf("Type = %q, want %q", env.Type, attestation.TypeCVEEntry)
	}
	// Issuer: cve:shortfp:<16-hex>:<key-id>
	if !strings.HasPrefix(env.Issuer, "cve:shortfp:") {
		t.Errorf("Issuer = %q, want prefix 'cve:shortfp:'", env.Issuer)
	}
	// ValidUntil: zero (no expiration for CVE entries).
	if !env.ValidUntil.IsZero() {
		t.Errorf("ValidUntil = %v, want zero (TTL=0 means no expiration)", env.ValidUntil)
	}
}

func TestPublish_PublishedAtAutoSet(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	before := time.Now().UTC()
	env, err := Publish(e, kr, 0)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if entry.PublishedAt.Before(before) || entry.PublishedAt.After(after) {
		t.Errorf("PublishedAt = %v, want between %v and %v", entry.PublishedAt, before, after)
	}
}

func TestPublish_InvalidEntry(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	e.ID = "bad-id-format"
	if _, err := Publish(e, kr, 0); err == nil {
		t.Errorf("Publish on invalid id should fail")
	}
}

func TestPublish_WithCustomIssuer(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0,
		WithIssuer("custom:publisher"),
		WithKeyID("k-test-123"),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Issuer should be "custom:publisher:k-test-123" (TODO-302 C1 fix).
	want := "custom:publisher:k-test-123"
	if env.Issuer != want {
		t.Errorf("Issuer = %q, want %q", env.Issuer, want)
	}
}

func TestPublish_WithCustomIssuer_NoKeyID(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0,
		WithIssuer("custom:publisher"),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if env.Issuer != "custom:publisher" {
		t.Errorf("Issuer = %q, want %q", env.Issuer, "custom:publisher")
	}
}

func TestPublish_WithPublishedAt(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	e.PublishedAt = time.Time{} // clear so WithPublishedAt takes effect
	fixedTime := time.Now().UTC().Add(1 * time.Minute)
	env, err := Publish(e, kr, 0, WithPublishedAt(fixedTime))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if !entry.PublishedAt.Equal(fixedTime) {
		t.Errorf("PublishedAt = %v, want %v", entry.PublishedAt, fixedTime)
	}
}

func TestPublish_IssuerFormat(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Format: cve:shortfp:<16-hex>:<key-id>
	parts := strings.Split(env.Issuer, ":")
	if len(parts) != 4 {
		t.Errorf("Issuer has %d colon-separated parts, want 4: %q", len(parts), env.Issuer)
	}
	if parts[0] != "cve" {
		t.Errorf("Issuer prefix = %q, want 'cve'", parts[0])
	}
	if parts[1] != "shortfp" {
		t.Errorf("Issuer shortfp marker = %q, want 'shortfp'", parts[1])
	}
	if len(parts[2]) != 16 {
		t.Errorf("Issuer shortfp length = %d, want 16", len(parts[2]))
	}
	if !isHexString(parts[2]) {
		t.Errorf("Issuer shortfp is not hex: %q", parts[2])
	}
	if parts[3] == "" {
		t.Errorf("Issuer key_id is empty")
	}
}

func TestPublish_Withdrawal(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	e.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Subject is unchanged.
	if env.Subject != "aegisgate://cve/AEGIS-2026-0001" {
		t.Errorf("Withdrawal subject = %q, want 'aegisgate://cve/AEGIS-2026-0001'", env.Subject)
	}
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if !entry.IsWithdrawal() {
		t.Errorf("Withdrawal entry should have IsWithdrawal = true")
	}
}

// =====================================================================
// Verify
// =====================================================================

func TestVerify_Nil(t *testing.T) {
	vr := Verify(context.Background(), nil)
	if vr.Valid {
		t.Errorf("Verify on nil should not be valid")
	}
	if vr.Reason == "" {
		t.Errorf("Verify on nil should have a reason")
	}
}

func TestVerify_HappyPath(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	vr := Verify(context.Background(), env)
	if !vr.Valid {
		t.Errorf("Verify failed: %s", vr.Reason)
	}
	if vr.Entry == nil {
		t.Errorf("Verify should populate Entry")
	}
	if vr.Entry.ID != "AEGIS-2026-0001" {
		t.Errorf("Entry.ID = %q, want 'AEGIS-2026-0001'", vr.Entry.ID)
	}
}

func TestVerify_RoundtripJSON(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	js, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	vr, err := VerifyJSON(context.Background(), js)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if !vr.Valid {
		t.Errorf("VerifyJSON roundtrip: %s", vr.Reason)
	}
}

func TestVerify_InvalidJSON(t *testing.T) {
	_, err := VerifyJSON(context.Background(), []byte("not json"))
	if err == nil {
		t.Errorf("VerifyJSON on invalid JSON should fail")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Tamper with the payload.
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	entry.Title = "TAMPERED TITLE"
	tamperedBytes, _ := json.Marshal(entry)
	env.RawPayload = tamperedBytes
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Errorf("Verify on tampered payload should fail")
	}
	if !strings.Contains(vr.Reason, "signature") {
		t.Errorf("Verify reason = %q, expected 'signature' in reason", vr.Reason)
	}
}

func TestVerify_WrongType(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Mutate Type after signing. The Type field is
	// part of the signed bytes, so this also breaks
	// the signature. The test just checks that Verify
	// returns !Valid.
	env.Type = attestation.TypeAgentIntent
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Errorf("Verify on wrong type should fail")
	}
}

func TestVerify_WrongSubject(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	// Re-sign with a non-cve subject kind.
	env, err := Publish(e, kr, 0, WithSubjectKind("manifest"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Errorf("Verify on wrong subject kind should fail")
	}
	if !strings.Contains(vr.Reason, "subject") {
		t.Errorf("Verify reason = %q, expected 'subject'", vr.Reason)
	}
}

func TestVerify_BadIssuerPrefix(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	// Use a custom issuer that doesn't start with
	// "cve:shortfp:". The verify path checks the
	// prefix.
	env, err := Publish(e, kr, 0, WithIssuer("rogue:shortfp:0123456789abcdef"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Errorf("Verify on bad issuer should fail")
	}
	if !strings.Contains(vr.Reason, "issuer") {
		t.Errorf("Verify reason = %q, expected 'issuer'", vr.Reason)
	}
}

func TestVerify_CVEIDMismatch(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Tamper with the entry's ID.
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	entry.ID = "AEGIS-2026-9999"
	tamperedBytes, _ := json.Marshal(entry)
	env.RawPayload = tamperedBytes
	vr := Verify(context.Background(), env)
	// This fails at signature check (we tampered the
	// signed payload).
	if vr.Valid {
		t.Errorf("Verify on mismatched CVE-ID should fail")
	}
}

// =====================================================================
// VerifyWithClock (testable time)
// =====================================================================

func TestVerifyWithClock_HappyPath(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Day 16 fix: use a clock-relative frozen time (now + 1 hour)
	// instead of the hardcoded 2026-06-18. Publish() sets
	// PublishedAt to time.Now(), so a frozen clock older than that
	// fails the "not yet valid" check. Using now + 1 hour keeps
	// the test anchored to the present.
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: time.Now().UTC().Add(1 * time.Hour)})
	if !vr.Valid {
		t.Errorf("VerifyWithClock: %s", vr.Reason)
	}
}

func TestVerifyWithClock_NilClock(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Should not panic on nil clock.
	vr := VerifyWithClock(context.Background(), env, nil)
	if !vr.Valid {
		t.Errorf("VerifyWithClock with nil clock: %s", vr.Reason)
	}
}

func TestVerifyWithClock_NotYetValid(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Set clock to 1 hour before PublishedAt.
	entry, _ := ParseEntry([]byte(env.RawPayload))
	now := entry.PublishedAt.Add(-1 * time.Hour)
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: now})
	if vr.Valid {
		t.Errorf("VerifyWithClock on not-yet-valid should fail")
	}
	if !strings.Contains(vr.Reason, "not yet valid") {
		t.Errorf("Reason = %q, expected 'not yet valid'", vr.Reason)
	}
}

func TestVerifyWithClock_Expired(t *testing.T) {
	// Set TTL > 0 to get a ValidUntil. The default
	// (TTL=0) means no expiration; this test forces
	// one.
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 1*time.Hour)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Set clock 2 hours after now (past ValidUntil).
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: time.Now().UTC().Add(2 * time.Hour)})
	if vr.Valid {
		t.Errorf("VerifyWithClock on expired should fail")
	}
	if !strings.Contains(vr.Reason, "expired") {
		t.Errorf("Reason = %q, expected 'expired'", vr.Reason)
	}
}

// =====================================================================
// Clock
// =====================================================================

func TestSystemClock_Now(t *testing.T) {
	before := time.Now().UTC()
	now := SystemClock{}.Now()
	after := time.Now().UTC()
	if now.Before(before) || now.After(after) {
		t.Errorf("SystemClock.Now() = %v, want between %v and %v", now, before, after)
	}
}

func TestSetDefaultClock(t *testing.T) {
	original := defaultClock
	defer SetDefaultClock(original)
	fc := frozenClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	SetDefaultClock(fc)
	if defaultClock != fc {
		t.Errorf("SetDefaultClock did not set defaultClock")
	}
	// Nil should not change.
	SetDefaultClock(nil)
	if defaultClock != fc {
		t.Errorf("SetDefaultClock(nil) should not change defaultClock")
	}
}

// =====================================================================
// Feed
// =====================================================================

func TestNewFeed(t *testing.T) {
	f := NewFeed()
	if f.Version != FeedVersion {
		t.Errorf("Version = %d, want %d", f.Version, FeedVersion)
	}
	if f.Len() != 0 {
		t.Errorf("Len = %d, want 0", f.Len())
	}
}

func TestFeed_AppendEntry(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	f := NewFeed()
	if err := f.AppendEntry(env); err != nil {
		t.Fatalf("AppendEntry: %v", err)
	}
	if f.Len() != 1 {
		t.Errorf("Len = %d, want 1", f.Len())
	}
}

func TestFeed_AppendNilEntry(t *testing.T) {
	f := NewFeed()
	if err := f.AppendEntry(nil); err == nil {
		t.Errorf("AppendEntry on nil should fail")
	}
}

func TestFeed_LatestByCVEID(t *testing.T) {
	kr := makeTestKeyRing(t)
	f := NewFeed()
	// Publish the entry, then a withdrawal of the same
	// entry. Latest should be the withdrawal.
	e1 := makeTestEntry(t)
	e1.PublishedAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	env1, _ := Publish(e1, kr, 0)
	f.AppendEntry(env1)

	e2 := makeTestEntry(t)
	e2.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	env2, _ := Publish(e2, kr, 0)
	f.AppendEntry(env2)

	// Latest should be env2 (later timestamp).
	latest := f.LatestByCVEID("AEGIS-2026-0001")
	if latest == nil {
		t.Fatalf("LatestByCVEID: got nil")
	}
	if latest != env2 {
		t.Errorf("LatestByCVEID: got env1, want env2 (later timestamp)")
	}
}

func TestFeed_LatestByCVEID_NoMatch(t *testing.T) {
	f := NewFeed()
	if got := f.LatestByCVEID("AEGIS-2026-9999"); got != nil {
		t.Errorf("LatestByCVEID on empty feed: got %v, want nil", got)
	}
}

func TestFeed_AllByCVEID(t *testing.T) {
	kr := makeTestKeyRing(t)
	f := NewFeed()
	e1 := makeTestEntry(t)
	e1.PublishedAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	env1, _ := Publish(e1, kr, 0)
	f.AppendEntry(env1)
	e2 := makeTestEntry(t)
	e2.PublishedAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	env2, _ := Publish(e2, kr, 0)
	f.AppendEntry(env2)

	all := f.AllByCVEID("AEGIS-2026-0001")
	if len(all) != 2 {
		t.Errorf("AllByCVEID: got %d entries, want 2", len(all))
	}
	// Sorted ascending by PublishedAt.
	if all[0] != env1 {
		t.Errorf("AllByCVEID[0] = env2, want env1 (earlier)")
	}
	if all[1] != env2 {
		t.Errorf("AllByCVEID[1] = env1, want env2 (later)")
	}
}

func TestFeed_AllByCVEID_NoMatch(t *testing.T) {
	f := NewFeed()
	if got := f.AllByCVEID("AEGIS-2026-9999"); got != nil {
		t.Errorf("AllByCVEID on empty feed: got %v, want nil", got)
	}
}

func TestFeed_WriteReadJSON(t *testing.T) {
	kr := makeTestKeyRing(t)
	f := NewFeed()
	e := makeTestEntry(t)
	env, _ := Publish(e, kr, 0)
	f.AppendEntry(env)

	// Write.
	data, err := f.WriteJSON()
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Read back.
	f2, err := ReadJSON(data)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if f2.Version != f.Version {
		t.Errorf("Version mismatch: got %d, want %d", f2.Version, f.Version)
	}
	if f2.Len() != f.Len() {
		t.Errorf("Len mismatch: got %d, want %d", f2.Len(), f.Len())
	}
}

func TestFeed_ReadJSON_BadVersion(t *testing.T) {
	data := []byte(`{"version": 999, "generated_at": "2026-06-18T00:00:00Z", "entries": []}`)
	if _, err := ReadJSON(data); err == nil {
		t.Errorf("ReadJSON on high version should fail")
	}
}

func TestFeed_WriteJSONFile_ReadJSONFile(t *testing.T) {
	kr := makeTestKeyRing(t)
	f := NewFeed()
	e := makeTestEntry(t)
	env, _ := Publish(e, kr, 0)
	f.AppendEntry(env)

	// Write to a temp file.
	tmp := filepath.Join(t.TempDir(), "feed.json")
	if err := f.WriteJSONFile(tmp); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	// Read back.
	f2, err := ReadJSONFile(tmp)
	if err != nil {
		t.Fatalf("ReadJSONFile: %v", err)
	}
	if f2.Len() != f.Len() {
		t.Errorf("Len mismatch: got %d, want %d", f2.Len(), f.Len())
	}
}

// =====================================================================
// helpers (extractCVEIDFromSubject, buildIssuer, isHexString, etc.)
// =====================================================================

func TestExtractCVEIDFromSubject(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"aegisgate://cve/AEGIS-2026-0001", "AEGIS-2026-0001"},
		{"aegisgate://cve/AEGIS-2026-9999999", "AEGIS-2026-9999999"},
		{"aegisgate://prompt/AEGIS-2026-0001", ""}, // wrong kind
		{"not-a-subject", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractCVEIDFromSubject(tc.subject)
		if got != tc.want {
			t.Errorf("extractCVEIDFromSubject(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
}

func TestBuildIssuer(t *testing.T) {
	e := makeTestEntry(t)
	issuer := buildIssuer(e, "k-test-123")
	want := "cve:shortfp:" + shortFingerprint("AegisGate Research") + ":k-test-123"
	if issuer != want {
		t.Errorf("buildIssuer = %q, want %q", issuer, want)
	}
}

func TestShortFingerprint(t *testing.T) {
	fp := shortFingerprint("test")
	if len(fp) != 16 {
		t.Errorf("shortFingerprint length = %d, want 16", len(fp))
	}
}

func TestShortFingerprint_Deterministic(t *testing.T) {
	fp1 := shortFingerprint("test")
	fp2 := shortFingerprint("test")
	if fp1 != fp2 {
		t.Errorf("shortFingerprint not deterministic")
	}
}

func TestIsHexString(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"abc", true},
		{"ABC", true},
		{"123", true},
		{"deadbeef", true},
		{"DEADBEEF", true},
		{"xyz", false},
		{"hello", false},
		{"abc!", false},
	}
	for _, tc := range cases {
		got := isHexString(tc.in)
		if got != tc.want {
			t.Errorf("isHexString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestHashSHA256Hex(t *testing.T) {
	// Known value: SHA-256("test") =
	// 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	want := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	got := _hashSHA256Hex([]byte("test"))
	if got != want {
		t.Errorf("_hashSHA256Hex = %q, want %q", got, want)
	}
}

func TestHexEncode(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0x00}, "00"},
		{[]byte{0xff}, "ff"},
		{[]byte{0xde, 0xad, 0xbe, 0xef}, "deadbeef"},
	}
	for _, tc := range cases {
		got := hexEncode(tc.in)
		if got != tc.want {
			t.Errorf("hexEncode(%x) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// =====================================================================
// applySignerOptions
// =====================================================================

func TestApplySignerOptions_Defaults(t *testing.T) {
	o := applySignerOptions(nil)
	if o.nowFn == nil {
		t.Errorf("nowFn should default to time.Now")
	}
}

func TestApplySignerOptions_Override(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	o := applySignerOptions([]SignerOption{
		WithSubjectKind("custom"),
		WithIssuer("custom:issuer"),
		WithKeyID("k-test"),
		WithPublishedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		withNowFn(now),
	})
	if o.subjectKind != "custom" {
		t.Errorf("subjectKind = %q, want 'custom'", o.subjectKind)
	}
	if o.issuer != "custom:issuer" {
		t.Errorf("issuer = %q, want 'custom:issuer'", o.issuer)
	}
	if o.keyID != "k-test" {
		t.Errorf("keyID = %q, want 'k-test'", o.keyID)
	}
	if o.nowFn() != now() {
		t.Errorf("nowFn() = %v, want %v", o.nowFn(), now())
	}
}

// =====================================================================
// ParseEntry
// =====================================================================

func TestParseEntry_HappyPath(t *testing.T) {
	e := makeTestEntry(t)
	js, _ := json.Marshal(e)
	got, err := ParseEntry(js)
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if got.ID != e.ID {
		t.Errorf("ID = %q, want %q", got.ID, e.ID)
	}
}

func TestParseEntry_InvalidJSON(t *testing.T) {
	_, err := ParseEntry([]byte("not json"))
	if err == nil {
		t.Errorf("ParseEntry on invalid JSON should fail")
	}
}

// =====================================================================
// Integration test: full roundtrip
// =====================================================================

func TestPublishVerify_FullRoundtrip(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Decode and re-encode the envelope to simulate
	// wire transmission.
	js, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	vr, err := VerifyJSON(context.Background(), js)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if !vr.Valid {
		t.Fatalf("VerifyJSON: %s", vr.Reason)
	}
	if vr.Entry.ID != "AEGIS-2026-0001" {
		t.Errorf("Entry.ID = %q, want 'AEGIS-2026-0001'", vr.Entry.ID)
	}
	if vr.IsWithdrawal {
		t.Errorf("IsWithdrawal = true, want false")
	}
}

// =====================================================================
// Sentinel error checks
// =====================================================================

func TestSentinelErrors(t *testing.T) {
	sentinels := map[string]error{
		"ErrCVEIDMismatch":     ErrCVEIDMismatch,
		"ErrCVEIssuerMismatch": ErrCVEIssuerMismatch,
		"ErrCVEExpired":        ErrCVEExpired,
	}
	for name, e := range sentinels {
		if e == nil {
			t.Errorf("%s is nil", name)
		}
		if !strings.HasPrefix(e.Error(), "cve:") {
			t.Errorf("%s = %q, want prefix 'cve:'", name, e.Error())
		}
	}
}

// =====================================================================
// Sample (example) entry: AEGIS-2026-0002
// =====================================================================

// TestSampleEntry_0002 exercises a second example entry
// (different ID, different vulnerability class) to make
// sure the schema is flexible enough to express
// multiple vulnerability types. This entry is
// illustrative; it is NOT a real disclosure.
func TestSampleEntry_0002(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := &CVEEntry{
		ID:           "AEGIS-2026-0002",
		Title:        "[EXAMPLE] Token-budget DoS via recursive summarization prompt",
		Description:  "EXAMPLE entry. An attacker can cause unbounded token usage by submitting a prompt that asks the model to recursively summarize its own output. This is a test fixture; not a real disclosure.",
		Affected:     []string{"openai/gpt-4-turbo@<2024-08-01"},
		Fixed:        []string{"openai/gpt-4-turbo@2024-08-01"},
		Score:        5.5,
		Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		References:   []string{"https://example.com/advisory/AEGIS-2026-0002"},
		Mitigations:  []string{"Apply a max-output-tokens limit at the application layer."},
		DiscoveredBy: "AegisGate Research",
		DisclosedAt:  time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
	}
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	vr := Verify(context.Background(), env)
	if !vr.Valid {
		t.Errorf("Verify on sample entry: %s", vr.Reason)
	}
	if vr.Entry.Score != 5.5 {
		t.Errorf("Score = %v, want 5.5", vr.Entry.Score)
	}
	if vr.Entry.Band != string(SeverityMedium) {
		t.Errorf("Band = %q, want %q", vr.Entry.Band, SeverityMedium)
	}
}

// =====================================================================
// Coverage gap tests (push from 87.4% to 90%+)
// =====================================================================

// TestFeed_NilReceiver covers the nil-receiver paths in
// the Feed methods (Len, LatestByCVEID, AllByCVEID).
func TestFeed_NilReceiver(t *testing.T) {
	var f *Feed
	if f.Len() != 0 {
		t.Errorf("nil feed Len = %d, want 0", f.Len())
	}
	if got := f.LatestByCVEID("AEGIS-2026-0001"); got != nil {
		t.Errorf("nil feed LatestByCVEID = %v, want nil", got)
	}
	if got := f.AllByCVEID("AEGIS-2026-0001"); got != nil {
		t.Errorf("nil feed AllByCVEID = %v, want nil", got)
	}
}

// TestFeed_AppendEntry_NilEntries covers the path where
// the Feed has a nil Entries slice (auto-initialize).
func TestFeed_AppendEntry_NilEntries(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, _ := Publish(e, kr, 0)
	f := &Feed{Version: FeedVersion} // Entries is nil
	if err := f.AppendEntry(env); err != nil {
		t.Fatalf("AppendEntry on nil Entries: %v", err)
	}
	if f.Entries == nil || len(f.Entries) != 1 {
		t.Errorf("Entries = %v, want length 1", f.Entries)
	}
}

// TestFeed_EntryTime_Error covers the error path in
// entryTime (malformed RawPayload).
func TestFeed_EntryTime_Error(t *testing.T) {
	// Build a feed with an envelope whose RawPayload is
	// not valid JSON.
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	env, _ := Publish(e, kr, 0)
	env.RawPayload = []byte("not json")
	f := NewFeed()
	f.AppendEntry(env)
	// AllByCVEID should skip the malformed entry.
	all := f.AllByCVEID("AEGIS-2026-0001")
	if all != nil {
		t.Errorf("AllByCVEID should skip malformed entry, got %d entries", len(all))
	}
	// LatestByCVEID should also skip it.
	latest := f.LatestByCVEID("AEGIS-2026-0001")
	if latest != nil {
		t.Errorf("LatestByCVEID should skip malformed entry, got %v", latest)
	}
}

// TestFeed_ReadJSON_DefaultVersion covers the path where
// Version is 0 or missing in the JSON.
func TestFeed_ReadJSON_DefaultVersion(t *testing.T) {
	data := []byte(`{"generated_at": "2026-06-18T00:00:00Z", "entries": []}`)
	f, err := ReadJSON(data)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if f.Version != FeedVersion {
		t.Errorf("Default Version = %d, want %d", f.Version, FeedVersion)
	}
}

// TestValidate_ReferenceTooLong covers the reference
// length check (not covered by TestValidate_BadReference).
func TestValidate_ReferenceTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.References = []string{strings.Repeat("a", MaxReferenceLen+1)}
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized reference should fail")
	}
}

// TestValidate_AffectedAndFixedLength covers the length
// checks for Affected and Fixed.
func TestValidate_AffectedAndFixedLength(t *testing.T) {
	e := makeTestEntry(t)
	e.Affected = []string{strings.Repeat("a", MaxAffectedLen+1)}
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized affected should fail")
	}
	e = makeTestEntry(t)
	e.Fixed = []string{strings.Repeat("a", MaxFixedLen+1)}
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized fixed should fail")
	}
}

// TestValidate_DiscoveredByTooLong covers the length
// check on DiscoveredBy.
func TestValidate_DiscoveredByTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.DiscoveredBy = strings.Repeat("a", MaxDiscoveredByLen+1)
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized discovered_by should fail")
	}
}

// TestValidate_VectorTooLong covers the length check
// on Vector.
func TestValidate_VectorTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.Vector = strings.Repeat("a", MaxVectorLen+1)
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized vector should fail")
	}
}

// TestValidate_MitigationTooLong covers the length
// check on Mitigations.
func TestValidate_MitigationTooLong(t *testing.T) {
	e := makeTestEntry(t)
	e.Mitigations = []string{strings.Repeat("a", MaxMitigationLen+1)}
	if err := e.Validate(); err == nil {
		t.Errorf("Validate on oversized mitigation should fail")
	}
}

// TestPublish_WithdrawalWithPublishedAt covers the
// path where a withdrawal ALSO has a PublishedAt (the
// auto-set from Publish).
func TestPublish_WithdrawalWithPublishedAt(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	e.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	entry, _ := ParseEntry([]byte(env.RawPayload))
	if !entry.IsWithdrawal() {
		t.Errorf("Withdrawal should have IsWithdrawal = true")
	}
	if entry.PublishedAt.IsZero() {
		t.Errorf("PublishedAt should be auto-set on withdrawal")
	}
}

// TestVerifyWithClock_ValidWithdrawal covers the path
// where the entry is a withdrawal (WithdrawnAt set).
// Withdrawals should still verify (they are valid
// entries).
func TestVerifyWithClock_ValidWithdrawal(t *testing.T) {
	kr := makeTestKeyRing(t)
	e := makeTestEntry(t)
	e.WithdrawnAt = time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	env, err := Publish(e, kr, 0)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Set clock to a time AFTER both the auto-set
	// PublishedAt and the WithdrawnAt. Use a
	// far-future fixed time so neither check fires.
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
	if !vr.Valid {
		t.Errorf("VerifyWithClock on valid withdrawal: %s", vr.Reason)
	}
	if !vr.IsWithdrawal {
		t.Errorf("VerifyResult.IsWithdrawal = false, want true")
	}
}
