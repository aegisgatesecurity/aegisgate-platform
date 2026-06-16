// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing tests (TODO-303)
//
// sign_test.go covers Sign + Verify: roundtrip, expired
// intent, tampered intent, cross-agent replay, and the
// various option combinations.

package agentintentsign

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

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

// makeTestTuple returns a valid IntentTuple for tests.
func makeTestTuple() *IntentTuple {
	now := time.Now().UTC()
	return &IntentTuple{
		AgentID:       "agent:test-agent@v1.0.0",
		Intent:        "Read the user's calendar for tomorrow",
		Justification: "User asked me to summarize their meetings",
		IssuedAt:      now,
		ValidUntil:    now.Add(1 * time.Hour),
	}
}

// --------------------------------------------------------------------
// Validate tests
// --------------------------------------------------------------------

func TestValidate_Valid(t *testing.T) {
	tup := makeTestTuple()
	if err := tup.Validate(); err != nil {
		t.Errorf("valid tuple: %v", err)
	}
}

func TestValidate_MissingAgentID(t *testing.T) {
	tup := makeTestTuple()
	tup.AgentID = ""
	if err := tup.Validate(); err == nil {
		t.Error("missing agent_id: expected error")
	}
}

func TestValidate_MissingIntent(t *testing.T) {
	tup := makeTestTuple()
	tup.Intent = ""
	if err := tup.Validate(); err == nil {
		t.Error("missing intent: expected error")
	}
}

func TestValidate_MissingJustification(t *testing.T) {
	tup := makeTestTuple()
	tup.Justification = ""
	if err := tup.Validate(); err == nil {
		t.Error("missing justification: expected error")
	}
}

func TestValidate_MissingValidUntil(t *testing.T) {
	tup := makeTestTuple()
	tup.ValidUntil = time.Time{}
	if err := tup.Validate(); err == nil {
		t.Error("missing valid_until: expected error")
	}
}

func TestValidate_AgentIDTooLong(t *testing.T) {
	tup := makeTestTuple()
	tup.AgentID = strings.Repeat("a", MaxAgentIDLen+1)
	if err := tup.Validate(); err == nil {
		t.Error("agent_id too long: expected error")
	}
}

func TestValidate_IntentTooLong(t *testing.T) {
	tup := makeTestTuple()
	tup.Intent = strings.Repeat("x", MaxIntentLen+1)
	if err := tup.Validate(); err == nil {
		t.Error("intent too long: expected error")
	}
}

func TestValidate_JustificationTooLong(t *testing.T) {
	tup := makeTestTuple()
	tup.Justification = strings.Repeat("y", MaxJustificationLen+1)
	if err := tup.Validate(); err == nil {
		t.Error("justification too long: expected error")
	}
}

func TestValidate_AgentIDMalformed(t *testing.T) {
	cases := []string{
		"agent with spaces",
		"agent\twith\ttabs",
		"agent\nwith\nnewlines",
		"agent;semi",
		"agent&",
	}
	for _, agentID := range cases {
		tup := makeTestTuple()
		tup.AgentID = agentID
		if err := tup.Validate(); err == nil {
			t.Errorf("agent_id %q: expected error", agentID)
		}
	}
}

func TestValidate_AgentIDValid(t *testing.T) {
	cases := []string{
		"agent:test@v1",
		"agent:test-agent",
		"model:openai/gpt-4",
		"agent.acme_corp",
		"v1.2.3",
	}
	for _, agentID := range cases {
		tup := makeTestTuple()
		tup.AgentID = agentID
		if err := tup.Validate(); err != nil {
			t.Errorf("agent_id %q: unexpected error %v", agentID, err)
		}
	}
}

func TestValidate_NilTuple(t *testing.T) {
	var tup *IntentTuple
	if err := tup.Validate(); err == nil {
		t.Error("nil tuple: expected error")
	}
}

// --------------------------------------------------------------------
// Sign tests
// --------------------------------------------------------------------

func TestSign_NilTuple(t *testing.T) {
	kr := makeTestKeyRing(t)
	if _, err := Sign(nil, kr); err == nil {
		t.Error("nil tuple: expected error")
	}
}

func TestSign_NilKeyRing(t *testing.T) {
	tup := makeTestTuple()
	if _, err := Sign(tup, nil); err == nil {
		t.Error("nil keyring: expected error")
	}
}

func TestSign_HappyPath(t *testing.T) {
	tup := makeTestTuple()
	tup.IntentID = "test-intent-001" // explicit for assertion
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Type != attestation.TypeAgentIntent {
		t.Errorf("type: got %q, want %q", env.Type, attestation.TypeAgentIntent)
	}
	if env.Subject != "aegisgate://intent/test-intent-001" {
		t.Errorf("subject: got %q, want aegisgate://intent/test-intent-001", env.Subject)
	}
	if env.Issuer == "" {
		t.Error("issuer is empty")
	}
	if env.ValidUntil.IsZero() {
		t.Error("ValidUntil is zero (TTL not applied)")
	}
	// Verify via attestation.Verify.
	if err := attestation.Verify(env); err != nil {
		t.Errorf("attestation.Verify: %v", err)
	}
}

func TestSign_IntentIDAutoGenerated(t *testing.T) {
	tup := makeTestTuple()
	tup.IntentID = "" // should be auto-generated
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Subject == "aegisgate://intent/" {
		t.Errorf("subject: %q, expected UUIDv4 suffix", env.Subject)
	}
	if !strings.HasPrefix(env.Subject, "aegisgate://intent/") || len(env.Subject) <= len("aegisgate://intent/") {
		t.Errorf("subject missing UUIDv4: %q", env.Subject)
	}
}

func TestSign_IssuedAtAutoGenerated(t *testing.T) {
	tup := makeTestTuple()
	tup.IssuedAt = time.Time{}
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Decode the tuple and check IssuedAt.
	tuple, _ := ParseTuple([]byte(env.RawPayload))
	if tuple.IssuedAt.IsZero() {
		t.Error("IssuedAt not auto-generated")
	}
}

func TestSign_ValidUntilAutoComputed(t *testing.T) {
	tup := makeTestTuple()
	tup.ValidUntil = time.Time{}
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tuple, _ := ParseTuple([]byte(env.RawPayload))
	if tuple.ValidUntil.IsZero() {
		t.Error("ValidUntil not auto-computed")
	}
	if !tuple.ValidUntil.After(time.Now().UTC()) {
		t.Error("ValidUntil is not in the future")
	}
}

func TestSign_ExpiredIntentRejected(t *testing.T) {
	tup := makeTestTuple()
	// Set ValidUntil to a time in the past.
	tup.ValidUntil = time.Now().UTC().Add(-1 * time.Hour)
	kr := makeTestKeyRing(t)
	if _, err := Sign(tup, kr); err == nil {
		t.Error("expired intent: expected error")
	}
}

func TestSign_TTLClampedToMax(t *testing.T) {
	tup := makeTestTuple()
	tup.ValidUntil = time.Time{} // let signer compute
	kr := makeTestKeyRing(t)
	// Way over MaxIntentTTL (24h).
	env, err := Sign(tup, kr, WithTTL(100*24*time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tuple, _ := ParseTuple([]byte(env.RawPayload))
	// ValidUntil should be ~24h from now, not 100 days.
	delta := tuple.ValidUntil.Sub(time.Now().UTC())
	if delta > 25*time.Hour {
		t.Errorf("ValidUntil: delta %v, want ~24h (clamped to MaxIntentTTL)", delta)
	}
}

func TestSign_TTLNonPositive(t *testing.T) {
	tup := makeTestTuple()
	tup.ValidUntil = time.Time{}
	kr := makeTestKeyRing(t)
	// Negative TTL should be treated as "use default".
	env, err := Sign(tup, kr, WithTTL(-1*time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tuple, _ := ParseTuple([]byte(env.RawPayload))
	delta := tuple.ValidUntil.Sub(time.Now().UTC())
	if delta < 30*time.Minute || delta > 2*time.Hour {
		t.Errorf("ValidUntil: delta %v, want ~1h (default)", delta)
	}
}

func TestSign_WithCustomOptions(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr,
		WithIntentID("test-intent-001"),
		WithContext("session-abc"),
		WithKeyID("k-custom"),
		WithTTL(30*time.Minute),
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Subject != "aegisgate://intent/test-intent-001" {
		t.Errorf("subject: got %q", env.Subject)
	}
	if !strings.Contains(env.Issuer, ":k-custom") {
		t.Errorf("issuer: got %q, want :k-custom suffix", env.Issuer)
	}
	tuple, _ := ParseTuple([]byte(env.RawPayload))
	if tuple.Context != "session-abc" {
		t.Errorf("context: got %q, want session-abc", tuple.Context)
	}
}

func TestSign_WithCustomIssuerAndKeyID(t *testing.T) {
	// C1 fix (TODO-302): when both WithIssuer and WithKeyID
	// are supplied, the keyID is appended.
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr,
		WithIssuer("custom:issuer:here"),
		WithKeyID("k-test123"),
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Issuer != "custom:issuer:here:k-test123" {
		t.Errorf("issuer: got %q, want %q", env.Issuer, "custom:issuer:here:k-test123")
	}
}

func TestSign_IssuerFormat(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Expected format: a2a-intent:shortfp:<16-hex>:<key-id>:<agent-id-sanitized>
	// The agent_id is the last component, sanitized to
	// replace colons with underscores.
	sanitizedAgent := sanitizeForIssuer(tup.AgentID)
	if !strings.HasSuffix(env.Issuer, ":"+sanitizedAgent) {
		t.Errorf("issuer: %q does not end with %q", env.Issuer, sanitizedAgent)
	}
	// 5 colon-delimited components (a2a-intent, shortfp, 16hex, keyid, agent_id).
	parts := strings.SplitN(env.Issuer, ":", 5)
	if len(parts) != 5 {
		t.Errorf("issuer: %d parts, want 5", len(parts))
	}
	if parts[0] != "a2a-intent" {
		t.Errorf("issuer: got prefix %q, want a2a-intent", parts[0])
	}
	if parts[1] != "shortfp" {
		t.Errorf("issuer: got %q, want shortfp", parts[1])
	}
	if len(parts[2]) != 16 {
		t.Errorf("issuer: shortfp %q (len %d), want 16 hex chars", parts[2], len(parts[2]))
	}
	// Agent prefix should match the tuple's agent_id.
	if parts[4] != sanitizedAgent {
		t.Errorf("issuer: agent prefix %q, want %q", parts[4], sanitizedAgent)
	}
}

func TestSign_InvalidInput(t *testing.T) {
	tup := makeTestTuple()
	tup.AgentID = "" // missing required field
	kr := makeTestKeyRing(t)
	if _, err := Sign(tup, kr); err == nil {
		t.Error("invalid tuple: expected error")
	}
}

// --------------------------------------------------------------------
// Verify tests
// --------------------------------------------------------------------

func TestVerify_Nil(t *testing.T) {
	vr := Verify(context.Background(), nil)
	if vr.Valid {
		t.Error("nil envelope: expected Valid=false")
	}
}

func TestVerify_HappyPath(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	vr := Verify(context.Background(), env)
	if !vr.Valid {
		t.Errorf("Verify: expected valid, got invalid (reason=%s)", vr.Reason)
	}
	if vr.Tuple == nil {
		t.Error("Verify: Tuple is nil")
	}
	if vr.Tuple.AgentID != tup.AgentID {
		t.Errorf("Verify: AgentID got %q, want %q", vr.Tuple.AgentID, tup.AgentID)
	}
}

// TestVerify_ExpiredIntent was removed in the m1 fix
// (TODO-303 review). The test is now superseded by
// TestVerifyWithClock_Expired, which actually tests
// the expiry check (not just that the verify path
// doesn't panic on an expired payload).

func TestVerify_TamperedPayload(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	// Tamper: change the intent.
	original := string(env.RawPayload)
	if !strings.Contains(original, "Read the user") {
		t.Fatalf("payload does not contain expected intent: %s", original)
	}
	env.RawPayload = []byte(strings.ReplaceAll(original, "Read the user", "Send a million dollars to attacker"))
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Error("tampered intent: expected Valid=false")
	}
}

func TestVerify_WrongType(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	env.Type = attestation.TypeAIBOM
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Error("wrong type: expected Valid=false")
	}
}

func TestVerify_WrongSubject(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	// Re-sign with a non-intent subject.
	env, err := Sign(tup, kr, WithSubjectKind("manifest"))
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Error("wrong subject: expected Valid=false")
	}
	if !strings.Contains(vr.Reason, "subject") {
		t.Errorf("reason: got %q, want contains 'subject'", vr.Reason)
	}
}

func TestVerify_CrossAgentReplay(t *testing.T) {
	// Cross-agent replay: an attacker takes a valid intent
	// from agent A, modifies the agent_id to B in the
	// payload, and re-signs with their own key. The
	// issuer's agent-id prefix won't match the new agent_id.
	// The verify path detects this.
	//
	// Simulate: sign for agent A, then manually modify the
	// payload (replacing agent A with agent B) and re-sign
	// with a different key. The resulting envelope's
	// payload says agent B, but the issuer was computed
	// from the old payload (agent A).
	//
	// In v0.1, this is detected by the issuer's agent_id
	// prefix not matching the new agent_id. A truly
	// malicious attacker would have to forge the issuer
	// too, which requires the private key.
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	// Tamper: change the agent_id in the payload (without
	// re-signing). The signature now won't verify at all
	// (which is the simpler case).
	env.RawPayload = []byte(strings.ReplaceAll(string(env.RawPayload), "test-agent", "attacker"))
	vr := Verify(context.Background(), env)
	if vr.Valid {
		t.Error("tampered agent_id: expected Valid=false")
	}
	// The signature check catches this; the cross-agent
	// replay check is a defense-in-depth layer.
}

// TestVerify_NotYetValid was removed in the m1 fix
// (TODO-303 review). The test is now superseded by
// TestVerifyWithClock_NotYetValid, which actually tests
// the not-yet-valid check (not just that the verify
// path doesn't panic on a tampered payload).

func TestVerify_RoundtripJSON(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	// Roundtrip through JSON.
	js, _ := jsonMarshal(env)
	vr, err := VerifyJSON(context.Background(), js)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if !vr.Valid {
		t.Errorf("VerifyJSON: expected valid, got invalid (reason=%s)", vr.Reason)
	}
}

func TestVerify_InvalidJSON(t *testing.T) {
	if _, err := VerifyJSON(context.Background(), []byte("not json")); err == nil {
		t.Error("non-JSON: expected error")
	}
}

// --------------------------------------------------------------------
// ParseTuple tests
// --------------------------------------------------------------------

func TestParseTuple_HappyPath(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	parsed, err := ParseTuple([]byte(env.RawPayload))
	if err != nil {
		t.Fatalf("ParseTuple: %v", err)
	}
	if parsed.AgentID != tup.AgentID {
		t.Errorf("roundtrip: AgentID got %q, want %q", parsed.AgentID, tup.AgentID)
	}
}

func TestParseTuple_InvalidJSON(t *testing.T) {
	if _, err := ParseTuple([]byte("not json")); err == nil {
		t.Error("non-JSON: expected error")
	}
}

// --------------------------------------------------------------------
// buildIssuer / shortFingerprint / sanitizeForIssuer tests
// --------------------------------------------------------------------

func TestBuildIssuer(t *testing.T) {
	tup := makeTestTuple()
	issuer := buildIssuer(tup, "k-test")
	// The full sanitized agent_id is at the end of the issuer.
	sanitizedAgent := sanitizeForIssuer(tup.AgentID)
	if !strings.HasSuffix(issuer, ":"+sanitizedAgent) {
		t.Errorf("issuer: %q does not end with %q", issuer, sanitizedAgent)
	}
	// 5 colon-delimited components (a2a-intent, shortfp, 16hex, keyid, agent_id).
	parts := strings.SplitN(issuer, ":", 5)
	if len(parts) != 5 {
		t.Errorf("issuer: %d parts, want 5", len(parts))
	}
	if parts[0] != "a2a-intent" {
		t.Errorf("issuer prefix: got %q, want a2a-intent", parts[0])
	}
}

func TestBuildIssuer_ColonsInAgentID(t *testing.T) {
	// Agent IDs with colons (e.g., "agent:test@v1") must
	// be sanitized (colons -> underscores) for the issuer
	// format to be unambiguous. The tail-match compare
	// handles this correctly.
	tup := makeTestTuple()
	tup.AgentID = "agent:test-agent@v1.0.0"
	issuer := buildIssuer(tup, "k-test")
	// The issuer must NOT contain the raw colons from the
	// agent_id (they would break the format). The
	// sanitized form replaces colons with underscores.
	expected := "agent_test-agent@v1.0.0"
	if !strings.HasSuffix(issuer, ":"+expected) {
		t.Errorf("issuer: %q does not end with %q", issuer, expected)
	}
}

func TestShortFingerprint(t *testing.T) {
	fp := shortFingerprint("test")
	if len(fp) != 16 {
		t.Errorf("shortFingerprint: len %d, want 16", len(fp))
	}
	// Same input -> same output.
	if fp != shortFingerprint("test") {
		t.Error("shortFingerprint: not deterministic")
	}
	// Different input -> different output.
	if fp == shortFingerprint("test2") {
		t.Error("shortFingerprint: collision")
	}
}

func TestSanitizeForIssuer(t *testing.T) {
	cases := map[string]string{
		"hello":        "hello",
		"hello:world":  "hello_world",
		"hello\nworld": "hello world",
		"hello\rworld": "hello world",
	}
	for input, want := range cases {
		if got := sanitizeForIssuer(input); got != want {
			t.Errorf("sanitizeForIssuer(%q): got %q, want %q", input, got, want)
		}
	}
}

// --------------------------------------------------------------------
// issuerMatchesAgent tests
// --------------------------------------------------------------------

func TestIssuerMatchesAgent_HappyPath(t *testing.T) {
	tup := makeTestTuple()
	issuer := buildIssuer(tup, "k-test")
	if !issuerMatchesAgent(issuer, tup.AgentID) {
		t.Error("issuer should match agent")
	}
}

func TestIssuerMatchesAgent_Mismatch(t *testing.T) {
	tup := makeTestTuple()
	issuer := buildIssuer(tup, "k-test")
	if issuerMatchesAgent(issuer, "agent:different@v1.0.0") {
		t.Error("issuer should NOT match different agent")
	}
}

func TestIssuerMatchesAgent_MalformedIssuer(t *testing.T) {
	if issuerMatchesAgent("not:enough:parts", "agent:test") {
		t.Error("malformed issuer: expected no-match")
	}
}

// C2 fix tests: validate that issuerMatchesAgent catches
// non-hex shortfp and empty key_id.
func TestIssuerMatchesAgent_NonHexShortfp(t *testing.T) {
	// Construct an issuer with 16 non-hex chars in the
	// shortfp position. The check should reject it.
	issuer := "a2a-intent:shortfp:zzzzzzzzzzzzzzzz:k-test:agent_test"
	if issuerMatchesAgent(issuer, "agent_test") {
		t.Error("non-hex shortfp: expected no-match")
	}
}

func TestIssuerMatchesAgent_ShortShortfp(t *testing.T) {
	// Shortfp shorter than 16 chars.
	issuer := "a2a-intent:shortfp:abc123:k-test:agent_test"
	if issuerMatchesAgent(issuer, "agent_test") {
		t.Error("short shortfp: expected no-match")
	}
}

func TestIssuerMatchesAgent_EmptyKeyID(t *testing.T) {
	// Empty key_id (colons with nothing between).
	issuer := "a2a-intent:shortfp:abcdef1234567890::agent_test"
	if issuerMatchesAgent(issuer, "agent_test") {
		t.Error("empty key_id: expected no-match")
	}
}

func TestIsHexString(t *testing.T) {
	cases := map[string]bool{
		"":             false, // empty
		"abc":          true,
		"ABC":          true,
		"123":          true,
		"abcdef123456": true,
		"ABCDEF123456": true,
		"ghij":         false, // non-hex letters
		"abc!":         false, // punctuation
		"abc def":      false, // space
		"abc\ndef":     false, // newline
	}
	for input, want := range cases {
		if got := isHexString(input); got != want {
			t.Errorf("isHexString(%q): got %v, want %v", input, got, want)
		}
	}
}

// --------------------------------------------------------------------
// applySignerOptions tests
// --------------------------------------------------------------------

func TestApplySignerOptions_Defaults(t *testing.T) {
	o := applySignerOptions(nil)
	if o.ttl != DefaultIntentTTL {
		t.Errorf("default TTL: got %v, want %v", o.ttl, DefaultIntentTTL)
	}
}

func TestApplySignerOptions_ClampHigh(t *testing.T) {
	o := applySignerOptions([]SignerOption{WithTTL(100 * 24 * time.Hour)})
	if o.ttl != MaxIntentTTL {
		t.Errorf("over-cap TTL: got %v, want %v (clamped)", o.ttl, MaxIntentTTL)
	}
}

func TestApplySignerOptions_NonPositive(t *testing.T) {
	o := applySignerOptions([]SignerOption{WithTTL(-1 * time.Hour)})
	if o.ttl != DefaultIntentTTL {
		t.Errorf("non-positive TTL: got %v, want default %v", o.ttl, DefaultIntentTTL)
	}
}

func TestApplySignerOptions_Override(t *testing.T) {
	o := applySignerOptions([]SignerOption{
		WithSubjectKind("custom"),
		WithIssuer("custom:issuer"),
		WithKeyID("k-foo"),
		WithContext("ctx"),
		WithIntentID("iid"),
		WithIssuedAt(time.Unix(100, 0)),
	})
	if o.subjectKind != "custom" || o.issuer != "custom:issuer" || o.keyID != "k-foo" ||
		o.context != "ctx" || o.intentID != "iid" || !o.issuedAt.Equal(time.Unix(100, 0)) {
		t.Errorf("overrides: %+v", o)
	}
}

// --------------------------------------------------------------------
// VerifyWithClock tests (m1 fix)
// --------------------------------------------------------------------

// frozenClock is a Clock that returns a fixed time. Used
// to test the verify-side expiry and not-yet-valid checks
// without sleeping.
type frozenClock struct {
	t time.Time
}

func (f frozenClock) Now() time.Time { return f.t }

func TestVerifyWithClock_Expired(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Use a clock 2 hours in the future; the intent
	// (valid for 1 hour from now) is now expired.
	future := time.Now().UTC().Add(2 * time.Hour)
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: future})
	if vr.Valid {
		t.Error("expired intent (with frozen clock): expected Valid=false")
	}
	if !strings.Contains(vr.Reason, "expired") {
		t.Errorf("reason: got %q, want contains 'expired'", vr.Reason)
	}
}

func TestVerifyWithClock_NotYetValid(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, err := Sign(tup, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Use a clock 2 hours in the past; the intent's
	// IssuedAt is in the future relative to the clock.
	past := time.Now().UTC().Add(-2 * time.Hour)
	vr := VerifyWithClock(context.Background(), env, frozenClock{t: past})
	if vr.Valid {
		t.Error("not-yet-valid intent (with frozen clock): expected Valid=false")
	}
	if !strings.Contains(vr.Reason, "not yet valid") {
		t.Errorf("reason: got %q, want contains 'not yet valid'", vr.Reason)
	}
}

func TestVerifyWithClock_NilClock(t *testing.T) {
	// A nil clock should fall back to SystemClock
	// (defensive: tests that pass nil don't panic).
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	vr := VerifyWithClock(context.Background(), env, nil)
	if !vr.Valid {
		t.Errorf("nil clock with valid envelope: expected valid, got invalid (reason=%s)", vr.Reason)
	}
}

func TestSystemClock_Now(t *testing.T) {
	before := time.Now().UTC()
	got := SystemClock{}.Now()
	after := time.Now().UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("SystemClock.Now() = %v, want between %v and %v", got, before, after)
	}
}

func TestSetDefaultClock(t *testing.T) {
	// Save and restore the default clock.
	saved := defaultClock
	defer func() { defaultClock = saved }()
	// Set a frozen clock.
	frozen := frozenClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	SetDefaultClock(frozen)
	// Verify it took effect.
	if defaultClock.Now() != frozen.Now() {
		t.Error("SetDefaultClock: default clock not updated")
	}
	// Setting nil is a no-op (defensive).
	SetDefaultClock(nil)
	if defaultClock.Now() != frozen.Now() {
		t.Error("SetDefaultClock(nil): default clock was changed")
	}
}

// --------------------------------------------------------------------
// VerifyResult.ToJSON test
// --------------------------------------------------------------------

func TestVerifyResult_ToJSON(t *testing.T) {
	tup := makeTestTuple()
	kr := makeTestKeyRing(t)
	env, _ := Sign(tup, kr)
	vr := Verify(context.Background(), env)
	out := vr.ToJSON()
	if !out.Valid {
		t.Errorf("ToJSON: Valid=false (reason=%s)", vr.Reason)
	}
	if out.Type != string(attestation.TypeAgentIntent) {
		t.Errorf("ToJSON: type got %q", out.Type)
	}
	if out.Subject == "" {
		t.Error("ToJSON: subject is empty")
	}
	if out.IntentID == "" {
		t.Error("ToJSON: intent_id is empty")
	}
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

func jsonMarshal(v interface{}) ([]byte, error) {
	return jsonMarshalImpl(v)
}
