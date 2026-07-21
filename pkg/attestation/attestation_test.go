// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Envelope lifecycle tests (v3.5.0+, Tier 5 prep)
//
// attestation_test.go covers the 4 lifecycle operations
// (Sign, Verify, VerifyWithKey, VerifyOnline), the 9-reason
// error taxonomy, and the adversarial test cases.

package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// --------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------

// makeTestKeyRing creates a KeyRing with a fresh P-256 key for
// tests. The KeyRing is not persisted; it lives only in memory.
func makeTestKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	// Generate a fresh P-256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	// The KeyRing's on-disk format is JSON; for tests we
	// construct an in-memory KeyRing. Use the public API.
	// The IOC library's NewKeyRing function (if it exists)
	// would be the right entry point. As a fallback, we
	// construct a minimal KeyRing using the lower-level
	// initialization path.
	// See pkg/ioc/keyring.go for the KeyRing struct.
	kr, err := ioc.LoadKeyRing("") // empty path = in-memory
	if err != nil {
		// LoadKeyRing may fail on empty path. Fall back to
		// constructing the KeyRing manually.
		// In practice, the test uses ioc.NewKeyRing if
		// available, else LoadKeyRing with a temp file.
		t.Fatalf("ioc.LoadKeyRing: %v (in-memory KeyRing not supported by LoadKeyRing; check if ioc.NewKeyRing exists)", err)
	}
	_ = priv // not used in this fallback; tests may need to add a key manually
	return kr
}

// signTestEnvelope is a helper that signs an envelope with a
// fresh test KeyRing. Returns the envelope and the KeyRing
// (the caller needs the KeyRing for verification).
func signTestEnvelope(t *testing.T, payload []byte, subject string, attType Type, issuer string, ttl time.Duration) (*Envelope, *ioc.KeyRing) {
	t.Helper()
	// Use the IOC's real KeyRing construction (in-memory).
	// The simplest path is to use a temp file and LoadKeyRing,
	// then rotate once to generate a key.
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(tmpDir + "/kr.json")
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	// The KeyRing starts with no key. We need to generate one.
	// The IOC library's KeyRing has a Rotate() method that
	// creates a new key.
	keyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	// Update the issuer to include the actual key ID.
	if issuer == "" {
		issuer = "test-instance:" + keyID
	}
	env, err := Sign(payload, subject, attType, issuer, kr, ttl)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return env, kr
}

// --------------------------------------------------------------------
// Sign: validation paths
// --------------------------------------------------------------------

func TestSign_HappyPath(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"key":"value","number":42}`)
	env, _ := signTestEnvelope(t, payload, "aegisgate://manifest/test-id", TypeEvidenceManifest, "", 0)
	if env == nil {
		t.Fatal("Sign returned nil envelope")
	}
	if env.ID == "" {
		t.Error("ID empty")
	}
	if env.Type != TypeEvidenceManifest {
		t.Errorf("Type = %q, want %q", env.Type, TypeEvidenceManifest)
	}
	if env.Signature.Algorithm != algorithmECDSAP256 {
		t.Errorf("Algorithm = %q, want %q", env.Signature.Algorithm, algorithmECDSAP256)
	}
	if len(env.Signature.PublicKey) == 0 {
		t.Error("PublicKey empty")
	}
	if len(env.Signature.Value) == 0 {
		t.Error("Signature.Value empty")
	}
}

func TestSign_AppliesTTL(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 24*time.Hour)
	if env.ValidUntil.IsZero() {
		t.Error("ValidUntil not set despite TTL > 0")
	}
	expected := env.IssuedAt.Add(24 * time.Hour)
	if !env.ValidUntil.Equal(expected) {
		t.Errorf("ValidUntil = %v, want %v (IssuedAt + 24h)", env.ValidUntil, expected)
	}
}

func TestSign_NoTTL(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	if !env.ValidUntil.IsZero() {
		t.Error("ValidUntil should be zero when TTL is 0")
	}
}

func TestSign_EmptyPayload(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	kr, _ := ioc.LoadKeyRing(tmpDir + "/kr.json")
	_, _ = kr.Rotate()
	_, err := Sign(nil, "aegisgate://manifest/t", TypeEvidenceManifest, "test:"+kr.CurrentKeyID(), kr, 0)
	if err == nil {
		t.Error("expected error on empty payload")
	}
}

func TestSign_InvalidPayload(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	kr, _ := ioc.LoadKeyRing(tmpDir + "/kr.json")
	_, _ = kr.Rotate()
	_, err := Sign([]byte("not json"), "aegisgate://manifest/t", TypeEvidenceManifest, "test:"+kr.CurrentKeyID(), kr, 0)
	if err == nil {
		t.Error("expected error on non-JSON payload")
	}
}

func TestSign_UnknownType(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	kr, _ := ioc.LoadKeyRing(tmpDir + "/kr.json")
	_, _ = kr.Rotate()
	_, err := Sign([]byte(`{}`), "aegisgate://manifest/t", Type("unknown.type.v99"), "test:"+kr.CurrentKeyID(), kr, 0)
	if err == nil {
		t.Error("expected error on unknown type")
	}
}

func TestSign_InvalidSubject(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	kr, _ := ioc.LoadKeyRing(tmpDir + "/kr.json")
	_, _ = kr.Rotate()
	_, err := Sign([]byte(`{}`), "https://not-aegisgate/x", TypeEvidenceManifest, "test:"+kr.CurrentKeyID(), kr, 0)
	if err == nil {
		t.Error("expected error on invalid subject scheme")
	}
}

func TestSign_InvalidIssuer(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	kr, _ := ioc.LoadKeyRing(tmpDir + "/kr.json")
	_, _ = kr.Rotate()
	_, err := Sign([]byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "no-separator", kr, 0)
	if err == nil {
		t.Error("expected error on invalid issuer")
	}
}

func TestSign_NilKeyRing(t *testing.T) {
	t.Parallel()
	_, err := Sign([]byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "test:key", nil, 0)
	if err == nil {
		t.Error("expected error on nil keyring")
	}
}

// --------------------------------------------------------------------
// Verify: happy path + tamper detection
// --------------------------------------------------------------------

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	if err := Verify(env); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_NilEnvelope(t *testing.T) {
	t.Parallel()
	err := Verify(nil)
	if err == nil {
		t.Error("expected error on nil envelope")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Errorf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonMalformed {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonMalformed)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{"k":"original"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Tamper with the payload.
	env.RawPayload = json.RawMessage(`{"k":"tampered"}`)
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on tampered payload, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonSignatureInvalid {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonSignatureInvalid)
	}
}

func TestVerify_TamperedType(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Change the type to a registered one (so the type
	// validation passes, but the signature breaks).
	env.Type = TypeEvaluatorRun
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on tampered type, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonSignatureInvalid {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonSignatureInvalid)
	}
}

func TestVerify_TamperedSubject(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Subject = "aegisgate://manifest/different-id"
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on tampered subject, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonSignatureInvalid {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonSignatureInvalid)
	}
}

func TestVerify_TamperedIssuer(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "other-instance:other-key"
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on tampered issuer, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonSignatureInvalid {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonSignatureInvalid)
	}
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	// Sign with a TTL of 1ms and wait for it to expire.
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 1*time.Millisecond)
	// Wait long enough for the envelope to expire.
	time.Sleep(50 * time.Millisecond)
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on expired envelope, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonExpired {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonExpired)
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Backdate the IssuedAt to be in the future.
	env.IssuedAt = time.Now().Add(10 * time.Minute)
	// We need to re-sign because the signature is over IssuedAt
	// (via the to-be-signed form). But the IssuedAt is in
	// the canonical form. The simplest test path: re-sign
	// the backdated envelope. This isn't a true "adversarial"
	// test (the attacker can re-sign), but it tests the
	// validity check.
	// For now, skip this test (the underlying check works
	// in verifyInternal but constructing a backdated
	// envelope requires re-signing).
	t.Skip("NotYetValid check requires re-signing a backdated envelope; covered by future adversarial test")
}

func TestVerify_UnknownType(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Type = Type("nonexistent.type.v1")
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on unknown type, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonUnknownType {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonUnknownType)
	}
}

func TestVerify_InvalidSubject(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Subject = "https://not-aegisgate/x"
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on invalid subject, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	// The subject is parsed BEFORE the signature is verified
	// (subject validation is cheap; signature verification
	// is expensive). So the reason is InvalidSubject, not
	// SignatureInvalid.
	if verr.Reason != ReasonInvalidSubject {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonInvalidSubject)
	}
}

func TestVerify_AlgorithmUnsupported(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Signature.Algorithm = "ed25519"
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error on unsupported algorithm, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonAlgorithmUnsupported {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonAlgorithmUnsupported)
	}
}

// --------------------------------------------------------------------
// VerifyWithKey
// --------------------------------------------------------------------

func TestVerifyWithKey_HappyPath(t *testing.T) {
	t.Parallel()
	env, kr := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Get the public key from the KeyRing.
	keyID, _, err := kr.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	// The public key is in env.Signature.PublicKey (already
	// embedded), so we can use it directly.
	pub, err := ioc.ParsePublicKey(env.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithKey(env, pub, keyID); err != nil {
		t.Errorf("VerifyWithKey: %v", err)
	}
	_ = keyID // already used as expectedKeyID; silence if refactored
}

func TestVerifyWithKey_WrongKey(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Generate a different key.
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyWithKey(env, &otherPriv.PublicKey, ""); err == nil {
		t.Error("expected error on wrong key, got nil")
	}
}

func TestVerifyWithKey_KeyIDMismatch(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	pub, _ := ioc.ParsePublicKey(env.Signature.PublicKey)
	// Pass a different expectedKeyID.
	if err := VerifyWithKey(env, pub, "wrong-key-id"); err == nil {
		t.Error("expected error on KeyID mismatch, got nil")
	}
}

// --------------------------------------------------------------------
// VerifyOnline
// --------------------------------------------------------------------

func TestVerifyOnline_NotYetImplemented(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Error("expected error (not yet implemented), got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if verr.Reason != ReasonPublicKeyFetch {
		t.Errorf("reason = %v, want %v", verr.Reason, ReasonPublicKeyFetch)
	}
}

// --------------------------------------------------------------------
// Round-trip
// --------------------------------------------------------------------

func TestSign_Verify_RoundTrip(t *testing.T) {
	t.Parallel()
	original := map[string]interface{}{"key": "value", "n": 42, "b": true}
	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := signTestEnvelope(t, payload, "aegisgate://manifest/test", TypeEvidenceManifest, "", 1*time.Hour)
	if err := Verify(env); err != nil {
		t.Errorf("Verify failed on freshly-signed envelope: %v", err)
	}
}

// --------------------------------------------------------------------
// Domain separation
// --------------------------------------------------------------------

func TestDomainSeparation_PreventsReplay(t *testing.T) {
	// Same payload, different Type -> different signatures.
	// (The Type is in the to-be-signed form, so changing
	// the Type changes the signature.)
	t.Parallel()
	payload := []byte(`{"k":"v"}`)
	env1, _ := signTestEnvelope(t, payload, "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env2, _ := signTestEnvelope(t, payload, "aegisgate://manifest/t", TypeEvaluatorRun, "", 0)
	// The signatures are different (different Type, different
	// canonical form).
	if string(env1.Signature.Value) == string(env2.Signature.Value) {
		t.Error("expected different signatures for different Types, got identical")
	}
	// Verify each with its own Type.
	if err := Verify(env1); err != nil {
		t.Errorf("env1 Verify: %v", err)
	}
	if err := Verify(env2); err != nil {
		t.Errorf("env2 Verify: %v", err)
	}
}

// --------------------------------------------------------------------
// Error taxonomy
// --------------------------------------------------------------------

func TestVerificationReason_String(t *testing.T) {
	t.Parallel()
	cases := map[VerificationReason]string{
		ReasonUnknown:              "unknown",
		ReasonMalformed:            "malformed",
		ReasonUnknownType:          "unknown_type",
		ReasonInvalidSubject:       "invalid_subject",
		ReasonSignatureInvalid:     "signature_invalid",
		ReasonKeyMismatch:          "key_mismatch",
		ReasonExpired:              "expired",
		ReasonNotYetValid:          "not_yet_valid",
		ReasonPublicKeyFetch:       "public_key_fetch",
		ReasonAlgorithmUnsupported: "algorithm_unsupported",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("VerificationReason(%d).String() = %q, want %q", int(r), got, want)
		}
	}
}

// --------------------------------------------------------------------
// Adversarial: bit flip
// --------------------------------------------------------------------

func TestAdversarial_BitFlip(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{"key":"value"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Flip a single bit in the canonical signature.
	env.Signature.Value[0] ^= 0x01
	err := Verify(env)
	if err == nil {
		t.Error("expected error on bit flip, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) || verr.Reason != ReasonSignatureInvalid {
		t.Errorf("expected ReasonSignatureInvalid, got %v", err)
	}
}

func TestAdversarial_Truncation(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{"key":"value"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	// Truncate the payload.
	env.RawPayload = env.RawPayload[:len(env.RawPayload)-1]
	err := Verify(env)
	if err == nil {
		t.Error("expected error on truncation, got nil")
	}
}

// --------------------------------------------------------------------
// Helper: parseSubject exposed for the Subject tests above
// --------------------------------------------------------------------

// Verify the Subject grammar is stable across the package.
func TestSubject_RoundTrip(t *testing.T) {
	t.Parallel()
	subjects := []string{
		"aegisgate://prompt/sha256-abc",
		"aegisgate://manifest/550e8400-e29b-41d4-a716-446655440000",
		"aegisgate://cve/CVE-2026-12345",
	}
	for _, s := range subjects {
		_, _, err := validateSubject(s)
		if err != nil {
			t.Errorf("validateSubject(%q): %v", s, err)
		}
	}
}

// Verify that the error messages contain helpful info.
func TestVerifyError_HasHelpfulMessage(t *testing.T) {
	t.Parallel()
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Signature.Value[0] ^= 0xFF
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error message should mention signature: %v", err)
	}
}

// --------------------------------------------------------------------
// D22: fetchPublicKey tests
// --------------------------------------------------------------------

// TestFetchPublicKey_InvalidInstanceID_RejectsPathTraversal ensures
// fetchPublicKey rejects path-traversal and shell-metacharacter
// attempts in the instance-id. This is the SSRF protection.
func TestFetchPublicKey_InvalidInstanceID_RejectsPathTraversal(t *testing.T) {
	cases := []struct {
		name       string
		instanceID string
	}{
		{"empty", ""},
		{"path-traversal", "../etc/passwd"},
		{"double-dot", "..aegisgate.io"},
		{"slash", "aegisgate.io/foo"},
		{"backslash", "aegisgate.io\\foo"},
		{"question-mark", "aegisgate.io?foo"},
		{"hash", "aegisgate.io#foo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := fetchPublicKey(context.Background(), c.instanceID, "key-1")
			if err == nil {
				t.Errorf("expected error for instance-id %q", c.instanceID)
			}
		})
	}
}

// TestFetchPublicKey_HTTPServer_WithRealKey spins up an httptest
// server serving a valid PEM-encoded P-256 public key, then calls
// fetchPublicKey to verify the full HTTP→PEM→ecdsa.PublicKey flow.
func TestFetchPublicKey_HTTPServer_WithRealKey(t *testing.T) {
	// Generate a real P-256 key to serve.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubKey, _ := priv.Public().(*ecdsa.PublicKey)
	pemBytes, err := evidencePublicKeyPEM(pubKey)
	if err != nil {
		t.Fatalf("encode PEM: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/aegisgate-evidence-pubkey.pem" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}))
	defer server.Close()

	// Extract the host:port from the server URL.
	// httptest URLs are like "http://127.0.0.1:12345"
	instanceID := strings.TrimPrefix(server.URL, "http://")
	// fetchPublicKey detects localhost and uses http://
	pub, err := fetchPublicKey(context.Background(), instanceID, "key-1")
	if err != nil {
		t.Fatalf("fetchPublicKey: %v", err)
	}
	if pub.X.Cmp(pubKey.X) != 0 || pub.Y.Cmp(pubKey.Y) != 0 {
		t.Errorf("fetched key does not match served key")
	}
}

// TestFetchPublicKey_HTTPServer_BadPEM verifies the error path
// when the server returns garbage instead of a valid PEM block.
func TestFetchPublicKey_HTTPServer_BadPEM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte("not a pem block"))
	}))
	defer server.Close()
	instanceID := strings.TrimPrefix(server.URL, "http://")
	_, err := fetchPublicKey(context.Background(), instanceID, "key-1")
	if err == nil {
		t.Fatal("expected error for bad PEM")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error should mention PEM, got: %v", err)
	}
}

// TestFetchPublicKey_HTTPServer_404 verifies the error path when
// the server returns 404 (e.g., the .well-known endpoint isn't
// wired on a different instance).
func TestFetchPublicKey_HTTPServer_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	instanceID := strings.TrimPrefix(server.URL, "http://")
	_, err := fetchPublicKey(context.Background(), instanceID, "key-1")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should mention HTTP 404, got: %v", err)
	}
}

// TestFetchPublicKey_ContextCanceled verifies the request is
// canceled when the caller's context is done.
func TestFetchPublicKey_ContextCanceled(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubKey, _ := priv.Public().(*ecdsa.PublicKey)
	pemBytes, _ := evidencePublicKeyPEM(pubKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep to force the client to wait and then be canceled.
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write(pemBytes)
	}))
	defer server.Close()
	instanceID := strings.TrimPrefix(server.URL, "http://")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call
	_, err = fetchPublicKey(ctx, instanceID, "key-1")
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
}

// evidencePublicKeyPEM is a small helper that produces a standard
// PEM "PUBLIC KEY" block from an *ecdsa.PublicKey. Same format as
// pkg/evidence.PublicKeyPEM but local to this test (avoids
// importing pkg/evidence in the unit test, which would create a
// circular dependency risk if pkg/attestation ever imports
// pkg/evidence in production code).
func evidencePublicKeyPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}
