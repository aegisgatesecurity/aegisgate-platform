// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.4.0+)
//
// pubkey_test.go covers the verifiable compliance primitive
// (c3 in the v3.4.0 roadmap): the canonical public key fetch
// and the rotation-guard query param on the verify endpoint.
//
// v3.4.0+.

package evidence
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B. See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPublicKeyPEM_RoundTrip confirms the PEM encoding can be
// decoded back to the same public key. This is the auditor's
// core guarantee: fetch PEM, decode, verify manifest, no
// surprises.
func TestPublicKeyPEM_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	if !strings.Contains(string(pemBytes), "BEGIN PUBLIC KEY") {
		t.Errorf("PEM missing BEGIN block: %q", string(pemBytes))
	}
	if !strings.Contains(string(pemBytes), "END PUBLIC KEY") {
		t.Errorf("PEM missing END block: %q", string(pemBytes))
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	if block.Type != pubKeyPEMType {
		t.Errorf("PEM block type = %q, want %q", block.Type, pubKeyPEMType)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("parsed key is %T, want *ecdsa.PublicKey", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", ecPub.Curve.Params().Name)
	}
	if ecPub.X.Cmp(key.PublicKey.X) != 0 || ecPub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("decoded public key does not match original")
	}
}

// TestPublicKeyPEM_NilKey returns an error rather than panicking.
// Important for the WellKnownHandler failure path.
func TestPublicKeyPEM_NilKey(t *testing.T) {
	_, err := PublicKeyPEM(nil)
	if err == nil {
		t.Error("PublicKeyPEM(nil) = nil err, want error")
	}
}

// TestPublicKeyPEM_WrongCurve returns an error for non-P256 keys.
// The platform only signs with P-256, so a non-P-256 key in the
// public-key endpoint would be a configuration bug.
func TestPublicKeyPEM_WrongCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PublicKeyPEM(&key.PublicKey)
	if err == nil {
		t.Error("PublicKeyPEM(P-384) = nil err, want error")
	}
}

// TestWellKnownHandler_HappyPath is the auditor's primary path:
// fetch the well-known URL, get a valid PEM, decode to a public
// key, verify a manifest against it.
func TestWellKnownHandler_HappyPath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := WellKnownHandler(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/aegisgate-evidence-pubkey.pem", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/x-pem-file") {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control header missing")
	}
	// Decode the response and confirm it's a valid public key
	// that matches the original.
	block, _ := pem.Decode(rr.Body.Bytes())
	if block == nil {
		t.Fatal("response body is not a valid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub := pub.(*ecdsa.PublicKey)
	if ecPub.X.Cmp(key.PublicKey.X) != 0 || ecPub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("well-known public key does not match original")
	}
}

// TestWellKnownHandler_HEAD does not write a body but does
// return 200 with the Content-Type header. Useful for auditors
// who want to check existence without transferring the key.
func TestWellKnownHandler_HEAD(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := WellKnownHandler(&key.PublicKey)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/.well-known/aegisgate-evidence-pubkey.pem", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD response body length = %d, want 0", rr.Body.Len())
	}
	if rr.Header().Get("Content-Type") == "" {
		t.Error("HEAD response missing Content-Type header")
	}
}

// TestWellKnownHandler_MethodNotAllowed returns 405 for POST etc.
// The well-known URL is read-only.
func TestWellKnownHandler_MethodNotAllowed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h, _ := WellKnownHandler(&key.PublicKey)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/.well-known/aegisgate-evidence-pubkey.pem", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestWellKnownHandler_NilKey returns an error at construction
// (fail-closed) rather than a handler that 500s on every call.
func TestWellKnownHandler_NilKey(t *testing.T) {
	_, err := WellKnownHandler(nil)
	if err == nil {
		t.Error("WellKnownHandler(nil) = nil err, want error")
	}
}

// TestWellKnownHandler_FullAuditorFlow is the end-to-end auditor
// workflow: build a manifest with the test key, fetch the
// well-known public key, use it to verify the manifest via
// VerifyWithKey. This is the primitive the entire c3 deliverable
// exists to enable.
func TestWellKnownHandler_FullAuditorFlow(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Build and sign a manifest with this key.
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	gen, _ := time.Parse(time.RFC3339, "2026-04-01T00:00:00Z")
	m := &Manifest{
		ManifestID: "auditor-flow-test",
		Framework:  "hipaa",
		Period: Period{
			Start: start,
			End:   end,
		},
		GeneratedAt: gen,
	}
	if err := signManifestForTest(m, key, "test-key-1"); err != nil {
		t.Fatal(err)
	}
	// Fetch the public key from the well-known handler.
	h, _ := WellKnownHandler(&key.PublicKey)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/aegisgate-evidence-pubkey.pem", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("well-known fetch failed: status=%d body=%q", rr.Code, rr.Body.String())
	}
	block, _ := pem.Decode(rr.Body.Bytes())
	if block == nil {
		t.Fatal("PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := pub.(*ecdsa.PublicKey)
	// Verify the manifest with the fetched key + matching keyID.
	if err := VerifyWithKey(m, ecPub, "test-key-1"); err != nil {
		t.Errorf("VerifyWithKey (matching keyID): %v", err)
	}
	// Now try with a wrong expected keyID - the rotation guard
	// should reject it with ErrKeyIDMismatch.
	err = VerifyWithKey(m, ecPub, "wrong-key")
	if err == nil {
		t.Error("VerifyWithKey with wrong expected key ID = nil err, want ErrKeyIDMismatch")
	} else if !strings.Contains(err.Error(), "key id mismatch") {
		t.Errorf("err = %v, want it to contain 'key id mismatch'", err)
	}
}

// TestAPI_Verify_ExpectedKeyID_Match exercises the new
// ?expected_key_id= query param on the verify endpoint: when
// the manifest's signature keyID matches, verified=true.
func TestAPI_Verify_ExpectedKeyID_Match(t *testing.T) {
	api, store := newTestAPI(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	gen, _ := time.Parse(time.RFC3339, "2026-04-01T00:00:00Z")
	m := &Manifest{
		ManifestID:  "rotation-guard-match",
		Framework:   "hipaa",
		Period:      Period{Start: start, End: end},
		GeneratedAt: gen,
	}
	if err := signManifestForTest(m, key, "current-key"); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := makeRequest(http.MethodGet, "/api/v1/compliance/evidence/"+m.ManifestID+"/verify?expected_key_id=current-key", "")
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	var res VerifyResult
	if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Errorf("Verified = false, want true (keyID matches). Reason: %q", res.Reason)
	}
}

// TestAPI_Verify_ExpectedKeyID_Mismatch exercises the rotation
// guard: when the auditor pins an expected keyID that does
// NOT match the manifest's signature keyID, verified=false
// with reason "key id mismatch".
func TestAPI_Verify_ExpectedKeyID_Mismatch(t *testing.T) {
	api, store := newTestAPI(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	gen, _ := time.Parse(time.RFC3339, "2026-04-01T00:00:00Z")
	m := &Manifest{
		ManifestID:  "rotation-guard-mismatch",
		Framework:   "hipaa",
		Period:      Period{Start: start, End: end},
		GeneratedAt: gen,
	}
	if err := signManifestForTest(m, key, "current-key"); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := makeRequest(http.MethodGet, "/api/v1/compliance/evidence/"+m.ManifestID+"/verify?expected_key_id=retired-key", "")
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (we always return 200 with a reason)", rr.Code)
	}
	var res VerifyResult
	if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Error("Verified = true, want false (rotation guard should reject retired key)")
	}
	if !strings.Contains(res.Reason, "key id mismatch") {
		t.Errorf("Reason = %q, want it to contain 'key id mismatch'", res.Reason)
	}
}

// TestAPI_Verify_NoExpectedKeyID exercises the existing behavior
// (no rotation guard) - the verify endpoint should still work
// without ?expected_key_id=, as before. Backward-compat check.
func TestAPI_Verify_NoExpectedKeyID(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID: "no-rotation-guard",
		Framework:  "hipaa",
		Period: Period{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		GeneratedAt: time.Now().UTC(),
	}
	signTestManifest(t, m)
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := makeRequest(http.MethodGet, "/api/v1/compliance/evidence/"+m.ManifestID+"/verify", "")
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var res VerifyResult
	if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Errorf("Verified = false, want true (no rotation guard). Reason: %q", res.Reason)
	}
}

// signManifestForTest signs a manifest with the given key and
// keyID. Mirrors the algorithm in builder.go (signManifest) so
// the auditor test exercises the same wire format the platform
// produces. This is duplicated in pubkey_test.go (only) because
// the existing signTestManifest helper hardcodes keyID="test-key".
func signManifestForTest(m *Manifest, key *ecdsa.PrivateKey, keyID string) error {
	m.Signature = Signature{}
	canonical, err := canonicalJSON(m)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return err
	}
	//nolint:staticcheck // SA1019: SEC 1 encoding for backward compat with v3.3.0
	pubBytes := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	m.Signature = Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     keyID,
		Value:     sig,
		PublicKey: pubBytes,
		SignedAt:  m.GeneratedAt,
	}
	return nil
}
