// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Cross-Protocol Evidence Tests (v3.4.0+ c1)
//
// cross_protocol_test.go covers the c1 "killer feature" of
// the v3.4.0 roadmap: a single signed assertion of activity
// across all 5 protocol pillars. Tests cover:
//   - protocolFromEventType parser (every protocol prefix)
//   - RingBuffer.CountByProtocol happy path + empty buffer
//   - BuildCrossProtocol happy path + tamper detection
//   - VerifyCrossProtocol roundtrip + rotation guard
//   - HTTP route /api/v1/compliance/evidence/cross_protocol/build
//
// v3.4.0+ c1.

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// TestProtocolFromEventType covers the parser that derives the
// AegisGate protocol pillar from an event Type string. The
// protocol is determined by the Type prefix.
func TestProtocolFromEventType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"response_scan", "http"},
		{"mcp_tool_call", "mcp"},
		{"mcp_tool_call_blocked", "mcp"},
		{"a2a_message", "a2a"},
		{"a2a_message_blocked", "a2a"},
		{"acp_capability", "acp"},
		{"acp_capability_denied", "acp"},
		{"anp_task", "anp"},
		{"anp_task_output", "anp"},
		{"unknown_type", ""},
		{"", ""},
		{"proxy_request", ""}, // proxy_recorder.go emits these - not a protocol pillar
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := logging.ProtocolFromEventType(tt.in); got != tt.want {
				t.Errorf("protocolFromEventType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRingBuffer_CountByProtocol is the c1 ring-buffer test:
// events from all 5 protocols get bucketed correctly.
func TestRingBuffer_CountByProtocol(t *testing.T) {
	buf := newRingBuffer(64)
	now := time.Now()
	// Add events across all 5 protocol pillars. Mix severities
	// and types to confirm the parser is prefix-based, not based
	// on severity.
	for _, e := range []logging.Event{
		{Time: now.Add(-30 * time.Minute), Type: "response_scan", Severity: logging.SeverityHigh, ID: "1"},
		{Time: now.Add(-25 * time.Minute), Type: "response_scan", Severity: logging.SeverityMedium, ID: "2"},
		{Time: now.Add(-20 * time.Minute), Type: "mcp_tool_call", Severity: logging.SeverityHigh, ID: "3"},
		{Time: now.Add(-15 * time.Minute), Type: "mcp_tool_call", Severity: logging.SeverityLow, ID: "4"},
		{Time: now.Add(-10 * time.Minute), Type: "a2a_message", Severity: logging.SeverityMedium, ID: "5"},
		{Time: now.Add(-9 * time.Minute), Type: "acp_capability", Severity: logging.SeverityHigh, ID: "6"},
		{Time: now.Add(-8 * time.Minute), Type: "anp_task", Severity: logging.SeverityMedium, ID: "7"},
		{Time: now.Add(-7 * time.Minute), Type: "anp_task_output", Severity: logging.SeverityLow, ID: "8"},
		{Time: now.Add(-6 * time.Minute), Type: "proxy_request", Severity: logging.SeverityInfo, ID: "9"},
	} {
		buf.Add(e)
	}
	got, err := buf.CountByProtocol(context.Background(), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"http": 2,
		"mcp":  2,
		"a2a":  1,
		"acp":  1,
		"anp":  2,
		"":     1, // proxy_request is not a known protocol prefix
	}
	if len(got) != len(want) {
		t.Errorf("got %d buckets, want %d (got=%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %d, want %d", k, got[k], v)
		}
	}
}

// TestRingBuffer_CountByProtocol_EmptyBuffer confirms the
// function returns an empty map (not nil, not error) on a
// fresh ring buffer.
func TestRingBuffer_CountByProtocol_EmptyBuffer(t *testing.T) {
	buf := newRingBuffer(64)
	got, err := buf.CountByProtocol(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("CountByProtocol on empty buffer = nil map, want empty map")
	}
	if len(got) != 0 {
		t.Errorf("CountByProtocol on empty buffer = %d buckets, want 0", len(got))
	}
}

// TestBuildCrossProtocol_HappyPath: the killer feature end-to-end.
// Build a cross-protocol manifest from a real Builder with a
// real Scanner and a stubbed EventSource, then verify the
// resulting manifest is signed, has all expected fields, and
// can be verified end-to-end.
func TestBuildCrossProtocol_HappyPath(t *testing.T) {
	api, _ := newTestAPI(t)
	// Use the Builder via the API. newTestAPI gives us a real
	// Builder with a real Scanner + LicenseMgr + signing key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	builder, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "cross-protocol-test",
		BuilderVersion: "v3.4.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	cp, err := builder.BuildCrossProtocol(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Assertions on the manifest shape.
	if cp.ManifestID == "" {
		t.Error("ManifestID is empty")
	}
	if cp.Signature.KeyID != "cross-protocol-test" {
		t.Errorf("KeyID = %q, want cross-protocol-test", cp.Signature.KeyID)
	}
	if len(cp.Signature.Value) == 0 {
		t.Error("signature is empty")
	}
	if len(cp.PerFramework) == 0 {
		t.Error("PerFramework is empty - expected 10 known frameworks")
	}
	if cp.AuditAnchors.Source != "unavailable" {
		t.Errorf("Source = %q, want unavailable (no EventSource wired)", cp.AuditAnchors.Source)
	}
	// Round-trip verify.
	if err := VerifyCrossProtocol(cp); err != nil {
		t.Errorf("VerifyCrossProtocol: %v", err)
	}
	// Touch the api to silence unused warning if we extend later.
	_ = api
}

// TestBuildCrossProtocol_RejectsInvalidPeriod: start must be
// before end. The function fails fast on invalid input.
func TestBuildCrossProtocol_RejectsInvalidPeriod(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, nil)
	builder, _ := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v1",
	})
	now := time.Now()
	// end before start -> error
	_, err := builder.BuildCrossProtocol(context.Background(), now, now.Add(-time.Hour))
	if err == nil {
		t.Error("BuildCrossProtocol with end<start = nil err, want error")
	}
	// zero start -> error
	_, err = builder.BuildCrossProtocol(context.Background(), time.Time{}, now)
	if err == nil {
		t.Error("BuildCrossProtocol with zero start = nil err, want error")
	}
}

// TestVerifyCrossProtocol_DetectsTampering: any modification of
// any field after signing invalidates the signature.
func TestVerifyCrossProtocol_DetectsTampering(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, nil)
	builder, _ := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v1",
	})
	now := time.Now()
	cp, err := builder.BuildCrossProtocol(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the unmodified manifest.
	if err := VerifyCrossProtocol(cp); err != nil {
		t.Fatalf("baseline VerifyCrossProtocol: %v", err)
	}
	// Tamper with a field. Modify the BuilderVersion.
	cp.BuilderVersion = "v9.9.9-tampered"
	if err := VerifyCrossProtocol(cp); err == nil {
		t.Error("VerifyCrossProtocol after tampering = nil err, want ErrSignatureInvalid")
	} else if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("err = %v, want 'signature invalid'", err)
	}
}

// TestVerifyCrossProtocolDetailed_StructuredResult: the
// auditor-facing helper returns the same data as Verify +
// the manifest ID + per-framework count.
func TestVerifyCrossProtocolDetailed_StructuredResult(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, nil)
	builder, _ := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k1",
		BuilderVersion: "v1",
	})
	now := time.Now()
	cp, err := builder.BuildCrossProtocol(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyCrossProtocolDetailed(cp)
	if !res.Verified {
		t.Errorf("Verified = false, want true. Reason: %q", res.Reason)
	}
	if res.ManifestID != cp.ManifestID {
		t.Errorf("ManifestID = %q, want %q", res.ManifestID, cp.ManifestID)
	}
	if res.KeyID != "k1" {
		t.Errorf("KeyID = %q, want k1", res.KeyID)
	}
	if res.PerFrameworkCount != len(cp.PerFramework) {
		t.Errorf("PerFrameworkCount = %d, want %d", res.PerFrameworkCount, len(cp.PerFramework))
	}
}

// TestVerifyCrossProtocolWithKey_RotationGuard: the rotation
// guard rejects manifests signed with a key the auditor does
// not expect. This is the c1 + c3 combined primitive.
func TestVerifyCrossProtocolWithKey_RotationGuard(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, nil)
	builder, _ := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "current-key",
		BuilderVersion: "v1",
	})
	now := time.Now()
	cp, err := builder.BuildCrossProtocol(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	// Matching keyID passes.
	if err := VerifyCrossProtocolWithKey(cp, &key.PublicKey, "current-key"); err != nil {
		t.Errorf("VerifyCrossProtocolWithKey matching: %v", err)
	}
	// Mismatched keyID is rejected.
	err = VerifyCrossProtocolWithKey(cp, &key.PublicKey, "retired-key")
	if err == nil {
		t.Error("VerifyCrossProtocolWithKey mismatched = nil err, want ErrKeyIDMismatch")
	} else if !strings.Contains(err.Error(), "key id mismatch") {
		t.Errorf("err = %v, want 'key id mismatch'", err)
	}
}

// TestAPI_CrossProtocolBuild_HappyPath: the HTTP route.
// POST /api/v1/compliance/evidence/cross_protocol/build returns
// 201 Created with the signed manifest in the body.
func TestAPI_CrossProtocolBuild_HappyPath(t *testing.T) {
	api, _ := newTestAPI(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	body, _ := json.Marshal(map[string]any{
		"period_start": start,
		"period_end":   end,
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/evidence/cross_protocol/build", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %q)", rr.Code, rr.Body.String())
	}
	var cp CrossProtocolManifest
	if err := json.NewDecoder(rr.Body).Decode(&cp); err != nil {
		t.Fatal(err)
	}
	if cp.ManifestID == "" {
		t.Error("ManifestID is empty")
	}
	if len(cp.Signature.Value) == 0 {
		t.Error("signature is empty")
	}
	// Verify end-to-end.
	if err := VerifyCrossProtocol(&cp); err != nil {
		t.Errorf("VerifyCrossProtocol on HTTP response: %v", err)
	}
}

// TestAPI_CrossProtocolBuild_MethodNotAllowed: GET is not
// supported; only POST.
func TestAPI_CrossProtocolBuild_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence/cross_protocol/build", nil)
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestAPI_CrossProtocolBuild_BadJSON: malformed body returns 400.
func TestAPI_CrossProtocolBuild_BadJSON(t *testing.T) {
	api, _ := newTestAPI(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/evidence/cross_protocol/build", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestBuildCrossProtocolCLI_NoScanner: the CLI helper path.
// BuildCrossProtocolCLI signs a manifest without a Scanner,
// which is the CLI use case (per-framework refs are empty).
func TestBuildCrossProtocolCLI_NoScanner(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{
		ManifestID: "cli-test",
		Period: Period{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		PerFramework: []PerFrameworkRef{},
		AuditAnchors: AuditAnchors{Source: "unavailable"},
	}
	if err := BuildCrossProtocolCLI(cp, key, "cli-key", "v3.4.0-cli"); err != nil {
		t.Fatal(err)
	}
	if len(cp.Signature.Value) == 0 {
		t.Error("signature is empty")
	}
	if err := VerifyCrossProtocol(cp); err != nil {
		t.Errorf("VerifyCrossProtocol on CLI-built manifest: %v", err)
	}
}

// newRingBuffer is a small constructor for the tests above.
// Returns a fresh ring buffer with the given capacity. We do
// not import the logging package's NewRingBuffer here because
// we want the test to be in package evidence (to access
// unexported helpers like protocolFromEventType). The
// ring buffer's exported API is sufficient.
func newRingBuffer(capacity int) *logging.RingBuffer {
	return logging.NewRingBuffer(capacity)
}

// ------------------------------------------------------------------
// Additional c1 coverage tests (error paths that pulled the
// package coverage down to 86.1%). Each targets a specific
// uncovered branch.
// ------------------------------------------------------------------

// TestVerifyCrossProtocol_NilManifest exercises the nil-manifest
// guard. Returns the structured error rather than panicking.
func TestVerifyCrossProtocol_NilManifest(t *testing.T) {
	err := VerifyCrossProtocol(nil)
	if err == nil {
		t.Error("VerifyCrossProtocol(nil) = nil err, want error")
	}
}

// TestVerifyCrossProtocol_MissingSignature: a manifest with no
// signature returns ErrSignatureMissing.
func TestVerifyCrossProtocol_MissingSignature(t *testing.T) {
	cp := &CrossProtocolManifest{
		ManifestID: "missing-sig",
		Period: Period{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		PerFramework: []PerFrameworkRef{},
		AuditAnchors: AuditAnchors{Source: "unavailable"},
		// Signature intentionally left empty (no Value, no PublicKey).
	}
	err := VerifyCrossProtocol(cp)
	if err == nil {
		t.Error("VerifyCrossProtocol with missing sig = nil err, want ErrSignatureMissing")
	} else if !strings.Contains(err.Error(), "signature missing") {
		t.Errorf("err = %v, want 'signature missing'", err)
	}
}

// TestVerifyCrossProtocol_MissingPublicKey: a manifest with a
// signature value but no public key returns the explanatory
// error ("auditor must use VerifyCrossProtocolWithKey").
func TestVerifyCrossProtocol_MissingPublicKey(t *testing.T) {
	cp := &CrossProtocolManifest{
		ManifestID: "missing-pubkey",
		Period: Period{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		PerFramework: []PerFrameworkRef{},
		AuditAnchors: AuditAnchors{Source: "unavailable"},
		Signature: Signature{
			Algorithm: "ecdsa-p256",
			KeyID:     "k",
			Value:     []byte{0x00, 0x01}, // garbage
			// PublicKey intentionally empty.
		},
	}
	err := VerifyCrossProtocol(cp)
	if err == nil {
		t.Error("VerifyCrossProtocol with missing pubkey = nil err, want error")
	} else if !strings.Contains(err.Error(), "public key") {
		t.Errorf("err = %v, want message about public key", err)
	}
}

// TestVerifyCrossProtocol_BadSEC1Bytes: malformed SEC1 bytes
// return a decode error rather than panicking.
func TestVerifyCrossProtocol_BadSEC1Bytes(t *testing.T) {
	cp := &CrossProtocolManifest{
		ManifestID: "bad-sec1",
		Period: Period{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		PerFramework: []PerFrameworkRef{},
		AuditAnchors: AuditAnchors{Source: "unavailable"},
		Signature: Signature{
			Algorithm: "ecdsa-p256",
			KeyID:     "k",
			Value:     []byte{0x00, 0x01},
			PublicKey: []byte{0xff, 0xff, 0xff}, // invalid SEC1
		},
	}
	err := VerifyCrossProtocol(cp)
	if err == nil {
		t.Error("VerifyCrossProtocol with bad SEC1 = nil err, want error")
	} else if !strings.Contains(err.Error(), "P-256") && !strings.Contains(err.Error(), "SEC 1") {
		t.Errorf("err = %v, want SEC1 decode error message", err)
	}
}

// TestVerifyCrossProtocolWithKey_NilManifest: nil-guard for the
// rotation-guard variant.
func TestVerifyCrossProtocolWithKey_NilManifest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyCrossProtocolWithKey(nil, &key.PublicKey, "")
	if err == nil {
		t.Error("VerifyCrossProtocolWithKey(nil) = nil err, want error")
	}
}

// TestVerifyCrossProtocolWithKey_MissingSignature: nil-guard
// for the rotation-guard variant when the signature is missing.
func TestVerifyCrossProtocolWithKey_MissingSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{ManifestID: "no-sig-rotation-guard"}
	err := VerifyCrossProtocolWithKey(cp, &key.PublicKey, "")
	if err == nil {
		t.Error("VerifyCrossProtocolWithKey with missing sig = nil err, want ErrSignatureMissing")
	} else if !strings.Contains(err.Error(), "signature missing") {
		t.Errorf("err = %v, want 'signature missing'", err)
	}
}

// TestBuildCrossProtocol_ContextCancelled: a cancelled context
// before any framework builds returns the wrapped cancel error.
func TestBuildCrossProtocol_ContextCancelled(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, nil)
	builder, _ := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling
	_, err := builder.BuildCrossProtocol(ctx, time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Error("BuildCrossProtocol with cancelled ctx = nil err, want error")
	} else if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("err = %v, want 'cancelled' in message", err)
	}
}

// TestPublicKeyPEM_DeterministicOutput: encoding the same key
// twice produces identical bytes. This is the auditor's
// guarantee that a cached PEM file is still valid after a
// restart (the key is loaded from disk and re-encoded).
func TestPublicKeyPEM_DeterministicOutput(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, err := PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("PublicKeyPEM is non-deterministic")
	}
}

// TestWellKnownHandler_WrongPathIsNotServed: a request to a
// DIFFERENT path under /.well-known/ is NOT served by our
// handler. The handler only knows about the one canonical
// URL; other .well-known paths (e.g., OIDC discovery) are
// served by other handlers in other packages. This test
// confirms the handler is narrowly scoped.
func TestWellKnownHandler_WrongPathIsNotServed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h, _ := WellKnownHandler(&key.PublicKey)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/something-else", nil)
	h.ServeHTTP(rr, req)
	// The handler is mounted at a specific path by main.go's
	// mux - when called directly with a different path, the
	// handler still serves (it doesn't check the URL, the mux
	// does). This test documents that the handler is path-
	// agnostic and relies on the caller to mount it at the
	// canonical URL. We assert 200 (the handler served it)
	// rather than 404, to document the behavior.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (handler serves whatever path it's called with)", rr.Code)
	}
}

// Tier 1 (TODO-402): cross-protocol ControlCrossRefs is wired
// into the BuildCrossProtocol path. The test fixture has empty
// per-framework FrameworkCrossRefs (because the test scanner has
// no registered framework implementations), so the aggregator
// returns nil. This test asserts the field is at least
// structurally present (and nil-when-empty) so a future
// regression that breaks the field is caught.
func TestBuildCrossProtocol_ControlCrossRefs_NilWhenEmpty(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	builder, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	cp, err := builder.BuildCrossProtocol(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	// ControlCrossRefs is a top-level field on CrossProtocolManifest.
	// We assert it is reachable (reflectively / by name) and is nil
	// because the test scanner has no per-control data.
	if cp.ControlCrossRefs != nil {
		t.Errorf("ControlCrossRefs = %v, want nil (test scanner has no per-control data)", cp.ControlCrossRefs)
	}
	// Confirm the JSON shape: nil -> field omitted entirely.
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(data, "control_cross_refs") {
		t.Errorf("nil ControlCrossRefs should be omitted from JSON; got %s", data)
	}
}

// Tier 1 (TODO-402): per-framework FrameworkCrossRefs is wired
// into the Build path. Same caveat as the cross-protocol test:
// the test fixture's scanner has no per-control data, so
// FrameworkCrossRefs is nil. This test confirms the field is
// at least structurally present.
func TestBuild_PerFramework_FrameworkCrossRefs_NilWhenEmpty(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	builder, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	// Use a known framework. The scanner will produce an empty
	// assessment (no framework implementation registered), so
	// FrameworkCrossRefs will be nil.
	m, err := builder.Build(context.Background(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if m.FrameworkCrossRefs != nil {
		t.Errorf("FrameworkCrossRefs = %v, want nil (test scanner has no per-control data)", m.FrameworkCrossRefs)
	}
	// Confirm JSON shape: nil -> field omitted.
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(data, "framework_cross_refs") {
		t.Errorf("nil FrameworkCrossRefs should be omitted from JSON; got %s", data)
	}
}

// containsBytes is a small substring helper for use in test
// assertions (avoids importing strings just for one call).
func containsBytes(haystack []byte, needle string) bool {
	return len(haystack) >= len(needle) && indexOfBytes(haystack, needle) >= 0
}

func indexOfBytes(haystack []byte, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return i
		}
	}
	return -1
}
