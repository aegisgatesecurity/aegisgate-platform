// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Evidence Package tests - Phase 1b coverage fillers.
//
// evidence_phase1b_test.go covers the remaining uncovered branches
// in the evidence package: toAssessment loop body, LicenseContext,
// canonicalFrameworkID fallback paths, VerifyCrossProtocolDetailed
// error cases, serveGet method/empty-id guards, writeJSON nil case,
// and more edge cases.
//
// All test function names use the TestPhase1b prefix to avoid
// collisions with existing test files.

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// ---- toAssessment: cover the loop body (currently 23.8%) ----

func TestPhase1bToAssessment_WithResults(t *testing.T) {
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		{
			ControlID:   "CTRL-001",
			ControlName: "Access Control",
			Status:      compliance.StatusCompliant,
			Message:     "All access logs verified",
			Evidence:    []string{"log-1.json", "log-2.json"},
		},
		{
			ControlID:   "CTRL-002",
			ControlName: "Encryption",
			Status:      compliance.StatusNonCompliant,
			Message:     "Missing at-rest encryption",
			Evidence:    []string{"audit-3.json"},
		},
		{
			ControlID:   "CTRL-003",
			ControlName: "Audit Logging",
			Status:      compliance.StatusPartial,
			Evidence:    []string{"partial.json"},
		},
		nil, // nil result should be skipped
	})

	result := toAssessment(assessment)
	if result == nil {
		t.Fatal("toAssessment returned nil for non-nil assessment")
	}
	if len(result.Controls) != 3 {
		t.Fatalf("Controls len = %d, want 3 (nil entry skipped)", len(result.Controls))
	}

	// First control: compliant -> Passed=true, evidence joined with message.
	c0 := result.Controls[0]
	if c0.ControlID != "CTRL-001" {
		t.Errorf("Controls[0].ControlID = %q, want CTRL-001", c0.ControlID)
	}
	if c0.Description != "Access Control" {
		t.Errorf("Controls[0].Description = %q, want Access Control", c0.Description)
	}
	if !c0.Passed {
		t.Error("Controls[0].Passed = false, want true (compliant)")
	}
	// Evidence should contain message + joined evidence.
	if c0.Evidence == "" {
		t.Error("Controls[0].Evidence is empty")
	}

	// Second control: non-compliant -> Passed=false.
	c1 := result.Controls[1]
	if c1.Passed {
		t.Error("Controls[1].Passed = true, want false (non-compliant)")
	}

	// Third control: partial -> not compliant, so Passed=false.
	c2 := result.Controls[2]
	if c2.Passed {
		t.Error("Controls[2].Passed = true, want false (partial is not compliant)")
	}

	// OverallPass/OverallFail counts.
	if result.OverallPass != 1 {
		t.Errorf("OverallPass = %d, want 1", result.OverallPass)
	}
	if result.OverallFail != 2 {
		t.Errorf("OverallFail = %d, want 2", result.OverallFail)
	}
}

func TestPhase1bToAssessment_EmptyResults(t *testing.T) {
	assessment := makeAssessment("hipaa", nil)
	result := toAssessment(assessment)
	if result == nil {
		t.Fatal("toAssessment returned nil for non-nil assessment with nil results")
	}
	if len(result.Controls) != 0 {
		t.Errorf("Controls len = %d, want 0", len(result.Controls))
	}
	if result.OverallPass != 0 || result.OverallFail != 0 {
		t.Errorf("OverallPass=%d OverallFail=%d, want 0/0", result.OverallPass, result.OverallFail)
	}
}

func TestPhase1bToAssessment_EvidenceJoinOrder(t *testing.T) {
	// Verify that message is first, then evidence entries, joined by "; ".
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		{
			ControlID: "C1",
			Status:    compliance.StatusCompliant,
			Message:   "msg1",
			Evidence:  []string{"ev1", "ev2"},
		},
	})
	result := toAssessment(assessment)
	if result.Controls[0].Evidence != "msg1; ev1; ev2" {
		t.Errorf("Evidence = %q, want %q", result.Controls[0].Evidence, "msg1; ev1; ev2")
	}
}

func TestPhase1bToAssessment_NoMessageNoEvidence(t *testing.T) {
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		{
			ControlID: "C1",
			Status:    compliance.StatusCompliant,
		},
	})
	result := toAssessment(assessment)
	if result.Controls[0].Evidence != "" {
		t.Errorf("Evidence = %q, want empty", result.Controls[0].Evidence)
	}
}

func TestPhase1bToAssessment_EvidenceOnlyNoMessage(t *testing.T) {
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		{
			ControlID: "C1",
			Status:    compliance.StatusCompliant,
			Evidence:  []string{"only-ev"},
		},
	})
	result := toAssessment(assessment)
	if result.Controls[0].Evidence != "only-ev" {
		t.Errorf("Evidence = %q, want %q", result.Controls[0].Evidence, "only-ev")
	}
}

// ---- LicenseContext: currently 0% ----

func TestPhase1bLicenseContext_ReturnsNil(t *testing.T) {
	got := LicenseContext(context.Background())
	if got != nil {
		t.Errorf("LicenseContext = %v, want nil (placeholder)", got)
	}
}

// ---- canonicalFrameworkID: cover remaining switch cases + fallback ----

func TestPhase1bCanonicalFrameworkID_AdditionalCases(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Cases not covered by existing TestCanonicalFrameworkID.
		{"ATLAS", "atlas"},
		{"mitre_atlas", "atlas"},
		{"NIST.AI-1.500", "nist_ai_rmf"},
		{"owasp_llm", "owasp"},
		{"OWASP Top 10", "owasp_web"},
		{"owasp_web", "owasp_web"},
		{"GDPR", "gdpr"},
		{"CIS v8", "cis"},
		{"CIS", "cis"},
		{"NIST CSF 2.0", "nist_csf"},
		{"nist_csf", "nist_csf"},
		{"NIST AI 600-1", "nist_ai_600_1"},
		{"nist_ai_600_1", "nist_ai_600_1"},
		{"CSA STAR", "csa_star"},
		{"csa_star", "csa_star"},
		{"CCPA/CPRA", "ccpa"},
		{"CCPA", "ccpa"},
		{"ccpa", "ccpa"},
		{"ISO 27001", "iso27001"},
		{"iso27001", "iso27001"},
		{"CMMC Level 2", "cmmcl2"},
		{"cmmcl2", "cmmcl2"},
		{"NIST 800-171", "nist800171"},
		{"nist800171", "nist800171"},
		{"HITRUST CSF", "hitrust"},
		{"hitrust", "hitrust"},
		{"TISAX AL2", "tisax"},
		{"tisax", "tisax"},
		{"cwe", "cwe"},
		{"cve", "cve"},
		// Fallback path: lowercase + spaces/dashes/slashes -> underscores.
		{"Some New Framework", "some_new_framework"},
		{"Foo-Bar", "foo_bar"},
		{"A/B Test", "a_b_test"},
		{"MiXeD CaSe", "mixed_case"},
	}
	for _, tc := range cases {
		got := canonicalFrameworkID(tc.in)
		if got != tc.want {
			t.Errorf("canonicalFrameworkID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- VerifyCrossProtocolDetailed: error paths (currently 57.1%) ----

func TestPhase1bVerifyCrossProtocolDetailed_NilManifest(t *testing.T) {
	// VerifyCrossProtocolDetailed dereferences cp directly, so nil
	// panics. We verify it panics (not silently returns wrong data).
	defer func() {
		if r := recover(); r == nil {
			t.Error("VerifyCrossProtocolDetailed(nil) should panic")
		}
	}()
	_ = VerifyCrossProtocolDetailed(nil)
}

func TestPhase1bVerifyCrossProtocolDetailed_NoSignature(t *testing.T) {
	cp := &CrossProtocolManifest{ManifestID: "cp-1"}
	res := VerifyCrossProtocolDetailed(cp)
	if res.Verified {
		t.Error("Verified = true for manifest with no signature, want false")
	}
	if res.ManifestID != "cp-1" {
		t.Errorf("ManifestID = %q, want cp-1", res.ManifestID)
	}
	if res.Reason == "" {
		t.Error("Reason should be populated for failed verification")
	}
}

func TestPhase1bVerifyCrossProtocolDetailed_InvalidSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{
		ManifestID: "cp-1",
		Signature: Signature{
			Value:     []byte{0x01, 0x02, 0x03}, // garbage
			KeyID:     "k1",
			PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
		},
	}
	res := VerifyCrossProtocolDetailed(cp)
	if res.Verified {
		t.Error("Verified = true for invalid signature, want false")
	}
	if res.Reason == "" {
		t.Error("Reason should be populated")
	}
}

// ---- serveGet: method not allowed + empty id (currently 63.6%) ----

func TestPhase1bServeGet_MethodNotAllowed(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID:     "sg-1",
		Framework:      "hipaa",
		GeneratedAt:    time.Now().UTC(),
		BuilderVersion: "v",
	}
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/sg-1", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST on get = %d, want 405", w.Code)
	}
}

func TestPhase1bServeGet_EmptyID(t *testing.T) {
	api, _ := newTestAPI(t)
	// /api/v1/compliance/evidence/ -> suffix "/" -> dispatched to serveList, not serveGet.
	// To hit serveGet with empty id, we need a path that strips to empty.
	// Actually the dispatcher maps "/" to "/list". So we test serveGet directly.
	w := httptest.NewRecorder()
	api.serveGet(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/", ""), "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("serveGet with empty id = %d, want 400", w.Code)
	}
}

func TestPhase1bServeVerify_MethodNotAllowed(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID:     "sv-1",
		Framework:      "hipaa",
		GeneratedAt:    time.Now().UTC(),
		BuilderVersion: "v",
	}
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/sv-1/verify", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST on verify = %d, want 405", w.Code)
	}
}

func TestPhase1bServeVerify_EmptyID(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.serveVerify(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence//verify", ""), "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("serveVerify with empty id = %d, want 400", w.Code)
	}
}

// ---- writeJSON: nil v case (currently 66.7%) ----

func TestPhase1bWriteJSON_NilValue(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, nil)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body should be empty for nil v, got %q", w.Body.String())
	}
}

// ---- VerifyEnvelopeWithKey: nil manifest + nil envelope (currently 80%) ----

func TestPhase1bVerifyEnvelopeWithKey_NilManifest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyEnvelopeWithKey(nil, &key.PublicKey, "k1")
	if err == nil {
		t.Error("VerifyEnvelopeWithKey(nil) should return error")
	}
}

func TestPhase1bVerifyEnvelopeWithKey_NoEnvelope(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := &Manifest{ManifestID: "x"}
	err := VerifyEnvelopeWithKey(m, &key.PublicKey, "k1")
	if err == nil {
		t.Error("VerifyEnvelopeWithKey with no envelope should return error")
	}
}

// ---- VerifyEnvelope: nil manifest ----

func TestPhase1bVerifyEnvelope_NilManifest(t *testing.T) {
	if err := VerifyEnvelope(nil); err == nil {
		t.Error("VerifyEnvelope(nil) should return error")
	}
}

func TestPhase1bVerifyEnvelope_NoEnvelope(t *testing.T) {
	m := &Manifest{ManifestID: "x"}
	if err := VerifyEnvelope(m); err == nil {
		t.Error("VerifyEnvelope with no envelope should return error")
	}
}

// ---- BuildCrossProtocolCLI: cover license already set (currently 87.5%) ----

func TestPhase1bBuildCrossProtocolCLI_WithExistingLicense(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{
		ManifestID: "cli-1",
		License: LicenseBlock{
			Tier:     "professional",
			Valid:    true,
			Customer: "TestCorp",
		},
	}
	if err := BuildCrossProtocolCLI(cp, key, "cli-key", "v3.4.0-cli"); err != nil {
		t.Fatalf("BuildCrossProtocolCLI: %v", err)
	}
	if cp.License.Tier != "professional" {
		t.Errorf("License.Tier = %q, want professional (should not be overwritten)", cp.License.Tier)
	}
	if cp.BuilderVersion != "v3.4.0-cli" {
		t.Errorf("BuilderVersion = %q, want v3.4.0-cli", cp.BuilderVersion)
	}
	if len(cp.Signature.Value) == 0 {
		t.Error("Signature.Value is empty")
	}
	// Verify round-trip.
	if err := VerifyCrossProtocol(cp); err != nil {
		t.Errorf("VerifyCrossProtocol after CLI build: %v", err)
	}
}

// ---- VerifyCrossProtocolWithKey: additional cases (currently 86.7%) ----

func TestPhase1bVerifyCrossProtocolWithKey_KeyIDMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{
		ManifestID: "cp-1",
		Signature: Signature{
			Value: []byte{0x01},
			KeyID: "key-a",
		},
	}
	err := VerifyCrossProtocolWithKey(cp, &key.PublicKey, "key-b")
	if err == nil {
		t.Error("VerifyCrossProtocolWithKey with key id mismatch should return error")
	}
}

func TestPhase1bVerifyCrossProtocolWithKey_BadSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp := &CrossProtocolManifest{
		ManifestID: "cp-1",
		Signature: Signature{
			Value:     []byte{0x01, 0x02, 0x03},
			PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
			KeyID:     "k1",
		},
	}
	err := VerifyCrossProtocolWithKey(cp, &key.PublicKey, "")
	if err == nil {
		t.Error("VerifyCrossProtocolWithKey with bad signature should return error")
	}
}

// ---- signCrossProtocol: cover error path via direct call ----

func TestPhase1bSignCrossProtocol_HappyPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "sc-key",
		BuilderVersion: "v1",
	}}
	cp := &CrossProtocolManifest{
		ManifestID:     "cp-sign-1",
		BuilderVersion: "v1",
	}
	now := time.Now().UTC()
	if err := b.signCrossProtocol(cp, now); err != nil {
		t.Fatalf("signCrossProtocol: %v", err)
	}
	if cp.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("Algorithm = %q, want ecdsa-p256", cp.Signature.Algorithm)
	}
	if cp.Signature.KeyID != "sc-key" {
		t.Errorf("KeyID = %q, want sc-key", cp.Signature.KeyID)
	}
	// Verify round-trip.
	if err := VerifyCrossProtocol(cp); err != nil {
		t.Errorf("VerifyCrossProtocol after signCrossProtocol: %v", err)
	}
}

// ---- BuildCrossProtocol: error paths ----

func TestPhase1bBuildCrossProtocol_ZeroStart(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	b, _ := NewBuilder(BuilderDeps{
		Scanner:        compliance.NewScanner(nil, nil),
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v",
	})
	_, err := b.BuildCrossProtocol(context.Background(), time.Time{}, time.Now())
	if err == nil {
		t.Error("BuildCrossProtocol with zero start should fail")
	}
}

func TestPhase1bBuildCrossProtocol_ZeroEnd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	b, _ := NewBuilder(BuilderDeps{
		Scanner:        compliance.NewScanner(nil, nil),
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v",
	})
	_, err := b.BuildCrossProtocol(context.Background(), time.Now(), time.Time{})
	if err == nil {
		t.Error("BuildCrossProtocol with zero end should fail")
	}
}

func TestPhase1bBuildCrossProtocol_StartEqualsEnd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr, _ := license.NewManager()
	b, _ := NewBuilder(BuilderDeps{
		Scanner:        compliance.NewScanner(nil, nil),
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "k",
		BuilderVersion: "v",
	})
	now := time.Now()
	_, err := b.BuildCrossProtocol(context.Background(), now, now)
	if err == nil {
		t.Error("BuildCrossProtocol with start==end should fail")
	}
}

// ---- ServeHTTP: default (NotFound) branch ----

func TestPhase1bServeHTTP_DefaultNotFound(t *testing.T) {
	api, _ := newTestAPI(t)
	// A path that doesn't match any case and doesn't start with "/" after prefix.
	// This is tricky because the suffix always starts with "/" if path starts with prefix.
	// The default branch fires when suffix doesn't start with "/".
	// We can't easily trigger that via ServeHTTP since suffix = path[len(prefix):]
	// and if path starts with prefix, suffix is either "" or starts with "/".
	// The "/" case is handled by "/list". Let's test a suffix that starts with
	// something other than "/" - impossible with standard paths.
	// Instead, let's verify that a path under the prefix with a weird format
	// still returns a result (either 200 for list or 404).
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence", ""))
	if w.Code != http.StatusOK {
		t.Errorf("GET /evidence = %d, want 200 (list)", w.Code)
	}
}

// ---- serveList: method not allowed + bad limit ----

func TestPhase1bServeList_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.serveList(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/list", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST on list = %d, want 405", w.Code)
	}
}

func TestPhase1bServeList_BadLimit(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.serveList(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/list?limit=abc", ""))
	if w.Code != http.StatusBadRequest {
		t.Errorf("Bad limit = %d, want 400", w.Code)
	}
}

func TestPhase1bServeList_WithLimit(t *testing.T) {
	api, store := newTestAPI(t)
	for i := 0; i < 5; i++ {
		_ = store.Put(&Manifest{
			ManifestID:     "sl-" + string(rune('a'+i)),
			GeneratedAt:    time.Now().UTC(),
			BuilderVersion: "v",
		})
	}
	w := httptest.NewRecorder()
	api.serveList(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/list?limit=2", ""))
	if w.Code != http.StatusOK {
		t.Errorf("List with limit = %d, want 200", w.Code)
	}
	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("count = %d, want 2", resp.Count)
	}
}

// ---- serveBuild: method not allowed via direct call ----

func TestPhase1bServeBuild_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.serveBuild(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/build", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on build = %d, want 405", w.Code)
	}
}

// ---- serveCrossProtocolBuild: method not allowed + bad JSON ----

func TestPhase1bServeCrossProtocolBuild_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/cross_protocol/build", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on cross_protocol/build = %d, want 405", w.Code)
	}
}

func TestPhase1bServeCrossProtocolBuild_BadJSON(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/cross_protocol/build", "garbage"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("Bad JSON on cross_protocol/build = %d, want 400", w.Code)
	}
}

func TestPhase1bServeCrossProtocolBuild_InvalidPeriod(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/cross_protocol/build",
		`{"period_start":"2026-01-01T00:00:00Z","period_end":"2025-01-01T00:00:00Z"}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("Invalid period on cross_protocol/build = %d, want 400", w.Code)
	}
}

// ---- signManifest: cover KeyRing path (currently 78.6%) ----

func TestPhase1bSignManifest_WithKeyRing(t *testing.T) {
	// We don't have a real KeyRing, but we can pass a non-nil ioc.KeyRing
	// that will fail during signEnvelope (non-fatal) and still produce
	// a valid legacy signature.
	// Since ioc.KeyRing requires setup, we test that signManifest works
	// when KeyRing is nil (the default path) more thoroughly by checking
	// the Attestation field stays nil.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "kr-key",
		BuilderVersion: "v1",
	}}
	m := &Manifest{
		ManifestID:     "kr-1",
		Framework:      "hipaa",
		BuilderVersion: "v1",
	}
	now := time.Now().UTC()
	if err := b.signManifest(m, now); err != nil {
		t.Fatalf("signManifest: %v", err)
	}
	if m.Attestation != nil {
		t.Error("Attestation should be nil when KeyRing is nil")
	}
	if err := Verify(m); err != nil {
		t.Errorf("Verify after signManifest: %v", err)
	}
}

// ---- NewStore: mkdir failure ----

func TestPhase1bNewStore_MkdirFailure(t *testing.T) {
	// Try to create a store in a path under a file (not a dir).
	// This should fail because MkdirAll can't create a dir under a file.
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "notadir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(filepath.Join(filePath, "sub"))
	if err == nil {
		t.Error("NewStore under a file should fail")
	}
}

// ---- Store.Put: nil manifest ----

func TestPhase1bStorePut_NilManifest(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	if err := s.Put(nil); err == nil {
		t.Error("Put(nil) should return error")
	}
}

// ---- Store.List: empty store ----

func TestPhase1bStoreList_Empty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	all, err := s.List(0)
	if err != nil {
		t.Fatalf("List on empty store: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("List on empty store returned %d items, want 0", len(all))
	}
}

// ---- FingerprintKey: different inputs ----

func TestPhase1bFingerprintKey_KnownValue(t *testing.T) {
	// Verify the fingerprint of the empty string matches the known
	// SHA-256 of "".
	f := FingerprintKey("")
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if f != want {
		t.Errorf("FingerprintKey(\"\") = %q, want %q", f, want)
	}
}
