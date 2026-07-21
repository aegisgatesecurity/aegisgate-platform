// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Evidence API tests (v3.3.0+ Track 2)
//
// api_test.go covers the HTTP API surface of pkg/evidence:
// the ServeHTTP dispatcher, the four sub-handlers (build, list,
// get, verify), and the request/response JSON shapes.
//
// v3.3.0+ Track 2.

package evidence
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// testKey generates a fresh ECDSA P-256 key for testing.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sec1PublicKey returns the SEC 1 encoded public key for the given
// private key (used to embed the public key in a test signature).
func sec1PublicKey(k *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
}

// newTestAPI builds a real evidence.API backed by a real Builder,
// a real Scanner (with a nil Registry - we only test the API surface),
// a real Store on t.TempDir(), and a fresh signing key.
func newTestAPI(t *testing.T) (*API, *Store) {
	t.Helper()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	licenseMgr, lerr := license.NewManager()
	if lerr != nil {
		t.Fatal(lerr)
	}
	key := testKey(t)
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     licenseMgr,
		SigningKey:     key,
		KeyID:          "test-key",
		BuilderVersion: "v3.3.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewAPI(builder, store), store
}

// signTestManifest signs a manifest with a fresh key (test-only).
func signTestManifest(t *testing.T, m *Manifest) {
	t.Helper()
	key := testKey(t)
	m.Signature = Signature{}
	canonical, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     "test-key",
		Value:     sig,
		PublicKey: sec1PublicKey(key),
		SignedAt:  time.Now().UTC(),
	}
}

// makeRequest builds an http.Request for the API. body may be nil.
func makeRequest(method, path string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return r
}

func TestAPI_NewAPI(t *testing.T) {
	api, _ := newTestAPI(t)
	if api == nil {
		t.Fatal("NewAPI returned nil")
	}
	if api.builder == nil {
		t.Error("API.builder is nil")
	}
	if api.store == nil {
		t.Error("API.store is nil")
	}
}

func TestAPI_Build_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/build", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on build = %d, want 405", w.Code)
	}
}

func TestAPI_Build_BadJSON(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/build", "not json"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("Bad JSON = %d, want 400", w.Code)
	}
}

func TestAPI_Build_NilFramework(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	// framework is empty - Builder.Build should reject it
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/build", `{"framework":"","period_start":"2026-01-01T00:00:00Z","period_end":"2026-03-31T23:59:59Z"}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("Empty framework = %d, want 400", w.Code)
	}
}

func TestAPI_List_Empty(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence", ""))
	if w.Code != http.StatusOK {
		t.Errorf("List = %d, want 200", w.Code)
	}
	var resp struct {
		Count     int        `json:"count"`
		Manifests []Manifest `json:"manifests"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 0 {
		t.Errorf("count = %d, want 0", resp.Count)
	}
}

func TestAPI_List_AfterPut(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID:        "test-list-1",
		Framework:         "hipaa",
		Period:            Period{Start: time.Now(), End: time.Now().Add(time.Hour)},
		GeneratedAt:       time.Now(),
		BuilderVersion:    "v3.3.0-test",
		License:           LicenseBlock{Tier: "community", Valid: false},
		FrameworkEvidence: FrameworkEvidence{Framework: "hipaa"},
		AuditAnchors:      AuditAnchors{Source: "unavailable"},
	}
	signTestManifest(t, m)
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence", ""))
	if w.Code != http.StatusOK {
		t.Errorf("List = %d, want 200", w.Code)
	}
	var resp struct {
		Count     int        `json:"count"`
		Manifests []Manifest `json:"manifests"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if len(resp.Manifests) != 1 || resp.Manifests[0].ManifestID != "test-list-1" {
		t.Errorf("manifests[0].ManifestID = %v, want test-list-1", resp.Manifests)
	}
}

func TestAPI_Get_Found(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID:        "test-get-1",
		Framework:         "hipaa",
		Period:            Period{Start: time.Now(), End: time.Now().Add(time.Hour)},
		GeneratedAt:       time.Now(),
		BuilderVersion:    "v3.3.0-test",
		License:           LicenseBlock{Tier: "community", Valid: false},
		FrameworkEvidence: FrameworkEvidence{Framework: "hipaa"},
		AuditAnchors:      AuditAnchors{Source: "unavailable"},
	}
	signTestManifest(t, m)
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/test-get-1", ""))
	if w.Code != http.StatusOK {
		t.Errorf("Get = %d, want 200", w.Code)
	}
}

func TestAPI_Get_NotFound(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/nonexistent", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("Get missing = %d, want 404", w.Code)
	}
}

func TestAPI_Verify_Valid(t *testing.T) {
	api, store := newTestAPI(t)
	m := &Manifest{
		ManifestID:        "test-verify-1",
		Framework:         "hipaa",
		Period:            Period{Start: time.Now(), End: time.Now().Add(time.Hour)},
		GeneratedAt:       time.Now(),
		BuilderVersion:    "v3.3.0-test",
		License:           LicenseBlock{Tier: "community", Valid: false},
		FrameworkEvidence: FrameworkEvidence{Framework: "hipaa"},
		AuditAnchors:      AuditAnchors{Source: "unavailable"},
	}
	signTestManifest(t, m)
	if err := store.Put(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/test-verify-1/verify", ""))
	if w.Code != http.StatusOK {
		t.Errorf("Verify = %d, want 200", w.Code)
	}
	var resp VerifyResult
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Verified {
		t.Errorf("Verified = false, want true; reason = %q", resp.Reason)
	}
}

func TestAPI_Verify_Missing(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/missing/verify", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("Verify missing = %d, want 404", w.Code)
	}
}

func TestAPI_ServeHTTP_UnknownSubpath(t *testing.T) {
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodGet, "/api/v1/compliance/evidence/some-id/garbage", ""))
	// Unknown subpath should return 404 (no such route).
	if w.Code != http.StatusNotFound {
		t.Errorf("Unknown subpath = %d, want 404", w.Code)
	}
}

func TestAPI_Build_ValidFramework_Returns201(t *testing.T) {
	// This test documents that the build path successfully returns a
	// signed manifest. The scanner falls back gracefully when the
	// license is invalid (the test license has no key), producing
	// reason_not_enforced="invalid_license" - this is the correct
	// signal for "customer does not own this module".
	api, _ := newTestAPI(t)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, makeRequest(http.MethodPost, "/api/v1/compliance/evidence/build", `{"framework":"hipaa","period_start":"2026-01-01T00:00:00Z","period_end":"2026-03-31T23:59:59Z"}`))
	if w.Code != http.StatusCreated {
		t.Errorf("Build = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	var m Manifest
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.ManifestID == "" {
		t.Error("ManifestID is empty")
	}
	if m.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("Signature.Algorithm = %q, want ecdsa-p256", m.Signature.Algorithm)
	}
	// The Builder signs with its injected key and embeds the public
	// key in the manifest. Verify() uses the embedded public key, so
	// the round-trip should succeed.
	if err := Verify(&m); err != nil {
		t.Errorf("Build-then-verify round-trip failed: %v", err)
	}
}

func TestAPI_StoreAppendAcrossOpens(t *testing.T) {
	// This is a smoke test for store append behavior across reopens.
	// Lives here because the API tests use the store; the store_test.go
	// file has the more comprehensive tests.
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		ManifestID:        "reopen-1",
		Framework:         "hipaa",
		GeneratedAt:       time.Now(),
		BuilderVersion:    "v3.3.0-test",
		License:           LicenseBlock{Tier: "community"},
		FrameworkEvidence: FrameworkEvidence{Framework: "hipaa"},
		AuditAnchors:      AuditAnchors{Source: "unavailable"},
	}
	signTestManifest(t, m)
	if err := s1.Put(m); err != nil {
		t.Fatal(err)
	}
	// Reopen.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get("reopen-1")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.ManifestID != "reopen-1" {
		t.Errorf("after reopen: id = %q, want reopen-1", got.ManifestID)
	}
}
