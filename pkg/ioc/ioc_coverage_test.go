// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// ioc_coverage_test.go contains additional unit tests that bring the
// IOC package's coverage above 80%. The main test file (ioc_test.go)
// focuses on the happy paths and the most important failure modes;
// this file covers the secondary failure modes and the periodic
// background tasks (Flush, RunFlusher, RunReceiver) that are
// awkward to test but must still be exercised.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

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
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// =========================================================================
// NewSync error paths
// =========================================================================

func TestNewSync_MissingFields(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	cases := []struct {
		name string
		cfg  SyncConfig
	}{
		{"missing instance id", SyncConfig{SigningKey: priv, KeyID: keyID, Store: store}},
		{"missing signing key", SyncConfig{InstanceID: "x", KeyID: keyID, Store: store}},
		{"missing key id", SyncConfig{InstanceID: "x", SigningKey: priv, Store: store}},
		{"missing store", SyncConfig{InstanceID: "x", SigningKey: priv, KeyID: keyID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSync(tc.cfg)
			if err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// =========================================================================
// Valid nil receiver + extra edge cases
// =========================================================================

func TestIOCValid_NilReceiver(t *testing.T) {
	var i *IOC
	if i.Valid() {
		t.Errorf("nil IOC should be invalid")
	}
}

func TestMergePeerIOC_RejectsInvalid(t *testing.T) {
	s, _ := NewStore(StoreConfig{Capacity: 100})
	// Invalid IOC (empty) — should be silently dropped.
	s.mergePeerIOC(IOC{})
	if s.Size() != 0 {
		t.Errorf("expected size 0, got %d", s.Size())
	}
}

func TestMergePeerIOC_WorseSeverity(t *testing.T) {
	s, _ := NewStore(StoreConfig{Capacity: 100})
	fp := strings.Repeat("a", 64)
	// Seed with low severity.
	_, _ = s.Observe(makeTestIOC(fp, SeverityLow))
	// Peer reports critical.
	peer := makeTestIOC(fp, SeverityCritical)
	peer.Count = 5
	peer.Source = "peer:x"
	s.mergePeerIOC(peer)
	stored := s.Get(fp)
	if stored.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (peer should win)", stored.Severity)
	}
	// Count should sum: 1 (local) + 5 (peer) = 6
	if stored.Count != 6 {
		t.Errorf("Count = %d, want 6", stored.Count)
	}
}

// =========================================================================
// Store: EvictOldest on empty store, Flush when not dirty, Flush error
// =========================================================================

func TestStore_EvictOldestOnEmpty(t *testing.T) {
	s, _ := NewStore(StoreConfig{Capacity: 3})
	// No IOCs. evictOldest should be a no-op (no panic).
	s.evictOldest()
	if s.Size() != 0 {
		t.Errorf("size = %d, want 0", s.Size())
	}
}

func TestStore_FlushNoDirty(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(StoreConfig{Capacity: 100, DiskPath: filepath.Join(dir, "ioc.json")})
	// No observations; Flush should be a no-op.
	if err := s.Flush(); err != nil {
		t.Errorf("Flush on empty: %v", err)
	}
	// File should NOT exist.
	if _, err := os.Stat(filepath.Join(dir, "ioc.json")); !os.IsNotExist(err) {
		t.Errorf("expected no file, stat err = %v", err)
	}
}

func TestStore_FlushInMemoryOnly(t *testing.T) {
	// No DiskPath -> Flush is a no-op.
	s, _ := NewStore(StoreConfig{Capacity: 100})
	_, _ = s.Observe(makeTestIOC(strings.Repeat("a", 64), SeverityHigh))
	if err := s.Flush(); err != nil {
		t.Errorf("Flush in-memory: %v", err)
	}
}

func TestStore_LoadCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.json")
	// Write garbage.
	if err := os.WriteFile(path, []byte("not valid json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Loading should error.
	_, err := NewStore(StoreConfig{Capacity: 100, DiskPath: path})
	if err == nil {
		t.Errorf("expected error loading corrupt file")
	}
}

func TestStore_RunFlusherCancelsCleanly(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(StoreConfig{
		Capacity:      100,
		FlushInterval: 50 * time.Millisecond,
		DiskPath:      filepath.Join(dir, "ioc.json"),
	})
	_, _ = s.Observe(makeTestIOC(strings.Repeat("a", 64), SeverityHigh))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunFlusher(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // let one tick run
	cancel()
	select {
	case <-done:
		// Flusher returned.
	case <-time.After(2 * time.Second):
		t.Errorf("RunFlusher did not return within 2s of cancel")
	}
	// File should exist (final flush on shutdown).
	if _, err := os.Stat(filepath.Join(dir, "ioc.json")); err != nil {
		t.Errorf("expected file after final flush, stat err = %v", err)
	}
}

// =========================================================================
// Sync handler: method not allowed, peer returns 4xx
// =========================================================================

func TestSync_ManifestMethodNotAllowed(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierProfessional, EnableShare: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ioc/manifest", nil)
	rec := httptest.NewRecorder()
	sync.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestSync_HealthMethodNotAllowed(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierProfessional, EnableShare: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ioc/health", nil)
	rec := httptest.NewRecorder()
	sync.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestSync_FetchPeerReturnsError(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierProfessional, EnableReceive: true,
	})
	// httptest server that returns 500.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nope"))
	}))
	defer server.Close()
	_, err := sync.FetchPeer(t.Context(), server.URL)
	if err == nil {
		t.Errorf("expected error on 500 response")
	}
}

func TestSync_FetchPeerBadJSON(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierProfessional, EnableReceive: true,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()
	_, err := sync.FetchPeer(t.Context(), server.URL)
	if err == nil {
		t.Errorf("expected error on bad JSON")
	}
}

func TestSync_FetchPeerBadURL(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierProfessional, EnableReceive: true,
	})
	_, err := sync.FetchPeer(t.Context(), "://bad-url")
	if err == nil {
		t.Errorf("expected error on bad URL")
	}
}

// =========================================================================
// RunReceiver: tier gate short-circuits
// =========================================================================

func TestSync_RunReceiver_TierGateShortCircuits(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	// Community tier with EnableReceive=true -> still cannot receive.
	sync, _ := NewSync(SyncConfig{
		InstanceID: "i", SigningKey: priv, KeyID: keyID, Store: store,
		Tier: tier.TierCommunity, EnableReceive: true,
	})
	// RunReceiver should return immediately without blocking.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		sync.RunReceiver(ctx)
		close(done)
	}()
	select {
	case <-done:
		// Good: RunReceiver returned because CanReceive() is false.
	case <-time.After(2 * time.Second):
		t.Errorf("RunReceiver did not return immediately for community tier")
	}
}

// =========================================================================
// Receiver.Ingest: nil bundle and missing-store
// =========================================================================

func TestReceiver_IngestNilBundle(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	r := NewReceiver(store)
	_, err := r.Ingest(nil)
	if err == nil {
		t.Errorf("expected error on nil bundle")
	}
}

func TestReceiver_NoStore(t *testing.T) {
	r := &Receiver{} // nil store
	// Build a fake bundle. Won't be touched.
	b := &Bundle{Attestations: []IOCAttestation{}}
	_, err := r.Ingest(b)
	if err == nil {
		t.Errorf("expected error on nil store")
	}
}

// =========================================================================
// SignAttestation with a non-P-256 key
// =========================================================================

func TestSignAttestation_NonP256Key(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}
	a := &IOCAttestation{
		Fingerprint: strings.Repeat("a", 64),
		InstanceID:  "inst",
		IOCType:     IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
	}
	if err := SignAttestation(a, priv, "k"); err == nil {
		t.Errorf("expected error on non-P-256 key")
	}
}

// =========================================================================
// Bundle: nil bundle paths
// =========================================================================

func TestBundle_SignNilBundle(t *testing.T) {
	var b *Bundle
	priv, _ := testKey(t)
	if err := b.Sign(priv, "k"); err == nil {
		t.Errorf("expected error on nil bundle")
	}
}

func TestBundle_SignNilKey(t *testing.T) {
	b := NewBundle("inst")
	if err := b.Sign(nil, "k"); err == nil {
		t.Errorf("expected error on nil key")
	}
}

func TestBundle_VerifyNilBundle(t *testing.T) {
	if err := VerifyBundleSignature(nil); err == nil {
		t.Errorf("expected error on nil bundle")
	}
}

func TestBundle_VerifyBadAlgorithm(t *testing.T) {
	priv, keyID := testKey(t)
	b := NewBundle("inst")
	_ = b.Sign(priv, keyID)
	b.Signature.Algorithm = "rsa-pss"
	if err := VerifyBundleSignature(b); err == nil {
		t.Errorf("expected error on bad algorithm")
	}
}

func TestBundle_VerifyKeyIDMismatch(t *testing.T) {
	priv, keyID := testKey(t)
	b := NewBundle("inst")
	_ = b.Sign(priv, keyID)
	b.Signature.KeyID = "different"
	if err := VerifyBundleSignature(b); err == nil {
		t.Errorf("expected error on keyId mismatch")
	}
}

func TestBundle_VerifyMalformedPubKey(t *testing.T) {
	priv, keyID := testKey(t)
	b := NewBundle("inst")
	_ = b.Sign(priv, keyID)
	b.PublicKey.Value = "not-base64!!!"
	if err := VerifyBundleSignature(b); err == nil {
		t.Errorf("expected error on malformed pub key")
	}
}

func TestBundle_VerifyAllBadAttestation(t *testing.T) {
	priv, keyID := testKey(t)
	b := NewBundle("inst")
	// Add a manually-constructed (unsigned) attestation.
	b.Add(IOCAttestation{
		Fingerprint: strings.Repeat("a", 64),
		InstanceID:  "inst",
		IOCType:     IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		// PublicKey and Signature are zero — verification will fail.
	})
	_ = b.Sign(priv, keyID)
	// VerifyAll should return an error for the unsigned attestation.
	if err := b.VerifyAll(); err == nil {
		t.Errorf("expected VerifyAll to fail on unsigned attestation")
	}
}

// =========================================================================
// PublicKeyToSEC1: non-P-256 key
// =========================================================================

func TestPublicKeyToSEC1_NonP256(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err := PublicKeyToSEC1(&priv.PublicKey)
	if err == nil {
		t.Errorf("expected error on non-P-256 key")
	}
}

func TestParsePublicKey_BadFormat(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x04, 0x01}},
		{"wrong first byte", make([]byte, 65)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.b) == 65 {
				tc.b[0] = 0x05 // not 0x04
			}
			_, err := ParsePublicKey(tc.b)
			if err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// =========================================================================
// Store loadFromDisk: file doesn't exist (should succeed silently)
// =========================================================================

func TestStore_LoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(StoreConfig{
		Capacity: 100,
		DiskPath: filepath.Join(dir, "does-not-exist.json"),
	})
	if err != nil {
		t.Errorf("expected no error for missing file, got: %v", err)
	}
	if s.Size() != 0 {
		t.Errorf("expected empty store, got %d", s.Size())
	}
}

// =========================================================================
// IOC JSON round-trip (sanity check on tags)
// =========================================================================

func TestIOC_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	ioc := &IOC{
		Fingerprint: strings.Repeat("a", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       5,
		Source:      "proxy",
	}
	b, err := json.Marshal(ioc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got IOC
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Fingerprint != ioc.Fingerprint {
		t.Errorf("Fingerprint mismatch: %q != %q", got.Fingerprint, ioc.Fingerprint)
	}
	if got.Count != 5 {
		t.Errorf("Count = %d, want 5", got.Count)
	}
}
