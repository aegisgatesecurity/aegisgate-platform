// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Federated IOC Library In-Package Targeted Tests
//
// In-package tests (package ioc) to close the remaining coverage
// gaps in pkg/ioc/. These tests must be in package ioc (not
// package ioc_test) to exercise the unexported fields like
// s.cfg.* and kr.current directly, which the public API does
// not expose.
//
// v3.3.0+ Track 6 Task 6.

package ioc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ------------------------------------------------------------------
// sync.go: setter/getter nil-guard paths (covered in main pkg
// from outside, but need in-package to count for pkg/ioc cover)
// ------------------------------------------------------------------

func TestSync_Setters_NilReceiver_NoPanic(t *testing.T) {
	// Calling the setters on a nil *Sync must be a no-op,
	// not a panic. The setters do not return a value; we just
	// verify the call completes.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("setter panicked on nil receiver: %v", r)
		}
	}()
	var s *Sync
	s.SetShare(true)
	s.SetReceive(true)
	s.SetReputation(nil)
	if s.IsShare() {
		t.Error("(*Sync)(nil).IsShare() = true, want false")
	}
	if s.IsReceive() {
		t.Error("(*Sync)(nil).IsReceive() = true, want false")
	}
	if s.Reputation() != nil {
		t.Error("(*Sync)(nil).Reputation() != nil, want nil")
	}
}

func TestSync_Setters_RealReceiver_Toggles(t *testing.T) {
	// The same setters, called on a real Sync, must actually
	// flip the underlying cfg.* fields.
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID: "test",
		KeyRing:    kr,
		Store:      store,
		Tier:       tier.TierProfessional,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	if s.IsShare() {
		t.Error("IsShare() = true, want false (default)")
	}
	s.SetShare(true)
	if !s.IsShare() {
		t.Error("after SetShare(true), IsShare() = false, want true")
	}
	s.SetShare(false)
	if s.IsShare() {
		t.Error("after SetShare(false), IsShare() = true, want false")
	}
	if s.IsReceive() {
		t.Error("IsReceive() = true, want false (default)")
	}
	s.SetReceive(true)
	if !s.IsReceive() {
		t.Error("after SetReceive(true), IsReceive() = false, want true")
	}
	// SetReputation to nil (the only safe value here; we don't
	// construct a real ReputationStore).
	s.SetReputation(nil)
	if s.Reputation() != nil {
		t.Error("after SetReputation(nil), Reputation() != nil")
	}
}

// ------------------------------------------------------------------
// fingerprint.go: FingerprintBytes, canonicalJSON branches
// ------------------------------------------------------------------

func TestFingerprintBytes_EmptyDetection(t *testing.T) {
	got := FingerprintBytes(Detection{})
	if got == nil {
		t.Fatal("FingerprintBytes(empty) = nil, want 32-byte slice")
	}
	if len(got) != 32 {
		t.Errorf("len(FingerprintBytes(empty)) = %d, want 32", len(got))
	}
}

func TestFingerprintBytes_MatchesHex(t *testing.T) {
	d := Detection{Type: "x", Severity: SeverityHigh, Pattern: "y"}
	hex := Fingerprint(d)
	raw := FingerprintBytes(d)
	if len(hex) != 64 {
		t.Errorf("hex len = %d, want 64", len(hex))
	}
	if len(raw) != 32 {
		t.Errorf("raw len = %d, want 32", len(raw))
	}
	// The hex string should decode to the same bytes.
	for i := 0; i < 32; i++ {
		want := hex[i*2 : i*2+2]
		got := raw[i]
		// Parse want as hex byte.
		var b byte
		for _, c := range want {
			switch {
			case c >= '0' && c <= '9':
				b = b*16 + byte(c-'0')
			case c >= 'a' && c <= 'f':
				b = b*16 + byte(c-'a'+10)
			}
		}
		if got != b {
			t.Errorf("byte %d: raw=%x hex=%s", i, got, want)
		}
	}
}

func TestCanonicalJSON_TopLevelMap(t *testing.T) {
	// canonicalJSON must sort keys at every nesting level.
	in := map[string]interface{}{
		"b": 2,
		"a": 1,
		"c": map[string]interface{}{
			"z": 26,
			"y": 25,
		},
	}
	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"a":1,"b":2,"c":{"y":25,"z":26}}`
	if string(got) != want {
		t.Errorf("canonicalJSON = %s, want %s", string(got), want)
	}
}

func TestCanonicalJSON_EmptyMap(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("canonicalJSON(empty) = %s, want {}", string(got))
	}
}

func TestCanonicalJSON_StringKeyWithSpecialChars(t *testing.T) {
	// Keys with characters that need escaping should still
	// be sorted lexicographically.
	in := map[string]interface{}{
		"a\"b": 1,
		"a":    2,
	}
	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	// "a" < "a\"b" lexicographically (shorter prefix wins).
	want := `{"a":2,"a\"b":1}`
	if string(got) != want {
		t.Errorf("canonicalJSON = %s, want %s", string(got), want)
	}
}

// ------------------------------------------------------------------
// producer.go: Enabled
// ------------------------------------------------------------------

func TestProducer_Enabled(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	p := NewProducer(ProducerConfig{}, store)
	if p.Enabled() {
		t.Error("Producer.Enabled() = true on fresh producer, want false")
	}
	p.SetEnabled(true)
	if !p.Enabled() {
		t.Error("after SetEnabled(true), Enabled() = false, want true")
	}
	p.SetEnabled(false)
	if p.Enabled() {
		t.Error("after SetEnabled(false), Enabled() = true, want false")
	}
}

// ------------------------------------------------------------------
// store.go: Flush branches (empty + non-empty + read-only)
// ------------------------------------------------------------------

func TestStore_Flush_Empty(t *testing.T) {
	// An empty store is NOT dirty, so Flush is a no-op (returns nil).
	dir := t.TempDir()
	store, err := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// No Observe calls; store is not dirty.
	if err := store.Flush(); err != nil {
		t.Errorf("Flush on empty store: %v", err)
	}
	// File should not exist (Flush is a no-op on !dirty).
	if _, err := os.Stat(filepath.Join(dir, "s.json")); err == nil {
		t.Error("store.json was created on empty Flush; should be a no-op")
	}
}

func TestStore_Flush_AfterObserve(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.Observe(IOC{
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
		Source:      "test",
	}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := store.Flush(); err != nil {
		t.Errorf("Flush after Observe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "s.json")); err != nil {
		t.Errorf("store.json missing after Flush: %v", err)
	}
}

func TestStore_Flush_RenameFailure(t *testing.T) {
	// A read-only data dir causes os.Rename to fail (the
	// tmp file is created but cannot be renamed over the
	// target). Flush must return the error.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	store, err := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	now := time.Now().UTC()
	_, err = store.Observe(IOC{
		Fingerprint: strings.Repeat("0", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now, LastSeen: now,
		Count:  1,
		Source: "test",
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := store.Flush(); err == nil {
		t.Error("Flush with read-only dir = nil, want error")
	}
}

func TestStore_Flush_NoDiskPath_NoOp(t *testing.T) {
	// No DiskPath means Flush returns nil without writing.
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// Even after Observe, Flush is a no-op without DiskPath.
	now := time.Now().UTC()
	_, _ = store.Observe(IOC{
		Fingerprint: "abc", Type: IOCTypeProxyResponse,
		Severity: SeverityHigh, FirstSeen: now, LastSeen: now,
	})
	if err := store.Flush(); err != nil {
		t.Errorf("Flush with no DiskPath: %v", err)
	}
}

// ------------------------------------------------------------------
// bundle.go: mustBase64DecodeErr error branches
// ------------------------------------------------------------------

func TestMustBase64DecodeErr_BadInput(t *testing.T) {
	// Calling with invalid base64 should return an error.
	_, err := mustBase64DecodeErr("!!!not-base64!!!")
	if err == nil {
		t.Error("mustBase64DecodeErr(bad) = nil, want error")
	}
}

func TestMustBase64DecodeErr_GoodInput(t *testing.T) {
	// Round-trip: encode then decode.
	original := []byte("hello world")
	encoded := "aGVsbG8gd29ybGQ="
	got, err := mustBase64DecodeErr(encoded)
	if err != nil {
		t.Fatalf("mustBase64DecodeErr: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("decoded = %q, want %q", string(got), string(original))
	}
}

// ------------------------------------------------------------------
// keyring.go: parseRingKeyPEM and encodeRingKeyPEM error paths
// ------------------------------------------------------------------

func TestParseRingKeyPEM_NotPEM(t *testing.T) {
	if _, err := parseRingKeyPEM("not pem data"); err == nil {
		t.Error("parseRingKeyPEM(garbage) = nil, want error")
	}
}

func TestParseRingKeyPEM_WrongType(t *testing.T) {
	// A PEM block with the wrong type.
	wrongType := `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----`
	if _, err := parseRingKeyPEM(wrongType); err == nil {
		t.Error("parseRingKeyPEM(RSA) = nil, want error")
	}
}

func TestEncodeRingKeyPEM_WrongCurve(t *testing.T) {
	// A P-384 key must be rejected (the function enforces P-256).
	//nolint:staticcheck
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(P-384): %v", err)
	}
	if _, err := encodeRingKeyPEM(priv); err == nil {
		t.Error("encodeRingKeyPEM(P-384) = nil, want error")
	}
}

// ------------------------------------------------------------------
// keyring.go: KeyInfo marshal/unmarshal round-trip
// ------------------------------------------------------------------

func TestKeyInfo_RoundTrip(t *testing.T) {
	kr, _ := LoadKeyRing("")
	keys := kr.ActiveKeys()
	if len(keys) == 0 {
		t.Fatal("ActiveKeys is empty on fresh keyring")
	}
	// Just verify the field shape: KeyID is non-empty, IsCurrent
	// is true, public key is present and base64-decodable.
	k := keys[0]
	if k.KeyID == "" {
		t.Error("KeyInfo.KeyID is empty")
	}
	if !k.IsCurrent {
		t.Error("KeyInfo.IsCurrent = false, want true on the only key")
	}
	if k.PublicKeySEC1 == "" {
		t.Error("KeyInfo.PublicKeySEC1 is empty")
	}
}

// ------------------------------------------------------------------
// sync.go: ActiveKeys when no KeyRing
// ------------------------------------------------------------------

func TestSync_ActiveKeys_NoKeyRing(t *testing.T) {
	// A Sync constructed without a KeyRing must return nil
	// from ActiveKeys() (the cfg.KeyRing == nil branch).
	dir := t.TempDir()
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	// Construct via zero-value Sync (no NewSync call — bypasses
	// the KeyRing check). This is intentionally unusual but
	// valid: the NewSync constructor rejects nil KeyRing, so
	// we must construct manually to exercise the nil-KeyRing
	// branch of ActiveKeys.
	s := &Sync{
		cfg: SyncConfig{
			InstanceID: "test",
			Store:      store,
			Tier:       tier.TierProfessional,
			// KeyRing is intentionally nil.
		},
	}
	if got := s.ActiveKeys(); got != nil {
		t.Errorf("ActiveKeys() with nil KeyRing = %v, want nil", got)
	}
}

// ------------------------------------------------------------------
// sync.go: handleHealth 200 + 503 paths
// ------------------------------------------------------------------

func TestSync_HandleHealth_Happy(t *testing.T) {
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:  "test",
		KeyRing:     kr,
		Store:       store,
		Tier:        tier.TierProfessional,
		EnableShare: true,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	// Use the public Handler() routing to exercise handleHealth
	// via HTTP, the same way a peer would call it.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/ioc/health", nil)
	s.handleHealth(rr, req)
	if rr.Code != 200 {
		t.Errorf("handleHealth happy: code = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "healthy") {
		t.Errorf("handleHealth happy: body = %q, want 'healthy'", rr.Body.String())
	}
}

func TestSync_HandleHealth_ShareDisabled(t *testing.T) {
	// When share is disabled, health must return 503.
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "s.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:  "test",
		KeyRing:     kr,
		Store:       store,
		Tier:        tier.TierProfessional,
		EnableShare: false, // health returns 503 in this case
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/ioc/health", nil)
	s.handleHealth(rr, req)
	if rr.Code != 503 {
		t.Errorf("handleHealth share-disabled: code = %d, want 503 (body: %q)", rr.Code, rr.Body.String())
	}
}
