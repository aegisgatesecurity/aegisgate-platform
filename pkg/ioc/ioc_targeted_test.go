// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Federated IOC Library Targeted Tests
//
// Targeted tests to close coverage gaps in pkg/ioc/ to push
// the package from 83% to 95%+. Each test targets a specific
// error path or edge case that the happy-path test suite
// does not exercise.
//
// v3.3.0+ Track 6 Task 6.

package ioc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ------------------------------------------------------------------
// attest.go: SignAttestationWithKeyRing error paths
// ------------------------------------------------------------------

func TestSignAttestationWithKeyRing_NilAttestation(t *testing.T) {
	kr, err := LoadKeyRing("")
	if err != nil {
		t.Fatalf("LoadKeyRing(ephemeral): %v", err)
	}
	if err := SignAttestationWithKeyRing(nil, kr); err == nil {
		t.Error("SignAttestationWithKeyRing(nil, kr) = nil, want error")
	}
}

func TestSignAttestationWithKeyRing_NilKeyRing(t *testing.T) {
	a := &IOCAttestation{IOCType: IOCTypeProxyResponse, Severity: SeverityHigh}
	if err := SignAttestationWithKeyRing(a, nil); err == nil {
		t.Error("SignAttestationWithKeyRing(a, nil) = nil, want error")
	}
}

func TestSignAttestationWithKeyRing_NoCurrentKey(t *testing.T) {
	// A KeyRing with no current key (keyring.current == "").
	// We can construct one by zeroing the field after loading.
	kr, err := LoadKeyRing("")
	if err != nil {
		t.Fatalf("LoadKeyRing(ephemeral): %v", err)
	}
	kr.mu.Lock()
	kr.current = ""
	kr.mu.Unlock()
	a := &IOCAttestation{IOCType: IOCTypeProxyResponse, Severity: SeverityHigh}
	if err := SignAttestationWithKeyRing(a, kr); err == nil {
		t.Error("SignAttestationWithKeyRing with no current key = nil, want error")
	}
}

// ------------------------------------------------------------------
// attest.go: SignAttestation (legacy single-key) error paths
// ------------------------------------------------------------------

func TestSignAttestation_NilAttestation(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := SignAttestation(nil, priv, "k1"); err == nil {
		t.Error("SignAttestation(nil) = nil, want error")
	}
}

func TestSignAttestation_LegacyPath_SignAndVerify(t *testing.T) {
	// Exercise the legacy single-key sign path. The sync.go
	// signAttestation method falls back to this when no
	// keyring is configured.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	//nolint:staticcheck // SA1019
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	keyID := "legacy-key-1"
	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
	}
	if err := SignAttestation(a, priv, keyID); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if a.Signature.Algorithm != AlgorithmECDSAP256 {
		t.Errorf("Signature.Algorithm = %q, want %q", a.Signature.Algorithm, AlgorithmECDSAP256)
	}
	if a.PublicKey.Value == "" {
		t.Error("PublicKey.Value is empty after sign")
	}
	// The signature must verify.
	if err := VerifyAttestation(a); err != nil {
		t.Errorf("VerifyAttestation: %v", err)
	}
	// And tampering with the payload must fail verification.
	a.Severity = SeverityLow
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation after tampering = nil, want error")
	}
	// And the pubBytes must be the SEC 1 encoding.
	_ = pubBytes
}

// ------------------------------------------------------------------
// attest.go: VerifyAttestation error paths
// ------------------------------------------------------------------

func TestVerifyAttestation_NilAttestation(t *testing.T) {
	if err := VerifyAttestation(nil); err == nil {
		t.Error("VerifyAttestation(nil) = nil, want error")
	}
}

func TestVerifyAttestation_UnsupportedSigAlgorithm(t *testing.T) {
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: "rsa-pss-256"},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with rsa-pss = nil, want error")
	}
}

func TestVerifyAttestation_UnsupportedPubKeyAlgorithm(t *testing.T) {
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256},
		PublicKey: PublicKeyEnvelope{Algorithm: "ed25519"},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with ed25519 pubkey = nil, want error")
	}
}

func TestVerifyAttestation_KeyIDMismatch(t *testing.T) {
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "sig-key"},
		PublicKey: PublicKeyEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "pub-key"},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with keyId mismatch = nil, want error")
	}
}

func TestVerifyAttestation_BadBase64PubKey(t *testing.T) {
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1"},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     "!!!not-base64!!!",
		},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with bad base64 = nil, want error")
	}
}

func TestVerifyAttestation_WrongLengthPubKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1"},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     short,
		},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with short pubkey = nil, want error")
	}
}

func TestVerifyAttestation_BadPrefixPubKey(t *testing.T) {
	// 65 bytes but the first byte is not 0x04 (SEC 1 uncompressed).
	bad := make([]byte, 65)
	bad[0] = 0x05 // not 0x04
	a := &IOCAttestation{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1"},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(bad),
		},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with bad prefix = nil, want error")
	}
}

func TestVerifyAttestation_BadSignature(t *testing.T) {
	// A 65-byte SEC 1 pub key with a bogus ASN.1 signature.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//nolint:staticcheck
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString([]byte("bogus-sig")),
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(pubBytes),
		},
	}
	if err := VerifyAttestation(a); err == nil {
		t.Error("VerifyAttestation with bogus sig = nil, want error")
	}
}

// ------------------------------------------------------------------
// bundle.go: Sign / Verify edge cases
// ------------------------------------------------------------------

func TestBundle_Sign_NilBundle(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := (*Bundle)(nil).Sign(priv, "k1"); err == nil {
		t.Error("(*Bundle)(nil).Sign = nil, want error")
	}
}

func TestBundle_SignWithKeyRing_NilBundle(t *testing.T) {
	kr, _ := LoadKeyRing("")
	if err := (*Bundle)(nil).SignWithKeyRing(kr); err == nil {
		t.Error("(*Bundle)(nil).SignWithKeyRing = nil, want error")
	}
}

func TestBundle_SignWithKeyRing_NilKeyRing(t *testing.T) {
	b := &Bundle{}
	if err := b.SignWithKeyRing(nil); err == nil {
		t.Error("Bundle.SignWithKeyRing(nil) = nil, want error")
	}
}

func TestBundle_VerifyAll_NilBundle(t *testing.T) {
	if err := (*Bundle)(nil).VerifyAll(); err == nil {
		t.Error("(*Bundle)(nil).VerifyAll = nil, want error")
	}
}

func TestBundle_Add_NilAttestation(t *testing.T) {
	b := &Bundle{}
	// Adding nil should not panic and should not grow the
	// attestations slice.
	before := len(b.Attestations)
	b.Add(IOCAttestation{}) // zero-value is not nil
	if len(b.Attestations) != before+1 {
		t.Errorf("len(Attestations) = %d, want %d", len(b.Attestations), before+1)
	}
}

// ------------------------------------------------------------------
// sync.go: AddDiscoveredPeer
// ------------------------------------------------------------------

func TestSync_AddDiscoveredPeer_NilSync(t *testing.T) {
	// AddDiscoveredPeer on a nil *Sync should be a no-op (no panic).
	var s *Sync
	s.AddDiscoveredPeer("https://x.example.com")
}

func TestSync_AddDiscoveredPeer_EmptyURL(t *testing.T) {
	// Spin up a real Sync.
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID: "test-instance",
		KeyRing:    kr,
		Store:      store,
		Tier:       tier.TierProfessional,
		Peers:      []string{"https://a.example.com"},
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	s.AddDiscoveredPeer("")
	if got := s.Peers(); len(got) != 1 {
		t.Errorf("peers after empty add = %v, want unchanged (1 entry)", got)
	}
}

func TestSync_AddDiscoveredPeer_DuplicateIsNoOp(t *testing.T) {
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID: "test-instance",
		KeyRing:    kr,
		Store:      store,
		Tier:       tier.TierProfessional,
		Peers:      []string{"https://a.example.com"},
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	s.AddDiscoveredPeer("https://a.example.com")
	if got := s.Peers(); len(got) != 1 {
		t.Errorf("peers after dup add = %v, want 1 (no duplicates)", got)
	}
}

func TestSync_AddDiscoveredPeer_NewURL(t *testing.T) {
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID: "test-instance",
		KeyRing:    kr,
		Store:      store,
		Tier:       tier.TierProfessional,
		Peers:      []string{"https://a.example.com"},
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	s.AddDiscoveredPeer("https://b.example.com")
	peers := s.Peers()
	if len(peers) != 2 {
		t.Errorf("peers = %v, want 2 entries", peers)
	}
	hasA, hasB := false, false
	for _, p := range peers {
		if p == "https://a.example.com" {
			hasA = true
		}
		if p == "https://b.example.com" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("peers = %v, want both a and b", peers)
	}
}

// ------------------------------------------------------------------
// sync.go: RunReceiver
// ------------------------------------------------------------------

func TestSync_RunReceiver_CanReceiveFalse_ReturnsImmediately(t *testing.T) {
	// On a tier that cannot receive (Community), RunReceiver
	// must return immediately without blocking.
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:     "test-instance",
		KeyRing:        kr,
		Store:          store,
		Tier:           tier.TierCommunity,
		EnableReceive:  false,
		GossipInterval: time.Hour, // would block for an hour if not guarded
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.RunReceiver(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good: returned without needing ctx timeout
	case <-ctx.Done():
		t.Fatal("RunReceiver did not return within 2s on Community tier; expected immediate exit")
	}
}

func TestSync_RunReceiver_ContextCancelStops(t *testing.T) {
	// On Professional+ with a long interval, RunReceiver should
	// exit promptly when the context is cancelled.
	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:     "test-instance",
		KeyRing:        kr,
		Store:          store,
		Tier:           tier.TierProfessional,
		EnableReceive:  true,
		Peers:          []string{}, // no peers, so the loop just blocks on the ticker
		GossipInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunReceiver(ctx)
		close(done)
	}()
	// Give it a moment to enter the for loop.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// good: returned after cancel
	case <-time.After(2 * time.Second):
		t.Fatal("RunReceiver did not return within 2s after context cancel")
	}
}

// ------------------------------------------------------------------
// sync.go: FetchPeer error paths (peer returns 500, malformed JSON)
// ------------------------------------------------------------------

func TestSync_FetchPeer_PeerReturnsError(t *testing.T) {
	// Server returns 500 with a JSON body. FetchPeer should
	// return an error mentioning the status code.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"backend down"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		KeyRing:       kr,
		Store:         store,
		Tier:          tier.TierProfessional,
		EnableReceive: true,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	_, ferr := s.FetchPeer(context.Background(), srv.URL)
	if ferr == nil {
		t.Fatal("FetchPeer on 500 = nil, want error")
	}
	if !strings.Contains(ferr.Error(), "500") {
		t.Errorf("FetchPeer error = %v, want it to mention status 500", ferr)
	}
}

func TestSync_FetchPeer_PeerReturnsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		KeyRing:       kr,
		Store:         store,
		Tier:          tier.TierProfessional,
		EnableReceive: true,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	_, ferr := s.FetchPeer(context.Background(), srv.URL)
	if ferr == nil {
		t.Fatal("FetchPeer on malformed JSON = nil, want error")
	}
	if !strings.Contains(ferr.Error(), "decode") {
		t.Errorf("FetchPeer error = %v, want it to mention 'decode'", ferr)
	}
}

func TestSync_FetchPeer_PeerReturnsInvalidSignature(t *testing.T) {
	// A syntactically valid Bundle whose signature is bad.
	// FetchPeer should return a "verify" error.
	bad := &Bundle{
		BundleID:   "test-bad-bundle",
		InstanceID: "evil-peer",
		IssuedAt:   time.Now().UTC(),
		Count:      1,
		Attestations: []IOCAttestation{
			{
				IOCType:  IOCTypeProxyResponse,
				Severity: SeverityHigh,
			},
		},
		// No signature: VerifyAll will fail.
	}
	data, _ := jsonEncode(bad)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dir := t.TempDir()
	kr, _ := LoadKeyRing("")
	store, _ := NewStore(StoreConfig{DiskPath: filepath.Join(dir, "store.json")})
	s, err := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		KeyRing:       kr,
		Store:         store,
		Tier:          tier.TierProfessional,
		EnableReceive: true,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	_, ferr := s.FetchPeer(context.Background(), srv.URL)
	if ferr == nil {
		t.Fatal("FetchPeer on bad signature = nil, want error")
	}
	if !strings.Contains(ferr.Error(), "verify") {
		t.Errorf("FetchPeer error = %v, want it to mention 'verify'", ferr)
	}
}

// ------------------------------------------------------------------
// sync.go: nil-receiver guards
// ------------------------------------------------------------------

func TestSync_NilSafeMethods(t *testing.T) {
	// All these methods must be safe to call on a nil *Sync.
	// (ActiveKeys is intentionally NOT nil-safe; it has a
	// documented precondition of a non-nil receiver.)
	var s *Sync
	if s.IsShare() {
		t.Error("(*Sync)(nil).IsShare() = true, want false")
	}
	if s.IsReceive() {
		t.Error("(*Sync)(nil).IsReceive() = true, want false")
	}
	if got := s.Peers(); got != nil {
		t.Errorf("(*Sync)(nil).Peers() = %v, want nil", got)
	}
	if got := s.Reputation(); got != nil {
		t.Errorf("(*Sync)(nil).Reputation() = %v, want nil", got)
	}
	s.SetShare(true)     // must not panic
	s.SetReceive(true)   // must not panic
	s.SetReputation(nil) // must not panic
}

// ------------------------------------------------------------------
// keyring.go: persist failure (read-only file)
// ------------------------------------------------------------------

func TestKeyRing_Rotate_PersistFailure(t *testing.T) {
	// A read-only data dir causes persistLocked to fail at
	// the os.WriteFile step. Rotate returns the error.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := LoadKeyRing(filepath.Join(dir, "key.json"))
	if err == nil {
		t.Fatal("LoadKeyRing on read-only dir should fail")
	}
}

// ------------------------------------------------------------------
// keyring.go: v1 migration (keyring_persisted_v1.json)
// ------------------------------------------------------------------

func TestKeyRing_LoadV1File(t *testing.T) {
	// Construct a v1 keyring file (single-key, the pre-Task-5
	// format) and verify LoadKeyRing migrates it to v2.
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	// Generate a fresh P-256 key and encode as v1.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, _ := x509.MarshalECPrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}))
	//nolint:staticcheck
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	v1 := iocKeyOnDiskV1{
		Algorithm:     "ecdsa-p256",
		KeyID:         "v1-migrated",
		PrivateKeyPEM: pemStr,
		PublicKeySEC1: base64.StdEncoding.EncodeToString(pubBytes),
	}
	data, _ := jsonEncode(v1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing(v1): %v", err)
	}
	if got := kr.CurrentKeyID(); got != "v1-migrated" {
		t.Errorf("CurrentKeyID = %q, want v1-migrated", got)
	}
	// After migration, the file should be re-written in v2 format.
	// Verify by reading the file and checking it has the v2 shape.
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), `"version":2`) &&
		!strings.Contains(string(after), `"version": 2`) {
		t.Errorf("v1 file not rewritten as v2; contents: %s", string(after))
	}
}

// ------------------------------------------------------------------
// keyring.go: LookupKey, Sign error paths
// ------------------------------------------------------------------

func TestKeyRing_LookupKey_Unknown(t *testing.T) {
	kr, _ := LoadKeyRing("")
	if got := kr.LookupKey("not-in-ring"); got != nil {
		t.Errorf("LookupKey(unknown) = %v, want nil", got)
	}
}

func TestKeyRing_Sign_NoCurrentKey(t *testing.T) {
	// A KeyRing with current == "" should fail Sign with a
	// clear error.
	kr, _ := LoadKeyRing("")
	kr.mu.Lock()
	kr.current = ""
	kr.mu.Unlock()
	_, _, err := kr.Sign([]byte("anything"))
	if err == nil {
		t.Error("KeyRing.Sign with no current key = nil, want error")
	}
}

func TestKeyRing_Sign_CurrentKeyNotInMap(t *testing.T) {
	// A KeyRing with current pointing to a non-existent entry
	// should also fail.
	kr, _ := LoadKeyRing("")
	kr.mu.Lock()
	kr.current = "ghost-key-id"
	kr.mu.Unlock()
	_, _, err := kr.Sign([]byte("anything"))
	if err == nil {
		t.Error("KeyRing.Sign with ghost current = nil, want error")
	}
}

// ------------------------------------------------------------------
// keyring.go: CurrentKey error paths
// ------------------------------------------------------------------

func TestKeyRing_CurrentKey_NoCurrent(t *testing.T) {
	kr, _ := LoadKeyRing("")
	kr.mu.Lock()
	kr.current = ""
	kr.mu.Unlock()
	_, _, err := kr.CurrentKey()
	if err == nil {
		t.Error("CurrentKey with no current = nil, want error")
	}
}

func TestKeyRing_CurrentKey_GhostID(t *testing.T) {
	kr, _ := LoadKeyRing("")
	kr.mu.Lock()
	kr.current = "ghost"
	kr.mu.Unlock()
	_, _, err := kr.CurrentKey()
	if err == nil {
		t.Error("CurrentKey with ghost id = nil, want error")
	}
}

// ------------------------------------------------------------------
// reputation.go: Observe mixed + edge cases
// ------------------------------------------------------------------

func TestReputationStore_Observe_EmptyInstanceID(t *testing.T) {
	rs, err := NewReputationStore(ReputationConfig{})
	if err != nil {
		t.Fatalf("NewReputationStore: %v", err)
	}
	// Empty InstanceID is a no-op (per the impl).
	rs.Observe("", 5, 0, "")
	if rs.Size() != 0 {
		t.Errorf("Size after empty InstanceID Observe = %d, want 0", rs.Size())
	}
}

func TestReputationStore_Observe_AllAccepted(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.Observe("peer-a", 10, 0, "")
	// Score should be near 1.0 (only one observation, no decay).
	score := rs.Score("peer-a")
	if score < 0.99 {
		t.Errorf("Score after all-accepted = %v, want >= 0.99", score)
	}
}

func TestReputationStore_Observe_AllRejected(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	// One all-rejected observation drops score from 1.0 to
	// 1.0*0.7 + 0.0*0.3 = 0.7.
	rs.Observe("peer-b", 0, 10, "bad signature")
	score := rs.Score("peer-b")
	if score > 0.71 || score < 0.69 {
		t.Errorf("Score after one all-rejected = %v, want ~0.7", score)
	}
	// Three consecutive rejections drop to 0.7^3 ≈ 0.343.
	rs.Observe("peer-b", 0, 10, "bad signature")
	rs.Observe("peer-b", 0, 10, "bad signature")
	score2 := rs.Score("peer-b")
	if score2 > 0.35 || score2 < 0.33 {
		t.Errorf("Score after 3 rejections = %v, want ~0.343", score2)
	}
}

func TestReputationStore_Observe_Mixed(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	// First, all-accepted to get score to 1.0.
	rs.Observe("peer-c", 10, 0, "")
	// Then mixed: 3 accepted, 1 rejected. With weight=0.3, the
	// new observation is 0.75, so score becomes
	// 1.0*0.7 + 0.75*0.3 = 0.7 + 0.225 = 0.925.
	rs.Observe("peer-c", 3, 1, "")
	score := rs.Score("peer-c")
	if score < 0.9 || score > 0.95 {
		t.Errorf("Score after mixed = %v, want ~0.925 (range 0.9-0.95)", score)
	}
}

func TestReputationStore_Observe_Neutral(t *testing.T) {
	// total == 0 (no IOCs exchanged) is treated as a neutral
	// observation (0.5), trending the score toward 0.5.
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.Observe("peer-d", 10, 0, "") // score -> 1.0
	rs.Observe("peer-d", 0, 0, "")  // neutral; score -> 1.0*0.7 + 0.5*0.3 = 0.85
	score := rs.Score("peer-d")
	if score < 0.84 || score > 0.86 {
		t.Errorf("Score after neutral = %v, want ~0.85 (range 0.84-0.86)", score)
	}
}

func TestReputationStore_Score_UnknownPeer(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	if got := rs.Score("never-seen"); got != 1.0 {
		t.Errorf("Score(unknown) = %v, want 1.0 (innocent until proven guilty)", got)
	}
}

func TestReputationStore_IsAcceptable(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{Threshold: 0.5})
	// Unknown peer is acceptable.
	if !rs.IsAcceptable("never-seen") {
		t.Error("IsAcceptable(unknown) = false, want true")
	}
	// All-accepted peer is acceptable.
	rs.Observe("peer-x", 10, 0, "")
	if !rs.IsAcceptable("peer-x") {
		t.Error("IsAcceptable(good peer) = false, want true")
	}
	// 3 consecutive all-rejected should drop below threshold.
	rs.Observe("peer-y", 0, 10, "bad")
	rs.Observe("peer-y", 0, 10, "bad")
	rs.Observe("peer-y", 0, 10, "bad")
	if rs.IsAcceptable("peer-y") {
		t.Error("IsAcceptable(3x rejected peer) = true, want false")
	}
}

func TestReputationStore_Flush_NoDiskPath(t *testing.T) {
	// Flush with no DiskPath is a no-op (no error).
	rs, _ := NewReputationStore(ReputationConfig{})
	if err := rs.Flush(); err != nil {
		t.Errorf("Flush with no DiskPath: %v", err)
	}
}

func TestReputationStore_LoadFromDisk_NoFile(t *testing.T) {
	// A non-existent file is treated as "first run" (no error).
	dir := t.TempDir()
	rs, err := NewReputationStore(ReputationConfig{DiskPath: filepath.Join(dir, "rep.json")})
	if err != nil {
		t.Fatalf("NewReputationStore: %v", err)
	}
	if rs.Size() != 0 {
		t.Errorf("Size = %d, want 0 (first run)", rs.Size())
	}
}

func TestReputationStore_RoundTrip(t *testing.T) {
	// Observe, flush, re-load, verify the score persisted.
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")
	rs1, _ := NewReputationStore(ReputationConfig{DiskPath: path})
	rs1.Observe("peer-z", 0, 5, "bad")
	rs1.Observe("peer-z", 0, 5, "bad")
	score1 := rs1.Score("peer-z")
	if err := rs1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	rs2, err := NewReputationStore(ReputationConfig{DiskPath: path})
	if err != nil {
		t.Fatalf("NewReputationStore (reload): %v", err)
	}
	score2 := rs2.Score("peer-z")
	if score1 != score2 {
		t.Errorf("score after reload = %v, want %v", score2, score1)
	}
}

// ------------------------------------------------------------------
// reputation.go: Flush failure path
// ------------------------------------------------------------------

func TestReputationStore_Flush_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	rs, _ := NewReputationStore(ReputationConfig{DiskPath: filepath.Join(dir, "rep.json")})
	rs.Observe("peer-q", 1, 0, "")
	if err := rs.Flush(); err == nil {
		t.Error("Flush on read-only dir = nil, want error")
	}
}

// ------------------------------------------------------------------
// reputation_math.go: decayFactor
// ------------------------------------------------------------------

func TestDecayFactor_ZeroHalfLife(t *testing.T) {
	if got := decayFactor(time.Hour, 0); got != 0 {
		t.Errorf("decayFactor(elapsed=1h, halfLife=0) = %v, want 0", got)
	}
}

func TestDecayFactor_ZeroElapsed(t *testing.T) {
	if got := decayFactor(0, time.Hour); got != 1.0 {
		t.Errorf("decayFactor(elapsed=0) = %v, want 1.0 (no decay)", got)
	}
}

func TestDecayFactor_HalfLife(t *testing.T) {
	// At elapsed == halfLife, decay should be ~0.5.
	got := decayFactor(time.Hour, time.Hour)
	if got < 0.49 || got > 0.51 {
		t.Errorf("decayFactor(elapsed=halfLife) = %v, want ~0.5", got)
	}
}

func TestDecayFactor_DoubleHalfLife(t *testing.T) {
	// At elapsed == 2 * halfLife, decay should be ~0.25.
	got := decayFactor(2*time.Hour, time.Hour)
	if got < 0.24 || got > 0.26 {
		t.Errorf("decayFactor(elapsed=2*halfLife) = %v, want ~0.25", got)
	}
}

// ------------------------------------------------------------------
// jsonEncode is a thin wrapper over encoding/json.
// ------------------------------------------------------------------

func jsonEncode(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
