// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// keyring_test.go contains unit tests for the KeyRing primitive
// and the v1->v2 migration. The tests cover the happy paths and
// the major failure modes: v1 migration, rotate-and-verify, sign
// with current key, verify with old retired key, atomic persist.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B. See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// TestKeyRing_GenerateFresh verifies that a fresh keyring (no
// on-disk file) generates a current key and can sign+verify.
func TestKeyRing_GenerateFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if kr.CurrentKeyID() == "" {
		t.Errorf("CurrentKeyID is empty")
	}
	// Sign + verify round-trip.
	digest := HashSHA256([]byte("hello"))
	keyID, sig, err := kr.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := kr.Verify(keyID, digest, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
	// The signature envelope's keyId should equal the current key.
	if keyID != kr.CurrentKeyID() {
		t.Errorf("keyId mismatch: %q != %q", keyID, kr.CurrentKeyID())
	}
}

// TestKeyRing_PersistAndReload verifies that a keyring survives
// process restarts (round-trip through disk).
func TestKeyRing_PersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	originalKeyID := kr.CurrentKeyID()

	// Reload.
	kr2, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing 2: %v", err)
	}
	if kr2.CurrentKeyID() != originalKeyID {
		t.Errorf("CurrentKeyID drift: %q != %q", kr2.CurrentKeyID(), originalKeyID)
	}
	// Sign with the original key, verify with the reloaded key.
	digest := HashSHA256([]byte("hello"))
	_, sig, err := kr.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := kr2.Verify(originalKeyID, digest, sig); err != nil {
		t.Errorf("Verify after reload: %v", err)
	}
}

// TestKeyRing_RotateGeneratesNewKey verifies that Rotate()
// returns a new keyId, that the old key is marked retired,
// and that the new key can sign+verify.
func TestKeyRing_RotateGeneratesNewKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	oldKeyID := kr.CurrentKeyID()

	newKeyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKeyID == oldKeyID {
		t.Errorf("new keyId should differ from old: %q", newKeyID)
	}
	if kr.CurrentKeyID() != newKeyID {
		t.Errorf("CurrentKeyID = %q, want %q", kr.CurrentKeyID(), newKeyID)
	}
	// The old key should be in the ring as retired.
	keys := kr.ActiveKeys()
	var oldKey, newKey *KeyInfo
	for i := range keys {
		if keys[i].KeyID == oldKeyID {
			oldKey = &keys[i]
		}
		if keys[i].KeyID == newKeyID {
			newKey = &keys[i]
		}
	}
	if oldKey == nil {
		t.Errorf("old key %q not in ActiveKeys", oldKeyID)
	} else {
		if !oldKey.RetiredAt.After(time.Time{}) {
			t.Errorf("old key not retired (RetiredAt = %v)", oldKey.RetiredAt)
		}
		if oldKey.IsCurrent {
			t.Errorf("old key still marked IsCurrent")
		}
	}
	if newKey == nil {
		t.Errorf("new key %q not in ActiveKeys", newKeyID)
	} else {
		if newKey.IsCurrent {
			// Wait, that's what we want. If we get here, fine.
		} else {
			t.Errorf("new key not marked IsCurrent")
		}
		if !newKey.RetiredAt.IsZero() {
			t.Errorf("new key has non-zero RetiredAt = %v", newKey.RetiredAt)
		}
	}
}

// TestKeyRing_OldKeyStillVerifies verifies that a retired key
// can still verify attestations it signed before rotation.
// This is the whole point of retaining retired keys.
func TestKeyRing_OldKeyStillVerifies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	oldKeyID := kr.CurrentKeyID()

	// Sign something with the old key.
	digest := HashSHA256([]byte("retired"))
	_, sig, err := kr.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Rotate.
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Verify with the old key. Should still work.
	if err := kr.Verify(oldKeyID, digest, sig); err != nil {
		t.Errorf("Verify with retired key: %v", err)
	}

	// Verify with the new key. Should fail (wrong key).
	newKeyID := kr.CurrentKeyID()
	if err := kr.Verify(newKeyID, digest, sig); err == nil {
		t.Errorf("Verify with new key against old signature should fail")
	}
}

// TestKeyRing_UnknownKeyFails verifies that Verify() rejects
// unknown keyIds.
func TestKeyRing_UnknownKeyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	digest := HashSHA256([]byte("x"))
	_, sig, _ := kr.Sign(digest)
	if err := kr.Verify("ioc-DOESNOTEXIST", digest, sig); err == nil {
		t.Errorf("expected error for unknown keyId")
	}
}

// TestKeyRing_LookupKeyReturnsSEC1 verifies that LookupKey
// returns a valid SEC 1-encoded public key for a known keyId.
func TestKeyRing_LookupKeyReturnsSEC1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	keyID := kr.CurrentKeyID()
	pub := kr.LookupKey(keyID)
	if pub == nil {
		t.Fatalf("LookupKey(%q) returned nil", keyID)
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Errorf("invalid SEC 1 encoding: len=%d, first byte=0x%x", len(pub), pub[0])
	}
	// Unknown keyId returns nil.
	if pub := kr.LookupKey("ioc-unknown"); pub != nil {
		t.Errorf("LookupKey of unknown keyId = %v, want nil", pub)
	}
}

// TestKeyRing_V1Migration verifies that a v1 file (the
// Task 4 format) is auto-migrated to v2 on first load.
func TestKeyRing_V1Migration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	// Write a v1 file by hand. The format is the same as the
	// Task 4 loadOrGenerateIOCKey output.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//nolint:staticcheck // SA1019: see SignAttestation.
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	keyID := "ioc-v1key01"
	pemBytes, _ := encodeRingKeyPEM(priv)
	v1 := iocKeyOnDiskV1{
		Algorithm:     "ecdsa-p256",
		KeyID:         keyID,
		PrivateKeyPEM: pemBytes,
		PublicKeySEC1: base64.StdEncoding.EncodeToString(pubBytes),
	}
	data, _ := json.MarshalIndent(v1, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	// Load. Should auto-migrate to v2.
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if kr.CurrentKeyID() != keyID {
		t.Errorf("CurrentKeyID = %q, want %q (migrated v1)", kr.CurrentKeyID(), keyID)
	}

	// Sign+verify works.
	digest := HashSHA256([]byte("v1"))
	_, sig, err := kr.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := kr.Verify(keyID, digest, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// The on-disk file should now be in v2 format.
	data2, _ := os.ReadFile(path)
	var onDisk keyRingOnDisk
	if err := json.Unmarshal(data2, &onDisk); err != nil {
		t.Fatalf("unmarshal v2: %v", err)
	}
	if onDisk.Version != KeyRingFileVersion {
		t.Errorf("on-disk version = %d, want %d", onDisk.Version, KeyRingFileVersion)
	}
	if onDisk.Current != keyID {
		t.Errorf("on-disk current = %q, want %q", onDisk.Current, keyID)
	}
	if len(onDisk.Keys) != 1 {
		t.Errorf("on-disk keys = %d, want 1", len(onDisk.Keys))
	}
}

// TestKeyRing_RotatePersistsImmediately verifies that Rotate
// persists the new state to disk (so a crash mid-rotation
// doesn't lose the new key).
func TestKeyRing_RotatePersistsImmediately(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	oldKeyID := kr.CurrentKeyID()
	newKeyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Reload from disk. The new keyId should be the current.
	kr2, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing after rotate: %v", err)
	}
	if kr2.CurrentKeyID() != newKeyID {
		t.Errorf("reloaded CurrentKeyID = %q, want %q",
			kr2.CurrentKeyID(), newKeyID)
	}
	// Both keys should be in the ring.
	keys := kr2.ActiveKeys()
	foundOld, foundNew := false, false
	for _, k := range keys {
		if k.KeyID == oldKeyID {
			foundOld = true
			if k.IsCurrent {
				t.Errorf("old key still IsCurrent after rotate")
			}
		}
		if k.KeyID == newKeyID {
			foundNew = true
			if !k.IsCurrent {
				t.Errorf("new key not IsCurrent after rotate")
			}
		}
	}
	if !foundOld {
		t.Errorf("old key %q not in ActiveKeys after rotate", oldKeyID)
	}
	if !foundNew {
		t.Errorf("new key %q not in ActiveKeys after rotate", newKeyID)
	}
}

// TestKeyRing_SignThenRotateThenVerifyOldSignature is the
// integration test for the whole "key rotation preserves
// verifiability of past signatures" story.
func TestKeyRing_SignThenRotateThenVerifyOldSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)

	// Sign 3 messages under the current key.
	oldKeyID := kr.CurrentKeyID()
	sigs := make([][]byte, 3)
	digests := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		digests[i] = HashSHA256([]byte(strings.Repeat("x", i+1)))
		_, sigs[i], _ = kr.Sign(digests[i])
	}

	// Rotate 3 more times. Now we have 4 keys total: 3 retired,
	// 1 current. The first 3 sigs should still verify under
	// the first key.
	for i := 0; i < 3; i++ {
		if _, err := kr.Rotate(); err != nil {
			t.Fatalf("Rotate %d: %v", i, err)
		}
	}

	for i := 0; i < 3; i++ {
		if err := kr.Verify(oldKeyID, digests[i], sigs[i]); err != nil {
			t.Errorf("sig %d verify with old key: %v", i, err)
		}
	}

	// The current key is the 4th.
	keys := kr.ActiveKeys()
	if len(keys) != 4 {
		t.Errorf("ActiveKeys len = %d, want 4", len(keys))
	}
	currentCount := 0
	for _, k := range keys {
		if k.IsCurrent {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Errorf("IsCurrent count = %d, want 1", currentCount)
	}
}

// TestKeyRing_EphemeralNoPersist verifies that an empty
// persist path generates an in-memory key (used by tests
// that don't need persistence).
func TestKeyRing_EphemeralNoPersist(t *testing.T) {
	kr, err := LoadKeyRing("")
	if err != nil {
		t.Fatalf("LoadKeyRing(ephemeral): %v", err)
	}
	if kr.CurrentKeyID() == "" {
		t.Errorf("ephemeral keyring has no current key")
	}
}

// TestKeyRing_BadV1FileFails verifies that a v1 file with
// an unparseable PEM is rejected (we don't silently
// regenerate, because that would be a key-loss bug).
func TestKeyRing_BadV1FileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	v1 := iocKeyOnDiskV1{
		Algorithm:     "ecdsa-p256",
		KeyID:         "ioc-bad",
		PrivateKeyPEM: "not a PEM block",
		PublicKeySEC1: base64.StdEncoding.EncodeToString(make([]byte, 65)),
	}
	data, _ := json.MarshalIndent(v1, "", "  ")
	_ = os.WriteFile(path, data, 0o600)
	_, err := LoadKeyRing(path)
	if err == nil {
		t.Errorf("expected error for unparseable v1 file")
	}
}

// TestKeyRing_BadV2FileFails verifies that a v2 file with
// a missing current keyId is rejected.
func TestKeyRing_BadV2FileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	onDisk := keyRingOnDisk{
		Version: 2,
		Current: "", // missing
		Keys:    []ringKey{},
	}
	data, _ := json.MarshalIndent(onDisk, "", "  ")
	_ = os.WriteFile(path, data, 0o600)
	_, err := LoadKeyRing(path)
	if err == nil {
		t.Errorf("expected error for v2 file with missing current keyId")
	}
}

// TestKeyRing_CorruptFileFails verifies that a completely
// corrupt file is rejected (not auto-migrated).
func TestKeyRing_CorruptFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	_ = os.WriteFile(path, []byte("not valid json at all"), 0o600)
	_, err := LoadKeyRing(path)
	if err == nil {
		t.Errorf("expected error for corrupt file")
	}
}

// TestKeyRing_SyncRotateKeyEndToEnd verifies that the Sync
// can rotate its keyring at runtime.
func TestKeyRing_SyncRotateKeyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	store, _ := NewStore(StoreConfig{Capacity: 100})
	sync, err := NewSync(SyncConfig{
		InstanceID: "test",
		KeyRing:    kr,
		Store:      store,
		Tier:       tier.TierCommunity, // irrelevant for this test
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	oldKeyID := sync.cfg.KeyRing.CurrentKeyID()
	newKeyID, err := sync.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKeyID == oldKeyID {
		t.Errorf("new keyId = old keyId: %q", newKeyID)
	}
	// ActiveKeys returns the redaction view.
	keys := sync.ActiveKeys()
	if len(keys) != 2 {
		t.Errorf("ActiveKeys len = %d, want 2", len(keys))
	}
}

// TestKeyRing_SyncRotateWithoutKeyRingFails verifies that
// RotateKey on a Sync that was constructed without a
// KeyRing returns an error.
func TestKeyRing_SyncRotateWithoutKeyRingFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	// Build a keyring just to get a key+keyID, then construct
	// a Sync WITHOUT the keyring.
	kr, _ := LoadKeyRing(path)
	_, priv, _ := kr.CurrentKey()
	_ = priv // we don't actually use this
	store, _ := NewStore(StoreConfig{Capacity: 100})
	// Use a single key from the keyring (to satisfy NewSync's
	// single-key path).
	_, priv2, _ := kr.CurrentKey()
	sync, err := NewSync(SyncConfig{
		InstanceID: "test",
		SigningKey: priv2,
		KeyID:      "ioc-direct",
		Store:      store,
		Tier:       tier.TierCommunity,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	_, err = sync.RotateKey()
	if err == nil {
		t.Errorf("expected error rotating without KeyRing")
	}
	if !strings.Contains(err.Error(), "KeyRing") {
		t.Errorf("err = %q, want contains 'KeyRing'", err.Error())
	}
}

// TestKeyRing_ActiveKeysIsSnapshot verifies that ActiveKeys
// returns a snapshot (not a live view), so callers can
// iterate without holding the lock.
func TestKeyRing_ActiveKeysIsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, _ := LoadKeyRing(path)
	keys := kr.ActiveKeys()
	if len(keys) != 1 {
		t.Fatalf("ActiveKeys len = %d, want 1", len(keys))
	}
	// Rotate in another goroutine. The snapshot should NOT
	// change.
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("snapshot changed after rotate: len = %d, want 1", len(keys))
	}
	// A new snapshot has 2 keys.
	keys2 := kr.ActiveKeys()
	if len(keys2) != 2 {
		t.Errorf("new snapshot len = %d, want 2", len(keys2))
	}
}

// ------------------------------------------------------------------
// v3.4.0+ retired-key TTL tests (b1)
// ------------------------------------------------------------------

// TestKeyRing_PruneExpired_NoneExpired is the common case:
// all retired keys are within the TTL, nothing is pruned.
func TestKeyRing_PruneExpired_NoneExpired(t *testing.T) {
	dir := t.TempDir()
	kr, err := LoadKeyRing(dir + "/key.json")
	if err != nil {
		t.Fatal(err)
	}
	kr.SetRetiredKeyTTL(90 * 24 * time.Hour)
	// Rotate twice to create two retired keys.
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	before := len(kr.ActiveKeys())
	removed := kr.PruneExpired(time.Now().UTC())
	after := len(kr.ActiveKeys())
	if len(removed) != 0 {
		t.Errorf("removed %d keys, want 0 (none expired yet)", len(removed))
	}
	if before != after {
		t.Errorf("ActiveKeys before=%d after=%d, want equal", before, after)
	}
}

// TestKeyRing_PruneExpired_OneExpired rotates twice and then
// back-dates the first retired key so it expires. The second
// retired key is still within the TTL. PruneExpired returns
// the expired key's ID and leaves the other in place.
func TestKeyRing_PruneExpired_OneExpired(t *testing.T) {
	dir := t.TempDir()
	kr, err := LoadKeyRing(dir + "/key.json")
	if err != nil {
		t.Fatal(err)
	}
	kr.SetRetiredKeyTTL(1 * time.Hour)
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	first, err := kr.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Manually back-date the first retired key's RetiredAt
	// to 2 hours ago (past the 1h TTL).
	kr.mu.Lock()
	for id, rk := range kr.keys {
		if id != kr.current && rk.KeyID != first {
			rk.RetiredAt = time.Now().UTC().Add(-2 * time.Hour)
			break
		}
	}
	kr.mu.Unlock()
	removed := kr.PruneExpired(time.Now().UTC())
	if len(removed) != 1 {
		t.Errorf("removed %d keys, want 1", len(removed))
	}
	// The current key must still be present.
	if kr.CurrentKeyID() == "" {
		t.Error("current key vanished after prune")
	}
}

// TestKeyRing_PruneExpired_CurrentKeyNeverPruned is the
// invariant: the current key is never pruned, even if its
// RetiredAt were zero and the TTL is 0.
func TestKeyRing_PruneExpired_CurrentKeyNeverPruned(t *testing.T) {
	dir := t.TempDir()
	kr, _ := LoadKeyRing(dir + "/key.json")
	kr.SetRetiredKeyTTL(0) // use default (90d)
	currentID := kr.CurrentKeyID()
	if currentID == "" {
		t.Fatal("no current key")
	}
	_ = kr.PruneExpired(time.Now().UTC().Add(365 * 24 * time.Hour)) // far future
	if kr.CurrentKeyID() != currentID {
		t.Error("current key was pruned (must never happen)")
	}
}

// TestKeyRing_SetRetiredKeyTTL confirms the setter takes
// effect and is observable via subsequent PruneExpired calls.
func TestKeyRing_SetRetiredKeyTTL(t *testing.T) {
	dir := t.TempDir()
	kr, _ := LoadKeyRing(dir + "/key.json")
	kr.SetRetiredKeyTTL(7 * 24 * time.Hour)
	kr.mu.RLock()
	got := kr.retiredKeyTTL
	kr.mu.RUnlock()
	if got != 7*24*time.Hour {
		t.Errorf("retiredKeyTTL = %v, want 7d", got)
	}
}
