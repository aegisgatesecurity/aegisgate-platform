// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - IOC Hardening Tests (v4.5.1+ Phase 4)
// =========================================================================
//
// hardening_test.go tests the Phase 4 hardening features:
//   - Rate limiting on gossip endpoints (enhanced)
//   - Key encryption at rest (AES-256-GCM)
//   - Soft quarantine for low-reputation IOCs
//
// Admin token auth is tested in the cmd/aegisgate-platform package
// (ioc_admin_api_test.go) since it depends on the main package's
// env-var wiring.
//
// v4.5.1+ Phase 4: Hardening.
// =========================================================================

package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// Rate Limiting Tests
// =========================================================================

// TestRateLimiter_BasicLimit verifies that the rate limiter allows
// up to `limit` requests per window and blocks beyond that.
func TestRateLimiter_BasicLimit(t *testing.T) {
	rl := newIOCRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Errorf("request 4 should be blocked")
	}
}

// TestRateLimiter_PerIP verifies that the rate limit is per-IP.
func TestRateLimiter_PerIP(t *testing.T) {
	rl := newIOCRateLimiter(2, time.Minute)
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")
	// 10.0.0.1 is at limit, but 10.0.0.2 should be allowed.
	if !rl.allow("10.0.0.2") {
		t.Errorf("10.0.0.2 should be allowed (per-IP limit)")
	}
}

// TestRateLimiter_WindowReset verifies that the rate limiter resets
// after the window expires.
func TestRateLimiter_WindowReset(t *testing.T) {
	rl := newIOCRateLimiter(1, 50*time.Millisecond)
	if !rl.allow("10.0.0.1") {
		t.Fatalf("first request should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatalf("second request should be blocked")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.allow("10.0.0.1") {
		t.Fatalf("request after window reset should be allowed")
	}
}

// TestSync_PeerAllowListBypass verifies that IPs in the peer
// allow-list bypass rate limiting.
func TestSync_PeerAllowListBypass(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	sync, err := NewSync(SyncConfig{
		InstanceID:         "test-instance",
		KeyRing:            makeTestKeyRing(t),
		Store:              store,
		EnableShare:        true,
		RateLimitPerMinute: 1,
		PeerAllowList:      []string{"10.0.0.0/24"},
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}

	// Exhaust the rate limit for a non-allowed IP.
	if !sync.rateLimiter.allow("192.168.1.1") {
		t.Fatalf("first request from non-allowed IP should be allowed")
	}
	// The allowed IP should bypass rate limiting.
	if !sync.isAllowedPeer("10.0.0.5") {
		t.Errorf("10.0.0.5 should be in allow-list (10.0.0.0/24)")
	}
	if !sync.isAllowedPeer("10.0.0.255") {
		t.Errorf("10.0.0.255 should be in allow-list (10.0.0.0/24)")
	}
	// Non-allowed IP should not bypass.
	if sync.isAllowedPeer("192.168.1.1") {
		t.Errorf("192.168.1.1 should NOT be in allow-list")
	}
	if sync.isAllowedPeer("10.1.0.0") {
		t.Errorf("10.1.0.0 should NOT be in allow-list (only 10.0.0.0/24)")
	}
}

// TestSync_PeerAllowList_SingleIP verifies that single IPs (without
// CIDR prefix) are treated as /32.
func TestSync_PeerAllowList_SingleIP(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	sync, err := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		KeyRing:       makeTestKeyRing(t),
		Store:         store,
		EnableShare:   true,
		PeerAllowList: []string{"10.0.0.5"},
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	if !sync.isAllowedPeer("10.0.0.5") {
		t.Errorf("10.0.0.5 should be allowed")
	}
	if sync.isAllowedPeer("10.0.0.6") {
		t.Errorf("10.0.0.6 should NOT be allowed (only 10.0.0.5)")
	}
}

// TestSync_PeerAllowList_InvalidCIDR verifies that invalid CIDR
// entries cause NewSync to error.
func TestSync_PeerAllowList_InvalidCIDR(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	_, err := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		KeyRing:       makeTestKeyRing(t),
		Store:         store,
		EnableShare:   true,
		PeerAllowList: []string{"not-a-valid-cidr"},
	})
	if err == nil {
		t.Fatalf("expected error for invalid CIDR entry")
	}
}

// =========================================================================
// Key Encryption Tests
// =========================================================================

// TestKeyEncryption_RoundTrip verifies that data encrypted with
// a passphrase can be decrypted with the same passphrase.
func TestKeyEncryption_RoundTrip(t *testing.T) {
	plaintext := []byte(`{"version":2,"current":"k-test","keys":[]}`)
	passphrase := "test-passphrase-12345"

	encrypted, err := encryptKeyFile(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptKeyFile: %v", err)
	}

	if !isEncryptedKeyFile(encrypted) {
		t.Errorf("encrypted data should be detected as encrypted")
	}

	decrypted, err := decryptKeyFile(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decryptKeyFile: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted != original:\n  got:  %s\n  want: %s", decrypted, plaintext)
	}
}

// TestKeyEncryption_WrongPassphrase verifies that decryption with
// the wrong passphrase fails.
func TestKeyEncryption_WrongPassphrase(t *testing.T) {
	plaintext := []byte(`{"version":2,"current":"k-test","keys":[]}`)
	encrypted, err := encryptKeyFile(plaintext, "correct-passphrase")
	if err != nil {
		t.Fatalf("encryptKeyFile: %v", err)
	}
	_, err = decryptKeyFile(encrypted, "wrong-passphrase")
	if err == nil {
		t.Errorf("decryption with wrong passphrase should fail")
	}
}

// TestKeyEncryption_NonEncryptedPassthrough verifies that
// decryptKeyFile on non-encrypted data returns it as-is.
func TestKeyEncryption_NonEncryptedPassthrough(t *testing.T) {
	plaintext := []byte(`{"version":2,"current":"k-test","keys":[]}`)
	result, err := decryptKeyFile(plaintext, "any-passphrase")
	if err != nil {
		t.Fatalf("decryptKeyFile on non-encrypted: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("non-encrypted passthrough mismatch")
	}
}

// TestKeyEncryption_IsEncryptedDetection verifies that regular
// keyring JSON is not detected as encrypted.
func TestKeyEncryption_IsEncryptedDetection(t *testing.T) {
	regular := []byte(`{"version":2,"current":"k-test","keys":[]}`)
	if isEncryptedKeyFile(regular) {
		t.Errorf("regular keyring JSON should not be detected as encrypted")
	}
}

// TestKeyRing_EncryptionAtRest verifies the full keyring lifecycle
// with encryption: create, persist, reload with passphrase.
func TestKeyRing_EncryptionAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	passphrase := "super-secret-passphrase-12345"

	// Create a keyring with encryption.
	kr1, err := LoadKeyRingWithPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("LoadKeyRingWithPassphrase (create): %v", err)
	}
	keyID1 := kr1.CurrentKeyID()
	if keyID1 == "" {
		t.Fatalf("no current key after create")
	}

	// Verify the on-disk file is encrypted.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !isEncryptedKeyFile(data) {
		t.Errorf("on-disk key file should be encrypted")
	}
	// Verify the file does NOT contain the plaintext key ID.
	if strings.Contains(string(data), keyID1) {
		t.Errorf("encrypted file should not contain plaintext key ID")
	}

	// Reload with the correct passphrase.
	kr2, err := LoadKeyRingWithPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("LoadKeyRingWithPassphrase (reload): %v", err)
	}
	if kr2.CurrentKeyID() != keyID1 {
		t.Errorf("reloaded keyID = %q, want %q", kr2.CurrentKeyID(), keyID1)
	}

	// Reload with the wrong passphrase should fail.
	_, err = LoadKeyRingWithPassphrase(path, "wrong-passphrase")
	if err == nil {
		t.Errorf("reload with wrong passphrase should fail")
	}

	// Reload without a passphrase should fail (file is encrypted).
	_, err = LoadKeyRing(path)
	if err == nil {
		t.Errorf("reload without passphrase should fail (file is encrypted)")
	}
}

// TestKeyRing_EncryptionRotation verifies that key rotation
// preserves encryption.
func TestKeyRing_EncryptionRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	passphrase := "rotation-test-passphrase"

	kr, err := LoadKeyRingWithPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("LoadKeyRingWithPassphrase: %v", err)
	}
	oldKeyID := kr.CurrentKeyID()

	// Rotate.
	newKeyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKeyID == oldKeyID {
		t.Fatalf("rotated keyID should differ")
	}

	// Reload and verify both keys are present.
	kr2, err := LoadKeyRingWithPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	keys := kr2.ActiveKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys after rotation, got %d", len(keys))
	}
	if kr2.CurrentKeyID() != newKeyID {
		t.Errorf("current key after reload = %q, want %q", kr2.CurrentKeyID(), newKeyID)
	}

	// File should still be encrypted.
	data, _ := os.ReadFile(path)
	if !isEncryptedKeyFile(data) {
		t.Errorf("file should still be encrypted after rotation")
	}
}

// TestKeyRing_PlaintextBackwardCompat verifies that plaintext
// keyrings still work when no passphrase is provided.
func TestKeyRing_PlaintextBackwardCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	// Create without encryption.
	kr1, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing (create): %v", err)
	}
	keyID := kr1.CurrentKeyID()

	// File should NOT be encrypted.
	data, _ := os.ReadFile(path)
	if isEncryptedKeyFile(data) {
		t.Errorf("file should not be encrypted when no passphrase is set")
	}

	// Reload without passphrase.
	kr2, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing (reload): %v", err)
	}
	if kr2.CurrentKeyID() != keyID {
		t.Errorf("reloaded keyID = %q, want %q", kr2.CurrentKeyID(), keyID)
	}
}

// TestKeyRing_EncryptionMigration verifies that a plaintext
// keyring can be migrated to encrypted by loading with a passphrase
// and then rotating (which triggers a persist with encryption).
func TestKeyRing_EncryptionMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	// Create without encryption (plaintext).
	kr1, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing (create plaintext): %v", err)
	}
	keyID := kr1.CurrentKeyID()

	// Load the plaintext file with a passphrase. This should work
	// (auto-detect plaintext, load as-is), and then subsequent
	// rotations will be encrypted.
	kr2, err := LoadKeyRingWithPassphrase(path, "migration-passphrase")
	if err != nil {
		t.Fatalf("LoadKeyRingWithPassphrase (migrate): %v", err)
	}
	if kr2.CurrentKeyID() != keyID {
		t.Errorf("migrated keyID = %q, want %q", kr2.CurrentKeyID(), keyID)
	}

	// Rotate — this should persist as encrypted.
	_, err = kr2.Rotate()
	if err != nil {
		t.Fatalf("Rotate after migration: %v", err)
	}

	// File should now be encrypted.
	data, _ := os.ReadFile(path)
	if !isEncryptedKeyFile(data) {
		t.Errorf("file should be encrypted after rotation with passphrase")
	}
}

// =========================================================================
// Soft Quarantine Tests
// =========================================================================

// TestSoftQuarantine_StoreMerge verifies that mergeQuarantinedIOC
// stores IOCs with the Quarantined flag set.
func TestSoftQuarantine_StoreMerge(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	ioc := IOC{
		Fingerprint: strings.Repeat("c", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:bad-peer",
	}
	store.mergeQuarantinedIOC(ioc)

	stored := store.Get(strings.Repeat("c", 64))
	if stored == nil {
		t.Fatalf("quarantined IOC not found in store")
	}
	if !stored.Quarantined {
		t.Errorf("stored IOC should have Quarantined=true")
	}
}

// TestSoftQuarantine_NoDowngrade verifies that a quarantined merge
// does NOT downgrade an existing trusted IOC.
func TestSoftQuarantine_NoDowngrade(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})

	// First, store a trusted IOC.
	trusted := IOC{
		Fingerprint: strings.Repeat("d", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       5,
		Source:      "proxy",
	}
	store.mergePeerIOC(trusted)

	// Now attempt a quarantined merge with the same fingerprint.
	quarantined := IOC{
		Fingerprint: strings.Repeat("d", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityCritical,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       3,
		Source:      "peer:bad-peer",
	}
	store.mergeQuarantinedIOC(quarantined)

	stored := store.Get(strings.Repeat("d", 64))
	if stored == nil {
		t.Fatalf("IOC not found in store")
	}
	if stored.Quarantined {
		t.Errorf("trusted IOC should NOT be downgraded to quarantined")
	}
	// The count should NOT have been increased by the quarantined merge.
	if stored.Count != 5 {
		t.Errorf("trusted IOC count = %d, want 5 (quarantined merge should not affect trusted IOC)", stored.Count)
	}
}

// TestSoftQuarantine_Promote verifies that PromoteQuarantined
// un-quarantines IOCs from a given source.
func TestSoftQuarantine_Promote(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})

	// Store two quarantined IOCs from different peers.
	ioc1 := IOC{
		Fingerprint: strings.Repeat("e", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:bad-peer-1",
	}
	ioc2 := IOC{
		Fingerprint: strings.Repeat("f", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:bad-peer-2",
	}
	store.mergeQuarantinedIOC(ioc1)
	store.mergeQuarantinedIOC(ioc2)

	// Verify both are quarantined.
	q, active := store.QuarantineStats()
	if q != 2 || active != 0 {
		t.Fatalf("quarantine stats = (%d, %d), want (2, 0)", q, active)
	}

	// Promote only peer:bad-peer-1.
	n := store.PromoteQuarantined("peer:bad-peer-1")
	if n != 1 {
		t.Errorf("promoted = %d, want 1", n)
	}

	// Verify the quarantine stats.
	q, active = store.QuarantineStats()
	if q != 1 || active != 1 {
		t.Errorf("after promote: quarantine stats = (%d, %d), want (1, 1)", q, active)
	}

	// Verify the specific IOCs.
	ioc1Stored := store.Get(strings.Repeat("e", 64))
	if ioc1Stored == nil || ioc1Stored.Quarantined {
		t.Errorf("ioc1 should be promoted (not quarantined)")
	}
	ioc2Stored := store.Get(strings.Repeat("f", 64))
	if ioc2Stored == nil || !ioc2Stored.Quarantined {
		t.Errorf("ioc2 should still be quarantined")
	}
}

// TestSoftQuarantine_CheckerExclusion verifies that the feedback
// loop checker does NOT recommend blocking for quarantined IOCs.
func TestSoftQuarantine_CheckerExclusion(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})

	// Store a quarantined IOC.
	fp := strings.Repeat("g", 64)
	ioc := IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityCritical,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       10,
		Source:      "peer:bad-peer",
	}
	store.mergeQuarantinedIOC(ioc)

	checker := NewIOCChecker(store, DefaultCheckerConfig())

	// Check the fingerprint — should be found but NOT recommended
	// for blocking because it's quarantined.
	result := checker.CheckFingerprint(fp, true)
	if !result.Found {
		t.Fatalf("IOC should be found in store")
	}
	if result.RecommendBlock {
		t.Errorf("should NOT recommend block for quarantined IOC")
	}
	if !strings.Contains(result.Reason, "quarantined") {
		t.Errorf("reason should mention quarantine, got: %q", result.Reason)
	}
}

// TestSoftQuarantine_CheckerAfterPromote verifies that a promoted
// IOC (previously quarantined) IS acted upon by the checker.
func TestSoftQuarantine_CheckerAfterPromote(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})

	fp := strings.Repeat("h", 64)
	ioc := IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityCritical,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       10,
		Source:      "peer:recovered-peer",
	}
	store.mergeQuarantinedIOC(ioc)

	// Before promotion: no block.
	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckFingerprint(fp, true)
	if result.RecommendBlock {
		t.Errorf("should NOT recommend block before promotion")
	}

	// Promote.
	store.PromoteQuarantined("peer:recovered-peer")

	// After promotion: should recommend block (peer source + local detection).
	result = checker.CheckFingerprint(fp, true)
	if !result.RecommendBlock {
		t.Errorf("should recommend block after promotion, reason: %q", result.Reason)
	}
}

// TestSoftQuarantine_Stats verifies that the checker stats
// include quarantined IOC count.
func TestSoftQuarantine_Stats(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	checker := NewIOCChecker(store, DefaultCheckerConfig())

	// Add a trusted IOC.
	trusted := IOC{
		Fingerprint: strings.Repeat("i", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "proxy",
	}
	store.mergePeerIOC(trusted)

	// Add a quarantined IOC.
	quarantined := IOC{
		Fingerprint: strings.Repeat("j", 64),
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:bad-peer",
	}
	store.mergeQuarantinedIOC(quarantined)

	stats := checker.Stats()
	if stats.QuarantinedIOCs != 1 {
		t.Errorf("QuarantinedIOCs = %d, want 1", stats.QuarantinedIOCs)
	}
	if stats.LocalIOCs != 1 {
		t.Errorf("LocalIOCs = %d, want 1", stats.LocalIOCs)
	}
}
