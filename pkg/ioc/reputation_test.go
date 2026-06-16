// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// reputation_test.go contains unit tests for the peer-reputation
// system. The tests cover: initial score (innocent until proven
// guilty), update via Observe, time decay, threshold gate,
// per-peer isolation, persistence, and integration with the
// Receiver.Ingest gate.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestReputation_InitialScoreIsOne verifies that a new peer
// starts with score 1.0 (innocent until proven guilty).
func TestReputation_InitialScoreIsOne(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	if s := rs.Score("unknown-peer"); s != 1.0 {
		t.Errorf("initial score = %f, want 1.0", s)
	}
}

// TestReputation_ObserveAcceptedBumpsScore verifies that a
// fully-accepted round increases the score.
func TestReputation_ObserveAcceptedBumpsScore(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{HalfLife: time.Hour})
	rs.Observe("peer-a", 10, 0, "")
	// Score should be 1.0 (newly created, 100% accept).
	if s := rs.Score("peer-a"); s != 1.0 {
		t.Errorf("score after all-accept = %f, want 1.0", s)
	}
}

// TestReputation_ObserveRejectedDropsScore verifies that a
// fully-rejected round drops the score.
func TestReputation_ObserveRejectedDropsScore(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{HalfLife: time.Hour})
	// First create the peer with a positive observation.
	rs.Observe("peer-a", 5, 0, "")
	// Then reject.
	rs.Observe("peer-a", 0, 5, "bad_signature")
	if s := rs.Score("peer-a"); s >= 1.0 {
		t.Errorf("score after rejection = %f, want < 1.0", s)
	}
}

// TestReputation_TickEWMADropsOnRejection verifies that a
// peer that receives N consecutive rejections drops its
// score predictably, independent of time elapsed. This is
// the tick-based EWMA model: every observation has a fixed
// weight (0.3), so N rejections in a row drop the score
// (1-0.3)^N from where it started.
func TestReputation_TickEWMADropsOnRejection(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{HalfLife: time.Hour})
	// Seed: 5 accepted (score stays at 1.0).
	rs.Observe("peer-a", 5, 0, "")
	// 1 rejection. Score should be 1.0 * 0.7 + 0.0 * 0.3 = 0.7.
	rs.Observe("peer-a", 0, 5, "bad_signature")
	if s := rs.Score("peer-a"); s < 0.65 || s > 0.75 {
		t.Errorf("score after 1 reject = %f, want ~0.7", s)
	}
	// 10 rejections total. Score should be 0.7^10 ~= 0.028.
	for i := 0; i < 9; i++ {
		rs.Observe("peer-a", 0, 5, "bad_signature")
	}
	if s := rs.Score("peer-a"); s > 0.05 {
		t.Errorf("score after 10 rejects = %f, want < 0.05", s)
	}
}

// TestReputation_TimeDecayOfStalePeer is a no-op for the
// tick-based model. A future iteration may add a
// "decay-toward-0.5-if-not-seen-in-HalfLife" pruning pass.
// For now, a peer that is silent keeps its score unchanged.
// This test documents the current behavior; it is not a
// regression test, just a behavior pin.
func TestReputation_TimeDecayOfStalePeer(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{HalfLife: time.Hour})
	rs.Observe("peer-a", 5, 0, "")
	scoreBefore := rs.Score("peer-a")
	time.Sleep(100 * time.Millisecond)
	scoreAfter := rs.Score("peer-a")
	if scoreBefore != scoreAfter {
		t.Errorf("score changed without Observe: before=%f after=%f",
			scoreBefore, scoreAfter)
	}
}

// TestReputation_Threshold verifies that IsAcceptable returns
// false for peers below the threshold.
func TestReputation_Threshold(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{
		Threshold: 0.5,
		HalfLife:  time.Hour,
	})
	// New peer: score 1.0, acceptable.
	if !rs.IsAcceptable("peer-a") {
		t.Errorf("new peer should be acceptable")
	}
	// Lots of rejections: score drops below 0.5.
	for i := 0; i < 100; i++ {
		rs.Observe("peer-a", 0, 10, "bad")
	}
	if rs.IsAcceptable("peer-a") {
		t.Errorf("peer should be below threshold after rejections")
	}
}

// TestReputation_PerPeerIsolation verifies that one peer's
// score does not affect another peer's score.
func TestReputation_PerPeerIsolation(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{Threshold: 0.5, HalfLife: time.Hour})
	rs.Observe("peer-good", 10, 0, "")
	for i := 0; i < 100; i++ {
		rs.Observe("peer-bad", 0, 10, "bad")
	}
	if rs.Score("peer-good") != 1.0 {
		t.Errorf("peer-good score affected: %f", rs.Score("peer-good"))
	}
	if rs.Score("peer-bad") >= 0.5 {
		t.Errorf("peer-bad not low enough: %f", rs.Score("peer-bad"))
	}
}

// TestReputation_ReputationReturnsSortedSnapshot verifies that
// Reputation() returns records sorted by InstanceID.
func TestReputation_ReputationReturnsSortedSnapshot(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.Observe("zebra", 1, 0, "")
	rs.Observe("alpha", 1, 0, "")
	rs.Observe("middle", 1, 0, "")
	recs := rs.Reputation()
	if len(recs) != 3 {
		t.Fatalf("len = %d, want 3", len(recs))
	}
	if recs[0].InstanceID != "alpha" || recs[1].InstanceID != "middle" || recs[2].InstanceID != "zebra" {
		t.Errorf("not sorted: %v", []string{recs[0].InstanceID, recs[1].InstanceID, recs[2].InstanceID})
	}
}

// TestReputation_PersistenceRoundTrip verifies that the
// reputation store survives process restarts.
func TestReputation_PersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")
	rs, _ := NewReputationStore(ReputationConfig{DiskPath: path, HalfLife: time.Hour})
	rs.Observe("peer-a", 5, 0, "")
	if err := rs.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// New store, same path.
	rs2, err := NewReputationStore(ReputationConfig{DiskPath: path, HalfLife: time.Hour})
	if err != nil {
		t.Fatalf("NewReputationStore 2: %v", err)
	}
	if s := rs2.Score("peer-a"); s != 1.0 {
		t.Errorf("reloaded score = %f, want 1.0", s)
	}
	if recs := rs2.Reputation(); len(recs) != 1 || recs[0].InstanceID != "peer-a" {
		t.Errorf("reloaded records = %+v", recs)
	}
}

// TestReputation_LoadMissingFileReturnsEmpty verifies that a
// missing on-disk file is not an error.
func TestReputation_LoadMissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")
	rs, err := NewReputationStore(ReputationConfig{DiskPath: path})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if rs.Size() != 0 {
		t.Errorf("expected empty store, got size %d", rs.Size())
	}
}

// TestReputation_ObserveEmptyInstanceIgnored verifies that
// an empty instance ID is silently ignored (defensive).
func TestReputation_ObserveEmptyInstanceIgnored(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.Observe("", 1, 0, "")
	if rs.Size() != 0 {
		t.Errorf("expected empty store, got size %d", rs.Size())
	}
}

// TestReputation_Concurrent verifies that Observe is safe
// for concurrent use.
func TestReputation_Concurrent(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{Threshold: 0.1, HalfLife: time.Hour})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			instanceID := "peer-" + string(rune('a'+id%3))
			for j := 0; j < 100; j++ {
				rs.Observe(instanceID, 1, 0, "")
			}
		}(i)
	}
	wg.Wait()
	if rs.Size() != 3 {
		t.Errorf("expected 3 peers (a, b, c), got %d", rs.Size())
	}
}

// TestReputation_DecayFactorMonotonic verifies that the
// decayFactor function decreases monotonically with
// elapsed time.
func TestReputation_DecayFactorMonotonic(t *testing.T) {
	halfLife := time.Hour
	elapsed := []time.Duration{
		0, time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 24 * time.Hour,
	}
	// Get the first value, then check each subsequent is <= prev.
	prev := decayFactor(elapsed[0], halfLife)
	for _, e := range elapsed[1:] {
		d := decayFactor(e, halfLife)
		if d > prev+1e-9 {
			t.Errorf("decayFactor non-monotonic at %v: %f > %f", e, d, prev)
		}
		prev = d
	}
}

// TestReputation_DecayFactorAtHalfLifeIsHalf verifies that
// the decay factor at the half-life is exactly 0.5.
func TestReputation_DecayFactorAtHalfLifeIsHalf(t *testing.T) {
	halfLife := time.Hour
	d := decayFactor(halfLife, halfLife)
	if d < 0.4999 || d > 0.5001 {
		t.Errorf("decayFactor at halfLife = %f, want 0.5", d)
	}
}

// TestReputation_DecayFactorZeroElapsedIsOne verifies that
// no elapsed time means no decay.
func TestReputation_DecayFactorZeroElapsedIsOne(t *testing.T) {
	d := decayFactor(0, time.Hour)
	if d != 1.0 {
		t.Errorf("decayFactor(0) = %f, want 1.0", d)
	}
}

// TestReputation_ReceiverRejectsBelowThreshold verifies that
// Receiver.Ingest rejects IOCs from a peer below the
// threshold, and that the rejection is recorded.
func TestReputation_ReceiverRejectsBelowThreshold(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	rs, _ := NewReputationStore(ReputationConfig{Threshold: 0.5, HalfLife: time.Hour})
	receiver := NewReceiver(store).WithReputation(rs)

	// Build a bundle from a "bad" peer, signed with a fresh
	// keyring.
	kr := makeTestKeyRing(t)
	bundle := NewBundle("bad-peer")
	att := IOCAttestation{
		Fingerprint: strings.Repeat("a", 64),
		InstanceID:  "bad-peer",
		IOCType:     IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
	}
	if err := SignAttestationWithKeyRing(&att, kr); err != nil {
		t.Fatalf("SignAttestationWithKeyRing: %v", err)
	}
	bundle.Add(att)
	if err := bundle.SignWithKeyRing(kr); err != nil {
		t.Fatalf("SignWithKeyRing: %v", err)
	}
	if err := bundle.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}

	// First round: bad-peer starts at 1.0, acceptable. Ingest.
	if _, err := receiver.Ingest(bundle); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	// Now drop the peer's score below threshold.
	for i := 0; i < 50; i++ {
		rs.Observe("bad-peer", 0, 10, "bad")
	}
	// Second round: rejected.
	_, err := receiver.Ingest(bundle)
	if err == nil {
		t.Errorf("expected error on Ingest from below-threshold peer")
	}
	if !strings.Contains(err.Error(), "below reputation threshold") {
		t.Errorf("err = %q, want contains 'below reputation threshold'", err.Error())
	}
	if store.Size() != 1 {
		t.Errorf("store size = %d, want 1 (only the first ingest succeeded)", store.Size())
	}
}

// TestReputation_ReceiverAcceptsGoodPeers verifies that
// Receiver.Ingest still works for peers with a good score.
func TestReputation_ReceiverAcceptsGoodPeers(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	rs, _ := NewReputationStore(ReputationConfig{Threshold: 0.3, HalfLife: time.Hour})
	receiver := NewReceiver(store).WithReputation(rs)

	kr := makeTestKeyRing(t)
	bundle := NewBundle("good-peer")
	att := IOCAttestation{
		Fingerprint: strings.Repeat("a", 64),
		InstanceID:  "good-peer",
		IOCType:     IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
	}
	if err := SignAttestationWithKeyRing(&att, kr); err != nil {
		t.Fatalf("SignAttestationWithKeyRing: %v", err)
	}
	bundle.Add(att)
	if err := bundle.SignWithKeyRing(kr); err != nil {
		t.Fatalf("SignWithKeyRing: %v", err)
	}
	n, err := receiver.Ingest(bundle)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	// The good peer's score should remain >= 1.0.
	if s := rs.Score("good-peer"); s < 1.0 {
		t.Errorf("good-peer score = %f, want >= 1.0", s)
	}
}

// TestReputation_NoStoreMeansNoReputationGate verifies the
// pre-Reputation behavior: a receiver without a reputation
// store accepts any peer whose bundle verifies.
func TestReputation_NoStoreMeansNoReputationGate(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	receiver := NewReceiver(store) // no reputation
	kr := makeTestKeyRing(t)
	bundle := NewBundle("any-peer")
	att := IOCAttestation{
		Fingerprint: strings.Repeat("a", 64),
		InstanceID:  "any-peer",
		IOCType:     IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
	}
	if err := SignAttestationWithKeyRing(&att, kr); err != nil {
		t.Fatalf("SignAttestationWithKeyRing: %v", err)
	}
	bundle.Add(att)
	if err := bundle.SignWithKeyRing(kr); err != nil {
		t.Fatalf("SignWithKeyRing: %v", err)
	}
	if _, err := receiver.Ingest(bundle); err != nil {
		t.Errorf("Ingest without reputation: %v", err)
	}
}

// TestReputation_NilReceiverReturnsNilStore verifies that
// nil-safe accessors work.
func TestReputation_NilReceiverReturnsNilStore(t *testing.T) {
	var r *Receiver
	if r.WithReputation(nil) != nil {
		t.Errorf("WithReputation on nil receiver = %v, want nil", r.WithReputation(nil))
	}
	if r.Reputation() != nil {
		t.Errorf("Reputation on nil receiver = %v, want nil", r.Reputation())
	}
}

// makeTestKeyRing is a small helper for tests that need a
// fresh in-memory keyring to sign bundles. Exported via the
// package since the test files are in the same package.
func makeTestKeyRing(t *testing.T) *KeyRing {
	t.Helper()
	kr, err := LoadKeyRing("")
	if err != nil {
		t.Fatalf("LoadKeyRing(ephemeral): %v", err)
	}
	return kr
}

// _ keeps os imported (used in TestReputation_LoadMissingFileReturnsEmpty
// indirectly via TempDir; no, TempDir doesn't need os).
var _ = os.Stat

// ------------------------------------------------------------------
// v3.4.0+ per-source IOC weights tests (b2)
// ------------------------------------------------------------------

// TestReputationStore_SourceWeight_Default: unknown peers
// get weight 1.0 (no scaling).
func TestReputationStore_SourceWeight_Default(t *testing.T) {
	rs, err := NewReputationStore(ReputationConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.SourceWeight("unknown-peer"); got != 1.0 {
		t.Errorf("SourceWeight(unknown) = %v, want 1.0", got)
	}
}

// TestReputationStore_SourceWeight_SetAndGet: setting a weight
// and then reading it returns the set value.
func TestReputationStore_SourceWeight_SetAndGet(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.SetSourceWeight("peer-a", 0.5)
	rs.SetSourceWeight("peer-b", 2.0)
	rs.SetSourceWeight("peer-c", 0.0) // explicit ignore
	if got := rs.SourceWeight("peer-a"); got != 0.5 {
		t.Errorf("SourceWeight(peer-a) = %v, want 0.5", got)
	}
	if got := rs.SourceWeight("peer-b"); got != 2.0 {
		t.Errorf("SourceWeight(peer-b) = %v, want 2.0", got)
	}
	if got := rs.SourceWeight("peer-c"); got != 0.0 {
		t.Errorf("SourceWeight(peer-c) = %v, want 0.0 (explicit ignore)", got)
	}
	// Unknown peer still gets 1.0.
	if got := rs.SourceWeight("peer-unknown"); got != 1.0 {
		t.Errorf("SourceWeight(peer-unknown) = %v, want 1.0", got)
	}
}

// TestReputationStore_SourceWeight_Overwrite: setting the same
// peer's weight twice replaces the prior value.
func TestReputationStore_SourceWeight_Overwrite(t *testing.T) {
	rs, _ := NewReputationStore(ReputationConfig{})
	rs.SetSourceWeight("peer-x", 1.5)
	rs.SetSourceWeight("peer-x", 0.25)
	if got := rs.SourceWeight("peer-x"); got != 0.25 {
		t.Errorf("SourceWeight(peer-x) = %v, want 0.25 (overwrite)", got)
	}
}
