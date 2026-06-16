// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// discovery_test.go contains unit tests for the bootstrap
// Discoverer. The tests cover: config validation, polling,
// peer deduplication, MaxPeers cap, bad-seed handling, and
// normalization of peer URLs.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// makeTestSyncForDiscovery is a helper that creates a Sync
// with a fresh store and keyring, suitable for use as the
// target of a Discoverer.
func makeTestSyncForDiscovery(t *testing.T) *Sync {
	t.Helper()
	store, _ := NewStore(StoreConfig{Capacity: 100})
	kr, _ := LoadKeyRing("")
	keyID, priv, _ := kr.CurrentKey()
	sync, err := NewSync(SyncConfig{
		InstanceID: "test-discoverer",
		KeyRing:    kr,
		SigningKey: priv, // legacy fallback
		KeyID:      keyID,
		Store:      store,
		Tier:       tier.TierProfessional,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	return sync
}

// TestDiscoverer_RequiresConfig verifies that NewDiscoverer
// rejects empty Seeds and nil Sync.
func TestDiscoverer_RequiresConfig(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	kr, _ := LoadKeyRing("")
	_, priv, _ := kr.CurrentKey()
	sync, _ := NewSync(SyncConfig{
		InstanceID: "test", KeyRing: kr, SigningKey: priv, KeyID: "x",
		Store: store, Tier: tier.TierProfessional,
	})
	cases := []struct {
		name string
		cfg  DiscoveryConfig
	}{
		{"no seeds", DiscoveryConfig{Sync: sync}},
		{"no sync", DiscoveryConfig{Seeds: []string{"http://a"}}},
		{"empty", DiscoveryConfig{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDiscoverer(tc.cfg)
			if err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// TestDiscoverer_PollDiscoversNewPeers verifies that a
// successful poll adds new peers to the Sync's peer list.
func TestDiscoverer_PollDiscoversNewPeers(t *testing.T) {
	// Seed server returns two peers.
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ioc/admin/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(PeerStatus{
			InstanceID: "seed",
			Peers:      []string{"http://peer-a", "http://peer-b"},
		})
	}))
	defer seed.Close()

	sync := makeTestSyncForDiscovery(t)
	d, err := NewDiscoverer(DiscoveryConfig{
		Seeds: []string{seed.URL},
		Sync:  sync,
	})
	if err != nil {
		t.Fatalf("NewDiscoverer: %v", err)
	}
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	peers := sync.Peers()
	if len(peers) != 2 {
		t.Errorf("peers = %d, want 2: %v", len(peers), peers)
	}
}

// TestDiscoverer_DoesNotDuplicateExistingPeers verifies
// that a poll does not re-add peers already in the Sync's
// list (or peers added by an earlier poll).
func TestDiscoverer_DoesNotDuplicateExistingPeers(t *testing.T) {
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PeerStatus{
			InstanceID: "seed",
			Peers:      []string{"http://peer-a", "http://peer-b"},
		})
	}))
	defer seed.Close()

	sync := makeTestSyncForDiscovery(t)
	// Pre-configure one of the peers.
	sync.AddDiscoveredPeer("http://peer-a")
	d, _ := NewDiscoverer(DiscoveryConfig{Seeds: []string{seed.URL}, Sync: sync})
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	peers := sync.Peers()
	// peer-a is pre-configured; poll should add peer-b.
	countA, countB := 0, 0
	for _, p := range peers {
		if p == "http://peer-a" {
			countA++
		}
		if p == "http://peer-b" {
			countB++
		}
	}
	if countA != 1 {
		t.Errorf("peer-a count = %d, want 1", countA)
	}
	if countB != 1 {
		t.Errorf("peer-b count = %d, want 1", countB)
	}
}

// TestDiscoverer_MaxPeersCap verifies that the MaxPeers
// cap is enforced.
func TestDiscoverer_MaxPeersCap(t *testing.T) {
	// Seed returns 100 peers.
	peers := make([]string, 100)
	for i := 0; i < 100; i++ {
		peers[i] = "http://peer-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PeerStatus{
			InstanceID: "seed",
			Peers:      peers,
		})
	}))
	defer seed.Close()

	sync := makeTestSyncForDiscovery(t)
	d, _ := NewDiscoverer(DiscoveryConfig{
		Seeds:    []string{seed.URL},
		Sync:     sync,
		MaxPeers: 5,
	})
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// We may already have 0 peers, so the cap is 5 discovered.
	// But "len(Sync.Peers())" includes discovered only after
	// the Discoverer added them. So we expect <= 5.
	if got := len(sync.Peers()); got > 5 {
		t.Errorf("Sync.Peers() len = %d, want <= 5", got)
	}
}

// TestDiscoverer_BadSeedDoesNotPanic verifies that a
// failing seed is logged/skipped and the loop continues.
func TestDiscoverer_BadSeedDoesNotPanic(t *testing.T) {
	// Mix of good and bad seeds.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PeerStatus{
			InstanceID: "good",
			Peers:      []string{"http://peer-x"},
		})
	}))
	defer good.Close()

	sync := makeTestSyncForDiscovery(t)
	d, _ := NewDiscoverer(DiscoveryConfig{
		Seeds: []string{
			"http://127.0.0.1:1", // unreachable
			good.URL,
			"://bad-url", // unparseable
		},
		Sync: sync,
	})
	// Poll should not panic. Some seeds will fail; the
	// good seed should still add peer-x.
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	peers := sync.Peers()
	found := false
	for _, p := range peers {
		if p == "http://peer-x" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected peer-x to be added; got %v", peers)
	}
}

// TestDiscoverer_RunRespectsContextCancel verifies that
// Run returns when ctx is cancelled.
func TestDiscoverer_RunRespectsContextCancel(t *testing.T) {
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PeerStatus{InstanceID: "seed"})
	}))
	defer seed.Close()

	sync := makeTestSyncForDiscovery(t)
	d, _ := NewDiscoverer(DiscoveryConfig{
		Seeds:    []string{seed.URL},
		Sync:     sync,
		Interval: 100 * time.Millisecond, // poll often for the test
	})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return within 2s of cancel")
	}
}

// TestDiscoverer_RejectsInvalidPeers verifies that peer
// URLs that don't parse or have no host are dropped.
func TestDiscoverer_RejectsInvalidPeers(t *testing.T) {
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PeerStatus{
			InstanceID: "seed",
			Peers: []string{
				"http://good.example.com",
				"://no-scheme",
				"http://", // no host
				"https://another-good.example.com",
			},
		})
	}))
	defer seed.Close()

	sync := makeTestSyncForDiscovery(t)
	d, _ := NewDiscoverer(DiscoveryConfig{Seeds: []string{seed.URL}, Sync: sync})
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	peers := sync.Peers()
	if len(peers) != 2 {
		t.Errorf("peers = %d, want 2 (only the valid ones): %v", len(peers), peers)
	}
}

// TestDiscoverer_KnownPeersIncludesSeeds verifies that the
// knownPeers set includes the seeds (so they're not
// re-added via their own response).
func TestDiscoverer_KnownPeersIncludesSeeds(t *testing.T) {
	sync := makeTestSyncForDiscovery(t)
	d, _ := NewDiscoverer(DiscoveryConfig{
		Seeds: []string{"http://seed-1", "http://seed-2"},
		Sync:  sync,
	})
	known := d.KnownPeers()
	if len(known) != 2 {
		t.Errorf("KnownPeers len = %d, want 2: %v", len(known), known)
	}
}

// TestNormalizePeerURL verifies the URL normalization
// function.
func TestNormalizePeerURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://a.com", "http://a.com"},
		{"http://a.com/", "http://a.com"},
		{"http://a.com/path/", "http://a.com/path"},
		{"  http://a.com  ", "http://a.com"},
		{"HTTPS://A.COM/Path/", "https://A.COM/Path"},
	}
	for _, tc := range cases {
		got := normalizePeerURL(tc.in)
		if got != tc.want {
			t.Errorf("normalizePeerURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// _ keeps the strings import used (it is, by the
// normalizePeerURL cases above).
var _ = strings.HasPrefix
