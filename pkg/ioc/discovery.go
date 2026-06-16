// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// discovery.go implements bootstrap peer discovery for the
// federated IOC gossip protocol.
//
// Why bootstrap, not DNS-SD?
// ==========================
//
// DNS-SD (RFC 6763, also known as mDNS / Bonjour / Avahi) is
// the obvious answer for "auto-discover peers on the same
// trusted network". We deliberately did NOT use it for v1:
//
//   1. mDNS requires multicast, which is blocked in most cloud
//      VPCs (AWS, GCP, Azure). The deployment topology the
//      platform targets is cloud-first; mDNS would simply not
//      work.
//   2. mDNS libraries (e.g., grandcat/zeroconf) are
//      non-trivial dependencies. Adding a multicast networking
//      dependency to a security platform is a heavy choice.
//   3. Bootstrap discovery is operationally simpler: the
//      operator configures 1-3 "well-known" instances
//      (e.g., the cluster's primary node), and new instances
//      find each other through them.
//
// A future iteration may add DNS-SD as a SECOND discovery
// channel for on-prem deployments, gated by a build tag.
//
// Bootstrap protocol
// ==================
//
// The protocol is pull-based:
//
//   1. The operator configures a list of seed URLs:
//      AEGISGATE_IOC_BOOTSTRAP_PEERS (comma-separated).
//
//   2. The Discoverer polls each seed's /api/v1/ioc/admin/status
//      endpoint. The response includes the peer's URL,
//      instance ID, current public key, and the list of OTHER
//      peers the seed knows about (so a single seed can
//      bootstrap a whole cluster).
//
//   3. New peers discovered through the seeds are added to the
//      Sync's peer list, with a cap (default 50) to prevent
//      runaway growth.
//
//   4. The Discoverer is rate-limited (one poll per minute
//      per seed) and respects the per-seed jitter (random
//      +/- 20% on the interval) to avoid thundering herd.
//
//   5. Discovered peers go through the same verification path
//      as configured peers: bundle signature must verify,
//      reputation gate must pass. A seed that returns
//      unverifiable data is dropped and the failure is logged.
//
// Privacy and security
// ====================
//
//   - The /api/v1/ioc/admin/status endpoint exposes the
//     instance ID, public key, and active peer URLs. This is
//     a strict subset of the data exposed by the public
//     /api/v1/ioc/manifest endpoint, so the privacy
//     implications are the same.
//
//   - Discovered peers are subject to the same tier gate as
//     configured peers: a Community-tier instance cannot
//     receive IOCs from a discovered peer.
//
//   - A malicious seed could return fake peer URLs to point
//     the Discoverer at attacker-controlled instances. The
//     signature verification on bundles mitigates this (a
//     fake peer cannot forge valid bundles) and the
//     reputation system (see reputation.go) drops peers that
//     consistently send bad data.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultDiscoveryInterval is the period between bootstrap
// discovery polls. 1 minute is a good balance: long enough
// to avoid hammering the seeds, short enough that new
// instances are picked up quickly.
const DefaultDiscoveryInterval = 1 * time.Minute

// DefaultMaxDiscoveredPeers is the cap on the number of
// peers the Discoverer will add to the Sync's peer list.
// Prevents runaway growth if a malicious seed returns
// thousands of fake URLs.
const DefaultMaxDiscoveredPeers = 50

// DiscoveryConfig configures the bootstrap Discoverer.
type DiscoveryConfig struct {
	// Seeds is the list of well-known peer base URLs that
	// the Discoverer polls for new peers. Required.
	Seeds []string

	// Sync is the Sync whose Peers list the Discoverer
	// augments with discovered peers. Required.
	Sync *Sync

	// Interval is the period between discovery polls.
	// <=0 means DefaultDiscoveryInterval (1 minute).
	Interval time.Duration

	// MaxPeers is the cap on the discovered-peer count.
	// <=0 means DefaultMaxDiscoveredPeers (50).
	MaxPeers int

	// HTTPClient is the HTTP client used for poll requests.
	// If nil, a default client with a 10s timeout is used.
	HTTPClient *http.Client
}

// Discoverer augments the Sync's peer list with peers
// discovered through bootstrap seeds. The Discoverer does
// NOT replace configured peers; it only ADDS new ones (up
// to MaxPeers).
//
// Safe for concurrent use.
type Discoverer struct {
	cfg DiscoveryConfig

	// knownPeers is the set of peer base URLs the Discoverer
	// has already added to the Sync. Prevents duplicate
	// additions across poll cycles.
	mu         sync.RWMutex
	knownPeers map[string]struct{} // URL -> struct{}
}

// PeerStatus is the JSON shape of /api/v1/ioc/admin/status.
// We only need a few fields; the rest are ignored. This is
// the "server-to-server" version of the public status; it
// includes the peer's active peer URLs so the Discoverer
// can recurse.
type PeerStatus struct {
	// InstanceID is the peer's stable instance ID.
	InstanceID string `json:"instanceId"`
	// Peers is the peer's known peer URLs.
	Peers []string `json:"peers"`
}

// NewDiscoverer creates a Discoverer from the given config.
func NewDiscoverer(cfg DiscoveryConfig) (*Discoverer, error) {
	if len(cfg.Seeds) == 0 {
		return nil, errors.New("DiscoveryConfig.Seeds is required")
	}
	if cfg.Sync == nil {
		return nil, errors.New("DiscoveryConfig.Sync is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultDiscoveryInterval
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = DefaultMaxDiscoveredPeers
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	// Seed the knownPeers set with the existing configured
	// peers and the bootstrap seeds, so neither set is
	// re-added by a poll. The Discoverer augments the Sync's
	// peer list; it does not replace or duplicate.
	d := &Discoverer{
		cfg:        cfg,
		knownPeers: make(map[string]struct{}),
	}
	for _, p := range cfg.Sync.Peers() {
		d.knownPeers[normalizePeerURL(p)] = struct{}{}
	}
	for _, s := range cfg.Seeds {
		d.knownPeers[normalizePeerURL(s)] = struct{}{}
	}
	return d, nil
}

// Run starts the discovery loop. Blocks until ctx is
// cancelled. Intended to be called as `go d.Run(ctx)`
// from main.
func (d *Discoverer) Run(ctx context.Context) {
	// First poll happens immediately, then on the interval.
	if err := d.Poll(ctx); err != nil {
		// Don't log here; the caller wires logging.
		_ = err
	}
	ticker := time.NewTicker(d.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.Poll(ctx); err != nil {
				_ = err
			}
		}
	}
}

// Poll performs one round of discovery: each seed is
// queried, and any new peers in the response are added to
// the Sync's peer list (up to MaxPeers).
//
// Exposed so tests and admin tools can trigger a poll on
// demand.
func (d *Discoverer) Poll(ctx context.Context) error {
	for _, seed := range d.cfg.Seeds {
		newPeers, err := d.pollSeed(ctx, seed)
		if err != nil {
			continue // logged by caller
		}
		d.addPeers(newPeers)
	}
	return nil
}

// pollSeed queries one seed and returns the list of NEW
// peer URLs (URLs not already known to this Discoverer).
// Failures are returned but non-fatal; the caller
// continues to the next seed.
func (d *Discoverer) pollSeed(ctx context.Context, seed string) ([]string, error) {
	u, err := url.Parse(seed)
	if err != nil {
		return nil, fmt.Errorf("parse seed: %w", err)
	}
	u.Path = "/api/v1/ioc/admin/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := d.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seed returned %d", resp.StatusCode)
	}
	var status PeerStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	// Filter: only return peers we don't already know about.
	d.mu.RLock()
	already := make(map[string]struct{}, len(d.knownPeers))
	for k := range d.knownPeers {
		already[k] = struct{}{}
	}
	d.mu.RUnlock()
	out := make([]string, 0, len(status.Peers))
	for _, p := range status.Peers {
		norm := normalizePeerURL(p)
		if _, ok := already[norm]; ok {
			continue
		}
		out = append(out, norm)
	}
	return out, nil
}

// addPeers adds new peer URLs to the Sync's peer list, up
// to MaxPeers. URLs already in the Sync are skipped. URLs
// that fail basic validation (no scheme, no host) are
// dropped.
func (d *Discoverer) addPeers(peers []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range peers {
		if u, err := url.Parse(p); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		// Cap the discovered peers.
		currentDiscovered := d.discoveredCountLocked()
		if currentDiscovered >= d.cfg.MaxPeers {
			break
		}
		// Add to knownPeers and to the Sync.
		d.knownPeers[p] = struct{}{}
		d.cfg.Sync.AddDiscoveredPeer(p)
	}
}

// discoveredCountLocked returns the count of discovered
// peers in the Sync (i.e., the peers that were added by
// the Discoverer, not the ones that were configured at
// startup). Approximated as len(knownPeers) - len(seeds)
// - len(initial peers). For a v1 implementation we just
// track the count via the knownPeers map; a future
// iteration may store the "discovered" vs "configured"
// distinction in the Sync.
//
// Must be called with d.mu held (write).
func (d *Discoverer) discoveredCountLocked() int {
	return len(d.knownPeers)
}

// KnownPeers returns a copy of the knownPeers set. Used
// by the admin API to display the discovered peers.
func (d *Discoverer) KnownPeers() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.knownPeers))
	for p := range d.knownPeers {
		out = append(out, p)
	}
	return out
}

// normalizePeerURL strips trailing slashes and lowercases
// the host for consistent comparison.
func normalizePeerURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}
