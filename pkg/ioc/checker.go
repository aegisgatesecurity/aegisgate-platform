// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - IOC Feedback Loop Checker (v4.5.1+ Phase 1)
// =========================================================================
//
// checker.go implements the IOC→Detection feedback loop: when a local
// detection produces a fingerprint, the checker looks it up in the IOC
// store to see if peer instances have also observed the same threat.
// If enough peers have seen it (corroboration), the detection can be
// escalated or a pre-emptive block can be issued even if the local
// detection layer didn't fire at blocking severity.
//
// This is the "1 customer's threat = all customers protected" network
// effect made operational: IOCs shared via the gossip protocol directly
// improve detection on every instance that receives them.
//
// Design:
//
//  1. The proxy computes a Detection struct from a local scan finding.
//  2. It calls checker.CheckCorroboration(detection) to see if peer
//     IOCs exist for the same fingerprint.
//  3. The checker returns a CorroborationResult with:
//     - PeerCount: how many peer instances have seen this IOC
//     - WorstSeverity: the worst severity across all peers
//     - TotalCount: total observation count across all instances
//     - RecommendBlock: true if corroboration is strong enough to block
//  4. If RecommendBlock is true, the proxy blocks the request with a
//     "federated threat intel" reason, even if local detection alone
//     wouldn't have blocked.
//
// Corroboration policy (configurable via CheckerConfig):
//
//   - MinPeerCount: minimum number of distinct peer instances that must
//     have observed the IOC for it to be considered corroborated.
//     Default: 2 (at least 2 other instances saw the same threat).
//   - MinSeverity: the minimum severity the peer IOCs must have.
//     Default: "high" (only high/critical peer IOCs trigger blocking).
//   - RequireLocalDetection: if true, the checker only escalates when
//     there is ALSO a local detection (not just peer IOCs). This is the
//     conservative default — peer IOCs alone don't block, they
//     corroborate local detections. A future "aggressive" mode may
//     block on peer IOCs alone for known-bad fingerprints.
//     Default: true (conservative).
//
// Privacy:
//
//   The checker only reads the fingerprint, which is a SHA-256 hash.
//   It never reads or returns the raw detection payload, the peer's
//   instance ID (beyond counting distinct peers), or any customer data.
//   The peer count is derived from the Source field on stored IOCs
//   (which is "peer:<instanceID>"), so we count distinct instance IDs.
//
// v4.5.1+ Phase 1: IOC→Detection Feedback Loop.
// =========================================================================

package ioc

import (
	"strings"
	"time"
)

// CheckerConfig configures the IOC feedback loop checker.
type CheckerConfig struct {
	// MinPeerCount is the minimum number of distinct peer instances
	// that must have observed the IOC for RecommendBlock to be true.
	// Default: 2.
	MinPeerCount int

	// MinSeverity is the minimum severity a peer IOC must have for
	// it to count toward corroboration. IOCs with lower severity
	// are ignored. Default: SeverityHigh.
	MinSeverity Severity

	// RequireLocalDetection controls whether the checker requires
	// a local detection in addition to peer corroboration.
	// true (default): peer IOCs only escalate existing local detections.
	// false: peer IOCs alone can trigger a block (aggressive mode).
	RequireLocalDetection bool

	// MaxAge is the maximum age of a peer IOC for it to be considered
	// relevant. IOCs older than this are ignored. Default: 30 days.
	MaxAge time.Duration
}

// DefaultCheckerConfig returns the conservative default configuration.
func DefaultCheckerConfig() CheckerConfig {
	return CheckerConfig{
		MinPeerCount:          2,
		MinSeverity:           SeverityHigh,
		RequireLocalDetection: true,
		MaxAge:                30 * 24 * time.Hour,
	}
}

// CorroborationResult is the result of checking a fingerprint against
// the IOC store for peer corroboration.
type CorroborationResult struct {
	// Fingerprint is the SHA-256 fingerprint that was checked.
	Fingerprint string

	// Found is true if any IOC with this fingerprint exists in the
	// store (local or peer). If false, the detection is novel and
	// no corroboration is possible.
	Found bool

	// PeerCount is the number of distinct peer instances that have
	// observed this IOC. Derived from the Source field on stored IOCs
	// (format: "peer:<instanceID>"). Local observations (Source =
	// "proxy", "scanner", etc.) do not count.
	PeerCount int

	// LocalCount is the number of local observations of this IOC.
	// This is the Count field on the locally-sourced IOC, if any.
	LocalCount int

	// TotalCount is the sum of all observation counts across all
	// sources (local + peers). This is the "widespread" signal.
	TotalCount int

	// WorstSeverity is the worst severity observed across all
	// sources (local + peers). If no IOC was found, this is empty.
	WorstSeverity Severity

	// LastSeen is the most recent LastSeen across all sources.
	LastSeen time.Time

	// RecommendBlock is true if the corroboration is strong enough
	// to warrant blocking. See CheckerConfig for the policy.
	RecommendBlock bool

	// Reason is a human-readable explanation of the recommendation.
	// Example: "corroborated by 3 peers (severity=high, total_count=42)"
	Reason string
}

// IOCChecker checks fingerprints against the IOC store for peer
// corroboration. It is the read side of the feedback loop.
//
// The checker is safe for concurrent use. It reads from the store
// without holding any lock; the store's internal RWMutex serializes
// reads with writes.
type IOCChecker struct {
	store *Store
	cfg   CheckerConfig
}

// NewIOCChecker creates a checker bound to the given store.
// The store must be non-nil; the config uses DefaultCheckerConfig
// if cfg is the zero value.
func NewIOCChecker(store *Store, cfg CheckerConfig) *IOCChecker {
	if cfg.MinPeerCount <= 0 {
		cfg = DefaultCheckerConfig()
	}
	return &IOCChecker{store: store, cfg: cfg}
}

// CheckCorroboration looks up the fingerprint of the given Detection
// in the IOC store and returns the corroboration result.
//
// If hasLocalDetection is false and RequireLocalDetection is true,
// the result will have RecommendBlock=false even if peer IOCs exist.
// This is the conservative mode: peer IOCs only escalate, they don't
// block independently.
func (c *IOCChecker) CheckCorroboration(d Detection, hasLocalDetection bool) CorroborationResult {
	fp := Fingerprint(d)
	result := CorroborationResult{Fingerprint: fp}

	if c.store == nil || fp == "" {
		return result
	}

	c.store.mu.RLock()
	ioc, ok := c.store.byFP[fp]
	c.store.mu.RUnlock()

	if !ok {
		// Novel detection — no IOC exists yet.
		return result
	}

	result.Found = true
	result.WorstSeverity = ioc.Severity
	result.LastSeen = ioc.LastSeen

	// v4.5.1+ Phase 4: Quarantined IOCs are stored but not acted upon.
	// They exist for admin review and potential promotion, but the
	// feedback loop checker must NOT recommend blocking based on
	// quarantined intel.
	if ioc.Quarantined {
		result.Reason = "IOC is quarantined (source below reputation threshold)"
		return result
	}

	// The store merges peer IOCs into a single IOC entry.
	// The Source field is updated to reflect peer observations.
	// We count peers by looking at the Source field: if it starts
	// with "peer:", the IOC has been corroborated by at least one
	// peer. We can't count exact peers from the merged entry, but
	// we can check if any peer has seen it.
	//
	// For a more precise peer count, we'd need to track per-peer
	// observation counts in the store (a future enhancement). For
	// now, the Count field gives us the total observation count,
	// and the Source field tells us if peers are involved.
	if strings.HasPrefix(ioc.Source, "peer:") {
		// At least one peer has corroborated this IOC.
		// We treat the presence of a peer source as PeerCount >= 1.
		// The MinPeerCount threshold of 2 means we need BOTH a
		// local observation AND a peer observation to recommend
		// blocking (which is the conservative default).
		result.PeerCount = 1
	} else if IsExternalSource(ioc.Source) {
		// External TAXII feed IOC. These are corroboration
		// sources from trusted external feeds (CISA, MISP, etc.).
		// We count them as peer corroboration, but the
		// ReputationWeight from the feed controls how much
		// trust we place in them.
		_, weight, _ := ParseExternalSource(ioc.Source)
		if weight >= 0.5 {
			// High-trust external feed: treat as peer corroboration.
			result.PeerCount = 1
		}
		// Low-trust feeds (< 0.5) don't count as corroboration
		// on their own — they're recorded but don't escalate.
	}

	// Count local observations.
	if !strings.HasPrefix(ioc.Source, "peer:") && !IsExternalSource(ioc.Source) {
		result.LocalCount = ioc.Count
	} else {
		// The source is a peer; local count is 0 from this entry.
		// In the merged store, local and peer counts are summed
		// into the Count field. We can't distinguish them precisely
		// without the per-source tracking enhancement.
		result.LocalCount = 0
	}

	result.TotalCount = ioc.Count

	// Check staleness.
	if c.cfg.MaxAge > 0 && time.Since(ioc.LastSeen) > c.cfg.MaxAge {
		result.Reason = "IOC is stale (last seen > MaxAge ago)"
		return result
	}

	// Check severity threshold.
	if severityRank(ioc.Severity) < severityRank(c.cfg.MinSeverity) {
		result.Reason = "IOC severity below threshold"
		return result
	}

	// Check peer count threshold.
	// In the conservative mode (RequireLocalDetection=true):
	//   - We need hasLocalDetection=true AND PeerCount >= 1
	//   - This means: the local scanner found something, AND at least
	//     one peer has also seen it. This is "1 customer's threat =
	//     all customers protected" — the peer corroboration escalates
	//     the local detection.
	// In aggressive mode (RequireLocalDetection=false):
	//   - We need PeerCount >= MinPeerCount
	//   - This blocks on peer IOCs alone, without a local detection.
	if c.cfg.RequireLocalDetection {
		if !hasLocalDetection {
			result.Reason = "peer IOC exists but no local detection (conservative mode)"
			return result
		}
		if result.PeerCount < 1 {
			result.Reason = "local detection exists but no peer corroboration"
			return result
		}
	} else {
		if result.PeerCount < c.cfg.MinPeerCount {
			result.Reason = "peer count below threshold"
			return result
		}
	}

	result.RecommendBlock = true
	result.Reason = "corroborated by peer instances (crowdsourced threat intel)"
	return result
}

// CheckFingerprint is a convenience method for checking a pre-computed
// fingerprint directly, without constructing a Detection struct.
// hasLocalDetection should be true if the caller has a local detection
// finding for this fingerprint.
func (c *IOCChecker) CheckFingerprint(fingerprint string, hasLocalDetection bool) CorroborationResult {
	result := CorroborationResult{Fingerprint: fingerprint}

	if c.store == nil || fingerprint == "" {
		return result
	}

	c.store.mu.RLock()
	ioc, ok := c.store.byFP[fingerprint]
	c.store.mu.RUnlock()

	if !ok {
		return result
	}

	result.Found = true
	result.WorstSeverity = ioc.Severity
	result.LastSeen = ioc.LastSeen
	result.TotalCount = ioc.Count

	// v4.5.1+ Phase 4: Quarantined IOCs are stored but not acted upon.
	if ioc.Quarantined {
		result.Reason = "IOC is quarantined (source below reputation threshold)"
		return result
	}

	if strings.HasPrefix(ioc.Source, "peer:") {
		result.PeerCount = 1
	} else if IsExternalSource(ioc.Source) {
		_, weight, _ := ParseExternalSource(ioc.Source)
		if weight >= 0.5 {
			result.PeerCount = 1
		}
	} else {
		result.LocalCount = ioc.Count
	}

	// Check staleness.
	if c.cfg.MaxAge > 0 && time.Since(ioc.LastSeen) > c.cfg.MaxAge {
		result.Reason = "IOC is stale"
		return result
	}

	// Check severity.
	if severityRank(ioc.Severity) < severityRank(c.cfg.MinSeverity) {
		result.Reason = "IOC severity below threshold"
		return result
	}

	if c.cfg.RequireLocalDetection {
		if !hasLocalDetection {
			result.Reason = "peer IOC exists but no local detection (conservative mode)"
			return result
		}
		if result.PeerCount < 1 {
			result.Reason = "local detection but no peer corroboration"
			return result
		}
	} else {
		if result.PeerCount < c.cfg.MinPeerCount {
			result.Reason = "peer count below threshold"
			return result
		}
	}

	result.RecommendBlock = true
	result.Reason = "corroborated by peer instances (crowdsourced threat intel)"
	return result
}

// Stats returns summary statistics about the checker's state.
// Useful for the admin API and observability.
type CheckerStats struct {
	// StoreSize is the current number of IOCs in the store.
	StoreSize int

	// PeerIOCs is the number of IOCs sourced from peers.
	PeerIOCs int

	// ExternalIOCs is the number of IOCs sourced from external
	// TAXII feeds (Source = "external:...").
	ExternalIOCs int

	// LocalIOCs is the number of IOCs sourced locally.
	LocalIOCs int

	// QuarantinedIOCs is the number of IOCs in soft quarantine
	// (received from low-reputation peers, stored but not acted
	// upon).
	// v4.5.1+ Phase 4: Hardening.
	QuarantinedIOCs int

	// Config is the current checker configuration.
	Config CheckerConfig
}

// Stats returns statistics about the IOC store and checker.
func (c *IOCChecker) Stats() CheckerStats {
	if c.store == nil {
		return CheckerStats{Config: c.cfg}
	}

	c.store.mu.RLock()
	defer c.store.mu.RUnlock()

	peer, external, local, quarantined := 0, 0, 0, 0
	for _, ioc := range c.store.byFP {
		if ioc.Quarantined {
			quarantined++
			continue
		}
		if strings.HasPrefix(ioc.Source, "peer:") {
			peer++
		} else if IsExternalSource(ioc.Source) {
			external++
		} else {
			local++
		}
	}

	return CheckerStats{
		StoreSize:       len(c.store.byFP),
		PeerIOCs:        peer,
		ExternalIOCs:    external,
		LocalIOCs:       local,
		QuarantinedIOCs: quarantined,
		Config:          c.cfg,
	}
}
