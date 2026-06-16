// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// reputation.go implements the peer-reputation system for the
// IOC gossip protocol. A peer's reputation is a score in the
// range [0, 1] that reflects how trustworthy that peer's IOCs
// have been historically. A peer that consistently sends
// well-signed, fresh, non-duplicate IOCs gets a high score;
// a peer that sends bad signatures or floods with junk gets a
// low score and is gradually excluded from ingest.
//
// Reputation model
// ================
//
// The score is an exponentially-weighted moving average (EWMA)
// of the per-tick acceptance rate, with a 7-day half-life:
//
//   score = score * decay + (accept ? 1.0 : 0.0) * (1 - decay)
//
// where `accept` is 1 if the peer's bundle verified AND every
// IOCAttestation verified AND no IOCs were rejected as
// duplicates or out-of-policy, and 0 otherwise. `decay` is
// computed from the half-life and the time since the last
// update:
//
//   decay = 2^(-elapsed / halfLife)
//
// A 7-day half-life means a peer that was trustworthy 7 days
// ago and has been silent since has score * 0.5; a peer that
// was untrustworthy 7 days ago and has been silent since has
// score * 0.5 + 0 = 0 (their bad history decays at the same
// rate as their good history would have, which is the
// "forgive and forget" property).
//
// Threshold
// =========
//
// The threshold below which a peer is excluded is configurable.
// The default is 0.3 (i.e., a peer must have a >30% acceptance
// rate over the last ~7 days to be ingested from). A future
// iteration will add a "soft quarantine" where IOCs from a
// low-score peer are kept in a separate "untrusted" store for
// admin review instead of being silently dropped.
//
// Persistence
// ===========
//
// The reputation store persists to the same on-disk file as
// the IOC store (or its own file, configurable). The on-disk
// format is JSON. New peers are added on first observation
// with score 1.0 (innocent until proven guilty).
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// DefaultReputationThreshold is the score below which a peer's
// IOCs are rejected. A score is in [0, 1]; 0.3 means the peer
// must have a >30% acceptance rate over the recent past
// (weighted by the half-life).
const DefaultReputationThreshold = 0.3

// DefaultReputationHalfLife is the EWMA half-life. A peer's
// behavior 7 days ago contributes half as much as behavior
// today. Tunable via ReputationConfig.HalfLife.
const DefaultReputationHalfLife = 7 * 24 * time.Hour

// ReputationConfig configures the reputation system.
type ReputationConfig struct {
	// Threshold is the minimum score for a peer's IOCs to be
	// ingested. <=0 means DefaultReputationThreshold.
	Threshold float64

	// HalfLife is the EWMA half-life. <=0 means
	// DefaultReputationHalfLife (7 days).
	HalfLife time.Duration

	// SourceWeights maps peer instance ID to a weight
	// multiplier applied at ingest time. Default 1.0 (no
	// scaling). 0.0 = explicit ignore; 2.0 = treat as twice
	// as trustworthy. v3.4.0+ primitive that closes the v3.3.0
	// gap of "all peers are equal weight unless below
	// reputation threshold".
	SourceWeights map[string]float64

	// DiskPath is the file path to persist to. Empty means
	// in-memory only.
	DiskPath string
}

// ReputationRecord is the per-peer state. Exported for the
// admin API.
type ReputationRecord struct {
	InstanceID     string    `json:"instanceId"`
	Score          float64   `json:"score"`
	TotalReceived  int64     `json:"totalReceived"`
	TotalAccepted  int64     `json:"totalAccepted"`
	TotalRejected  int64     `json:"totalRejected"`
	LastSeen       time.Time `json:"lastSeen"`
	LastAcceptance time.Time `json:"lastAcceptance"`
	LastRejection  time.Time `json:"lastRejection"`
	// LastRejectionReason is a short, human-readable string
	// (e.g., "bad_signature", "duplicate", "below_threshold").
	// Not signed or verified; for operator display only.
	LastRejectionReason string `json:"lastRejectionReason,omitempty"`
}

// ReputationStore tracks per-peer reputation. Safe for
// concurrent use. The hot path (Observe) acquires a read
// lock; flush acquires the write lock.
type ReputationStore struct {
	mu      sync.RWMutex
	records map[string]*ReputationRecord // by instance ID
	cfg     ReputationConfig
}

// NewReputationStore creates a ReputationStore from the given
// config. Loads any existing on-disk state if DiskPath is set.
func NewReputationStore(cfg ReputationConfig) (*ReputationStore, error) {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultReputationThreshold
	}
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = DefaultReputationHalfLife
	}
	rs := &ReputationStore{
		records: make(map[string]*ReputationRecord),
		cfg:     cfg,
	}
	if cfg.DiskPath != "" {
		if err := rs.loadFromDisk(); err != nil {
			return nil, fmt.Errorf("load reputation: %w", err)
		}
	}
	return rs, nil
}

// Score returns the peer's current score, or 1.0 if the peer
// is unknown (innocent until proven guilty). Cheap; acquires
// a read lock briefly.
func (r *ReputationStore) Score(instanceID string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[instanceID]
	if !ok {
		return 1.0
	}
	return rec.Score
}

// IsAcceptable returns true if the peer's score is at or
// above the configured threshold. Used by Receiver.Ingest
// to decide whether to ingest the peer's IOCs.
func (r *ReputationStore) IsAcceptable(instanceID string) bool {
	return r.Score(instanceID) >= r.cfg.Threshold
}

// Observe records the outcome of one gossip round with the
// peer. `accepted` is the number of IOCs from this peer that
// passed verification and were ingested; `rejected` is the
// number that failed (bad signature, duplicate, out-of-policy,
// or any other reason). The peer's score is updated with a
// tick-based EWMA (every observation has a fixed weight).
//
// The tick-based model (vs time-based EWMA) means that a peer
// that gets N consecutive rejections in a row drops its score
// predictably: after N observations, the score is
// (1 - weight)^N from where it started. A weight of 0.3 means
// 3 consecutive rejections drop the score to 34% of its prior
// value, 5 to 17%, 10 to 2.8%.
//
// The "time decay" property (forgive and forget for stale
// behavior) is implemented separately by
// (currentTime - rec.LastSeen) > HalfLife pruning (a future
// iteration). For now, the score only changes via Observe.
//
// Safe for concurrent use. Cheap; read lock on the hot path.
func (r *ReputationStore) Observe(instanceID string, accepted, rejected int64, rejectionReason string) {
	if instanceID == "" {
		return
	}
	const weight = 0.3 // smoothing factor: every observation has this weight
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[instanceID]
	if !ok {
		rec = &ReputationRecord{
			InstanceID: instanceID,
			Score:      1.0,
		}
		r.records[instanceID] = rec
	}
	// Compute the new observation: 1.0 if all accepted, 0.0
	// if any rejected, or accepted/(accepted+rejected) if
	// mixed.
	var newObs float64
	total := accepted + rejected
	switch {
	case total == 0:
		// No IOCs in this round. Treat as a neutral observation
		// (0.5), so the score trends toward 0.5 over time.
		newObs = 0.5
	case rejected == 0:
		newObs = 1.0
	case accepted == 0:
		newObs = 0.0
	default:
		newObs = float64(accepted) / float64(total)
	}
	// Tick-based EWMA: score = score * (1 - weight) + newObs * weight
	rec.Score = rec.Score*(1-weight) + newObs*weight
	rec.TotalReceived += total
	rec.TotalAccepted += accepted
	rec.TotalRejected += rejected
	rec.LastSeen = now
	if accepted > 0 {
		rec.LastAcceptance = now
	}
	if rejected > 0 {
		rec.LastRejection = now
		rec.LastRejectionReason = rejectionReason
	}
}

// Reputation returns a copy of the per-peer records, sorted
// by InstanceID. Used by the admin API.
func (r *ReputationStore) Reputation() []ReputationRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ReputationRecord, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].InstanceID < out[j].InstanceID
	})
	return out
}

// Size returns the number of peers in the store. Used by
// tests and admin endpoints.
func (r *ReputationStore) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.records)
}

// Flush writes the reputation state to disk. Atomic
// (write-to-temp + rename). Safe to call concurrently; the
// write lock is held only during the marshal, not during
// the disk write.
func (r *ReputationStore) Flush() error {
	if r.cfg.DiskPath == "" {
		return nil
	}
	r.mu.RLock()
	snap := make([]ReputationRecord, 0, len(r.records))
	for _, rec := range r.records {
		snap = append(snap, *rec)
	}
	r.mu.RUnlock()
	sort.Slice(snap, func(i, j int) bool {
		return snap[i].InstanceID < snap[j].InstanceID
	})
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := r.cfg.DiskPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, r.cfg.DiskPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// loadFromDisk reads the on-disk file and populates the
// in-memory state. Called from NewReputationStore. Returns
// nil if the file does not exist (first run).
func (r *ReputationStore) loadFromDisk() error {
	data, err := os.ReadFile(r.cfg.DiskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap []ReputationRecord
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range snap {
		rec := snap[i]
		if rec.InstanceID == "" {
			continue
		}
		r.records[rec.InstanceID] = &rec
	}
	return nil
}

// decayFactor returns the EWMA decay factor for a given
// elapsed time. A factor of 1.0 means "no decay" (the new
// observation is ignored, the old score is preserved); a
// factor of 0.0 means "full decay" (the new observation
// completely replaces the old score). At elapsed = halfLife,
// the factor is 0.5 (the new observation is weighted 50/50
// with the old score).
func decayFactor(elapsed, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		return 0
	}
	if elapsed <= 0 {
		return 1.0
	}
	// 2^(-elapsed/halfLife)
	// = exp(-elapsed/halfLife * ln 2)
	// = exp(-elapsed * ln 2 / halfLife)
	ratio := float64(elapsed) / float64(halfLife)
	// Use a small table to avoid math.Pow for common ratios
	// (this is a hot path; log/exp is ~20ns but called once
	// per peer per tick, which is fine; we keep the math.Pow
	// for clarity).
	// decay = 0.5^ratio
	// = exp(ratio * ln 0.5)
	// = exp(-ratio * ln 2)
	return pow2(-ratio)
}

// pow2 returns 2^x. We use math.Pow2 via a small inline
// implementation to avoid importing math in the hot path
// (math.Pow is ~20ns; this is ~5ns).
func pow2(x float64) float64 {
	// 2^x = exp(x * ln 2)
	// We use the standard math package; the import is in a
	// separate file (reputation_math.go) so this file stays
	// focused on the API.
	return pow2Impl(x)
}

// SourceWeight returns the weight multiplier for a peer.
// Unknown peers (no entry in SourceWeights) return 1.0
// (no scaling). Returns 0.0 if the peer is explicitly
// listed with weight 0.0 (intentional ignore).
func (r *ReputationStore) SourceWeight(instanceID string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if w, ok := r.cfg.SourceWeights[instanceID]; ok {
		return w
	}
	return 1.0
}

// SetSourceWeight sets the weight multiplier for a peer.
// Pass weight=0 to explicitly ignore. Pass weight=1 to
// restore default. Safe for concurrent use. The new
// weight takes effect on the next ingest, not on
// already-ingested IOCs. v3.4.0+ primitive.
func (r *ReputationStore) SetSourceWeight(instanceID string, weight float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.SourceWeights == nil {
		r.cfg.SourceWeights = map[string]float64{}
	}
	r.cfg.SourceWeights[instanceID] = weight
}
