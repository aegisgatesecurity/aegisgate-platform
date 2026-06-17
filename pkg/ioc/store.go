// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// store.go implements the local IOC store. The store is keyed by
// IOC fingerprint and holds the current state of every locally-
// observed IOC: FirstSeen, LastSeen, Count, worst Severity observed.
//
// In-memory: the primary store is a sync.Map (or RWMutex+map for
// iteration). It is the only structure the hot path (the producer)
// reads from on every event, and it must be lock-free or close to it.
//
// On-disk: a periodic flush writes the in-memory state to a JSON
// file under the configured store dir. This survives process
// restarts. The on-disk format is a single JSON object: a map from
// fingerprint to IOC. It is NOT a database; if the in-memory state
// is large (millions of IOCs), a future iteration may switch to
// SQLite or BoltDB. For v3.5.0 the JSON file is sufficient because
// the IOC count is bounded by the IOC TTL (see Config) and the
// typical instance will hold <100K IOCs.
//
// The store does NOT include raw detection payloads. It carries
// exactly what crosses the gossip boundary: IOC + minimal metadata.
// This is the privacy boundary.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultStoreCapacity is the soft cap on the in-memory IOC count.
// When the cap is hit, the oldest IOCs (by LastSeen) are evicted.
// This keeps memory bounded and biases the store toward recent
// IOCs, which are the most operationally useful.
const DefaultStoreCapacity = 100_000

// DefaultFlushInterval is how often the store writes its in-memory
// state to disk. 30 seconds is a good balance: long enough that we
// don't churn the disk, short enough that a crash loses at most
// 30 seconds of IOC observations.
const DefaultFlushInterval = 30 * time.Second

// DefaultMaxAge is the maximum age (LastSeen) of an IOC in the
// store. IOCs older than this are evicted on flush. 30 days matches
// the Professional tier's log retention and is a reasonable
// operational window for IOC sharing.
const DefaultMaxAge = 30 * 24 * time.Hour

// StoreConfig configures the IOC store. All fields are optional;
// zero values get sensible defaults.
type StoreConfig struct {
	// Capacity is the soft cap on in-memory IOCs. <=0 means
	// DefaultStoreCapacity (100K).
	Capacity int

	// FlushInterval is how often the store flushes to disk. <=0
	// means DefaultFlushInterval (30s).
	FlushInterval time.Duration

	// MaxAge is the maximum age of an IOC in the store. <=0 means
	// DefaultMaxAge (30 days). IOCs older than this are evicted
	// on flush.
	MaxAge time.Duration

	// DiskPath is the file path to flush to. Empty means the
	// store is in-memory only and does not persist across
	// restarts. The parent directory is created on first flush.
	DiskPath string
}

// Store is the local IOC store. Safe for concurrent use.
//
// Typical lifecycle:
//   - main.go creates a Store with NewStore(cfg)
//   - Producer calls Observe() on every event
//   - Sync HTTP handler calls Snapshot() / SnapshotSince() to build
//     a Bundle to serve
//   - A goroutine calls RunFlusher(ctx) to periodically persist
type Store struct {
	cfg StoreConfig

	mu     sync.RWMutex
	byFP   map[string]*IOC // fingerprint -> IOC
	order  []string        // insertion-order list of fingerprints; for stable iteration
	dirty  bool            // true if the in-memory state has unflushed changes
	closed bool
}

// NewStore creates a Store from the given config. Loads any
// existing on-disk state if DiskPath is set and the file exists.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.Capacity <= 0 {
		cfg.Capacity = DefaultStoreCapacity
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	s := &Store{
		cfg:   cfg,
		byFP:  make(map[string]*IOC),
		order: []string{},
	}
	if cfg.DiskPath != "" {
		if err := s.loadFromDisk(); err != nil {
			return nil, fmt.Errorf("load store: %w", err)
		}
	}
	return s, nil
}

// Observe records a new observation of an IOC. If the IOC's
// fingerprint is already in the store, Count is incremented and
// LastSeen is updated. If the new observation has a worse Severity
// than the stored one, the stored severity is updated. FirstSeen
// is preserved.
//
// The function does NOT compute the fingerprint; the caller is
// expected to compute it via Fingerprint(Detection) and supply
// the IOC struct. This keeps the store free of detection-event
// knowledge: it just stores IOCs.
//
// Returns the (possibly updated) IOC that is now in the store.
// The returned pointer is the same object stored; callers must
// not mutate it after Observe returns.
func (s *Store) Observe(ioc IOC) (*IOC, error) {
	if !ioc.Valid() {
		return nil, errors.New("invalid IOC")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if existing, ok := s.byFP[ioc.Fingerprint]; ok {
		// Update in place.
		existing.Count++
		if ioc.LastSeen.After(existing.LastSeen) || ioc.LastSeen.IsZero() {
			existing.LastSeen = ioc.LastSeen
		}
		if ioc.LastSeen.IsZero() {
			existing.LastSeen = now
		}
		existing.Severity = WorseSeverity(existing.Severity, ioc.Severity)
		s.dirty = true
		return existing, nil
	}

	// New IOC. Stamp FirstSeen/LastSeen to now if the caller
	// did not (the producer should always set them, but we
	// are defensive).
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = now
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = now
	}

	// Capacity check: if at cap, evict the IOC with the
	// oldest LastSeen. This is O(N) in the worst case, but
	// the cap is 100K and eviction is rare (only on insert
	// at cap), so this is acceptable.
	if len(s.byFP) >= s.cfg.Capacity {
		s.evictOldest()
	}

	stored := ioc
	s.byFP[ioc.Fingerprint] = &stored
	s.order = append(s.order, ioc.Fingerprint)
	s.dirty = true
	return &stored, nil
}

// Get returns the IOC with the given fingerprint, or nil if not
// in the store.
func (s *Store) Get(fingerprint string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byFP[fingerprint]
}

// Size returns the current number of IOCs in the store.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byFP)
}

// Snapshot returns a copy of every IOC in the store, in
// LastSeen-descending order (most recent first). The returned
// slice is safe to iterate without holding the store lock.
func (s *Store) Snapshot() []IOC {
	s.mu.RLock()
	out := make([]IOC, 0, len(s.byFP))
	for _, ioc := range s.byFP {
		out = append(out, *ioc)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// SnapshotSince returns a copy of every IOC with LastSeen >=
// since, in LastSeen-descending order. This is the delta query
// used by the gossip sync protocol.
func (s *Store) SnapshotSince(since time.Time) []IOC {
	s.mu.RLock()
	out := make([]IOC, 0, len(s.byFP))
	for _, ioc := range s.byFP {
		if ioc.LastSeen.Before(since) {
			continue
		}
		out = append(out, *ioc)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// evictOldest removes the IOC with the oldest LastSeen. Called
// when the store is at capacity. The caller must hold s.mu.
func (s *Store) evictOldest() {
	if len(s.byFP) == 0 {
		return
	}
	var oldestFP string
	var oldestTime time.Time
	first := true
	for fp, ioc := range s.byFP {
		if first || ioc.LastSeen.Before(oldestTime) {
			oldestFP = fp
			oldestTime = ioc.LastSeen
			first = false
		}
	}
	if oldestFP != "" {
		delete(s.byFP, oldestFP)
		// Also remove from order. Order is not critical for
		// correctness, so a linear scan is fine.
		for i, fp := range s.order {
			if fp == oldestFP {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	}
}

// Prune removes IOCs with LastSeen older than maxAge. Returns
// the number of IOCs removed. Typically called from RunFlusher.
func (s *Store) Prune(maxAge time.Duration) int {
	cutoff := time.Now().UTC().Add(-maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for fp, ioc := range s.byFP {
		if ioc.LastSeen.Before(cutoff) {
			delete(s.byFP, fp)
			removed++
		}
	}
	// Rebuild order.
	newOrder := make([]string, 0, len(s.byFP))
	for _, fp := range s.order {
		if _, ok := s.byFP[fp]; ok {
			newOrder = append(newOrder, fp)
		}
	}
	s.order = newOrder
	if removed > 0 {
		s.dirty = true
	}
	return removed
}

// RunFlusher runs the periodic flush loop. It flushes to disk
// (if DiskPath is set) and prunes old IOCs on every tick. Blocks
// until ctx is cancelled.
//
// Intended to be called as `go store.RunFlusher(ctx)` from main.go.
func (s *Store) RunFlusher(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown.
			_ = s.Flush()
			return
		case <-ticker.C:
			_ = s.Prune(s.cfg.MaxAge)
			_ = s.Flush()
		}
	}
}

// Flush writes the in-memory state to disk if (a) DiskPath is
// set and (b) there are unflushed changes. The write is atomic
// (write-to-temp, then rename) so a crash mid-flush leaves the
// previous good state intact.
func (s *Store) Flush() error {
	if s.cfg.DiskPath == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	// Snapshot under lock; release before disk write.
	snap := make([]IOC, 0, len(s.byFP))
	for _, ioc := range s.byFP {
		snap = append(snap, *ioc)
	}
	s.dirty = false
	s.mu.Unlock()

	// Marshal.
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		// Re-mark dirty so we retry on the next tick.
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("marshal: %w", err)
	}

	// Ensure parent dir.
	dir := filepath.Dir(s.cfg.DiskPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("mkdir: %w", err)
	}

	// Atomic write: temp file + rename.
	tmp := s.cfg.DiskPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.cfg.DiskPath); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// mergePeerIOC merges an IOC received from a peer into the
// local store. The merge policy is:
//
//   - FirstSeen: keep the earlier one (min).
//   - LastSeen:  keep the later one (max).
//   - Count:     sum the counts.
//   - Severity:  take the worse one.
//
// Unlike Observe (which increments Count by 1 on each call),
// mergePeerIOC adds the peer-reported count to the local count,
// which is the correct behavior for gossip: the peer is saying
// "I have seen this IOC this many times", and we want the
// combined "us + them" count.
//
// Used by Receiver.Ingest after bundle.VerifyAll() has confirmed
// the bundle is authentic. Not exported because it is only
// meaningful in the context of a verified peer bundle.
func (s *Store) mergePeerIOC(ioc IOC) {
	if !ioc.Valid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if existing, ok := s.byFP[ioc.Fingerprint]; ok {
		if ioc.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = ioc.FirstSeen
		}
		if ioc.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = ioc.LastSeen
		}
		existing.Count += ioc.Count
		existing.Severity = WorseSeverity(existing.Severity, ioc.Severity)
		// Update the Source to reflect that this IOC has
		// been seen by a peer, but only if the existing
		// source was already a peer source (don't overwrite
		// a local source with a peer one on the first merge).
		s.dirty = true
		return
	}
	// New IOC from peer.
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = now
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = now
	}
	if len(s.byFP) >= s.cfg.Capacity {
		s.evictOldest()
	}
	stored := ioc
	s.byFP[ioc.Fingerprint] = &stored
	s.order = append(s.order, ioc.Fingerprint)
	s.dirty = true
}

// loadFromDisk reads the on-disk file and populates the in-memory
// state. Called from NewStore if DiskPath is set. Silently returns
// nil if the file does not exist (first run). Returns an error for
// any other failure.
func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.cfg.DiskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap []IOC
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range snap {
		if !snap[i].Valid() {
			continue
		}
		stored := snap[i]
		s.byFP[stored.Fingerprint] = &stored
		s.order = append(s.order, stored.Fingerprint)
	}
	return nil
}
