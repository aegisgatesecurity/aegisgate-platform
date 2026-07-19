// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ D1 PostgreSQL)
// =========================================================================
//
// store_adapter.go adapts the in-memory Store to implement StoreInterface.
// The in-memory Store's methods don't accept context.Context, so the adapter
// ignores the context and delegates to the existing methods.
//
// This adapter allows both Store and PostgresStore to be used interchangeably
// wherever StoreInterface is expected (e.g., /check handler, sync handler).
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package ioc

import (
	"context"
	"time"
)

// Verify Store implements StoreInterface at compile time.
var _ StoreInterface = (*StoreAdapter)(nil)

// StoreAdapter wraps an in-memory Store to implement StoreInterface.
// The context parameter is ignored since in-memory operations are
// synchronous and don't support cancellation.
type StoreAdapter struct {
	inner *Store
}

// NewStoreAdapter creates a StoreInterface adapter for an in-memory Store.
func NewStoreAdapter(s *Store) *StoreAdapter {
	return &StoreAdapter{inner: s}
}

// Observe records a new observation of an IOC. Context is ignored.
func (a *StoreAdapter) Observe(ctx context.Context, ioc IOC) (*IOC, error) {
	return a.inner.Observe(ioc)
}

// ObserveBatch records multiple IOCs. Context is ignored.
// The in-memory Store processes these sequentially via Observe.
func (a *StoreAdapter) ObserveBatch(ctx context.Context, iocs []IOC) error {
	for i := range iocs {
		if _, err := a.inner.Observe(iocs[i]); err != nil {
			return err
		}
	}
	return nil
}

// Get returns the IOC with the given fingerprint. Context is ignored.
func (a *StoreAdapter) Get(ctx context.Context, fingerprint string) (*IOC, error) {
	return a.inner.Get(fingerprint), nil
}

// Size returns the number of IOCs. Context is ignored.
func (a *StoreAdapter) Size(ctx context.Context) (int, error) {
	return a.inner.Size(), nil
}

// Snapshot returns all IOCs sorted by LastSeen descending. Context is ignored.
func (a *StoreAdapter) Snapshot(ctx context.Context) ([]IOC, error) {
	return a.inner.Snapshot(), nil
}

// SnapshotSince returns IOCs with LastSeen >= since. Context is ignored.
func (a *StoreAdapter) SnapshotSince(ctx context.Context, since time.Time) ([]IOC, error) {
	return a.inner.SnapshotSince(since), nil
}

// Query implements indexed query for the in-memory Store by falling
// back to a linear scan with filtering. This is O(N) but acceptable
// for Community/Developer tiers where the store is capped at 100K.
func (a *StoreAdapter) Query(ctx context.Context, filter IOCQuery) ([]IOC, error) {
	snap := a.inner.Snapshot()
	var result []IOC
	for _, ioc := range snap {
		if !matchFilter(ioc, filter) {
			continue
		}
		result = append(result, ioc)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	// Apply offset after collecting.
	if filter.Offset > 0 && filter.Offset < len(result) {
		result = result[filter.Offset:]
	} else if filter.Offset > 0 {
		result = nil
	}
	return result, nil
}

// Prune removes IOCs older than maxAge. Context is ignored.
func (a *StoreAdapter) Prune(ctx context.Context, maxAge time.Duration) (int, error) {
	return a.inner.Prune(maxAge), nil
}

// Flush writes the in-memory state to disk. Context is ignored.
func (a *StoreAdapter) Flush(ctx context.Context) error {
	return a.inner.Flush()
}

// Close stops the flusher goroutine. Context is ignored.
func (a *StoreAdapter) Close() error {
	// The in-memory Store doesn't have a Close method in the current
	// implementation. The flusher is stopped via context cancellation
	// passed to RunFlusher. This is a no-op here.
	return nil
}

// matchFilter checks if an IOC matches the query filter criteria.
func matchFilter(ioc IOC, filter IOCQuery) bool {
	if filter.Type != "" && ioc.Type != filter.Type {
		return false
	}
	if filter.SeverityMin != "" && severityRank(ioc.Severity) < severityRank(filter.SeverityMin) {
		return false
	}
	if filter.Category != "" && ioc.Category != filter.Category {
		return false
	}
	if filter.SourceProvider != "" && ioc.SourceProvider != filter.SourceProvider {
		return false
	}
	if filter.AffectsLens != nil && ioc.AffectsLens != *filter.AffectsLens {
		return false
	}
	if filter.AffectsGateway != nil && ioc.AffectsGateway != *filter.AffectsGateway {
		return false
	}
	if !filter.Since.IsZero() && ioc.LastSeen.Before(filter.Since) {
		return false
	}
	return true
}
