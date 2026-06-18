// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Retention Jobs
// =========================================================================
//
// retention.go runs three scheduled jobs:
//
//   1. 90-day raw event purge
//      Every 24 hours, remove any raw event whose timestamp is
//      older than 90 days. The events live in the IOC store's
//      on-disk JSON file under the configured store dir; the
//      purge reads the file, removes old entries, and writes
//      it back atomically.
//
//   2. 24-hour "send_anyway" event purge
//      Every 24 hours, remove any event whose user_action is
//      "send_anyway" and whose timestamp is older than 24 hours.
//      This is the privacy-policy commitment: events where the
//      user dismissed the warning and sent the prompt anyway
//      are particularly sensitive and are purged after 24 hours
//      rather than the 90-day default. The remaining 89.9 days
//      of headroom is for the aggregated IOC, not the raw
//      event.
//
//   3. 24-hour coarse IP geolocation cache flush
//      Every 24 hours, clear the in-memory IP-to-coarse-country
//      cache. We keep this for the 24 hours between scheduled
//      flushes to bound the cache size.
//
// The jobs are wired up in server.go's RunRetention method,
// which takes a context.Context and blocks until the context
// is cancelled. The retention interval (1 hour between checks,
// or 24 hours between runs) is configurable via env vars; we
// default to 1h between checks and 24h between runs.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RetentionInterval is how often the retention jobs run.
// Default: 1 hour. Configurable via LENS_RETENTION_INTERVAL.
const DefaultRetentionInterval = 1 * time.Hour

// SendAnywayRetention is how long "send_anyway" events are retained.
// Default: 24 hours. Configurable via LENS_SEND_ANYWAY_RETENTION.
const DefaultSendAnywayRetention = 24 * time.Hour

// retentionState holds the in-memory caches that need periodic
// flushing. The 90-day and 24-hour purges operate on the IOC
// store's on-disk file; the IP geolocation cache is in-memory.
type retentionState struct {
	mu             sync.Mutex
	storePath      string
	eventRetention time.Duration
	sendAnyway     time.Duration
	ipGeoCache     map[string]ipGeoEntry // IP -> coarse country
	audit          *auditLogger
	logger         *slog.Logger
}

// ipGeoEntry is one entry in the IP-to-coarse-country cache.
// We only retain the country code, the city is dropped.
type ipGeoEntry struct {
	countryCode string
	storedAt    time.Time
}

// newRetentionState creates a retentionState.
func newRetentionState(storePath string, eventRetention, sendAnyway time.Duration, audit *auditLogger, logger *slog.Logger) *retentionState {
	return &retentionState{
		storePath:      storePath,
		eventRetention: eventRetention,
		sendAnyway:     sendAnyway,
		ipGeoCache:     make(map[string]ipGeoEntry),
		audit:          audit,
		logger:         logger,
	}
}

// RunRetention blocks until ctx is cancelled, running the three
// retention jobs every interval. The first run happens after
// one interval (not at startup), to avoid racing with server
// startup. Adjust by calling RunRetention with a shorter interval
// for tests.
func (r *retentionState) RunRetention(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRetentionInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce runs all three retention jobs once. Exposed for tests
// and for an admin endpoint that triggers a manual run.
func (r *retentionState) runOnce(ctx context.Context) {
	start := time.Now()
	eventsPurged := r.purgeOldEvents(ctx)
	sendAnywayPurged := r.purgeSendAnywayEvents(ctx)
	r.flushIPGeoCache(ctx)
	r.audit.RecordReceived(ctx, "retention", "", "") // placeholder
	r.logger.Info("lens_retention_complete",
		slog.Int("events_purged", eventsPurged),
		slog.Int("send_anyway_purged", sendAnywayPurged),
		slog.Duration("duration", time.Since(start)),
	)
}

// purgeOldEvents removes events older than r.eventRetention
// from the on-disk store. Returns the number of events purged.
func (r *retentionState) purgeOldEvents(ctx context.Context) int {
	return r.purgeStore(ctx, func(ts time.Time, action string) bool {
		return time.Since(ts) > r.eventRetention
	})
}

// purgeSendAnywayEvents removes send_anyway events older than
// r.sendAnyway from the on-disk store. Returns the number purged.
func (r *retentionState) purgeSendAnywayEvents(ctx context.Context) int {
	return r.purgeStore(ctx, func(ts time.Time, action string) bool {
		return action == string(UserActionSendAnyway) && time.Since(ts) > r.sendAnyway
	})
}

// purgeStore reads the IOC store's on-disk file, applies the
// filter function, writes the filtered file back atomically, and
// returns the number of entries removed.
//
// We deliberately do NOT use the IOC store's Prune method
// because the store's internal data structure is keyed by IOC
// fingerprint, not by raw event. The Lens's raw events live in
// a separate file (events.jsonl) under the store path. This
// file is the source of truth for raw events and is what we
// purge here.
//
// File format: newline-delimited JSON. Each line is one
// {timestamp, user_action, ...} record. We stream-read, filter,
// and stream-write to a temp file, then rename atomically.
func (r *retentionState) purgeStore(ctx context.Context, shouldRemove func(ts time.Time, action string) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	eventsPath := filepath.Join(r.storePath, "events.jsonl") // #nosec G304 -- events.jsonl is the service's own data file, path is hardcoded
	f, err := os.Open(eventsPath)                            // #nosec G304 -- see above
	if err != nil {
		// File may not exist on first run; that's fine.
		if os.IsNotExist(err) {
			return 0
		}
		r.logger.Error("lens_retention_open_failed",
			slog.String("path", eventsPath),
			slog.String("err", err.Error()),
		)
		return 0
	}
	defer f.Close() // #nosec G104 -- close error is non-fatal in a read-only close; the OS will release the fd on process exit

	// Stream-decode and stream-encode. We use a temp file in
	// the same directory, then rename atomically.
	dec := json.NewDecoder(f)
	tmpPath := eventsPath + ".tmp"
	tmp, err := os.Create(tmpPath) // #nosec G304 -- tmp file in the service's data dir, name is hardcoded
	if err != nil {
		r.logger.Error("lens_retention_tmp_create_failed",
			slog.String("path", tmpPath),
			slog.String("err", err.Error()),
		)
		return 0
	}
	enc := json.NewEncoder(tmp)

	purged := 0
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			r.logger.Error("lens_retention_decode_failed",
				slog.String("err", err.Error()),
			)
			_ = tmp.Close()        // #nosec G104 -- best-effort close
			_ = os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
			return purged
		}
		ts, _ := rec["timestamp"].(float64)
		action, _ := rec["user_action"].(string)
		if shouldRemove(time.Unix(int64(ts), 0).UTC(), action) {
			purged++
			continue
		}
		if err := enc.Encode(rec); err != nil {
			r.logger.Error("lens_retention_encode_failed",
				slog.String("err", err.Error()),
			)
			_ = tmp.Close()        // #nosec G104 -- best-effort close
			_ = os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
			return purged
		}
	}
	_ = tmp.Close() // #nosec G104 -- close before rename; the rename is the real durability boundary
	if err := os.Rename(tmpPath, eventsPath); err != nil {
		r.logger.Error("lens_retention_rename_failed",
			slog.String("err", err.Error()),
		)
		_ = os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
		return purged
	}
	return purged
}

// flushIPGeoCache clears the in-memory IP geolocation cache.
// The cache is repopulated lazily on next lookups.
func (r *retentionState) flushIPGeoCache(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cleared := len(r.ipGeoCache)
	r.ipGeoCache = make(map[string]ipGeoEntry)
	r.logger.Info("lens_ip_geo_cache_flushed",
		slog.Int("entries_cleared", cleared),
	)
}

// lookUpIPGeo returns the coarse country code for an IP,
// or "ZZ" (unknown) if the IP is not in the cache. The cache
// is bounded by the 24-hour retention job.
func (r *retentionState) lookUpIPGeo(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.ipGeoCache[ip]; ok {
		return e.countryCode
	}
	return "ZZ"
}

// storeIPGeo records the coarse country code for an IP.
// Called by the rate-limit middleware on first sight of a
// new IP (no third-party geolocation library is imported;
// the country is derived from the X-Country-Code header
// set by the edge proxy, or "ZZ" if not available).
func (r *retentionState) storeIPGeo(ip, countryCode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ipGeoCache[ip] = ipGeoEntry{
		countryCode: countryCode,
		storedAt:    time.Now().UTC(),
	}
}

// Validate is a small helper used in tests to assert that
// the retention state is consistent.
func (r *retentionState) validate() error {
	if r.eventRetention <= 0 {
		return fmt.Errorf("eventRetention must be positive, got %v", r.eventRetention)
	}
	if r.sendAnyway <= 0 {
		return fmt.Errorf("sendAnyway must be positive, got %v", r.sendAnyway)
	}
	return nil
}

// sortByTime is a small helper to sort a slice of timestamps
// in ascending order. Not used by the retention logic itself
// (the on-disk file is time-ordered already), but available
// for tests.
func sortByTime(times []time.Time) {
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
}
