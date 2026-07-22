// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Audit Log Search HTTP Handlers
// =========================================================================
//
// HTTP API for the audit log search subsystem. The package is split:
//
//   - search.go      - query types and pure matcher/pagination
//   - search_test.go - unit tests for the matcher
//   - handler.go     - this file: HTTP handlers + adapter from
//                       logging.Event to the loggingEvent interface
//
// v1 scope (the v3.x close-out plan):
//   - GET /api/v1/audit/search?from=&to=&user=&action=&severity=&type=&limit=&offset=&sort=
//   - GET /api/v1/audit/events/:id
//   - GET /api/v1/audit/users/:user/timeline
//   - GET /api/v1/audit/stats
//
// All handlers are GET-only, read-only, and license-gated via the
// standard LicenseMiddleware (same pattern as /api/v1/compliance/*).
// In-memory event source: the Searcher holds a snapshot of the
// audit ring buffer, refreshed on each request. For v2 we can
// add a persistent backend.
//
// The loggingEvent interface (defined in search.go) lets us
// avoid an import cycle with pkg/logging: pkg/audit -> pkg/logging
// -> pkg/audit would be circular if we imported logging.Event
// directly. The adapter below bridges at the handler boundary.
// =========================================================================

package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// Searcher is the HTTP-facing entry point. It owns a snapshot of
// audit events and serves search/status requests. v1: the snapshot
// is taken from the configured EventSource on each request, so
// callers see events up to "right now" minus source latency.
// v2: add caching with a configurable refresh interval.
type Searcher struct {
	mu      sync.RWMutex
	source  EventSource
	licence *license.Manager
}

// EventSource is the subset of evidence.EventSource we depend on
// for v1. Kept as a package-local interface so the audit package
// doesn't pull in pkg/evidence at the type level (it does pull
// it in for license-middleware integration in main, but that's
// via main binary not this package).
type EventSource interface {
	// SnapshotBetween returns events with Time in [start, end].
	// Either bound may be zero for "no bound".
	SnapshotBetween(start, end time.Time) []logging.Event
}

// NewSearcher creates a new audit searcher. source and lic may
// not be nil. If either is nil, handlers return 500 (fail-closed,
// same as the compliance API pattern).
func NewSearcher(source EventSource, lic *license.Manager) *Searcher {
	return &Searcher{source: source, licence: lic}
}

// ServeHTTP implements http.Handler. Strips the /api/v1/audit
// prefix if present and dispatches on the suffix. All routes
// require a valid license (LicenseMiddleware runs upstream in
// the main binary's router).
func (s *Searcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.source == nil || s.licence == nil {
		writeError(w, http.StatusInternalServerError, "audit search not configured (source or manager nil)")
		return
	}
	path := r.URL.Path
	const prefix = "/api/v1/audit"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		path = path[len(prefix):]
	}
	if path == "" || path == "/" {
		path = "/search"
	}
	switch {
	case path == "/search" || strings.HasPrefix(path, "/search?"):
		s.serveSearch(w, r)
	case path == "/stats" || strings.HasPrefix(path, "/stats?"):
		s.serveStats(w, r)
	case strings.HasPrefix(path, "/events/"):
		s.serveEventByID(w, r, strings.TrimPrefix(path, "/events/"))
	case strings.HasPrefix(path, "/users/"):
		s.serveUserTimeline(w, r, strings.TrimPrefix(path, "/users/"))
	default:
		http.NotFound(w, r)
	}
}

// serveSearch handles GET /api/v1/audit/search.
func (s *Searcher) serveSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "search requires GET")
		return
	}
	q := ParseSearchQuery(r.URL.Query())

	// Take a snapshot from the source under the read lock.
	s.mu.RLock()
	events := s.source.SnapshotBetween(q.From, q.To)
	s.mu.RUnlock()

	// Convert from logging.Event to the loggingEvent interface.
	adapted := make([]loggingEvent, len(events))
	for i, e := range events {
		adapted[i] = loggingEventAdapter{e}
	}

	result := q.Search(adapted)
	writeJSON(w, http.StatusOK, searchResponse{
		Events: result.Events,
		Total:  result.Total,
		Limit:  result.Limit,
		Offset: result.Offset,
	})
}

// serveEventByID handles GET /api/v1/audit/events/:id. Looks up the
// event with the given ID across the entire snapshot (no time
// range). Returns 404 if not found.
func (s *Searcher) serveEventByID(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "events lookup requires GET")
		return
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing event id")
		return
	}
	s.mu.RLock()
	events := s.source.SnapshotBetween(time.Time{}, time.Time{})
	s.mu.RUnlock()
	for _, e := range events {
		if e.ID == id {
			writeJSON(w, http.StatusOK, e)
			return
		}
	}
	writeError(w, http.StatusNotFound, "event not found")
}

// serveUserTimeline handles GET /api/v1/audit/users/:user/timeline.
// Returns all events for the user, sorted newest-first. No time
// range filter (use the search endpoint for that).
func (s *Searcher) serveUserTimeline(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "timeline requires GET")
		return
	}
	if user == "" {
		writeError(w, http.StatusBadRequest, "missing user")
		return
	}
	s.mu.RLock()
	events := s.source.SnapshotBetween(time.Time{}, time.Time{})
	s.mu.RUnlock()

	adapted := make([]loggingEvent, 0, len(events))
	for _, e := range events {
		if strings.EqualFold(e.User, user) {
			adapted = append(adapted, loggingEventAdapter{e})
		}
	}
	// Reuse Search with a query that matches everything but the user
	// filter is already applied. Pass an empty EventType to avoid
	// type filtering and a huge limit to get all.
	q := SearchQuery{Limit: adaptedLen(adapted), SortAsc: false}
	result := q.Search(adapted)
	writeJSON(w, http.StatusOK, searchResponse{
		Events: result.Events,
		Total:  result.Total,
		Limit:  result.Limit,
		Offset: result.Offset,
	})
}

// serveStats handles GET /api/v1/audit/stats. Returns counts
// grouped by severity, action, and time bucket. The time bucket
// is the last 1 hour, 24 hours, and 7 days.
//
// v1: stats are computed in-memory from the snapshot. This is
// fine for ring-buffer-backed sources (typically 10K events).
// For larger sources, v2 should push the count queries into the
// store.
func (s *Searcher) serveStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "stats requires GET")
		return
	}
	now := time.Now()
	cutoffs := map[string]time.Time{
		"1h":  now.Add(-1 * time.Hour),
		"24h": now.Add(-24 * time.Hour),
		"7d":  now.Add(-7 * 24 * time.Hour),
	}
	stats := statsResponse{
		Buckets:    make(map[string]bucketStats, len(cutoffs)),
		BySeverity: make(map[string]int),
		ByAction:   make(map[string]int),
	}

	s.mu.RLock()
	all := s.source.SnapshotBetween(time.Time{}, time.Time{})
	s.mu.RUnlock()

	for name, cutoff := range cutoffs {
		b := bucketStats{}
		for _, e := range all {
			if e.Time.Before(cutoff) {
				continue
			}
			b.Total++
			stats.BySeverity[string(e.Severity)]++
			stats.ByAction[e.Action]++
		}
		stats.Buckets[name] = b
	}
	writeJSON(w, http.StatusOK, stats)
}

// searchResponse is the JSON shape returned by /audit/search and
// /audit/users/:user/timeline.
type searchResponse struct {
	Events []loggingEvent `json:"events"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// statsResponse is the JSON shape returned by /audit/stats.
type statsResponse struct {
	Buckets    map[string]bucketStats `json:"buckets"`
	BySeverity map[string]int         `json:"bySeverity"`
	ByAction   map[string]int         `json:"byAction"`
}

type bucketStats struct {
	Total int `json:"total"`
}

// loggingEventAdapter bridges logging.Event (the canonical event
// type in pkg/logging) to the loggingEvent interface defined in
// search.go. We do this adapter dance to avoid an import cycle.
type loggingEventAdapter struct{ e logging.Event }

func (a loggingEventAdapter) GetID() string       { return a.e.ID }
func (a loggingEventAdapter) GetTime() time.Time  { return a.e.Time }
func (a loggingEventAdapter) GetType() string     { return a.e.Type }
func (a loggingEventAdapter) GetAction() string   { return a.e.Action }
func (a loggingEventAdapter) GetSeverity() string { return string(a.e.Severity) }
func (a loggingEventAdapter) GetUser() string     { return a.e.User }
func (a loggingEventAdapter) GetMessage() string  { return a.e.Message }

// adaptedLen returns len(e) without forcing a type assertion
// (used in serveUserTimeline to size the limit).
func adaptedLen(e []loggingEvent) int { return len(e) }

// writeJSON writes a 200-class JSON response. Used by all handlers.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes a JSON error response. Matches the compliance
// API's error shape for consistency.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Ensure the searcher satisfies http.Handler at compile time.
var _ http.Handler = (*Searcher)(nil)

// Ensure the searcher can be used with the context-based middleware
// pattern (e.g., for cancellation). v2 may add this; v1 doesn't
// because all handlers are fast in-memory lookups.
var _ = context.Background
