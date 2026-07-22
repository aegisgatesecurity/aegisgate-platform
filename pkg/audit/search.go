// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Audit Log Search (v3.x Work Item 11)
// =========================================================================
//
// Provides a query/parse layer over an audit event source (typically a
// logging.RingBuffer) so the HTTP handlers in handler.go can serve
// filtered event lists. The package is split into two files:
//
//   - search.go  (this file): pure types, no I/O
//   - handler.go:             HTTP handlers + a thin Searcher wrapper
//
// v1 scope:
//   - Filter by time range, user, action, severity, type (event type)
//   - Pagination (limit + offset)
//   - Sortable by time (default: newest first)
//   - Read-only - the source is not mutated
//
// Out of scope (v2):
//   - Full-text search on the message field
//   - Long-term cold storage (currently only the in-memory ring buffer)
//   - SIEM forwarding (already in siem_dispatcher.go)
//
// v1 deliberately uses the same EventSource abstraction the SIEM
// dispatcher uses (pkg/evidence.EventSource) so any source that
// implements it works for both forwarding and search.
// =========================================================================

package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// loggingEvent is a small, package-local interface satisfied by
// logging.Event (the canonical event type) and any other audit event
// type with at least these fields. We use an interface (not a
// concrete dependency on pkg/logging) to avoid an import cycle:
// pkg/audit -> pkg/logging -> pkg/audit would be a cycle if
// pkg/audit exported types referring to logging.Event.
//
// All fields are read via the interface so the search layer does not
// care about the concrete event type.
type loggingEvent interface {
	GetID() string
	GetTime() time.Time
	GetType() string
	GetAction() string
	GetSeverity() string
	GetUser() string
	GetMessage() string
}

// SearchQuery is the parsed, validated form of an HTTP /audit/search
// request. Fields map 1:1 to query parameters.
type SearchQuery struct {
	// From is the inclusive lower bound on event time. Zero = no lower
	// bound.
	From time.Time
	// To is the inclusive upper bound on event time. Zero = no upper
	// bound.
	To time.Time
	// User is the user identifier substring filter. Empty = no
	// filter. Substring match is case-insensitive.
	User string
	// Action is the action substring filter. Empty = no filter.
	// Substring match is case-insensitive.
	Action string
	// Severity is the exact severity match. Empty = no filter. For
	// severity ordering see logging.Severity constants.
	Severity string
	// EventType is the event type substring filter. Empty = no
	// filter. Substring match is case-insensitive.
	EventType string
	// Limit caps the number of returned events. Must be > 0; values
	// <= 0 are treated as defaultLimit (100).
	Limit int
	// Offset skips the first N events after filtering. Must be >= 0;
	// negative values are treated as 0.
	Offset int
	// SortAsc sorts oldest-first; the default (false) is newest-first.
	SortAsc bool
}

// SearchResult is the response payload for /audit/search.
type SearchResult struct {
	// Events is the page of matching events, ordered per
	// SearchQuery.SortAsc. Each element is the canonical Event
	// (logging.Event) — the handler serializes it to JSON.
	Events []loggingEvent
	// Total is the total number of events that matched the filters
	// (before Limit/Offset). For UI pagination.
	Total int
	// Limit and Offset echo the applied pagination for client
	// validation.
	Limit  int
	Offset int
}

// Defaults applied to user input. These are not configurable per
// request; they're the v1 product decisions.
const (
	defaultLimit = 100
	maxLimit     = 1000
)

// ParseSearchQuery normalises raw HTTP form values into a SearchQuery.
// Missing or empty values are treated as "no filter". The limit is
// clamped to [1, maxLimit]. An explicit zero limit means "use
// defaultLimit".
//
// The function does not validate that From <= To; the matcher just
// returns zero results if the range is inverted.
func ParseSearchQuery(params map[string][]string) SearchQuery {
	q := SearchQuery{
		Limit: defaultLimit,
	}
	if v, ok := firstValue(params, "from"); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.From = t
		}
	}
	if v, ok := firstValue(params, "to"); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.To = t
		}
	}
	if v, ok := firstValue(params, "user"); ok {
		q.User = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := firstValue(params, "action"); ok {
		q.Action = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := firstValue(params, "severity"); ok {
		q.Severity = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := firstValue(params, "type"); ok {
		q.EventType = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := firstValue(params, "limit"); ok && v != "" {
		var lim int
		fmt.Sscanf(v, "%d", &lim)
		if lim > 0 {
			q.Limit = lim
		}
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	if v, ok := firstValue(params, "offset"); ok && v != "" {
		var off int
		fmt.Sscanf(v, "%d", &off)
		if off > 0 {
			q.Offset = off
		}
	}
	if v, ok := firstValue(params, "sort"); ok {
		q.SortAsc = strings.EqualFold(v, "asc")
	}
	return q
}

// firstValue returns the first value for the given key and whether
// the key was present. Go's map indexing makes "present with empty
// value" distinct from "absent".
func firstValue(params map[string][]string, key string) (string, bool) {
	if params == nil {
		return "", false
	}
	vals, ok := params[key]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// Matches reports whether an event matches the query. The matcher
// is exact for Severity (events have a fixed severity scale) and
// case-insensitive substring for User/Action/EventType. Time-range
// matching is inclusive on both ends.
func (q SearchQuery) Matches(e loggingEvent) bool {
	t := e.GetTime()
	if !q.From.IsZero() && t.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && t.After(q.To) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.GetSeverity(), q.Severity) {
		return false
	}
	if q.User != "" && !strings.Contains(strings.ToLower(e.GetUser()), q.User) {
		return false
	}
	if q.Action != "" && !strings.Contains(strings.ToLower(e.GetAction()), q.Action) {
		return false
	}
	if q.EventType != "" && !strings.Contains(strings.ToLower(e.GetType()), q.EventType) {
		return false
	}
	return true
}

// Search filters and paginates events from an in-memory slice. It
// is the in-process implementation used by the HTTP handlers; tests
// exercise it directly with synthetic event slices. For a persistent
// source, the same Matches predicate can be pushed down into the
// store later (v2).
//
// Pre-conditions: the input slice may be unsorted. Search sorts
// the filtered slice in-place according to q.SortAsc.
func (q SearchQuery) Search(events []loggingEvent) SearchResult {
	// Filter pass.
	filtered := make([]loggingEvent, 0, len(events))
	for _, e := range events {
		if q.Matches(e) {
			filtered = append(filtered, e)
		}
	}
	total := len(filtered)
	// Sort pass.
	sort.SliceStable(filtered, func(i, j int) bool {
		ti, tj := filtered[i].GetTime(), filtered[j].GetTime()
		if q.SortAsc {
			return ti.Before(tj)
		}
		return ti.After(tj)
	})
	// Pagination pass.
	start := q.Offset
	if start > total {
		start = total
	}
	end := start + q.Limit
	if end > total {
		end = total
	}
	if start > end {
		start = end
	}
	return SearchResult{
		Events: filtered[start:end],
		Total:  total,
		Limit:  q.Limit,
		Offset: q.Offset,
	}
}
