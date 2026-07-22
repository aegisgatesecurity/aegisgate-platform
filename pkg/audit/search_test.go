// SPDX-License-Identifier: Apache-2.0
// Tests for the search/parser layer. Pure functions, no HTTP.

package audit

import (
	"testing"
	"time"
)

// fakeEvent is the test adapter from a small struct to loggingEvent.
// Using a local struct (not pkg/logging.Event) avoids the import
// cycle and keeps the test self-contained.
type fakeEvent struct {
	id       string
	t        time.Time
	typ      string
	action   string
	severity string
	user     string
	message  string
}

func (e fakeEvent) GetID() string       { return e.id }
func (e fakeEvent) GetTime() time.Time  { return e.t }
func (e fakeEvent) GetType() string     { return e.typ }
func (e fakeEvent) GetAction() string   { return e.action }
func (e fakeEvent) GetSeverity() string { return e.severity }
func (e fakeEvent) GetUser() string     { return e.user }
func (e fakeEvent) GetMessage() string  { return e.message }

func TestParseSearchQuery_Defaults(t *testing.T) {
	q := ParseSearchQuery(nil)
	if q.Limit != defaultLimit {
		t.Errorf("default limit = %d, want %d", q.Limit, defaultLimit)
	}
	if q.Offset != 0 {
		t.Errorf("default offset = %d, want 0", q.Offset)
	}
	if q.SortAsc {
		t.Errorf("default sort should be newest-first")
	}
}

func TestParseSearchQuery_TimeRange(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{
		"from": {"2026-01-01T00:00:00Z"},
		"to":   {"2026-12-31T23:59:59Z"},
	})
	if q.From.IsZero() || q.To.IsZero() {
		t.Errorf("from/to not parsed: from=%v to=%v", q.From, q.To)
	}
	if q.From.Year() != 2026 || q.To.Year() != 2026 {
		t.Errorf("year not parsed: from=%v to=%v", q.From, q.To)
	}
}

func TestParseSearchQuery_InvalidTime(t *testing.T) {
	// Invalid times are silently ignored (zero value), not an error.
	// This matches the principle of "lenient parsing" - a bad filter
	// just means no filtering on that dimension.
	q := ParseSearchQuery(map[string][]string{
		"from": {"not-a-time"},
	})
	if !q.From.IsZero() {
		t.Errorf("invalid from time should be zero value, got %v", q.From)
	}
}

func TestParseSearchQuery_LimitClamping(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{"limit": {"5000"}})
	if q.Limit != maxLimit {
		t.Errorf("limit should be clamped to %d, got %d", maxLimit, q.Limit)
	}
}

func TestParseSearchQuery_SortAsc(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{"sort": {"asc"}})
	if !q.SortAsc {
		t.Errorf("sort=asc should set SortAsc=true")
	}
	q = ParseSearchQuery(map[string][]string{"sort": {"desc"}})
	if q.SortAsc {
		t.Errorf("sort=desc should set SortAsc=false")
	}
}

func TestMatches_AllFields(t *testing.T) {
	e := fakeEvent{
		t:        time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		typ:      "auth",
		action:   "block",
		severity: "high",
		user:     "Alice",
	}
	q := SearchQuery{
		From:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:        time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		Severity:  "high",
		User:      "ali", // substring, case-insensitive
		Action:    "blo", // substring
		EventType: "au",  // substring
	}
	if !q.Matches(e) {
		t.Errorf("event should match all filters")
	}
}

func TestMatches_TimeOutOfRange(t *testing.T) {
	e := fakeEvent{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	q := SearchQuery{
		From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if q.Matches(e) {
		t.Errorf("event before From should not match")
	}
}

func TestMatches_SeverityMismatch(t *testing.T) {
	e := fakeEvent{severity: "low"}
	q := SearchQuery{Severity: "high"}
	if q.Matches(e) {
		t.Errorf("severity mismatch should not match")
	}
}

func TestSearch_FilterAndPaginate(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// 5 events, 2 minutes apart, 3 are "auth" type, 2 are "threat".
	events := []loggingEvent{
		fakeEvent{id: "e1", t: base, typ: "auth"},
		fakeEvent{id: "e2", t: base.Add(2 * time.Minute), typ: "threat"},
		fakeEvent{id: "e3", t: base.Add(4 * time.Minute), typ: "auth"},
		fakeEvent{id: "e4", t: base.Add(6 * time.Minute), typ: "threat"},
		fakeEvent{id: "e5", t: base.Add(8 * time.Minute), typ: "auth"},
	}
	q := SearchQuery{EventType: "auth", Limit: 2}
	r := q.Search(events)
	if r.Total != 3 {
		t.Errorf("Total = %d, want 3 (3 auth events)", r.Total)
	}
	if len(r.Events) != 2 {
		t.Errorf("len(Events) = %d, want 2 (Limit=2)", len(r.Events))
	}
	// Newest first: e5, then e3.
	if r.Events[0].GetID() != "e5" || r.Events[1].GetID() != "e3" {
		t.Errorf("events out of order: %s, %s", r.Events[0].GetID(), r.Events[1].GetID())
	}
}

func TestSearch_OffsetBeyondResults(t *testing.T) {
	events := []loggingEvent{
		fakeEvent{id: "e1", t: time.Now()},
		fakeEvent{id: "e2", t: time.Now()},
	}
	q := SearchQuery{Offset: 10, Limit: 5}
	r := q.Search(events)
	if len(r.Events) != 0 {
		t.Errorf("offset beyond results should return empty, got %d", len(r.Events))
	}
	if r.Total != 2 {
		t.Errorf("Total = %d, want 2", r.Total)
	}
}

func TestSearch_SortAsc(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	events := []loggingEvent{
		fakeEvent{id: "newer", t: base.Add(10 * time.Minute)},
		fakeEvent{id: "older", t: base},
	}
	q := SearchQuery{SortAsc: true, Limit: 10}
	r := q.Search(events)
	if r.Events[0].GetID() != "older" {
		t.Errorf("SortAsc: first should be 'older', got %q", r.Events[0].GetID())
	}
}

func TestSearch_EmptyInput(t *testing.T) {
	q := SearchQuery{}
	r := q.Search(nil)
	if r.Total != 0 || len(r.Events) != 0 {
		t.Errorf("empty input should return zero, got %+v", r)
	}
}
