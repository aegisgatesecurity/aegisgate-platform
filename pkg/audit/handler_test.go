// SPDX-License-Identifier: Apache-2.0
// Tests for the HTTP handler layer in handler.go.
//
// Tests use a fake EventSource so we don't depend on a real
// ring buffer or scanner. The license manager is a real one
// (license.NewManager) but we don't gate the tests on it -
// LicenseMiddleware runs upstream in the main binary, not in
// this package. Here we just exercise the handlers directly.

package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// fakeEventSource is a test source. It stores a slice of events
// and returns them on SnapshotBetween. Time-bounded: only events
// in [start, end] are returned.
type fakeEventSource struct {
	events []logging.Event
}

func (s *fakeEventSource) SnapshotBetween(start, end time.Time) []logging.Event {
	out := make([]logging.Event, 0, len(s.events))
	for _, e := range s.events {
		if !start.IsZero() && e.Time.Before(start) {
			continue
		}
		if !end.IsZero() && e.Time.After(end) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// newTestSearcher creates a Searcher with a fake source and a real
// license manager (the manager isn't actually exercised in the
// tests, but we need a non-nil one for NewSearcher to work).
func newTestSearcher(events []logging.Event) *Searcher {
	lic, _ := license.NewManager()
	_ = lic // we don't actually use the manager in handler tests
	return NewSearcher(&fakeEventSource{events: events}, lic)
}

// sampleEvents returns 3 events spanning different times, users,
// and severities. The base time is 30 minutes before time.Now() so
// all 3 events fall in the 1h stats bucket and the 24h bucket.
// Used across multiple tests.
func sampleEvents() []logging.Event {
	base := time.Now().Add(-30 * time.Minute)
	return []logging.Event{
		{ID: "e1", Time: base, Type: "auth", Action: "allow",
			Severity: logging.SeverityLow, User: "alice", Message: "login"},
		{ID: "e2", Time: base.Add(5 * time.Minute), Type: "threat", Action: "block",
			Severity: logging.SeverityHigh, User: "bob", Message: "intrusion"},
		{ID: "e3", Time: base.Add(10 * time.Minute), Type: "auth", Action: "deny",
			Severity: logging.SeverityMedium, User: "alice", Message: "fail"},
	}
}

// helper to run a request and return the recorded response.
func runRequest(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// =====================================================================
// /search
// =====================================================================

func TestSearchHandler_Basic(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3", resp.Total)
	}
	if len(resp.Events) != 3 {
		t.Errorf("len(Events) = %d, want 3", len(resp.Events))
	}
}

func TestSearchHandler_StripsPrefix(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	// Both /audit/search and /api/v1/audit/search should hit the
	// same handler.
	rr1 := runRequest(t, s, "GET", "/audit/search")
	rr2 := runRequest(t, s, "GET", "/api/v1/audit/search")
	if rr1.Code != http.StatusOK || rr2.Code != http.StatusOK {
		t.Errorf("prefix variants: %d, %d", rr1.Code, rr2.Code)
	}
}

func TestSearchHandler_FilterByUser(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search?user=alice")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2 (alice has 2 events)", resp.Total)
	}
	for _, e := range resp.Events {
		if e.GetUser() != "alice" {
			t.Errorf("non-alice event in results: %s", e.GetUser())
		}
	}
}

func TestSearchHandler_FilterByType(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search?type=auth")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2 (auth type has 2 events)", resp.Total)
	}
}

func TestSearchHandler_FilterBySeverity(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search?severity=high")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1 (one high-severity event)", resp.Total)
	}
}

func TestSearchHandler_FilterByTimeRange(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	// e1 is at base, e2 at base+5m, e3 at base+10m
	// Asking for >= base+3m and <= base+7m should return only e2.
	// sampleEvents() builds events relative to time.Now(), so the
	// test's base must be the same anchor (not a hardcoded wall
	// clock date) for the filter to actually match the events.
	base := time.Now().Add(-30 * time.Minute)
	from := base.Add(3 * time.Minute).Format(time.RFC3339)
	to := base.Add(7 * time.Minute).Format(time.RFC3339)
	rr := runRequest(t, s, "GET",
		fmt.Sprintf("/api/v1/audit/search?from=%s&to=%s", from, to))
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if len(resp.Events) == 1 && resp.Events[0].GetID() != "e2" {
		t.Errorf("got event %s, want e2", resp.Events[0].GetID())
	}
}

func TestSearchHandler_Pagination(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search?limit=2")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("len(Events) = %d, want 2 (limit=2)", len(resp.Events))
	}
	if resp.Limit != 2 {
		t.Errorf("Limit = %d, want 2", resp.Limit)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3 (total before pagination)", resp.Total)
	}
}

func TestSearchHandler_SortAsc(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/search?sort=asc")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Newest-first by default; sort=asc means oldest first.
	if len(resp.Events) >= 2 {
		if resp.Events[0].GetID() != "e1" {
			t.Errorf("asc: first should be e1, got %s", resp.Events[0].GetID())
		}
		if resp.Events[len(resp.Events)-1].GetID() != "e3" {
			t.Errorf("asc: last should be e3, got %s",
				resp.Events[len(resp.Events)-1].GetID())
		}
	}
}

func TestSearchHandler_MethodNotAllowed(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "POST", "/api/v1/audit/search")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestSearchHandler_UnknownRoute(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/unknown")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestSearchHandler_NilSource(t *testing.T) {
	lic, _ := license.NewManager()
	s := NewSearcher(nil, lic)
	rr := runRequest(t, s, "GET", "/api/v1/audit/search")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestSearchHandler_NilLicense(t *testing.T) {
	s := NewSearcher(&fakeEventSource{}, nil)
	rr := runRequest(t, s, "GET", "/api/v1/audit/search")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// =====================================================================
// /events/:id
// =====================================================================

func TestEventsHandler_Found(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/events/e2")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// The response is the raw event JSON, not wrapped.
	var got logging.Event
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "e2" {
		t.Errorf("ID = %q, want e2", got.ID)
	}
}

func TestEventsHandler_NotFound(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/events/does-not-exist")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// =====================================================================
// /users/:user/timeline
// =====================================================================

func TestUserTimelineHandler(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/users/alice/timeline")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2 (alice has 2 events)", resp.Total)
	}
	for _, e := range resp.Events {
		if !strings.EqualFold(e.GetUser(), "alice") {
			t.Errorf("non-alice event: %s", e.GetUser())
		}
	}
}

func TestUserTimelineHandler_NoEvents(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/users/charlie/timeline")
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0 (charlie has no events)", resp.Total)
	}
	if len(resp.Events) != 0 {
		t.Errorf("len(Events) = %d, want 0", len(resp.Events))
	}
}

// =====================================================================
// /stats
// =====================================================================

func TestStatsHandler(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp statsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// All 3 sample events are within the 1h bucket.
	if b := resp.Buckets["1h"]; b.Total != 3 {
		t.Errorf("1h bucket = %d, want 3", b.Total)
	}
	// BySeverity: 1 low, 1 high, 1 medium.
	if resp.BySeverity["low"] != 1 {
		t.Errorf("bySeverity[low] = %d, want 1", resp.BySeverity["low"])
	}
	if resp.BySeverity["high"] != 1 {
		t.Errorf("bySeverity[high] = %d, want 1", resp.BySeverity["high"])
	}
	// ByAction: 1 allow, 1 block, 1 deny.
	if resp.ByAction["allow"] != 1 || resp.ByAction["block"] != 1 || resp.ByAction["deny"] != 1 {
		t.Errorf("byAction counts wrong: %+v", resp.ByAction)
	}
}

func TestStatsHandler_Empty(t *testing.T) {
	s := newTestSearcher(nil)
	rr := runRequest(t, s, "GET", "/api/v1/audit/stats")
	var resp statsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for name, b := range resp.Buckets {
		if b.Total != 0 {
			t.Errorf("empty stats: bucket %s has %d", name, b.Total)
		}
	}
}

// silence unused-import linter for tier (used in license.NewManager
// signature but not directly here).
var _ = tier.TierCommunity
