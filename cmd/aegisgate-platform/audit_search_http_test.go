// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Audit Log Search HTTP endpoint tests (v3.x
// close-out, Work Item 11, commit 4 of 4)
// =========================================================================
//
// Tests for the audit log search HTTP wiring. The handler-level
// logic (search/matcher/pagination/JSON shape) is tested in
// pkg/audit/handler_test.go and pkg/audit/search_test.go; these
// tests cover the wire-up:
//
//   - the routes are mounted on /api/v1/audit/ and /audit/
//   - GET is the only allowed method (POST returns 405)
//   - the prefix stripping works (both with and without /api/v1)
//   - the handler returns 500 when the event source is nil
//     (fail-closed)
//   - a basic search round-trip with a real logging.RingBuffer
//     works end-to-end (event add -> snapshot -> search -> JSON)
//
// Uses a stub license manager (the Searcher takes one but the
// auth middleware is permissive in tests, so the license isn't
// exercised). The audit.Searcher does not require a license.Manager
// in its constructor to be non-nil, but the production wire-up
// passes nil and the fail-closed check at the start of ServeHTTP
// is for source == nil, not manager. So nil manager is OK here.
// =========================================================================

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// authMWForAuditTest builds a permissive auth middleware (matches
// the posture/attestation test pattern). The audit handlers
// themselves don't depend on auth state.
func authMWForAuditTest() *auth.Middleware {
	return auth.NewMiddleware(&auth.Config{RequireAuth: false})
}

// licenseMgrForAuditTest creates a license manager with the
// embedded public key. The Searcher needs a non-nil license.Manager
// or it returns 500 at the start of ServeHTTP. The auth middleware
// in these tests is permissive, so the license isn't actually
// enforced - the manager just needs to exist.
func licenseMgrForAuditTest(t *testing.T) *license.Manager {
	t.Helper()
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("license.NewManager: %v", err)
	}
	return mgr
}

// ringBufferSource returns a non-nil audit.EventSource backed by a
// fresh in-memory ring buffer. The RingBuffer implements
// evidence.EventSource (which has SnapshotBetween as one of its
// methods), and Go's structural typing means it also satisfies
// audit.EventSource (which is the SnapshotBetween-only subset).
func ringBufferSource() audit.EventSource {
	return logging.NewRingBuffer(logging.DefaultCapacity)
}

func TestWireAuditSearchHandlers_NilSource(t *testing.T) {
	authMW := authMWForAuditTest()
	mux := http.NewServeMux()
	mgr := licenseMgrForAuditTest(t)
	// Pass nil source - the handler should fail-closed with 500.
	wireAuditSearchHandlers(mux, authMW, nil, mgr)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("nil source: got status %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestWireAuditSearchHandlers_SearchRouteMounted(t *testing.T) {
	authMW := authMWForAuditTest()
	mux := http.NewServeMux()
	mgr := licenseMgrForAuditTest(t)
	wireAuditSearchHandlers(mux, authMW, ringBufferSource(), mgr)

	// /api/v1/audit/search with a real source - should be 200 with empty results.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/audit/search: got status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestWireAuditSearchHandlers_AuditAliasMounted(t *testing.T) {
	// The /audit/ alias (no /api/v1 prefix) should also work, per
	// commit 3 fix #3 (the ServeHTTP now strips both prefixes).
	authMW := authMWForAuditTest()
	mux := http.NewServeMux()
	mgr := licenseMgrForAuditTest(t)
	wireAuditSearchHandlers(mux, authMW, ringBufferSource(), mgr)

	req := httptest.NewRequest(http.MethodGet, "/audit/search", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /audit/search: got status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestWireAuditSearchHandlers_MethodNotAllowed(t *testing.T) {
	authMW := authMWForAuditTest()
	mux := http.NewServeMux()
	mgr := licenseMgrForAuditTest(t)
	wireAuditSearchHandlers(mux, authMW, ringBufferSource(), mgr)

	// POST should be rejected at the handler level.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/search", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/audit/search: got status %d, want 405", rr.Code)
	}
}

func TestWireAuditSearchHandlers_UnknownRoute(t *testing.T) {
	authMW := authMWForAuditTest()
	mux := http.NewServeMux()
	mgr := licenseMgrForAuditTest(t)
	wireAuditSearchHandlers(mux, authMW, ringBufferSource(), mgr)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /api/v1/audit/nonexistent: got status %d, want 404", rr.Code)
	}
}

func TestWireAuditSearchHandlers_EndToEndSearch(t *testing.T) {
	// Add 3 events to the ring buffer, then query through the HTTP
	// endpoint. This exercises the full path: wire -> Searcher ->
	// RingBuffer.SnapshotBetween -> search.Match -> JSON response.
	src := logging.NewRingBuffer(logging.DefaultCapacity)
	base := time.Now().Add(-30 * time.Minute)
	src.Add(logging.Event{ID: "e1", Time: base, Type: "auth", Action: "allow", Severity: logging.SeverityLow, User: "alice", Message: "login"})
	src.Add(logging.Event{ID: "e2", Time: base.Add(5 * time.Minute), Type: "threat", Action: "block", Severity: logging.SeverityHigh, User: "bob", Message: "intrusion"})
	src.Add(logging.Event{ID: "e3", Time: base.Add(10 * time.Minute), Type: "auth", Action: "deny", Severity: logging.SeverityMedium, User: "alice", Message: "fail"})

	authMW := authMWForAuditTest()
	mgr := licenseMgrForAuditTest(t)
	mux := http.NewServeMux()
	wireAuditSearchHandlers(mux, authMW, src, mgr)

	// 1. Unfiltered search should return all 3.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("search: status = %d, body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Total is float64 in the unmarshaled map.
		if total, _ := resp["total"].(float64); int(total) != 3 {
			t.Errorf("unfiltered search: total = %v, want 3", resp["total"])
		}
	}

	// 2. Filtered search by user=alice should return 2.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search?user=alice", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("filtered search: status = %d, body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if total, _ := resp["total"].(float64); int(total) != 2 {
			t.Errorf("user=alice search: total = %v, want 2", resp["total"])
		}
	}

	// 3. Stats endpoint should report 1 of each severity globally.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stats", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("stats: status = %d, body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			BySeverity map[string]int `json:"bySeverity"`
			ByAction   map[string]int `json:"byAction"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.BySeverity["low"] != 1 || resp.BySeverity["high"] != 1 || resp.BySeverity["medium"] != 1 {
			t.Errorf("bySeverity counts wrong: %+v", resp.BySeverity)
		}
	}

	// 4. User timeline for alice should return 2 events.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/users/alice/timeline", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("timeline: status = %d, body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if total, _ := resp["total"].(float64); int(total) != 2 {
			t.Errorf("alice timeline: total = %v, want 2", resp["total"])
		}
	}
}

func TestWireAuditSearchHandlers_EventByID(t *testing.T) {
	src := logging.NewRingBuffer(logging.DefaultCapacity)
	src.Add(logging.Event{ID: "e1", Time: time.Now(), Type: "auth", Action: "allow", Severity: logging.SeverityLow, User: "alice", Message: "login"})
	src.Add(logging.Event{ID: "e2", Time: time.Now(), Type: "threat", Action: "block", Severity: logging.SeverityHigh, User: "bob", Message: "intrusion"})

	authMW := authMWForAuditTest()
	mgr := licenseMgrForAuditTest(t)
	mux := http.NewServeMux()
	wireAuditSearchHandlers(mux, authMW, src, mgr)

	// Found
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events/e2", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("events/e2: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var got logging.Event
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != "e2" {
			t.Errorf("ID = %q, want e2", got.ID)
		}
	}

	// Not found
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events/does-not-exist", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("events/does-not-exist: status = %d, want 404", rr.Code)
		}
	}
}
