// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

var errTestMarshal = errors.New("test marshal error")

// ----- handler.go gaps -----

// TestPhase1c_ServeHTTP_AliasPath exercises the /audit alias routing
// (without the /api/v1 prefix) to cover the aliasRoot branch.
func TestPhase1c_ServeHTTP_AliasPath(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/audit/search?user=alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp searchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2 (alice has 2 events)", resp.Total)
	}
}

// TestPhase1c_ServeHTTP_AliasRootDefault exercises the case where
// the path after stripping the alias is empty → defaults to /search.
func TestPhase1c_ServeHTTP_AliasRootDefault(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestPhase1c_ServeEventByID_WrongMethod covers the method check
// in serveEventByID (POST should be rejected).
func TestPhase1c_ServeEventByID_WrongMethod(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "POST", "/api/v1/audit/events/e1")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestPhase1c_ServeEventByID_EmptyID covers the empty-ID check.
func TestPhase1c_ServeEventByID_EmptyID(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/events/")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestPhase1c_ServeUserTimeline_WrongMethod covers the method check
// in serveUserTimeline.
func TestPhase1c_ServeUserTimeline_WrongMethod(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "POST", "/api/v1/audit/users/alice/timeline")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestPhase1c_ServeUserTimeline_EmptyUser covers the empty-user check.
func TestPhase1c_ServeUserTimeline_EmptyUser(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "GET", "/api/v1/audit/users//timeline")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestPhase1c_ServeStats_WrongMethod covers the method check in serveStats.
func TestPhase1c_ServeStats_WrongMethod(t *testing.T) {
	s := newTestSearcher(sampleEvents())
	rr := runRequest(t, s, "POST", "/api/v1/audit/stats")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestPhase1c_ServeStats_OldEvent adds an event older than 1h to
// exercise the "continue" branch in the bucket loop (events before
// the 1h cutoff are skipped).
func TestPhase1c_ServeStats_OldEvent(t *testing.T) {
	events := append(sampleEvents(), logging.Event{
		ID:       "old",
		Time:     time.Now().Add(-2 * time.Hour),
		Type:     "auth",
		Action:   "allow",
		Severity: logging.SeverityLow,
		User:     "charlie",
		Message:  "old event",
	})
	s := newTestSearcher(events)
	rr := runRequest(t, s, "GET", "/api/v1/audit/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestPhase1c_ToEvents_JSONFallback covers the fallback path in
// toEvents when a non-loggingEventAdapter type is passed. fakeEvent
// has unexported fields, so JSON marshal produces {} and the
// unmarshal produces a zero-value logging.Event.
func TestPhase1c_ToEvents_JSONFallback(t *testing.T) {
	in := []loggingEvent{
		fakeEvent{id: "e1", t: time.Now(), typ: "auth", action: "allow",
			severity: "low", user: "alice", message: "login"},
	}
	out := toEvents(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	// fakeEvent has unexported fields → JSON round-trip yields zero Event.
	if out[0].ID != "" {
		t.Errorf("expected zero-value Event from JSON fallback, got ID=%q", out[0].ID)
	}
}

// ----- search.go gaps -----

// TestPhase1c_ParseSearchQuery_Action covers the "action" param
// parsing branch in ParseSearchQuery.
func TestPhase1c_ParseSearchQuery_Action(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{
		"action": {"allow"},
	})
	if q.Action != "allow" {
		t.Errorf("Action = %q, want %q", q.Action, "allow")
	}
}

// TestPhase1c_ParseSearchQuery_Type covers the "type" param parsing
// branch in ParseSearchQuery.
func TestPhase1c_ParseSearchQuery_Type(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{
		"type": {"auth"},
	})
	if q.EventType != "auth" {
		t.Errorf("EventType = %q, want %q", q.EventType, "auth")
	}
}

// TestPhase1c_ParseSearchQuery_Offset covers the "offset" param
// parsing branch (valid positive integer).
func TestPhase1c_ParseSearchQuery_Offset(t *testing.T) {
	q := ParseSearchQuery(map[string][]string{
		"offset": {"10"},
	})
	if q.Offset != 10 {
		t.Errorf("Offset = %d, want 10", q.Offset)
	}
}

// TestPhase1c_Matches_ToRangeExcluded covers the "To" time range
// exclusion branch in Matches (event is after To → false).
func TestPhase1c_Matches_ToRangeExcluded(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	e := fakeEvent{t: base.Add(1 * time.Hour)}
	q := SearchQuery{To: base}
	if q.Matches(e) {
		t.Error("event after To should not match")
	}
}

// TestPhase1c_Matches_ActionMismatch covers the action mismatch
// branch in Matches.
func TestPhase1c_Matches_ActionMismatch(t *testing.T) {
	e := fakeEvent{action: "allow"}
	q := SearchQuery{Action: "block"}
	if q.Matches(e) {
		t.Error("action mismatch should not match")
	}
}

// ----- toEvents JSON fallback error paths -----

// marshalErrEvent fails to marshal to JSON.
type marshalErrEvent struct{}

func (marshalErrEvent) GetID() string       { return "" }
func (marshalErrEvent) GetTime() time.Time  { return time.Time{} }
func (marshalErrEvent) GetType() string     { return "" }
func (marshalErrEvent) GetAction() string   { return "" }
func (marshalErrEvent) GetSeverity() string { return "" }
func (marshalErrEvent) GetUser() string     { return "" }
func (marshalErrEvent) GetMessage() string  { return "" }
func (marshalErrEvent) MarshalJSON() ([]byte, error) {
	return nil, errTestMarshal
}

// arrayEvent marshals to a JSON array (not an object), which fails
// to unmarshal into logging.Event.
type arrayEvent struct{}

func (arrayEvent) GetID() string       { return "" }
func (arrayEvent) GetTime() time.Time  { return time.Time{} }
func (arrayEvent) GetType() string     { return "" }
func (arrayEvent) GetAction() string   { return "" }
func (arrayEvent) GetSeverity() string { return "" }
func (arrayEvent) GetUser() string     { return "" }
func (arrayEvent) GetMessage() string  { return "" }
func (arrayEvent) MarshalJSON() ([]byte, error) {
	return []byte("[1,2,3]"), nil
}

// TestPhase1c_ToEvents_MarshalError covers the json.Marshal error
// branch in toEvents.
func TestPhase1c_ToEvents_MarshalError(t *testing.T) {
	out := toEvents([]loggingEvent{marshalErrEvent{}})
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	// Marshal failed → out[0] should be zero-value logging.Event.
	if out[0].ID != "" {
		t.Errorf("expected zero-value Event, got ID=%q", out[0].ID)
	}
}

// TestPhase1c_ToEvents_UnmarshalError covers the json.Unmarshal
// error branch in toEvents.
func TestPhase1c_ToEvents_UnmarshalError(t *testing.T) {
	out := toEvents([]loggingEvent{arrayEvent{}})
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	// Unmarshal of [1,2,3] into logging.Event fails → zero value.
	if out[0].ID != "" {
		t.Errorf("expected zero-value Event, got ID=%q", out[0].ID)
	}
}

// ----- tsa.go gaps -----

// TestPhase1c_TSAClient_Endpoints covers the Endpoints() accessor.
func TestPhase1c_TSAClient_Endpoints(t *testing.T) {
	cfg := TSAConfig{
		Enabled:   true,
		Endpoints: []string{"http://tsa1.example.com", "http://tsa2.example.com"},
	}
	client := NewTSAClient(cfg)
	got := client.Endpoints()
	if len(got) != 2 {
		t.Fatalf("len(Endpoints()) = %d, want 2", len(got))
	}
	if got[0] != "http://tsa1.example.com" {
		t.Errorf("Endpoints()[0] = %q, want %q", got[0], "http://tsa1.example.com")
	}
}

// TestPhase1c_VerifyToken_InvalidTokenBytes covers the
// parseTokenMessageImprint error branch in VerifyToken by passing
// non-DER bytes.
func TestPhase1c_VerifyToken_InvalidTokenBytes(t *testing.T) {
	cfg := DefaultTSAConfig()
	client := NewTSAClient(cfg)
	token := &TimestampToken{
		Token:     []byte("not-valid-der"),
		Timestamp: time.Now().UTC(),
	}
	err := client.VerifyToken(token, []byte("test-data"))
	if err == nil {
		t.Error("expected error for invalid token bytes")
	}
}

// TestPhase1c_VerifyAuditEvent_InvalidTokenBytes covers the
// parseTokenMessageImprint error branch in VerifyAuditEvent.
func TestPhase1c_VerifyAuditEvent_InvalidTokenBytes(t *testing.T) {
	cfg := DefaultTSAConfig()
	client := NewTSAClient(cfg)
	signed := &AuditEventTSA{
		EventID:  "evt-1",
		Token:    &TimestampToken{Token: []byte("not-valid-der")},
		DataHash: []byte{1, 2, 3},
	}
	err := client.VerifyAuditEvent(signed)
	if err == nil {
		t.Error("expected error for invalid token bytes")
	}
}

// TestPhase1c_SignAuditEvent_FailingEndpoint covers the
// RequestTimestamp failure path in SignAuditEvent by using an
// unreachable endpoint.
func TestPhase1c_SignAuditEvent_FailingEndpoint(t *testing.T) {
	cfg := TSAConfig{
		Enabled:    true,
		Endpoints:  []string{"http://127.0.0.1:1"}, // unreachable port
		Timeout:    100 * time.Millisecond,
		RetryCount: 0,
	}
	client := NewTSAClient(cfg)
	_, err := client.SignAuditEvent("evt-fail", []byte("test-data"))
	if err == nil {
		t.Error("expected error for failing endpoint")
	}
}
