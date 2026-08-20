// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Maintenance Window Tests
// =========================================================================

package maintenance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// State tests
// ---------------------------------------------------------------------------

func TestNewStateIsInactive(t *testing.T) {
	s := New()
	if s.IsActive() {
		t.Error("New state should be inactive")
	}
}

func TestEnableActivatesState(t *testing.T) {
	s := New()
	s.Enable("Test maintenance")
	if !s.IsActive() {
		t.Error("State should be active after Enable()")
	}
}

func TestDisableDeactivatesState(t *testing.T) {
	s := New()
	s.Enable("Test")
	s.Disable()
	if s.IsActive() {
		t.Error("State should be inactive after Disable()")
	}
}

func TestEnableSetsMessage(t *testing.T) {
	s := New()
	s.Enable("Custom message")
	status := s.Status()
	if status.Message != "Custom message" {
		t.Errorf("Message = %q, want 'Custom message'", status.Message)
	}
}

func TestDisableResetsMessage(t *testing.T) {
	s := New()
	s.Enable("Custom")
	s.Disable()
	status := s.Status()
	if !strings.Contains(status.Message, "Maintenance in progress") {
		t.Errorf("Message should reset to default, got %q", status.Message)
	}
}

func TestSetMessage(t *testing.T) {
	s := New()
	s.SetMessage("New message")
	if s.message.Load().(string) != "New message" {
		t.Error("SetMessage failed")
	}
}

func TestSetRetryAfter(t *testing.T) {
	s := New()
	s.SetRetryAfter(120)
	if s.retryAfter.Load() != 120 {
		t.Error("SetRetryAfter failed")
	}
}

// ---------------------------------------------------------------------------
// Schedule tests
// ---------------------------------------------------------------------------

func TestScheduleImmediate(t *testing.T) {
	s := New()
	start := time.Now().Add(-1 * time.Minute) // past = immediate
	end := time.Now().Add(1 * time.Hour)

	err := s.Schedule(start, end, "Scheduled test")
	if err != nil {
		t.Fatalf("Schedule error: %v", err)
	}
	if !s.IsActive() {
		t.Error("Should be active immediately when start time is in the past")
	}
	if !s.scheduled.Load() {
		t.Error("Scheduled flag should be true")
	}
}

func TestScheduleFuture(t *testing.T) {
	s := New()
	start := time.Now().Add(2 * time.Second)
	end := time.Now().Add(4 * time.Second)

	err := s.Schedule(start, end, "Future test")
	if err != nil {
		t.Fatalf("Schedule error: %v", err)
	}
	if s.IsActive() {
		t.Error("Should not be active immediately for future start time")
	}

	// Wait for activation
	time.Sleep(3 * time.Second)
	if !s.IsActive() {
		t.Error("Should be active after start time passes")
	}

	// Wait for auto-disable
	time.Sleep(3 * time.Second)
	if s.IsActive() {
		t.Error("Should be inactive after end time passes")
	}
}

func TestScheduleEndTimeBeforeStartTime(t *testing.T) {
	s := New()
	start := time.Now().Add(1 * time.Hour)
	end := time.Now().Add(30 * time.Minute)

	err := s.Schedule(start, end, "Invalid")
	if err == nil {
		t.Fatal("Should error when end is before start")
	}
}

func TestScheduleSetsReason(t *testing.T) {
	s := New()
	start := time.Now().Add(-1 * time.Minute)
	end := time.Now().Add(1 * time.Hour)

	s.Schedule(start, end, "Security patch")
	status := s.Status()
	if status.Reason != "Security patch" {
		t.Errorf("Reason = %q, want 'Security patch'", status.Reason)
	}
}

func TestScheduleSetsTimes(t *testing.T) {
	s := New()
	start := time.Now().Add(-1 * time.Minute).UTC()
	end := time.Now().Add(1 * time.Hour).UTC()

	s.Schedule(start, end, "Test")
	status := s.Status()
	if status.StartTime == "" {
		t.Error("StartTime should be set")
	}
	if status.EndTime == "" {
		t.Error("EndTime should be set")
	}
}

func TestDisableCancelsScheduledTimer(t *testing.T) {
	s := New()
	start := time.Now().Add(1 * time.Hour)
	end := time.Now().Add(2 * time.Hour)

	s.Schedule(start, end, "Test")
	s.Disable()
	if s.scheduled.Load() {
		t.Error("Scheduled flag should be false after Disable")
	}
}

// ---------------------------------------------------------------------------
// Middleware tests
// ---------------------------------------------------------------------------

func TestMiddlewareInactivePassesThrough(t *testing.T) {
	s := New()
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := s.Middleware(inner)
	req := httptest.NewRequest("GET", "/some/path", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if !innerCalled {
		t.Error("Inner handler should be called when maintenance is inactive")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestMiddlewareActiveReturns503(t *testing.T) {
	s := New()
	s.Enable("Test maintenance")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Inner handler should NOT be called during maintenance")
	})

	mw := s.Middleware(inner)
	req := httptest.NewRequest("GET", "/some/path", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestMiddlewareActiveAllowsHealthEndpoint(t *testing.T) {
	s := New()
	s.Enable("Test")
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
	})

	mw := s.Middleware(inner)

	for _, path := range []string{"/health", "/version", "/api/v1/maintenance", "/ready"} {
		innerCalled = false
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
		if !innerCalled {
			t.Errorf("Inner handler should be called for %s during maintenance", path)
		}
	}
}

func TestMiddleware503HasRetryAfterHeader(t *testing.T) {
	s := New()
	s.Enable("Test")
	s.SetRetryAfter(120)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := s.Middleware(inner)
	req := httptest.NewRequest("GET", "/some/path", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Header().Get("Retry-After") != "120" {
		t.Errorf("Retry-After = %q, want '120'", w.Header().Get("Retry-After"))
	}
}

func TestMiddleware503HasContentType(t *testing.T) {
	s := New()
	s.Enable("Test")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := s.Middleware(inner)
	req := httptest.NewRequest("GET", "/some/path", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Error("503 response should have JSON content type")
	}
}

func TestMiddleware503BodyContainsMessage(t *testing.T) {
	s := New()
	s.Enable("Custom maintenance message")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := s.Middleware(inner)
	req := httptest.NewRequest("GET", "/some/path", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["message"] != "Custom maintenance message" {
		t.Errorf("503 body message = %v, want 'Custom maintenance message'", body["message"])
	}
	if body["error"] != "maintenance_mode" {
		t.Errorf("503 body error = %v, want 'maintenance_mode'", body["error"])
	}
}

// ---------------------------------------------------------------------------
// Handler (API) tests
// ---------------------------------------------------------------------------

func TestHandlerGetStatus(t *testing.T) {
	s := New()
	h := s.Handler()

	req := httptest.NewRequest("GET", "/api/v1/maintenance", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp StatusResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Active {
		t.Error("Status should be inactive by default")
	}
}

func TestHandlerPostEnable(t *testing.T) {
	s := New()
	h := s.Handler()

	body := `{"message":"API enable","retry_after_seconds":30}`
	req := httptest.NewRequest("POST", "/api/v1/maintenance", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST enable = %d, want %d", w.Code, http.StatusOK)
	}
	if !s.IsActive() {
		t.Error("Should be active after POST enable")
	}
	if s.retryAfter.Load() != 30 {
		t.Error("RetryAfter should be 30")
	}
}

func TestHandlerDeleteDisable(t *testing.T) {
	s := New()
	s.Enable("Test")
	h := s.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/maintenance", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("DELETE disable = %d, want %d", w.Code, http.StatusOK)
	}
	if s.IsActive() {
		t.Error("Should be inactive after DELETE disable")
	}
}

func TestHandlerPutSchedule(t *testing.T) {
	s := New()
	h := s.Handler()

	start := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	end := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"start_time":%q,"end_time":%q,"reason":"API schedule"}`, start, end)

	req := httptest.NewRequest("PUT", "/api/v1/maintenance", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("PUT schedule = %d, want %d", w.Code, http.StatusOK)
	}
	if !s.IsActive() {
		t.Error("Should be active immediately (start time in past)")
	}
}

func TestHandlerPutScheduleInvalidTime(t *testing.T) {
	s := New()
	h := s.Handler()

	body := `{"start_time":"invalid","end_time":"also-invalid"}`
	req := httptest.NewRequest("PUT", "/api/v1/maintenance", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT schedule with invalid time = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandlerPutScheduleEndBeforeStart(t *testing.T) {
	s := New()
	h := s.Handler()

	start := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"start_time":%q,"end_time":%q}`, start, end)

	req := httptest.NewRequest("PUT", "/api/v1/maintenance", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT schedule with end before start = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandlerPostEmptyBody(t *testing.T) {
	s := New()
	h := s.Handler()

	req := httptest.NewRequest("POST", "/api/v1/maintenance", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST with empty body = %d, want %d", w.Code, http.StatusOK)
	}
	if !s.IsActive() {
		t.Error("Should be active after POST with empty body")
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	s := New()
	h := s.Handler()

	req := httptest.NewRequest("PATCH", "/api/v1/maintenance", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// StatusResponse tests
// ---------------------------------------------------------------------------

func TestStatusResponseInactive(t *testing.T) {
	s := New()
	status := s.Status()
	if status.Active {
		t.Error("Active should be false")
	}
	if status.Scheduled {
		t.Error("Scheduled should be false")
	}
}

func TestStatusResponseActive(t *testing.T) {
	s := New()
	s.Enable("Test reason")
	status := s.Status()
	if !status.Active {
		t.Error("Active should be true")
	}
	if status.Message != "Test reason" {
		t.Errorf("Message = %q, want 'Test reason'", status.Message)
	}
}

func TestStatusResponseScheduled(t *testing.T) {
	s := New()
	start := time.Now().Add(-1 * time.Minute)
	end := time.Now().Add(1 * time.Hour)
	s.Schedule(start, end, "Scheduled test")

	status := s.Status()
	if !status.Scheduled {
		t.Error("Scheduled should be true")
	}
	if status.Reason != "Scheduled test" {
		t.Errorf("Reason = %q, want 'Scheduled test'", status.Reason)
	}
}
