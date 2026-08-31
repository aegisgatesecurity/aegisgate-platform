// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Maintenance Windows
// =========================================================================
//
// Provides a maintenance mode system that returns 503 Service Unavailable
// with Retry-After headers for all proxy traffic during scheduled downtime.
//
// The maintenance state is held in an atomic bool for lock-free reads on the
// hot path (every proxy request). A scheduled maintenance window uses a
// background goroutine with a time.Timer to enable/disable automatically.
//
// The dashboard API (/api/v1/maintenance) and CLI (aegisgate maintenance)
// are the control surfaces; the proxy middleware enforces the state.
//
// =========================================================================

package maintenance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// State holds the maintenance mode state.
type State struct {
	// active is read on every proxy request — must be lock-free
	active atomic.Bool

	// scheduled indicates a time-based maintenance window is active
	scheduled atomic.Bool

	// message shown to clients in the 503 response
	message atomic.Value // string

	// retryAfter tells clients when to try again (seconds)
	retryAfter atomic.Int64

	// startTime and endTime for scheduled windows
	mu        sync.RWMutex
	startTime time.Time
	endTime   time.Time
	reason    string

	// timer for scheduled window auto-disable
	timer *time.Timer
}

// New creates a new maintenance State.
func New() *State {
	s := &State{}
	s.message.Store("Maintenance in progress. Please try again later.")
	s.retryAfter.Store(60)
	return s
}

// IsActive returns true if maintenance mode is currently active.
// This is the hot-path call used by the proxy middleware.
func (s *State) IsActive() bool {
	return s.active.Load()
}

// Enable activates maintenance mode immediately.
func (s *State) Enable(reason string) {
	if reason != "" {
		s.message.Store(reason)
	}
	s.active.Store(true)
	s.mu.Lock()
	s.reason = reason
	s.mu.Unlock()
}

// Disable deactivates maintenance mode immediately.
// If a scheduled window is active, the timer is cancelled.
func (s *State) Disable() {
	s.active.Store(false)
	s.scheduled.Store(false)
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.startTime = time.Time{}
	s.endTime = time.Time{}
	s.reason = ""
	s.mu.Unlock()
	// Reset message to default
	s.message.Store("Maintenance in progress. Please try again later.")
}

// Schedule activates maintenance mode at startTime and auto-disables at endTime.
// If startTime is in the past, maintenance is enabled immediately.
// Returns an error if endTime is not after startTime.
func (s *State) Schedule(startTime, endTime time.Time, reason string) error {
	if !endTime.After(startTime) {
		return fmt.Errorf("end time must be after start time")
	}

	now := time.Now()
	delay := startTime.Sub(now)

	s.mu.Lock()
	s.startTime = startTime
	s.endTime = endTime
	s.reason = reason
	s.scheduled.Store(true)
	if reason != "" {
		s.message.Store(reason)
	}
	s.mu.Unlock()

	if delay <= 0 {
		// Start immediately
		s.active.Store(true)
	} else {
		// Schedule the activation
		time.AfterFunc(delay, func() {
			s.active.Store(true)
		})
	}

	// Schedule auto-disable
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(endTime.Sub(now), func() {
		s.active.Store(false)
		s.scheduled.Store(false)
	})
	s.mu.Unlock()

	return nil
}

// SetMessage sets the message shown in the 503 response.
func (s *State) SetMessage(msg string) {
	if msg != "" {
		s.message.Store(msg)
	}
}

// SetRetryAfter sets the Retry-After header value in seconds.
func (s *State) SetRetryAfter(seconds int64) {
	if seconds > 0 {
		s.retryAfter.Store(seconds)
	}
}

// Status returns the current maintenance status for API responses.
func (s *State) Status() StatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := StatusResponse{
		Active:     s.active.Load(),
		Scheduled:  s.scheduled.Load(),
		Message:    s.message.Load().(string),
		RetryAfter: s.retryAfter.Load(),
	}

	if !s.startTime.IsZero() {
		resp.StartTime = s.startTime.Format(time.RFC3339)
	}
	if !s.endTime.IsZero() {
		resp.EndTime = s.endTime.Format(time.RFC3339)
	}
	if s.reason != "" {
		resp.Reason = s.reason
	}

	return resp
}

// StatusResponse is the JSON response for the maintenance API.
type StatusResponse struct {
	Active     bool   `json:"active"`
	Scheduled  bool   `json:"scheduled"`
	Message    string `json:"message,omitempty"`
	Reason     string `json:"reason,omitempty"`
	StartTime  string `json:"start_time,omitempty"`
	EndTime    string `json:"end_time,omitempty"`
	RetryAfter int64  `json:"retry_after_seconds,omitempty"`
}

// Middleware returns an http.Handler that returns 503 when maintenance
// is active, and calls next when maintenance is inactive.
//
// Paths starting with /health, /version, and /api/v1/maintenance are
// always allowed through (even during maintenance) so monitoring and
// the dashboard can still check platform state.
func (s *State) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.IsActive() {
			next.ServeHTTP(w, r)
			return
		}

		// Allow health checks and maintenance API through
		path := r.URL.Path
		if path == "/health" || path == "/version" || path == "/api/v1/maintenance" || path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		// Return 503 with Retry-After
		retryAfter := s.retryAfter.Load()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]interface{}{
			"error":       "maintenance_mode",
			"message":     s.message.Load().(string),
			"retry_after": retryAfter,
		})
	})
}

// writeJSON encodes a value as JSON to the response writer, ignoring errors.
// HTTP response write errors are not actionable after headers are sent.
func writeJSON(w http.ResponseWriter, v interface{}) { //nosec G104 -- intentional: HTTP response errors not actionable
	_ = json.NewEncoder(w).Encode(v)
}

// Handler returns an http.Handler for the /api/v1/maintenance API endpoint.
// Supports GET (status), POST (enable), DELETE (disable), PUT (schedule).
func (s *State) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, s.Status())

		case http.MethodPost:
			// Enable maintenance mode
			var req struct {
				Message    string `json:"message"`
				RetryAfter int64  `json:"retry_after_seconds"`
			}
			if r.Body != nil {
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
					w.WriteHeader(http.StatusBadRequest)
					writeJSON(w, map[string]string{"error": "invalid request body"})
					return
				}
			}
			msg := req.Message
			if msg == "" {
				msg = "Maintenance mode enabled via API"
			}
			s.Enable(msg)
			if req.RetryAfter > 0 {
				s.SetRetryAfter(req.RetryAfter)
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(w, s.Status())

		case http.MethodDelete:
			// Disable maintenance mode
			s.Disable()
			w.WriteHeader(http.StatusOK)
			writeJSON(w, s.Status())

		case http.MethodPut:
			// Schedule maintenance window
			var req struct {
				StartTime string `json:"start_time"`
				EndTime   string `json:"end_time"`
				Reason    string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]string{"error": "invalid request body"})
				return
			}

			startTime, err := time.Parse(time.RFC3339, req.StartTime)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]string{"error": "start_time must be RFC3339 format"})
				return
			}
			endTime, err := time.Parse(time.RFC3339, req.EndTime)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]string{"error": "end_time must be RFC3339 format"})
				return
			}

			if err := s.Schedule(startTime, endTime, req.Reason); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]string{"error": err.Error()})
				return
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(w, s.Status())

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			writeJSON(w, map[string]string{"error": "method not allowed"})
		}
	})
}
