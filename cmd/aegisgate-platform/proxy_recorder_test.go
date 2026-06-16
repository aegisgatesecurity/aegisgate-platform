// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Proxy Recorder Middleware Tests (v3.3.0+ Track 6)
//
// Verifies the proxy recorder middleware captures requests and
// responses into the global ring buffer, and that the no-op path
// (no recorder configured) does not panic.
//
// v3.3.0+ Track 6 Task 1.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

func TestProxyRecorderMiddleware_NoRecorder(t *testing.T) {
	// With no recorder installed, the middleware must not panic.
	logging.SetDefault(nil)
	t.Cleanup(func() { logging.SetDefault(nil) })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := proxyRecorderMiddleware(next)
	req := httptest.NewRequest("GET", "/v1/chat", nil)
	rrw := httptest.NewRecorder()
	h.ServeHTTP(rrw, req)
	if rr := rrw.Result(); rr.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.StatusCode)
	}
}

func TestProxyRecorderMiddleware_RecordsRequestAndResponse(t *testing.T) {
	ring := logging.NewRingBuffer(100)
	logging.SetDefault(ring)
	t.Cleanup(func() { logging.SetDefault(nil) })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "hello")
	})
	h := proxyRecorderMiddleware(next)
	req := httptest.NewRequest("POST", "/v1/chat", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.1, 10.0.0.1")
	rrw := httptest.NewRecorder()
	h.ServeHTTP(rrw, req)
	// Verify the ring buffer received both events.
	types, _ := ring.CountByType(nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if types["proxy_request"] != 1 {
		t.Errorf("proxy_request count = %d, want 1", types["proxy_request"])
	}
	if types["proxy_response"] != 1 {
		t.Errorf("proxy_response count = %d, want 1", types["proxy_response"])
	}
	// The source IP should be the first X-Forwarded-For entry.
	// (We can verify this by inspecting the event directly.)
	// For now, we trust the CountByType assertions above.
}

func TestProxyRecorderMiddleware_SeverityFromStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   logging.Severity
	}{
		{"2xx is Info", http.StatusOK, logging.SeverityInfo},
		{"3xx is Info", http.StatusFound, logging.SeverityInfo},
		{"4xx (not 401/403) is Medium", http.StatusBadRequest, logging.SeverityMedium},
		{"401 is High", http.StatusUnauthorized, logging.SeverityHigh},
		{"403 is High", http.StatusForbidden, logging.SeverityHigh},
		{"5xx is High", http.StatusInternalServerError, logging.SeverityHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ring := logging.NewRingBuffer(100)
			logging.SetDefault(ring)
			t.Cleanup(func() { logging.SetDefault(nil) })
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
			})
			h := proxyRecorderMiddleware(next)
			req := httptest.NewRequest("GET", "/", nil)
			rrw := httptest.NewRecorder()
			h.ServeHTTP(rrw, req)
			sevs, _ := ring.CountBySeverity(nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			if sevs[c.want] < 1 {
				t.Errorf("severity count[%s] = %d, want >= 1 (full map: %v)", c.want, sevs[c.want], sevs)
			}
		})
	}
}

func TestClientIPForProxy(t *testing.T) {
	cases := []struct {
		name, remote, xff, want string
	}{
		{"no xff", "192.0.2.1:8080", "", "192.0.2.1"},
		{"with xff single", "10.0.0.1:8080", "203.0.113.5", "203.0.113.5"},
		{"with xff chain", "10.0.0.1:8080", "203.0.113.5, 10.0.0.1", "203.0.113.5"},
		{"no port in remote", "192.0.2.1", "", "192.0.2.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = c.remote
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			got := clientIPForProxy(req)
			if got != c.want {
				t.Errorf("clientIPForProxy = %q, want %q", got, c.want)
			}
		})
	}
}
