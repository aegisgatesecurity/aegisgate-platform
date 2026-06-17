// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Proxy Recorder Middleware (v3.3.0+ Track 6)
// =========================================================================
//
// proxy_recorder.go wraps the upstream proxy.ServeHTTP with a thin
// middleware that records every request and response to the global
// audit event ring buffer. This is the "Option B" hook for the proxy:
// single-file modification in main.go, captures all proxy traffic
// without touching the upstream codebase (which lives in a separate
// package path and cannot import aegisgate-platform packages).
//
// v3.3.0+ Track 6 Task 1.

package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// proxyRecorderMiddleware wraps an http.Handler (typically the upstream
// proxy) and records every request/response to the global audit ring
// buffer. The middleware is a no-op when the recorder is not configured.
func proxyRecorderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logging.Record(logging.Event{
			Type:     "proxy_request",
			Severity: logging.SeverityInfo,
			Message:  "proxy request received",
			SourceIP: clientIPForProxy(r),
			Action:   r.Method,
		})
		srw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(srw, r)
		sev := logging.SeverityInfo
		switch {
		case srw.status >= 500:
			sev = logging.SeverityHigh
		case srw.status == http.StatusUnauthorized || srw.status == http.StatusForbidden:
			sev = logging.SeverityHigh
		case srw.status >= 400:
			sev = logging.SeverityMedium
		}
		logging.Record(logging.Event{
			Type:        "proxy_response",
			Severity:    sev,
			Message:     "proxy response sent",
			SourceIP:    clientIPForProxy(r),
			Action:      r.Method,
			Destination: r.URL.Path,
			Pattern:     fmt.Sprintf("status=%d", srw.status),
		})
		_ = start
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// clientIPForProxy extracts the client IP, preferring X-Forwarded-For.
//
// XSS (CodeQL go/reflected-xss): the X-Forwarded-For
// header is user-controlled and could contain HTML
// or script characters. We validate that the extracted
// value is a valid IP address using net.ParseIP; if
// it isn't (e.g., a malicious header), we fall back
// to RemoteAddr (which is host:port from the TCP
// socket and is not user-controlled).
func clientIPForProxy(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the comma-separated list.
		first := strings.SplitN(xff, ",", 2)[0]
		candidate := strings.TrimSpace(first)
		// Validate: must parse as an IP address. This
		// strips any non-IP payload (e.g., HTML, scripts)
		// from the X-Forwarded-For header.
		if ip := net.ParseIP(candidate); ip != nil {
			return candidate
		}
	}
	// Fall back to RemoteAddr (host:port).
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}
