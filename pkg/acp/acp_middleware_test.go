// SPDX-License-Identifier: Apache-2.0
// ACP Middleware Tests
package acp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewMiddleware(t *testing.T) {
	scanner := NewACPResponseScanner()
	m := NewMiddleware(scanner)
	if m == nil {
		t.Fatal("Expected non-nil middleware")
	}
	if m.scanner == nil {
		t.Error("Expected non-nil scanner")
	}
}

func TestNewMiddlewareWithConfig(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	m := NewMiddlewareWithConfig(cfg)
	if m == nil {
		t.Fatal("Expected non-nil middleware with config")
	}
}

func TestWrapHandlerNilBody(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	mw := NewMiddlewareWithConfig(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	t.Logf("Nil body status: %d", rr.Code)
}

func TestWrapHandlerEmptyBody(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	mw := NewMiddlewareWithConfig(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	t.Logf("Empty body status: %d", rr.Code)
}

func TestWrapHandlerOKResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	mw := NewMiddlewareWithConfig(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("status-ok"))
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestCheckRateLimitNewBucket(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 10
	cfg.RateLimitPerMinute = 60
	scanner := NewACPResponseScannerWithConfig(cfg)

	err := scanner.CheckRateLimit("new-identity")
	if err != nil {
		t.Errorf("New bucket should allow: %v", err)
	}
}

func TestGetRateLimitRemainingAfterExhaustion(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 2
	cfg.RateLimitPerMinute = 60
	scanner := NewACPResponseScannerWithConfig(cfg)

	scanner.CheckRateLimit("exhaust")
	scanner.CheckRateLimit("exhaust")

	remaining := scanner.GetRateLimitRemaining("exhaust")
	if remaining != 0 {
		t.Errorf("Expected 0 remaining, got %d", remaining)
	}
}

func TestValidateACPMessageBlockedAfterUnblock(t *testing.T) {
	scanner := NewACPResponseScanner()
	scanner.BlockMethod("test.method")
	err := scanner.ValidateACPMessage(&ACPMessage{Method: "test.method"})
	if err != ErrMethodBlocked {
		t.Errorf("Expected ErrMethodBlocked, got: %v", err)
	}
	scanner.UnblockMethod("test.method")
	err = scanner.ValidateACPMessage(&ACPMessage{Method: "test.method"})
	if err != nil {
		t.Errorf("Expected nil after unblock, got: %v", err)
	}
}

func TestClearSessionStatsNonExistent(t *testing.T) {
	scanner := NewACPResponseScanner()
	scanner.ClearSessionStats("non-existent")
}

func TestResetAllSessionStatsEmpty(t *testing.T) {
	scanner := NewACPResponseScanner()
	stats := scanner.ResetAllSessionStats()
	if len(stats) != 0 {
		t.Errorf("Expected 0 stats, got %d", len(stats))
	}
}

func TestIsMethodBlockedNonExistent(t *testing.T) {
	scanner := NewACPResponseScanner()
	if scanner.IsMethodBlocked("non-existent") {
		t.Error("Expected false")
	}
}

func TestMiddlewareFuncRateLimit(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 1
	cfg.RateLimitPerMinute = 60
	mw := NewMiddlewareWithConfig(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.MiddlewareFunc(handler)

	req1 := httptest.NewRequest("GET", "/acp", nil)
	req1.Header.Set("X-ACP-Session", "rate-test")
	rr1 := httptest.NewRecorder()
	wrapped(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest("GET", "/acp", nil)
	req2.Header.Set("X-ACP-Session", "rate-test")
	rr2 := httptest.NewRecorder()
	wrapped(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rr2.Code)
	}
}

func TestResponseWriterWrite(t *testing.T) {
	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		buffer:         &bytes.Buffer{},
	}

	data := []byte("test response content")
	n, err := rw.Write(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}
}

func TestResponseWriterWriteString(t *testing.T) {
	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		buffer:         &bytes.Buffer{},
	}

	n, err := rw.WriteString("string test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if n != 11 {
		t.Errorf("Expected 11 bytes, got %d", n)
	}
}

func TestExtractSessionIDHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/acp", nil)
	req.Header.Set("X-ACP-Session", "header-session")
	sessionID := extractSessionID(req)
	if sessionID != "header-session" {
		t.Errorf("Expected header-session, got %s", sessionID)
	}
}

func TestExtractSessionIDCookie(t *testing.T) {
	req := httptest.NewRequest("GET", "/acp", nil)
	req.AddCookie(&http.Cookie{Name: "acp_session", Value: "cookie-session"})
	sessionID := extractSessionID(req)
	if sessionID != "cookie-session" {
		t.Errorf("Expected cookie-session, got %s", sessionID)
	}
}

func TestExtractSessionIDQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/acp?session=query-session", nil)
	sessionID := extractSessionID(req)
	if sessionID != "query-session" {
		t.Errorf("Expected query-session, got %s", sessionID)
	}
}

func TestExtractSessionIDNone(t *testing.T) {
	req := httptest.NewRequest("GET", "/acp", nil)
	sessionID := extractSessionID(req)
	if sessionID != "" {
		t.Errorf("Expected empty session, got %s", sessionID)
	}
}

func TestParseACPMessageNil(t *testing.T) {
	_, err := parseACPMessage(nil)
	if err != ErrNilMessage {
		t.Errorf("Expected ErrNilMessage, got %v", err)
	}
}

func TestParseACPMessageEmpty(t *testing.T) {
	_, err := parseACPMessage([]byte{})
	if err != ErrNilMessage {
		t.Errorf("Expected ErrNilMessage, got %v", err)
	}
}

func TestParseACPMessageValid(t *testing.T) {
	msg, err := parseACPMessage([]byte(`{"method":"test.method","params":{}}`))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected non-nil message")
	}
}
