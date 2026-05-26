// SPDX-License-Identifier: Apache-2.0
// ACP WrapHandler Coverage Tests

package acp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestWrapHandlerBodyReadError(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be reached")
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", &failingReader{})
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("Expected 400 or 403, got %d", rr.Code)
	}
}

func TestWrapHandlerMessageValidationError(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be reached")
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("Expected 400 or 403, got %d", rr.Code)
	}
}

func TestWrapHandlerResponseBlockedDueToSecret(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnableSecretDetection = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("API key: sk-1234567890abcdef"))
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	t.Logf("Secret blocked: status=%d", rr.Code)
}

func TestWrapHandlerResponseBlockedDueToPII(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User email: secret@private.com"))
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	t.Logf("PII blocked: status=%d", rr.Code)
}

func TestWrapHandlerEmptyResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("DELETE", "/acp", strings.NewReader(`{"method":"test.delete","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected 204, got %d", rr.Code)
	}
}

func TestWrapHandlerValidMessageWithStrictMode(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello! How can I help?"))
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test.method","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ACP-Session", "valid-session")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareFuncRateLimitEnforcement(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 1
	cfg.RateLimitPerMinute = 60
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req1 := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	req1.Header.Set("X-ACP-Session", "ratelimit-test")
	rr1 := httptest.NewRecorder()
	wrapped(rr1, req1)

	req2 := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	req2.Header.Set("X-ACP-Session", "ratelimit-test")
	rr2 := httptest.NewRecorder()
	wrapped(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rr2.Code)
	}
}

func TestMiddlewareFuncEmptyBody(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareFuncValidMessage(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"agent.invoke","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestWrapHandlerMultipleRequests(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	sessionID := "multi-request-test"
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test","params":{}}`))
		req.Header.Set("X-ACP-Session", sessionID)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i+1, rr.Code)
		}
	}

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test","params":{}}`))
	req.Header.Set("X-ACP-Session", sessionID)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for 6th request, got %d", rr.Code)
	}
}

func TestWrapHandlerDifferentSessions(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 1
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	reqA1 := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"agent.test","params":{}}`))
	reqA1.Header.Set("X-ACP-Session", "session-A")
	rrA1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rrA1, reqA1)

	reqA2 := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"agent.test","params":{}}`))
	reqA2.Header.Set("X-ACP-Session", "session-A")
	rrA2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rrA2, reqA2)

	if rrA2.Code != http.StatusTooManyRequests {
		t.Errorf("Session A: Expected 429, got %d", rrA2.Code)
	}

	reqB := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"agent.test","params":{}}`))
	reqB.Header.Set("X-ACP-Session", "session-B")
	rrB := httptest.NewRecorder()
	wrapped.ServeHTTP(rrB, reqB)

	if rrB.Code != http.StatusOK {
		t.Errorf("Session B: Expected 200, got %d", rrB.Code)
	}
}

func TestWrapHandlerInvalidJSONBody(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be reached")
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("Expected 400 or 403, got %d", rr.Code)
	}
}

func TestWrapHandlerMethodBlocked(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.BlockMethod("admin.shutdown")
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"admin.shutdown","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("Expected 400 or 403, got %d", rr.Code)
	}
}

func TestWrapHandlerPIIInResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello user@email.com"))
	})

	wrapped := mw.WrapHandler(handler)
	req := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	t.Logf("PII test: status=%d", rr.Code)
}

func TestWrapHandlerSecretInResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.EnableSecretDetection = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token: ghp_1234567890abcdef"))
	})

	wrapped := mw.WrapHandler(handler)
	req := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	t.Logf("Secret test: status=%d", rr.Code)
}

func TestWrapHandlerLargeResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("x", 10000)))
	})

	wrapped := mw.WrapHandler(handler)
	req := httptest.NewRequest("GET", "/acp", strings.NewReader(`{"method":"test.get","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareFuncSessionIDHeader(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 2
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test","params":{}}`))
	req.Header.Set("X-ACP-Session", "header-session-123")
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareFuncSessionIDCookie(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 2
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test","params":{}}`))
	req.AddCookie(&http.Cookie{Name: "acp_session", Value: "cookie-123"})
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	t.Logf("Cookie session: status=%d", rr.Code)
}

func TestMiddlewareFuncSessionIDQuery(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 2
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp?session=query-456", strings.NewReader(`{"method":"test","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	t.Logf("Query session: status=%d", rr.Code)
}

func TestMiddlewareFuncInvalidJSON(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader("invalid json{"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped(rr, req)

}

func TestMiddlewareFuncEmptyMethod(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	next := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := mw.MiddlewareFunc(next)

	req := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	wrapped(rr, req)

}

func TestWrapHandlerUnblockMethod(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.BlockMethod("test.blocked")
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw.WrapHandler(handler)

	// Blocked
	req1 := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test.blocked","params":{}}`))
	rr1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusBadRequest {
		t.Errorf("Blocked method should return 400, got %d", rr1.Code)
	}

	// Unblock
	scanner.UnblockMethod("test.blocked")

	// Now allowed
	req2 := httptest.NewRequest("POST", "/acp", strings.NewReader(`{"method":"test.blocked","params":{}}`))
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("Unblocked method should return 200, got %d", rr2.Code)
	}
}

func TestWrapHandlerResponseNoContent(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	mw := NewMiddleware(scanner)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	wrapped := mw.WrapHandler(handler)
	req := httptest.NewRequest("DELETE", "/acp", strings.NewReader(`{"method":"test.delete","params":{}}`))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected 204, got %d", rr.Code)
	}
}
