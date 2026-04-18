// Package security provides benchmark tests for security middleware.
// These tests measure the performance overhead of individual and combined middleware.
//
// Run benchmarks with: go test -bench=. -benchmem ./pkg/security/...
//
//go:build !integration
// +build !integration

package security

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// Benchmark Helpers
// ============================================================================

// simpleHandler is a minimal HTTP handler for benchmarking baseline performance
func simpleHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// echoHandler is a handler that echoes back request body for payload benchmarks
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.Body != nil {
			_, _ = io.Copy(w, r.Body)
		} else {
			w.Write([]byte("OK"))
		}
	})
}

// ============================================================================
// Baseline Benchmarks (No Middleware)
// ============================================================================

// BenchmarkBaseline_NoMiddleware_GET measures baseline GET performance
func BenchmarkBaseline_NoMiddleware_GET(b *testing.B) {
	handler := simpleHandler()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkBaseline_NoMiddleware_POST measures baseline POST performance
func BenchmarkBaseline_NoMiddleware_POST(b *testing.B) {
	handler := simpleHandler()
	body := []byte("test data")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// ============================================================================
// Security Headers Benchmarks
// ============================================================================

// BenchmarkSecurityHeaders_GET measures Security Headers middleware overhead
func BenchmarkSecurityHeaders_GET(b *testing.B) {
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkSecurityHeaders_POST measures Security Headers with POST
func BenchmarkSecurityHeaders_POST(b *testing.B) {
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(simpleHandler())
	body := []byte("test data")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkSecurityHeaders_SecureHeaders measures convenience middleware
func BenchmarkSecurityHeaders_SecureHeaders(b *testing.B) {
	handler := SecureHeadersMiddleware(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// ============================================================================
// Panic Recovery Benchmarks
// ============================================================================

// BenchmarkPanicRecovery_Normal measures recovery middleware with normal handler
func BenchmarkPanicRecovery_Normal(b *testing.B) {
	recovery := NewPanicRecoveryMiddleware()
	handler := recovery.Handler(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkPanicRecovery_WithoutMiddleware measures overhead of defer/recover
func BenchmarkPanicRecovery_WithoutMiddleware(b *testing.B) {
	handler := simpleHandler()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// ============================================================================
// CSRF Middleware Benchmarks
// ============================================================================

// BenchmarkCSRF_GET measures CSRF middleware overhead for GET (safe method)
func BenchmarkCSRF_GET(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCSRF_POST_WithToken measures CSRF with token validation
func BenchmarkCSRF_POST_WithToken(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())

	// First GET to obtain token
	rec := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, reqGet)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		b.Fatal("CSRF cookie not set")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCSRF_POST_WithoutToken measures CSRF rejection performance
func BenchmarkCSRF_POST_WithoutToken(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			b.Fatalf("expected 403, got: %d", rec.Code)
		}
	}
}

// ============================================================================
// Audit Middleware Benchmarks
// ============================================================================

// BenchmarkAudit_Disabled measures Audit middleware with logging disabled
func BenchmarkAudit_Disabled(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	handler := AuditMiddleware(auditLogger, simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkAudit_Enabled measures Audit middleware with logging enabled
func BenchmarkAudit_Enabled(b *testing.B) {
	auditLogger := NewAuditLogger(true, []EventType{AuditEventAccess, AuditEventSecurity})
	handler := AuditMiddleware(auditLogger, simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkAudit_POST measures Audit middleware with body
func BenchmarkAudit_POST(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	handler := AuditMiddleware(auditLogger, simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// ============================================================================
// Middleware Combination Benchmarks
// ============================================================================

// BenchmarkCombo_HeadersRecovery combines SecurityHeaders + PanicRecovery
func BenchmarkCombo_HeadersRecovery_GET(b *testing.B) {
	recovery := NewPanicRecoveryMiddleware()
	base := simpleHandler()
	wrapped := recovery.Handler(base)
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(wrapped)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCombo_HeadersCSRF combines SecurityHeaders + CSRF
func BenchmarkCombo_HeadersCSRF_GET(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	base := simpleHandler()
	wrapped := csrf.Handler(base)
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(wrapped)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCombo_HeadersCSRF_POST combines SecurityHeaders + CSRF with valid token
func BenchmarkCombo_HeadersCSRF_POST(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	base := simpleHandler()
	wrapped := csrf.Handler(base)
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(wrapped)

	rec := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, reqGet)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		b.Fatal("CSRF cookie not set")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCombo_FullChain combines all middleware: Recovery <- Headers <- CSRF <- Audit
func BenchmarkCombo_FullChain_GET(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	recovery := NewPanicRecoveryMiddleware()

	base := simpleHandler()
	withAudit := AuditMiddleware(auditLogger, base)
	withCSRF := csrf.Handler(withAudit)
	withHeaders := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(withCSRF)
	handler := recovery.Handler(withHeaders)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// BenchmarkCombo_FullChain_POST combines all middleware with POST + CSRF token
func BenchmarkCombo_FullChain_POST(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	recovery := NewPanicRecoveryMiddleware()

	base := simpleHandler()
	withAudit := AuditMiddleware(auditLogger, base)
	withCSRF := csrf.Handler(withAudit)
	withHeaders := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(withCSRF)
	handler := recovery.Handler(withHeaders)

	rec := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, reqGet)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		b.Fatal("CSRF cookie not set")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d", rec.Code)
		}
	}
}

// ============================================================================
// Payload Size Benchmarks
// ============================================================================

// generatePayload creates a payload of specified size
func generatePayload(size int) []byte {
	return make([]byte, size)
}

// BenchmarkPayload_Small_1KB_NoMiddleware measures baseline with 1KB payload
func BenchmarkPayload_Small_1KB_NoMiddleware(b *testing.B) {
	payload := generatePayload(1024)
	handler := echoHandler()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkPayload_Medium_10KB_NoMiddleware measures baseline with 10KB payload
func BenchmarkPayload_Medium_10KB_NoMiddleware(b *testing.B) {
	payload := generatePayload(10 * 1024)
	handler := echoHandler()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkPayload_Large_100KB_NoMiddleware measures baseline with 100KB payload
func BenchmarkPayload_Large_100KB_NoMiddleware(b *testing.B) {
	payload := generatePayload(100 * 1024)
	handler := echoHandler()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkPayload_Headers_1KB measures SecurityHeaders with 1KB payload
func BenchmarkPayload_Headers_1KB(b *testing.B) {
	payload := generatePayload(1024)
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(echoHandler())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkPayload_FullChain_10KB measures full middleware chain with 10KB payload
func BenchmarkPayload_FullChain_10KB(b *testing.B) {
	payload := generatePayload(10 * 1024)
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	recovery := NewPanicRecoveryMiddleware()

	base := echoHandler()
	withAudit := AuditMiddleware(auditLogger, base)
	withCSRF := csrf.Handler(withAudit)
	withHeaders := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(withCSRF)
	handler := recovery.Handler(withHeaders)

	// Get CSRF token first
	rec := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, reqGet)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		b.Fatal("CSRF cookie not set")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		handler.ServeHTTP(rec, req)
	}
}

// ============================================================================
// Parallel Benchmarks (Concurrency)
// ============================================================================

// BenchmarkParallel_Baseline_NoMiddleware measures baseline concurrency
func BenchmarkParallel_Baseline_NoMiddleware(b *testing.B) {
	handler := simpleHandler()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkParallel_Headers measures concurrent Security Headers
func BenchmarkParallel_Headers(b *testing.B) {
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkParallel_CSRF_GET measures concurrent CSRF GET requests
func BenchmarkParallel_CSRF_GET(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkParallel_PanicRecovery measures concurrent Panic Recovery
func BenchmarkParallel_PanicRecovery(b *testing.B) {
	recovery := NewPanicRecoveryMiddleware()
	handler := recovery.Handler(simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkParallel_Audit_Disabled measures concurrent Audit (disabled)
func BenchmarkParallel_Audit_Disabled(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	handler := AuditMiddleware(auditLogger, simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkParallel_FullChain_GET measures concurrent full stack
func BenchmarkParallel_FullChain_GET(b *testing.B) {
	auditLogger := NewAuditLogger(false, []EventType{AuditEventAccess})
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	recovery := NewPanicRecoveryMiddleware()

	base := simpleHandler()
	withAudit := AuditMiddleware(auditLogger, base)
	withCSRF := csrf.Handler(withAudit)
	withHeaders := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(withCSRF)
	handler := recovery.Handler(withHeaders)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)
		}
	})
}

// ============================================================================
// HTTP Method Variation Benchmarks
// ============================================================================

// BenchmarkMethod_GET_NoMiddleware measures GET requests
func BenchmarkMethod_GET_NoMiddleware(b *testing.B) {
	handler := simpleHandler()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMethod_POST_NoMiddleware measures POST requests
func BenchmarkMethod_POST_NoMiddleware(b *testing.B) {
	handler := echoHandler()
	body := []byte("test data")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMethod_PUT_NoMiddleware measures PUT requests
func BenchmarkMethod_PUT_NoMiddleware(b *testing.B) {
	handler := echoHandler()
	body := []byte("test data")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/test", bytes.NewReader(body))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMethod_DELETE_NoMiddleware measures DELETE requests
func BenchmarkMethod_DELETE_NoMiddleware(b *testing.B) {
	handler := simpleHandler()
	req := httptest.NewRequest(http.MethodDelete, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMethod_GET_WithHeaders measures GET with Security Headers
func BenchmarkMethod_GET_WithHeaders(b *testing.B) {
	handler := SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMethod_GET_WithCSRF measures GET with CSRF middleware (safe method)
func BenchmarkMethod_GET_WithCSRF(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

// BenchmarkMemory_CSRFTokenCreation measures CSRF token creation
func BenchmarkMemory_CSRFTokenCreation(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())
	handler := csrf.Handler(simpleHandler())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMemory_CSRFTokenValidation measures CSRF token verification
func BenchmarkMemory_CSRFTokenValidation(b *testing.B) {
	csrf := NewCSRFMiddleware(DefaultCSRFConfig())

	// Get a token
	rec := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler := csrf.Handler(simpleHandler())
	handler.ServeHTTP(rec, reqGet)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		b.Fatal("CSRF cookie not set")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("data")))
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
	}
}
