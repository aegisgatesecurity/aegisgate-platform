// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Comprehensive Coverage Tests
// =========================================================================
//
// This file is the second test file for pkg/lensbackend. Its
// purpose is to bring the package's coverage above the
// Platform's 80% per-package floor (enforced by the CI's
// "Check per-package coverage floor" step in .github/workflows/
// ci.yml).
//
// The companion file server_test.go contains the original
// 10 unit tests that exercise the schema, domain hash,
// rate limiter, server startup, and bearer-token auth. This
// file adds tests for everything else.
//
// Run: go test -race -short ./pkg/lensbackend/...
// =========================================================================

package lensbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// =========================================================================
// audit.go
// =========================================================================

func TestAuditLogger_RecordReceived(t *testing.T) {
	dir := t.TempDir()
	ring := newRingBufferForTest()
	a := newAuditLogger(ring, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordReceived(context.Background(), "req-1", "hash-1", "pii_email")
	// Verify via the ring buffer (SnapshotBetween returns
	// events in the given time window; pass the full window).
	now := time.Now()
	events := ring.SnapshotBetween(now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "lens_audit" {
		t.Errorf("Type = %q, want lens_audit", events[0].Type)
	}
}

func TestAuditLogger_RecordAccepted(t *testing.T) {
	dir := t.TempDir()
	ring := newRingBufferForTest()
	a := newAuditLogger(ring, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordAccepted(context.Background(), "req-2", "hash-2", "pii_email", "send_anyway", 10)
	now := time.Now()
	events := ring.SnapshotBetween(now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestAuditLogger_RecordRejected(t *testing.T) {
	dir := t.TempDir()
	ring := newRingBufferForTest()
	a := newAuditLogger(ring, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordRejected(context.Background(), "req-3", "hash-3", "pii_email", "validation_failed", 2)
	now := time.Now()
	events := ring.SnapshotBetween(now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestAuditLogger_RecordRateLimited(t *testing.T) {
	dir := t.TempDir()
	ring := newRingBufferForTest()
	a := newAuditLogger(ring, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordRateLimited(context.Background(), "req-4", "hash-4", "rate_limited")
	now := time.Now()
	events := ring.SnapshotBetween(now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestAuditLogger_FormatAuditMessage(t *testing.T) {
	dir := t.TempDir()
	ring := newRingBufferForTest()
	a := newAuditLogger(ring, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordAccepted(context.Background(), "rid", "dhm", "pii_email", "send_anyway", 5)
	now := time.Now()
	events := ring.SnapshotBetween(now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if len(events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if !strings.Contains(events[0].Message, "rid") ||
		!strings.Contains(events[0].Message, "dhm") ||
		!strings.Contains(events[0].Message, "pii_email") ||
		!strings.Contains(events[0].Message, "send_anyway") {
		t.Errorf("Message missing expected parts: %q", events[0].Message)
	}
}

func TestAuditLogger_NilRing(t *testing.T) {
	dir := t.TempDir()
	a := newAuditLogger(nil, slogForTest(filepath.Join(dir, "audit.log")))
	a.RecordAccepted(context.Background(), "rid", "dhm", "pii_email", "send_anyway", 1)
	// No panic is success.
}

// =========================================================================
// config.go
// =========================================================================

func TestLoadConfig_AllEnvVars(t *testing.T) {
	t.Setenv("LENS_PORT", "12345")
	t.Setenv("LENS_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("LENS_TLS_KEY", "/tmp/key.pem")
	t.Setenv("LENS_BEARER_TOKEN", "test-token")
	t.Setenv("LENS_EVENT_RETENTION_DAYS", "30")
	t.Setenv("LENS_IOC_STORE_PATH", "/tmp/lens-ioc")
	t.Setenv("LENS_RATE_LIMIT_PER_MIN", "5000")
	t.Setenv("LENS_HMAC_KEY", "")
	t.Setenv("LENS_LOG_PATH", "/tmp/lens.log")
	t.Setenv("LENS_PUBLIC_URL", "https://lens.example.com")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Port != 12345 {
		t.Errorf("Port = %d, want 12345", cfg.Port)
	}
	if cfg.TLSCert != "/tmp/cert.pem" {
		t.Errorf("TLSCert = %q", cfg.TLSCert)
	}
	if cfg.TLSKey != "/tmp/key.pem" {
		t.Errorf("TLSKey = %q", cfg.TLSKey)
	}
	if cfg.BearerToken != "test-token" {
		t.Errorf("BearerToken = %q", cfg.BearerToken)
	}
	if cfg.EventRetention != 30*24*time.Hour {
		t.Errorf("EventRetention = %v", cfg.EventRetention)
	}
	if cfg.IOCStorePath != "/tmp/lens-ioc" {
		t.Errorf("IOCStorePath = %q", cfg.IOCStorePath)
	}
	if cfg.RateLimitPerMin != 5000 {
		t.Errorf("RateLimitPerMin = %d", cfg.RateLimitPerMin)
	}
	if cfg.LogPath != "/tmp/lens.log" {
		t.Errorf("LogPath = %q", cfg.LogPath)
	}
	if cfg.PublicURL != "https://lens.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
}

func TestLoadConfig_InvalidRetentionDays(t *testing.T) {
	t.Setenv("LENS_EVENT_RETENTION_DAYS", "not-a-number")
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for non-numeric retention days")
	}
}

func TestLoadConfig_NegativeRetentionDays(t *testing.T) {
	t.Setenv("LENS_EVENT_RETENTION_DAYS", "-5")
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for negative retention days")
	}
}

func TestLoadConfig_InvalidRateLimit(t *testing.T) {
	t.Setenv("LENS_RATE_LIMIT_PER_MIN", "abc")
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for non-numeric rate limit")
	}
}

func TestLoadConfig_ZeroRateLimit(t *testing.T) {
	// Zero is REJECTED -- the spec says the rate limiter
	// requires a positive cap. (Use a very high value if
	// you want "effectively unlimited".)
	t.Setenv("LENS_RATE_LIMIT_PER_MIN", "0")
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for zero rate limit")
	}
}

// =========================================================================
// domain_hash.go
// =========================================================================

func TestExtractSNI_FromTLS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := ExtractSNI(r); got != "" {
		t.Errorf("ExtractSNI(nil TLS) = %q, want empty", got)
	}
}

func TestExtractSNI_FromHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Original-SNI", "chat.openai.com")
	if got := ExtractSNI(r); got != "chat.openai.com" {
		t.Errorf("ExtractSNI(X-Original-SNI) = %q", got)
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("X-Forwarded-SNI", "claude.ai")
	if got := ExtractSNI(r2); got != "claude.ai" {
		t.Errorf("ExtractSNI(X-Forwarded-SNI) = %q", got)
	}
}

func TestVerifyDomainHash_Match(t *testing.T) {
	hash := ComputeDomainHash("chat.openai.com")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Original-SNI", "chat.openai.com")
	if err := VerifyDomainHash(r, hash); err != nil {
		t.Errorf("VerifyDomainHash match: %v", err)
	}
}

func TestVerifyDomainHash_Mismatch(t *testing.T) {
	hash := ComputeDomainHash("chat.openai.com")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Original-SNI", "claude.ai")
	err := VerifyDomainHash(r, hash)
	if err == nil {
		t.Error("expected error for SNI/domain_hash mismatch")
	}
	// The error wraps a sentinel; check by error string.
	if err != nil && !strings.Contains(err.Error(), "domain_hash mismatch") {
		t.Errorf("error message should mention 'domain_hash mismatch', got %v", err)
	}
}

func TestVerifyDomainHash_NoTLS(t *testing.T) {
	hash := ComputeDomainHash("chat.openai.com")
	r := httptest.NewRequest("GET", "/", nil)
	if err := VerifyDomainHash(r, hash); err != ErrNoTLS {
		t.Errorf("expected ErrNoTLS, got %v", err)
	}
}

// =========================================================================
// handlers.go
// =========================================================================

func TestHandlers_HandleTelemetry_ValidationError(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_HandleTelemetry_UnknownField(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	body := `{"domain_hash":"abc","category":"pii_email","severity":"high","user_action":"send_anyway","timestamp":1234567890,"model_version":"0.1.0+x","lens_version":"0.1.0","confidence":1.0,"prompt_content":"forbidden"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (unknown field rejected)", resp.StatusCode)
	}
}

func TestHandlers_HandleTelemetry_AuthRequired(t *testing.T) {
	srv := newServerForTest(t, "correct-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/api/v1/lens/telemetry", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_HandleCheck_CleanDomain(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/check?domain=chat.openai.com", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["verdict"] != "clean" {
		t.Errorf("verdict = %v, want clean", body["verdict"])
	}
}

func TestHandlers_HandleCheck_MissingDomain(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/check", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_HandleCheck_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/check", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHandlers_HandleStats(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["window_start"] == nil {
		t.Error("window_start is missing")
	}
}

func TestHandlers_HandleStats_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHandlers_HandleTelemetry_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/telemetry", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestNewRequestID(t *testing.T) {
	r1 := newRequestID()
	time.Sleep(2 * time.Millisecond)
	r2 := newRequestID()
	if r1 == r2 {
		t.Errorf("newRequestID returned same value twice: %s", r1)
	}
	if len(r1) != 16 {
		t.Errorf("newRequestID length = %d, want 16", len(r1))
	}
}

func TestIOCSeverityRank(t *testing.T) {
	cases := []struct {
		s    ioc.Severity
		want int
	}{
		{ioc.SeverityCritical, 5},
		{ioc.SeverityHigh, 4},
		{ioc.SeverityMedium, 3},
		{ioc.SeverityLow, 2},
		{ioc.SeverityInfo, 1},
	}
	for _, c := range cases {
		if got := iocSeverityRank(c.s); got != c.want {
			t.Errorf("iocSeverityRank(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestSplitFields(t *testing.T) {
	got := splitFields("a b c d e f g", 3)
	if len(got) != 3 {
		t.Fatalf("splitFields returned %d fields, want 3", len(got))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c d e f g" {
		t.Errorf("splitFields: %v", got)
	}
}

func TestInMaintenance_True(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !srv.inMaintenance(ctx) {
		t.Error("inMaintenance(cancelled) = false, want true")
	}
}

func TestInMaintenance_False(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	if srv.inMaintenance(context.Background()) {
		t.Error("inMaintenance(background) = true, want false")
	}
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusCreated, map[string]string{"foo": "bar"})
	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusBadRequest, "test_code", "test message")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "test_code" || body["message"] != "test message" {
		t.Errorf("body = %v", body)
	}
}

func TestNewHandlers(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	h := NewHandlers(srv)
	if h == nil {
		t.Fatal("NewHandlers returned nil")
	}
	if h.server != srv {
		t.Error("NewHandlers.server mismatch")
	}
}

// =========================================================================
// ioc_writer.go
// =========================================================================

func TestCategoryToIOCType_AllBranches(t *testing.T) {
	cases := []struct {
		cat  string
		want ioc.IOCType
	}{
		{string(CategoryPIIEmail), ioc.IOCTypePIIDetected},
		{string(CategoryPIIPhone), ioc.IOCTypePIIDetected},
		{string(CategoryPIISSN), ioc.IOCTypePIIDetected},
		{string(CategoryPIICreditCard), ioc.IOCTypePIIDetected},
		{string(CategorySecretAPIKey), ioc.IOCTypeSecretLeak},
		{string(CategorySourceCode), ioc.IOCTypeSecretLeak},
		{"unknown_category", ioc.IOCTypePIIDetected},
	}
	for _, c := range cases {
		if got := categoryToIOCType(c.cat); got != c.want {
			t.Errorf("categoryToIOCType(%q) = %q, want %q", c.cat, got, c.want)
		}
	}
}

func TestSeverityToIOC_AllBranches(t *testing.T) {
	cases := []struct {
		s    string
		want ioc.Severity
	}{
		{string(SeverityCritical), ioc.SeverityCritical},
		{string(SeverityHigh), ioc.SeverityHigh},
		{string(SeverityMedium), ioc.SeverityMedium},
		{string(SeverityLow), ioc.SeverityLow},
		{string(SeverityInfo), ioc.SeverityInfo},
		{"unknown", ioc.SeverityInfo},
	}
	for _, c := range cases {
		if got := severityToIOC(c.s); got != c.want {
			t.Errorf("severityToIOC(%q) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestSourceProviderFromDomainHash_AllBranches(t *testing.T) {
	hashChat := ComputeDomainHash("chat.openai.com")
	if got := sourceProviderFromDomainHash(hashChat); got != "chatgpt" {
		t.Errorf("sourceProviderFromDomainHash(chat) = %q, want chatgpt", got)
	}
	hashClaude := ComputeDomainHash("claude.ai")
	if got := sourceProviderFromDomainHash(hashClaude); got != "claude" {
		t.Errorf("sourceProviderFromDomainHash(claude) = %q, want claude", got)
	}
	hashGemini := ComputeDomainHash("gemini.google.com")
	if got := sourceProviderFromDomainHash(hashGemini); got != "gemini" {
		t.Errorf("sourceProviderFromDomainHash(gemini) = %q, want gemini", got)
	}
	hashCopilot := ComputeDomainHash("copilot.microsoft.com")
	if got := sourceProviderFromDomainHash(hashCopilot); got != "copilot" {
		t.Errorf("sourceProviderFromDomainHash(copilot) = %q, want copilot", got)
	}
	if got := sourceProviderFromDomainHash("0000000000000000"); got != "unknown" {
		t.Errorf("sourceProviderFromDomainHash(unknown) = %q, want unknown", got)
	}
}

func TestPatternFromCategory_AllBranches(t *testing.T) {
	cases := []struct {
		cat  string
		want string
	}{
		{string(CategoryPIIEmail), "pii_email"},
		{string(CategoryPIIPhone), "pii_phone"},
		{string(CategoryPIISSN), "pii_ssn"},
		{string(CategoryPIICreditCard), "pii_credit_card"},
		{string(CategorySecretAPIKey), "secret_api_key"},
		{string(CategorySourceCode), "source_code"},
		{"unknown", "unknown"},
	}
	for _, c := range cases {
		if got := patternFromCategory(c.cat); got != c.want {
			t.Errorf("patternFromCategory(%q) = %q, want %q", c.cat, got, c.want)
		}
	}
}

func TestIOCWriter_FlushEmpty(t *testing.T) {
	store := newStoreForTest(t)
	w := newIOCWriter(store, 10)
	if err := w.flush(context.Background()); err != nil {
		t.Errorf("flush empty: %v", err)
	}
}

func TestIOCWriter_Add_NoSNI(t *testing.T) {
	store := newStoreForTest(t)
	w := newIOCWriter(store, 10)
	e := Event{
		DomainHash:   "abc",
		Category:     string(CategoryPIIEmail),
		Severity:     string(SeverityHigh),
		UserAction:   string(UserActionSendAnyway),
		Timestamp:    time.Now().Unix(),
		ModelVersion: "0.1.0+x",
		LensVersion:  "0.1.0",
		Confidence:   1.0,
	}
	if err := w.add(context.Background(), e); err != nil {
		t.Errorf("add: %v", err)
	}
}

func TestIOCWriter_Flush_WithPending(t *testing.T) {
	store := newStoreForTest(t)
	w := newIOCWriter(store, 2)
	for i := 0; i < 3; i++ {
		e := Event{
			DomainHash:   "abc",
			Category:     string(CategoryPIIEmail),
			Severity:     string(SeverityHigh),
			UserAction:   string(UserActionSendAnyway),
			Timestamp:    time.Now().Unix(),
			ModelVersion: "0.1.0+x",
			LensVersion:  "0.1.0",
			Confidence:   1.0,
		}
		if err := w.add(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.flushLocked(context.Background()); err != nil {
		t.Errorf("flushLocked: %v", err)
	}
	if got := store.Size(); got == 0 {
		t.Error("expected store to have at least one IOC after flush")
	}
}

// =========================================================================
// ratelimit.go
// =========================================================================

func TestRateLimit_Middleware_Allowed(t *testing.T) {
	rl := NewLensRateLimiter(nil, 100)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Lens-Domain-Hash", "abc")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestRateLimit_Middleware_RateLimited(t *testing.T) {
	rl := NewLensRateLimiter(nil, 2)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.Header.Set("X-Lens-Domain-Hash", "def")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("req %d: status = %d, want 200", i, rr.Code)
		}
	}
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Lens-Domain-Hash", "def")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd req: status = %d, want 429", rr.Code)
	}
}

func TestWriteTooManyRequests(t *testing.T) {
	rl := NewLensRateLimiter(nil, 1)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Lens-Domain-Hash", "ghi")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req) // 1st: allowed
	handler.ServeHTTP(rr, req) // 2nd: 429
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Errorf("body not JSON: %v", err)
	}
}

func TestInstallationKey_Deterministic(t *testing.T) {
	hmacKey := make([]byte, 32)
	rl := NewLensRateLimiter(hmacKey, 100)
	k1 := rl.installationKey("test-hash")
	k2 := rl.installationKey("test-hash")
	if k1 != k2 {
		t.Error("installationKey is not deterministic")
	}
	k3 := rl.installationKey("different-hash")
	if k1 == k3 {
		t.Error("different hashes produced the same key")
	}
}

func TestAllowGlobal(t *testing.T) {
	rl := NewLensRateLimiter(nil, 3)
	for i := 0; i < 3; i++ {
		if !rl.AllowGlobal() {
			t.Errorf("req %d: AllowGlobal = false", i)
		}
	}
	if rl.AllowGlobal() {
		t.Error("4th: AllowGlobal = true, want false")
	}
}

// =========================================================================
// retention.go
// =========================================================================

func TestRetention_NewRetentionState(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	if rs == nil {
		t.Fatal("newRetentionState returned nil")
	}
}

func TestRetention_Validate(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	if err := rs.validate(); err != nil {
		t.Errorf("validate (valid): %v", err)
	}
	rs.eventRetention = 0
	if err := rs.validate(); err == nil {
		t.Error("expected error for zero eventRetention")
	}
	rs.eventRetention = 90 * 24 * time.Hour
	rs.sendAnyway = 0
	if err := rs.validate(); err == nil {
		t.Error("expected error for zero sendAnyway")
	}
}

func TestRetention_LookUpIPGeo_Miss(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	if got := rs.lookUpIPGeo("1.2.3.4"); got != "ZZ" {
		t.Errorf("lookUpIPGeo empty: got %q, want ZZ", got)
	}
}

func TestRetention_StoreAndLookUpIPGeo(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	rs.storeIPGeo("1.2.3.4", "US")
	if got := rs.lookUpIPGeo("1.2.3.4"); got != "US" {
		t.Errorf("lookUpIPGeo after store: got %q, want US", got)
	}
}

func TestRetention_FlushIPGeoCache(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	rs.storeIPGeo("1.2.3.4", "US")
	rs.flushIPGeoCache(context.Background())
	if got := rs.lookUpIPGeo("1.2.3.4"); got != "ZZ" {
		t.Errorf("after flush: got %q, want ZZ (cache should be empty)", got)
	}
}

func TestRetention_PurgeStore_NoFile(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	n := rs.purgeStore(context.Background(), func(ts time.Time, action string) bool { return true })
	if n != 0 {
		t.Errorf("purgeStore on missing file: got %d, want 0", n)
	}
}

func TestRetention_PurgeStore_WithData(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	old := time.Now().Add(-100 * 24 * time.Hour).Unix()
	recent := time.Now().Unix()
	lines := []string{
		`{"timestamp":` + itoaForTest(old) + `,"user_action":"send_anyway"}`,
		`{"timestamp":` + itoaForTest(recent) + `,"user_action":"send_anyway"}`,
		`{"timestamp":` + itoaForTest(recent) + `,"user_action":"edit"}`,
	}
	if err := os.WriteFile(eventsPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	n := rs.purgeStore(context.Background(), func(ts time.Time, action string) bool {
		return time.Since(ts) > 90*24*time.Hour
	})
	if n != 1 {
		t.Errorf("purgeStore: got %d, want 1", n)
	}
	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	count := bytes.Count(data, []byte("\n"))
	if count != 2 {
		t.Errorf("after purge: %d lines, want 2", count)
	}
}

func TestRetention_RunRetention_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		rs.RunRetention(ctx, 10*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunRetention did not return after context cancel")
	}
}

func TestRetention_RunOnce(t *testing.T) {
	dir := t.TempDir()
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	rs.runOnce(context.Background())
}

func TestRetention_PurgeOldEvents(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	old := time.Now().Add(-100 * 24 * time.Hour).Unix()
	if err := os.WriteFile(eventsPath, []byte(
		`{"timestamp":`+itoaForTest(old)+`,"user_action":"send_anyway"}`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	rs := newRetentionState(dir, 90*24*time.Hour, 24*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	n := rs.purgeOldEvents(context.Background())
	if n != 1 {
		t.Errorf("purgeOldEvents: got %d, want 1", n)
	}
}

func TestRetention_PurgeSendAnywayEvents(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	old := time.Now().Add(-48 * time.Hour).Unix()
	if err := os.WriteFile(eventsPath, []byte(
		`{"timestamp":`+itoaForTest(old)+`,"user_action":"send_anyway"}`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	rs := newRetentionState(dir, 90*24*time.Hour, 48*time.Hour, nil, slogForTest(filepath.Join(dir, "r.log")))
	n := rs.purgeSendAnywayEvents(context.Background())
	if n != 1 {
		t.Errorf("purgeSendAnywayEvents: got %d, want 1", n)
	}
}

func TestSortByTime(t *testing.T) {
	times := []time.Time{
		time.Unix(3, 0),
		time.Unix(1, 0),
		time.Unix(2, 0),
	}
	sortByTime(times)
	if !times[0].Equal(time.Unix(1, 0)) ||
		!times[1].Equal(time.Unix(2, 0)) ||
		!times[2].Equal(time.Unix(3, 0)) {
		t.Errorf("sortByTime: %v", times)
	}
}

// =========================================================================
// server.go
// =========================================================================

func TestServer_NewServer_NoTLS(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    dir,
		RateLimitPerMin: 100,
		BearerToken:     "test",
	}, "test-ver")
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestServer_NewServer_InvalidStorePath(t *testing.T) {
	_, err := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    "/nonexistent/path/that/cannot/be/created\x00invalid",
		RateLimitPerMin: 100,
		BearerToken:     "test",
	}, "test-ver")
	if err == nil {
		t.Error("expected error for invalid store path")
	}
}

func TestServer_NewServer_HMACKey(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, "hmac.key")
	if err := os.WriteFile(hmacPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    dir,
		RateLimitPerMin: 100,
		BearerToken:     "test",
		HMACKeyPath:     hmacPath,
	}, "test-ver")
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil with HMAC key")
	}
}

func TestServer_NewServer_ShortHMACKey(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, "hmac.key")
	if err := os.WriteFile(hmacPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    dir,
		RateLimitPerMin: 100,
		BearerToken:     "test",
		HMACKeyPath:     hmacPath,
	}, "test-ver")
	if err == nil {
		t.Error("expected error for short HMAC key")
	}
}

func TestServer_NewServer_HMACKeyNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    dir,
		RateLimitPerMin: 100,
		BearerToken:     "test",
		HMACKeyPath:     "/nonexistent/hmac.key",
	}, "test-ver")
	if err == nil {
		t.Error("expected error for missing HMAC key file")
	}
}

func TestServer_AppendRawEvent(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	e := Event{
		DomainHash:   "abc1234567890def",
		Category:     string(CategoryPIIEmail),
		Severity:     string(SeverityHigh),
		UserAction:   string(UserActionSendAnyway),
		Timestamp:    time.Now().Unix(),
		ModelVersion: "0.1.0+x",
		LensVersion:  "0.1.0",
		Confidence:   1.0,
	}
	if err := srv.appendRawEvent(context.Background(), e); err != nil {
		t.Fatalf("appendRawEvent: %v", err)
	}
	path := filepath.Join(srv.cfg.IOCStorePath, "events.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "abc1234567890def") {
		t.Errorf("events.jsonl does not contain domain_hash: %s", data)
	}
}

func TestServer_RunRetention(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.RunRetention(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunRetention did not return after context cancel")
	}
}

func TestServer_LocalAddr(t *testing.T) {
	dir := t.TempDir()
	srv, _ := NewServer(&Config{
		Port:            9999,
		IOCStorePath:    dir,
		RateLimitPerMin: 100,
		BearerToken:     "test",
	}, "test-ver")
	addr := srv.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr returned nil")
	}
}

func TestSlogOutput_FallbackToStdout(t *testing.T) {
	if got := slogOutput(""); got != os.Stdout {
		t.Error("slogOutput(\"\") should return os.Stdout")
	}
}

func TestSlogOutput_OpensFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.txt")
	f := slogOutput(path)
	if f == os.Stdout {
		t.Error("slogOutput with path should not return os.Stdout")
	}
	f.Close()
}

func TestSlogOutput_FallsBackOnError(t *testing.T) {
	dir := t.TempDir()
	f := slogOutput(dir)
	if f != os.Stdout {
		t.Error("slogOutput on directory should fall back to stdout")
	}
}

func TestServer_ListenAndServe_HTTP(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ln, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv.httpServer.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	srv.cfg.Port = port
	go func() { _ = srv.httpServer.Serve(ln) }()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/lens/healthz", port))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: status = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestServer_ListenAndServe_Plaintext(t *testing.T) {
	// ListenAndServe wraps httpServer.ListenAndServe. We
	// can't easily start it on a fixed port and shut it
	// down (it would block), so we just exercise the branch
	// where TLS is not configured -- the function calls
	// httpServer.ListenAndServe (without TLS) and returns
	// its error.
	srv := newServerForTest(t, "test-token")
	srv.cfg.TLSCert = ""
	srv.cfg.TLSKey = ""
	// Start in a goroutine and immediately shut down. The
	// function will return an error (because the listener
	// is closed), which is fine.
	oldAddr := srv.httpServer.Addr
	srv.httpServer.Addr = "127.0.0.1:0" // any free port; we'll close immediately
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	// Give it a moment to bind, then shut down.
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	select {
	case <-done:
		// good -- ListenAndServe returned
	case <-time.After(2 * time.Second):
		t.Error("ListenAndServe did not return after Shutdown")
	}
	srv.httpServer.Addr = oldAddr
}

// =========================================================================
// Test helpers
// =========================================================================

func newServerForTest(t *testing.T, token string) *Server {
	t.Helper()
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     token,
	}, "test-ver")
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func newStoreForTest(t *testing.T) *ioc.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := ioc.NewStore(ioc.StoreConfig{
		Capacity: 100,
		DiskPath: filepath.Join(dir, "ioc.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newIOCWriterForTest(t *testing.T) *iocWriter {
	t.Helper()
	return newIOCWriter(newStoreForTest(t), 100)
}

func slogForTest(path string) *slog.Logger {
	h := slog.NewTextHandler(slogOutput(path), &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(h)
}

func itoaForTest(n int64) string {
	return strconv.FormatInt(n, 10)
}

func newLocalListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func newRingBufferForTest() *logging.RingBuffer {
	return logging.NewRingBuffer(10)
}
