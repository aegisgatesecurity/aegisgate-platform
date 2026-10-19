// SPDX-License-Identifier: Apache-2.0

package lensbackend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// newTestServer is a convenience wrapper around httptest.NewServer.
func newTestServer(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	return httptest.NewServer(srv.Mux())
}

// TestPhase1bHandleTelemetry_MethodNotAllowed exercises the GET rejection path.
func TestPhase1bHandleTelemetry_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
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

// TestPhase1bHandleTelemetry_BodyReadFailure exercises the body read error path
// by sending a body larger than the 4KB limit.
func TestPhase1bHandleTelemetry_BodyReadFailure(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	// Create a body larger than 4096 bytes
	largeBody := strings.Repeat("x", 5000)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(largeBody))
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

// TestPhase1bHandleTelemetry_EmptyBody exercises the decode failure path.
func TestPhase1bHandleTelemetry_EmptyBody(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(""))
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

// TestPhase1bAudit_RecordAccepted_NilReceiver exercises the nil safety check.
func TestPhase1bAudit_RecordAccepted_NilReceiver(t *testing.T) {
	var a *auditLogger
	a.RecordAccepted(nil, "req-1", "hash", "cat", "action", 10)
}

// TestPhase1bAudit_RecordRejected_NilReceiver exercises the nil safety check.
func TestPhase1bAudit_RecordRejected_NilReceiver(t *testing.T) {
	var a *auditLogger
	a.RecordRejected(nil, "req-1", "hash", "cat", "reason", 10)
}

// TestPhase1bAudit_RecordRateLimited_NilReceiver exercises the nil safety check.
func TestPhase1bAudit_RecordRateLimited_NilReceiver(t *testing.T) {
	var a *auditLogger
	a.RecordRateLimited(nil, "req-1", "hash", "reason")
}

// TestPhase1bAudit_RecordReceived_NilReceiver exercises the nil safety check.
func TestPhase1bAudit_RecordReceived_NilReceiver(t *testing.T) {
	var a *auditLogger
	a.RecordReceived(nil, "req-1", "hash", "cat")
}

// TestPhase1bIOCSeverityRank tests the severity ranking helper.
func TestPhase1bIOCSeverityRank(t *testing.T) {
	tests := []struct {
		sev  ioc.Severity
		want int
	}{
		{"critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := iocSeverityRank(tt.sev)
		if got != tt.want {
			t.Errorf("iocSeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

// TestPhase1bHandleStats_MethodNotAllowed exercises the method check.
func TestPhase1bHandleStats_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
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

// TestPhase1bHandleFPReport_MethodNotAllowed exercises the method check.
func TestPhase1bHandleFPReport_MethodNotAllowed(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/fp-report", nil)
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

// TestPhase1bHandleFPReport_DecodeFailure exercises the decode error path.
func TestPhase1bHandleFPReport_DecodeFailure(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader("not json"))
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

// TestPhase1bNewIOCWriter_DefaultFlushN exercises the flushN < 1 branch.
func TestPhase1bNewIOCWriter_DefaultFlushN(t *testing.T) {
	w := newIOCWriter(newStoreForTest(t), 0)
	if w.flushN != 100 {
		t.Errorf("expected default flushN=100, got %d", w.flushN)
	}
}

// TestPhase1bNewIOCWriter_NegativeFlushN exercises the flushN < 1 branch.
func TestPhase1bNewIOCWriter_NegativeFlushN(t *testing.T) {
	w := newIOCWriter(newStoreForTest(t), -5)
	if w.flushN != 100 {
		t.Errorf("expected default flushN=100, got %d", w.flushN)
	}
}

// TestPhase1bRunRetention_ImmediateCancel exercises the context cancellation path.
func TestPhase1bRunRetention_ImmediateCancel(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	srv.retent.RunRetention(ctx, 10*time.Millisecond)
	// If we get here without hanging, the test passes
}

// TestPhase1bExtractSNI_NoTLS exercises the no-TLS path.
func TestPhase1bExtractSNI_NoTLS(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	sni := ExtractSNI(r)
	_ = sni
}

// TestPhase1bExtractSNI_WithTLS exercises the TLS SNI extraction.
func TestPhase1bExtractSNI_WithTLS(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	sni := ExtractSNI(r)
	_ = sni
}

// TestPhase1bHandleFPReport_InvalidHash exercises the hash validation path.
func TestPhase1bHandleFPReport_InvalidHash(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	body := `{"hashed_domain":"short","category":"pii_email","severity":"high","action":"cancel"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bHandleFPReport_InvalidCategory exercises the category validation.
func TestPhase1bHandleFPReport_InvalidCategory(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	body := `{"hashed_domain":"0123456789abcdef","category":"invalid_cat","severity":"high","action":"cancel"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bHandleFPReport_InvalidSeverity exercises the severity validation.
func TestPhase1bHandleFPReport_InvalidSeverity(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	body := `{"hashed_domain":"0123456789abcdef","category":"pii_email","severity":"critical","action":"cancel"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bHandleFPReport_InvalidAction exercises the action validation.
func TestPhase1bHandleFPReport_InvalidAction(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	body := `{"hashed_domain":"0123456789abcdef","category":"pii_email","severity":"high","action":"invalid_action"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bHandleFPReport_BodyReadFailure exercises the body too-large path.
func TestPhase1bHandleFPReport_BodyReadFailure(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	largeBody := strings.Repeat("x", 5000)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(largeBody))
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

// TestPhase1bHandleTelemetry_ValidateFail exercises the validate_failed path
// by sending a valid JSON event with an invalid version.
func TestPhase1bHandleTelemetry_ValidateFail(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	body := `{"lens_event_version":99,"domain_hash":"0123456789abcdef","facet":"pii","category":"pii_email","severity":"high","user_action":"send_anyway","timestamp":9999999999,"model_version":"0.1.0","lens_version":"0.1.0","confidence":1.0}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(body))
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

// TestPhase1bHandleTelemetry_DomainHashFail exercises the domain_hash
// verification failure path (no TLS SNI in test server).
func TestPhase1bHandleTelemetry_DomainHashFail(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	// Send a valid event — decode and validate will pass, but
	// domain hash verification will fail (no TLS in test server)
	body := `{"lens_event_version":1,"domain_hash":"0123456789abcdef","facet":"pii","category":"pii_email","severity":"high","user_action":"send_anyway","timestamp":9999999999,"model_version":"0.1.0","lens_version":"0.1.0","confidence":1.0}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (domain hash fail)", resp.StatusCode)
	}
}

// TestPhase1bPurgeStore_NonExistentFile exercises the file-not-found path.
func TestPhase1bPurgeStore_NonExistentFile(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	removed := srv.retent.purgeStore(context.Background(), func(ts time.Time, action string) bool {
		return false
	})
	if removed != 0 {
		t.Errorf("expected 0 removed for non-existent file, got %d", removed)
	}
}

// TestPhase1bPurgeStore_WithFile exercises the read/filter/write path
// by creating an events.jsonl file in the server's store path.
func TestPhase1bPurgeStore_WithFile(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	// Write events.jsonl to the server's actual store path
	eventsPath := filepath.Join(srv.retent.storePath, "events.jsonl")
	oldData := `{"timestamp":1,"user_action":"send_anyway"}
{"timestamp":2,"user_action":"cancel"}
`
	if err := os.WriteFile(eventsPath, []byte(oldData), 0600); err != nil {
		t.Fatal(err)
	}
	// Purge all events (filter returns true for all)
	removed := srv.retent.purgeStore(context.Background(), func(ts time.Time, action string) bool {
		return true
	})
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
}

// TestPhase1bRunRetention_RunOnce exercises a single retention cycle.
func TestPhase1bRunRetention_RunOnce(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx := context.Background()
	srv.retent.runOnce(ctx)
	// Should not panic
}

// TestPhase1bRunRetention_DefaultInterval exercises the interval <= 0 branch.
func TestPhase1bRunRetention_DefaultInterval(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv.retent.RunRetention(ctx, 0) // interval=0 triggers default
}

// TestPhase1bRunRetention_TickerFires exercises the ticker fire path
// by using a very short interval and letting it tick once.
func TestPhase1bRunRetention_TickerFires(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	srv.retent.RunRetention(ctx, 5*time.Millisecond)
	// The ticker fires every 5ms; the context expires after 50ms.
	// This covers the case <-t.C branch.
}

// TestPhase1bLocalAddr exercises the LocalAddr method.
func TestPhase1bLocalAddr(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	addr := srv.LocalAddr()
	_ = addr
}

// TestPhase1bLocalAddr_NilHTTPServer exercises the nil path.
func TestPhase1bLocalAddr_NilHTTPServer(t *testing.T) {
	srv := &Server{}
	addr := srv.LocalAddr()
	if addr != nil {
		t.Fatal("expected nil for server without httpServer")
	}
}

// TestPhase1bFacetFromCategory exercises the FacetFromCategory function.
func TestPhase1bFacetFromCategory(t *testing.T) {
	// Known category
	f := FacetFromCategory("pii_email")
	if f != FacetPII {
		t.Errorf("expected FacetPII for pii_email, got %v", f)
	}
	// Unknown category
	f = FacetFromCategory("nonexistent_category")
	if f != "" {
		t.Errorf("expected empty facet for unknown category, got %v", f)
	}
}

// TestPhase1bHandleTelemetry_ValidEvent exercises the domain hash verification
// failure path with a valid event (no TLS in test, so domain hash check fails).
// This covers the domain_hash_no_tls error path in HandleTelemetry.
func TestPhase1bHandleTelemetry_DomainHashNoTLS(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	// Valid event that passes decode + validate but fails domain hash (no TLS)
	body := `{"lens_event_version":1,"domain_hash":"abcdef0123456789","facet":"pii","category":"pii_email","severity":"high","user_action":"send_anyway","timestamp":9999999999,"model_version":"0.1.0","lens_version":"0.1.0","confidence":1.0}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/telemetry", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Should get 400 due to domain hash mismatch (no TLS SNI)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPhase1bHandleFPReport_UnknownFacet exercises the unknown facet path
// by sending a category that doesn't map to any facet prefix.
func TestPhase1bHandleFPReport_UnknownFacet(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	// "zzz_unknown" doesn't match any facet prefix
	body := `{"hashed_domain":"0123456789abcdef","category":"zzz_unknown","severity":"high","action":"cancel"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bHandleFPReport_NonHexHash exercises the non-hex hash validation.
func TestPhase1bHandleFPReport_NonHexHash(t *testing.T) {
	srv := newServerForTest(t, "test-token")
	ts := newTestServer(t, srv)
	defer ts.Close()
	// 16 chars but not all lowercase hex
	body := `{"hashed_domain":"GGHHIIJJKKLLMMNN","category":"pii_email","severity":"high","action":"cancel"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/lens/fp-report", strings.NewReader(body))
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

// TestPhase1bIsValidCategory exercises the isValidCategory helper.
func TestPhase1bIsValidCategory(t *testing.T) {
	// Valid category
	if !isValidCategory("pii_email") {
		t.Error("expected pii_email to be valid")
	}
	// Invalid category
	if isValidCategory("nonexistent_category") {
		t.Error("expected nonexistent_category to be invalid")
	}
}

// TestPhase1bNewServer_NilConfig exercises the nil config error path.
func TestPhase1bNewServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil, "test")
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}
