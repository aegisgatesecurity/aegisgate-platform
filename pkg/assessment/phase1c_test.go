// SPDX-License-Identifier: Apache-2.0

package assessment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =========================================================================
// scheduler.go gaps
// =========================================================================

func TestPhase1c_ChannelAlertHandler(t *testing.T) {
	ch := make(chan PostureAlert, 1)
	h := NewChannelAlertHandler(ch)

	alert := PostureAlert{Type: AlertScoreDrop, Severity: AlertHigh, Message: "test"}
	if err := h.Deliver(alert); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}
	select {
	case got := <-ch:
		if got.Type != AlertScoreDrop {
			t.Errorf("got type %s, want %s", got.Type, AlertScoreDrop)
		}
	default:
		t.Error("no alert received on channel")
	}

	// Channel full → error.
	fullCh := make(chan PostureAlert, 0)
	fullH := NewChannelAlertHandler(fullCh)
	if err := fullH.Deliver(alert); err == nil {
		t.Error("expected error when channel is full")
	}
}

func TestPhase1c_WebhookAlertHandler(t *testing.T) {
	alert := PostureAlert{Type: AlertScoreDrop, Severity: AlertHigh, Message: "test"}

	// Empty URL.
	h := &WebhookAlertHandler{URL: ""}
	if err := h.Deliver(alert); err == nil {
		t.Error("expected error for empty URL")
	}

	// Successful POST.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	h2 := &WebhookAlertHandler{URL: srv.URL, Timeout: 5 * time.Second}
	if err := h2.Deliver(alert); err != nil {
		t.Errorf("Deliver failed: %v", err)
	}

	// Error status code.
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvErr.Close()
	h3 := &WebhookAlertHandler{URL: srvErr.URL, Timeout: 5 * time.Second}
	if err := h3.Deliver(alert); err == nil {
		t.Error("expected error for 500 response")
	}

	// Unreachable URL.
	h4 := &WebhookAlertHandler{URL: "http://127.0.0.1:1", Timeout: 100 * time.Millisecond}
	if err := h4.Deliver(alert); err == nil {
		t.Error("expected error for unreachable URL")
	}

	// Default timeout (0 → 10s).
	h5 := &WebhookAlertHandler{URL: srv.URL}
	if err := h5.Deliver(alert); err != nil {
		t.Errorf("Deliver with default timeout failed: %v", err)
	}
}

func TestPhase1c_MultiAlertHandler(t *testing.T) {
	ch1 := make(chan PostureAlert, 1)
	ch2 := make(chan PostureAlert, 1)
	h1 := NewChannelAlertHandler(ch1)
	h2 := NewChannelAlertHandler(ch2)

	multi := NewMultiAlertHandler(h1, h2)
	alert := PostureAlert{Type: AlertNewGaps, Message: "multi"}
	if err := multi.Deliver(alert); err != nil {
		t.Errorf("MultiAlertHandler.Deliver failed: %v", err)
	}
	if len(ch1) != 1 || len(ch2) != 1 {
		t.Error("not all handlers received the alert")
	}

	// One handler fails (full channel), other succeeds.
	fullCh := make(chan PostureAlert, 0)
	fullH := NewChannelAlertHandler(fullCh)
	okCh := make(chan PostureAlert, 1)
	okH := NewChannelAlertHandler(okCh)
	multi2 := NewMultiAlertHandler(fullH, okH)
	if err := multi2.Deliver(alert); err == nil {
		t.Error("expected error from full channel handler")
	}
	if len(okCh) != 1 {
		t.Error("second handler should still receive alert")
	}
}

func TestPhase1c_DefaultSchedulerConfig(t *testing.T) {
	cfg := DefaultSchedulerConfig()
	if cfg.Interval != 24*time.Hour {
		t.Errorf("Interval = %v, want 24h", cfg.Interval)
	}
	if cfg.MinScore != 0.80 {
		t.Errorf("MinScore = %v, want 0.80", cfg.MinScore)
	}
	if !cfg.AlertOnRegression {
		t.Error("AlertOnRegression should be true")
	}
	if !cfg.AlertOnNewGaps {
		t.Error("AlertOnNewGaps should be true")
	}
	if cfg.AlertOnComplete {
		t.Error("AlertOnComplete should be false")
	}
	if cfg.RunnerConfig == nil {
		t.Error("RunnerConfig should not be nil")
	}
	if cfg.AlertHandler == nil {
		t.Error("AlertHandler should not be nil")
	}
}

func TestPhase1c_NewScheduler_Defaults(t *testing.T) {
	// Zero-value config should get defaults applied.
	s := NewScheduler(SchedulerConfig{})
	if s.cfg.Interval != 24*time.Hour {
		t.Errorf("Interval = %v, want 24h", s.cfg.Interval)
	}
	if s.cfg.MinScore != 0.80 {
		t.Errorf("MinScore = %v, want 0.80", s.cfg.MinScore)
	}
	if s.cfg.RunnerConfig == nil {
		t.Error("RunnerConfig should be defaulted")
	}
	if s.cfg.AlertHandler == nil {
		t.Error("AlertHandler should be defaulted")
	}
}

// =========================================================================
// runner.go gaps
// =========================================================================

func TestPhase1c_NewRunner_NilConfig(t *testing.T) {
	r, err := NewRunner(nil)
	if err != nil {
		t.Fatalf("NewRunner(nil) failed: %v", err)
	}
	if r == nil {
		t.Fatal("runner should not be nil")
	}
}

func TestPhase1c_Runner_Accessors(t *testing.T) {
	r, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}

	// Before running: Latest nil, Get nil, History empty.
	if r.Latest() != nil {
		t.Error("Latest() should be nil before Run()")
	}
	if r.Get("nonexistent") != nil {
		t.Error("Get() should return nil for unknown ID")
	}
	if hist := r.History(0, 10); len(hist) != 0 {
		t.Errorf("History() should be empty, got %d", len(hist))
	}

	// Run an assessment.
	result, err := r.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// After running: Latest should return the result.
	if r.Latest() == nil {
		t.Error("Latest() should not be nil after Run()")
	}
	if r.Latest().ID != result.ID {
		t.Errorf("Latest().ID = %q, want %q", r.Latest().ID, result.ID)
	}
	if r.Get(result.ID) == nil {
		t.Error("Get() should return the result by ID")
	}
	if hist := r.History(0, 10); len(hist) != 1 {
		t.Errorf("History() should have 1 result, got %d", len(hist))
	}
}

// =========================================================================
// assessment_http.go gaps — not-found and no-store error paths
// =========================================================================

func TestPhase1c_HTTP_NotFoundPaths(t *testing.T) {
	store := NewAssessmentStore()
	handler := NewAssessmentHTTPHandler(store, nil)
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()

	endpoints := []string{
		"/current/radar",
		"/current/gaps",
		"/current/compliance",
		"/current/pdf",
		"/current/signed",
	}
	for _, ep := range endpoints {
		resp, err := http.Get(srv.URL + ep)
		if err != nil {
			t.Fatalf("GET %s failed: %v", ep, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", ep, resp.StatusCode)
		}
	}
}

func TestPhase1c_HTTP_NoStorePaths(t *testing.T) {
	// nil store → history and trend should return 503.
	handler := NewAssessmentHTTPHandler(nil, nil)
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()

	for _, ep := range []string{"/history", "/trend"} {
		resp, err := http.Get(srv.URL + ep)
		if err != nil {
			t.Fatalf("GET %s failed: %v", ep, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s: expected 503, got %d", ep, resp.StatusCode)
		}
	}
}

func TestPhase1c_HTTP_RunMethodNotAllowed(t *testing.T) {
	store := NewAssessmentStore()
	handler := NewAssessmentHTTPHandler(store, nil)
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/run")
	if err != nil {
		t.Fatalf("GET /run failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// =========================================================================
// signed_report.go gaps — Verify error paths
// =========================================================================

func TestPhase1c_SignReport_EmptyBytes(t *testing.T) {
	result := &AssessmentResult{ID: "test"}
	_, err := SignReport(result, nil, ReportFormatJSON, SignReportConfig{})
	if err == nil {
		t.Error("expected error for empty report bytes")
	}
}

func TestPhase1c_Verify_NilEnvelope(t *testing.T) {
	var s *SignedAssessmentReport
	if err := s.Verify(); err == nil {
		t.Error("expected error for nil envelope")
	}
}

func TestPhase1c_Verify_WrongAlgorithm(t *testing.T) {
	s := &SignedAssessmentReport{Algorithm: "RSA"}
	if err := s.Verify(); err == nil {
		t.Error("expected error for wrong algorithm")
	}
}

func TestPhase1c_Verify_BadBase64Report(t *testing.T) {
	s := &SignedAssessmentReport{
		Algorithm:    "Ed25519",
		ReportBase64: "!!!not-base64!!!",
	}
	if err := s.Verify(); err == nil {
		t.Error("expected error for bad base64 report")
	}
}

func TestPhase1c_Verify_BadBase64Signature(t *testing.T) {
	s := &SignedAssessmentReport{
		Algorithm:       "Ed25519",
		ReportBase64:    "dGVzdA==",
		SignatureBase64: "!!!not-base64!!!",
	}
	if err := s.Verify(); err == nil {
		t.Error("expected error for bad base64 signature")
	}
}

func TestPhase1c_Verify_BadBase64PublicKey(t *testing.T) {
	s := &SignedAssessmentReport{
		Algorithm:       "Ed25519",
		ReportBase64:    "dGVzdA==",
		SignatureBase64: "dGVzdA==",
		PublicKeyBase64: "!!!not-base64!!!",
	}
	if err := s.Verify(); err == nil {
		t.Error("expected error for bad base64 public key")
	}
}

func TestPhase1c_Verify_InvalidPublicKeySize(t *testing.T) {
	s := &SignedAssessmentReport{
		Algorithm:       "Ed25519",
		ReportBase64:    "dGVzdA==",
		SignatureBase64: "dGVzdA==",
		PublicKeyBase64: "dGVzdA==", // 4 bytes, not 32
	}
	if err := s.Verify(); err == nil {
		t.Error("expected error for invalid public key size")
	}
}

func TestPhase1c_Verify_InvalidSignatureSize(t *testing.T) {
	// Encode a valid 32-byte public key.
	pubKey := make([]byte, 32)
	s := &SignedAssessmentReport{
		Algorithm:       "Ed25519",
		ReportBase64:    "dGVzdA==",
		SignatureBase64: "dGVzdA==", // 4 bytes, not 64
		PublicKeyBase64: jsonEncodeBase64(pubKey),
	}
	if err := s.Verify(); err == nil {
		t.Error("expected error for invalid signature size")
	}
}

func TestPhase1c_SignedReportFromJSON_Error(t *testing.T) {
	_, err := SignedReportFromJSON([]byte("!!!invalid json!!!"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// =========================================================================
// ioc_feedback.go gaps — regexSuggestion and responseSuggestion branches
// =========================================================================

func TestPhase1c_RegexSuggestion_Branches(t *testing.T) {
	tests := []struct {
		name       string
		owasp      string
		srName     string
		wantSubstr string
	}{
		{"LLM01_nonenglish", "LLM01", "non-english prompt injection", "CJK"},
		{"LLM01_base64", "LLM01", "base64 encoded injection", "base64"},
		{"LLM01_homoglyph", "LLM01", "homoglyph unicode attack", "homoglyph"},
		{"LLM01_default", "LLM01", "generic injection", "prompt injection variant"},
		{"LLM02", "LLM02", "sensitive data", "sensitive data"},
		{"LLM03_eval", "LLM03", "eval with user input", "dangerous function"},
		{"LLM03_tool", "LLM03", "malicious tool description", "dangerous tool"},
		{"LLM03_default", "LLM03", "generic supply chain", "supply chain"},
		{"LLM04_embed", "LLM04", "embedding manipulation", "RAG poisoning"},
		{"LLM04_training", "LLM04", "training data injection", "training data"},
		{"LLM04_default", "LLM04", "generic poisoning", "data and model"},
		{"LLM05", "LLM05", "response threat", "response content threat"},
		{"LLM06_privilege", "LLM06", "privilege escalation admin", "privilege escalation"},
		{"LLM06_default", "LLM06", "generic agency", "excessive agency"},
		{"LLM07", "LLM07", "system prompt extraction", "system prompt"},
		{"LLM08_retrieval", "LLM08", "RAG retrieval context override", "RAG retrieval"},
		{"LLM08_default", "LLM08", "generic vector store", "vector store"},
		{"LLM09", "LLM09", "hallucination gap", "hallucination"},
		{"LLM10_overflow", "LLM10", "token overflow attack", "unbounded token"},
		{"LLM10_default", "LLM10", "generic resource exhaustion", "resource exhaustion"},
		{"unknown", "UNKNOWN", "unknown owasp", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sr := ScenarioResult{Name: tc.srName, OWASP: tc.owasp}
			suggestion, _ := regexSuggestion(sr)
			if tc.wantSubstr != "" && !contains(suggestion, tc.wantSubstr) {
				t.Errorf("regexSuggestion: expected to contain %q, got %q", tc.wantSubstr, suggestion)
			}
		})
	}
}

func TestPhase1c_ResponseSuggestion_Branches(t *testing.T) {
	tests := []struct {
		name       string
		owasp      string
		srName     string
		wantSubstr string
	}{
		{"LLM05_apikey", "LLM05", "api key leak", "sk-"},
		{"LLM05_dangerous", "LLM05", "dangerous import", "dangerous import"},
		{"LLM05_default", "LLM05", "generic response gap", "response content"},
		{"LLM09_hallucination", "LLM09", "hallucination fabricated source", "fabricated"},
		{"LLM09_toxic", "LLM09", "toxic harmful content", "toxicity"},
		{"LLM09_default", "LLM09", "generic guard gap", "response guard"},
		{"unknown", "UNKNOWN", "unknown owasp", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sr := ScenarioResult{Name: tc.srName, OWASP: tc.owasp}
			suggestion, _ := responseSuggestion(sr)
			if tc.wantSubstr != "" && !contains(suggestion, tc.wantSubstr) {
				t.Errorf("responseSuggestion: expected to contain %q, got %q", tc.wantSubstr, suggestion)
			}
		})
	}
}

func TestPhase1c_ValidationReport_String(t *testing.T) {
	vr := ValidationReport{Summary: "test summary"}
	if vr.String() != "test summary" {
		t.Errorf("String() = %q, want %q", vr.String(), "test summary")
	}
}

func TestPhase1c_GapAnalysisReport_Summary(t *testing.T) {
	r := &GapAnalysisReport{
		AssessmentID:  "test-001",
		TotalGaps:     3,
		IOCsRecorded:  2,
		FederatedGaps: 1,
		PerOWASP:      map[string]int{"LLM01": 2, "LLM05": 1},
		Recommendations: []PatternRecommendation{
			{Priority: "high", Suggestion: "Add pattern X", FixType: "regex",
				TargetLayer: "scanner", AffectedScenarios: []string{"s1"}},
		},
	}
	s := r.Summary()
	if !contains(s, "test-001") {
		t.Error("Summary should contain assessment ID")
	}
	if !contains(s, "Total gaps: 3") {
		t.Error("Summary should contain total gaps")
	}
	if !contains(s, "LLM01: 2 gap(s)") {
		t.Error("Summary should contain OWASP breakdown")
	}
	if !contains(s, "Add pattern X") {
		t.Error("Summary should contain recommendation text")
	}
}

// =========================================================================
// Helpers
// =========================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func jsonEncodeBase64(data []byte) string {
	// Use encoding/base64 directly via json round-trip to avoid import
	b, _ := json.Marshal(data)
	// json.Marshal on []byte returns a base64 string (quoted)
	var s string
	json.Unmarshal(b, &s)
	return s
}
