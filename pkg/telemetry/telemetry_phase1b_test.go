// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Telemetry Phase 1b Unit Tests
//
// Targets uncovered code paths in config.go, patterns.go, routing.go, and server.go
// to push package coverage from 84.3% to 90%+.

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// =============================================================================
// Validate (config.go:102) — test all error paths
// =============================================================================

func TestPhase1bValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"too high", 65536},
		{"very negative", -9999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Port:               tt.port,
				EventRetentionDays: 90,
				StorePath:          t.TempDir(),
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error for port %d, got nil", tt.port)
			}
			if !strings.Contains(err.Error(), "invalid port") {
				t.Errorf("expected 'invalid port' error, got %q", err.Error())
			}
		})
	}
}

func TestPhase1bValidate_InvalidRetentionDays(t *testing.T) {
	tests := []struct {
		name string
		days int
	}{
		{"zero", 0},
		{"negative", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Port:               9091,
				EventRetentionDays: tt.days,
				StorePath:          t.TempDir(),
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error for retention days %d, got nil", tt.days)
			}
			if !strings.Contains(err.Error(), "invalid retention days") {
				t.Errorf("expected 'invalid retention days' error, got %q", err.Error())
			}
		})
	}
}

func TestPhase1bValidate_TLSMismatch(t *testing.T) {
	tests := []struct {
		name string
		cert string
		key  string
	}{
		{"cert set, key empty", "/path/to/cert.pem", ""},
		{"key set, cert empty", "", "/path/to/key.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Port:               9091,
				EventRetentionDays: 90,
				StorePath:          t.TempDir(),
				TLSCert:            tt.cert,
				TLSKey:             tt.key,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected TLS mismatch error, got nil")
			}
			if !strings.Contains(err.Error(), "TLS cert and key") {
				t.Errorf("expected TLS mismatch error, got %q", err.Error())
			}
		})
	}
}

func TestPhase1bValidate_ValidConfig(t *testing.T) {
	cfg := &Config{
		Port:               9091,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil error for valid config, got %v", err)
	}

	// Valid with both TLS set
	cfg.TLSCert = "/path/to/cert.pem"
	cfg.TLSKey = "/path/to/key.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil error for valid TLS config, got %v", err)
	}

	// Valid with boundary port values
	cfg.TLSCert = ""
	cfg.TLSKey = ""
	cfg.Port = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil error for port=1, got %v", err)
	}
	cfg.Port = 65535
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil error for port=65535, got %v", err)
	}

	// Valid with retention days = 1
	cfg.Port = 9091
	cfg.EventRetentionDays = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil error for retention=1, got %v", err)
	}
}

// =============================================================================
// severityToString (patterns.go:52) — test unknown severity
// =============================================================================

func TestPhase1bSeverityToString_Unknown(t *testing.T) {
	// Pass a severity value not in the defined constants
	result := severityToString(scanner.Severity(999))
	if result != "medium" {
		t.Errorf("expected 'medium' for unknown severity, got %q", result)
	}

	// Negative severity should also default to medium
	result = severityToString(scanner.Severity(-1))
	if result != "medium" {
		t.Errorf("expected 'medium' for negative severity, got %q", result)
	}
}

// =============================================================================
// LoadPlatformPatterns (patterns.go:28) — verify all patterns have valid fields
// =============================================================================

func TestPhase1bLoadPlatformPatterns_AllFieldsValid(t *testing.T) {
	patterns := LoadPlatformPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected non-empty patterns")
	}

	for i, p := range patterns {
		if p.ID == "" {
			t.Errorf("pattern[%d]: empty ID", i)
		}

		if p.Regex == "" {
			t.Errorf("pattern[%d] %q: empty Regex", i, p.ID)
		}
		if p.Severity == "" {
			t.Errorf("pattern[%d] %q: empty Severity", i, p.ID)
		}
		// Category should be lowercase
		if p.Category != "" && strings.ToLower(string(p.Category)) != string(p.Category) {
			t.Errorf("pattern[%d] %q: category not lowercase: %q", i, p.ID, p.Category)
		}
	}
}

// =============================================================================
// GetAllStats (routing.go:169) — test empty and non-empty paths
// =============================================================================

func TestPhase1bGetAllStats_Empty(t *testing.T) {
	router := NewEventRouter(nil)
	stats := router.GetAllStats()
	if stats == nil {
		t.Fatal("expected non-nil map for empty stats")
	}
	if len(stats) != 0 {
		t.Errorf("expected 0 sources in empty stats, got %d", len(stats))
	}
}

func TestPhase1bGetAllStats_NonEmpty(t *testing.T) {
	router := NewEventRouter(nil)

	// Route events from multiple sources
	for _, src := range []contracts.EventSource{
		contracts.SourceLens,
		contracts.SourceRampart,
		contracts.SourceScanner,
	} {
		e := contracts.Event{
			ID:            "evt-" + string(src),
			Source:        src,
			SchemaVersion: "v1",
			Timestamp:     time.Now().UTC(),
			Categories:    []string{"secrets"},
			Severities:    []string{"high"},
			Rules:         []string{"rule_a"},
		}
		if err := router.Route(e); err != nil {
			t.Fatalf("Route failed: %v", err)
		}
	}

	stats := router.GetAllStats()
	if len(stats) != 3 {
		t.Errorf("expected 3 sources, got %d", len(stats))
	}

	// Verify each source has correct data
	for src, s := range stats {
		if s.Events != 1 {
			t.Errorf("source %s: expected 1 event, got %d", src, s.Events)
		}
		if s.Categories["secrets"] != 1 {
			t.Errorf("source %s: expected secrets=1, got %d", src, s.Categories["secrets"])
		}
		if s.Severities["high"] != 1 {
			t.Errorf("source %s: expected high=1, got %d", src, s.Severities["high"])
		}
		if s.Rules["rule_a"] != 1 {
			t.Errorf("source %s: expected rule_a=1, got %d", src, s.Rules["rule_a"])
		}
		// Verify it's a copy (modifying should not affect router)
		s.Events = 999
		orig := router.GetSourceStats(src)
		if orig.Events != 1 {
			t.Errorf("source %s: GetAllStats did not return a copy, original changed to %d", src, orig.Events)
		}
	}
}

// =============================================================================
// GetSummary (routing.go:285) — test edge cases: empty, >10 rules (truncation)
// =============================================================================

func TestPhase1bGetSummary_Empty(t *testing.T) {
	router := NewEventRouter(nil)
	summary := router.GetSummary()

	totalEvents, ok := summary["total_events"].(int64)
	if !ok || totalEvents != 0 {
		t.Errorf("expected total_events=0, got %v", summary["total_events"])
	}

	bySource, ok := summary["by_source"].(map[string]interface{})
	if !ok {
		t.Fatal("expected by_source map")
	}
	if len(bySource) != 0 {
		t.Errorf("expected empty by_source, got %d entries", len(bySource))
	}
}

func TestPhase1bGetSummary_TopRulesTruncation(t *testing.T) {
	router := NewEventRouter(nil)

	// Create an event with 15 rules to test the top-10 truncation
	rules := make([]string, 15)
	for i := 0; i < 15; i++ {
		rules[i] = fmt.Sprintf("rule_%02d", i)
	}

	e := contracts.Event{
		ID:            "evt-trunc",
		Source:        contracts.SourceScanner,
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
		Rules:         rules,
	}
	if err := router.Route(e); err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	summary := router.GetSummary()
	bySource, ok := summary["by_source"].(map[string]interface{})
	if !ok {
		t.Fatal("expected by_source map")
	}

	scannerStats, ok := bySource["scanner"].(map[string]interface{})
	if !ok {
		t.Fatal("expected scanner entry")
	}

	topRules, ok := scannerStats["top_rules"].([]ruleCount)
	if !ok {
		t.Fatalf("expected top_rules to be []ruleCount, got %T", scannerStats["top_rules"])
	}

	if len(topRules) != 10 {
		t.Errorf("expected top_rules truncated to 10, got %d", len(topRules))
	}

	// Verify sorting: first entry should have highest count (all have count 1, but verify sorted)
	for i := 0; i < len(topRules); i++ {
		if topRules[i].Count != 1 {
			t.Errorf("rule[%d] %q: expected count=1, got %d", i, topRules[i].Rule, topRules[i].Count)
		}
	}
}

func TestPhase1bGetSummary_MultipleSourcesWithRules(t *testing.T) {
	router := NewEventRouter(nil)

	// Route from two sources with rules
	e1 := contracts.Event{
		ID:            "e1",
		Source:        contracts.SourceLens,
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
		Rules:         []string{"rule_a", "rule_b"},
	}
	e2 := contracts.Event{
		ID:            "e2",
		Source:        contracts.SourceRampart,
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
		Rules:         []string{"rule_c"},
	}
	router.Route(e1)
	router.Route(e2)

	summary := router.GetSummary()

	totalDetections, ok := summary["total_detections"].(int64)
	if !ok {
		t.Fatalf("expected total_detections to be int64, got %T", summary["total_detections"])
	}
	if totalDetections != 0 {
		t.Errorf("expected total_detections=0 (no detections set), got %d", totalDetections)
	}

	bySource := summary["by_source"].(map[string]interface{})
	if len(bySource) != 2 {
		t.Errorf("expected 2 sources, got %d", len(bySource))
	}

	lensStats := bySource["lens"].(map[string]interface{})
	topRules := lensStats["top_rules"].([]ruleCount)
	if len(topRules) != 2 {
		t.Errorf("expected 2 top rules for lens, got %d", len(topRules))
	}
}

// =============================================================================
// NewServer (server.go:55) — test nil config, invalid config, bad store path
// =============================================================================

func TestPhase1bNewServer_NilConfig(t *testing.T) {
	s, err := NewServer(nil, "test")
	if err == nil {
		if s != nil {
			s = nil
		}
		t.Fatal("expected error for nil config, got nil")
	}
	if !strings.Contains(err.Error(), "config must be non-nil") {
		t.Errorf("expected 'config must be non-nil' error, got %q", err.Error())
	}
	if s != nil {
		t.Error("expected nil server for nil config")
	}
}

func TestPhase1bNewServer_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Port:               0, // invalid
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
	}
	s, err := NewServer(cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid config (port=0), got nil")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected 'invalid config' error, got %q", err.Error())
	}
	if s != nil {
		t.Error("expected nil server for invalid config")
	}
}

func TestPhase1bNewServer_BadStorePath(t *testing.T) {
	// Use a path under a non-existent parent that can't be created
	// (e.g., under /proc or a file path)
	cfg := &Config{
		Port:               9091,
		EventRetentionDays: 90,
		StorePath:          "/proc/cannot/create/this/path",
		RateLimitPerMin:    10000,
	}
	s, err := NewServer(cfg, "test")
	if err == nil {
		t.Fatal("expected error for bad store path, got nil")
	}
	if !strings.Contains(err.Error(), "create store path") {
		t.Errorf("expected 'create store path' error, got %q", err.Error())
	}
	if s != nil {
		t.Error("expected nil server for bad store path")
	}
}

func TestPhase1bNewServer_DefaultConfig(t *testing.T) {
	cfg := &Config{
		Port:               9091,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
	}
	s, err := NewServer(cfg, "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.version != "v1.0.0" {
		t.Errorf("expected version 'v1.0.0', got %q", s.version)
	}
	if s.cfg != cfg {
		t.Error("expected cfg to match input")
	}
	if s.router == nil {
		t.Error("expected non-nil router")
	}
	if s.httpServer != nil {
		t.Error("expected nil httpServer before ListenAndServe")
	}
}

// =============================================================================
// ListenAndServe (server.go:112) — test server lifecycle (start/stop)
// =============================================================================

func TestPhase1bListenAndServe_Lifecycle(t *testing.T) {
	// Get an ephemeral port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &Config{
		Port:               port,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
		APIKey:             "test-lifecycle-key",
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe(ctx)
	}()

	// Wait for server to be ready by polling healthz
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", port))
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		cancel()
		t.Fatalf("server did not become ready: %v", lastErr)
	}

	// Make a request to an authenticated endpoint with correct auth
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/v1/stats", port), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-lifecycle-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("stats: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Shut down the server
	cancel()

	// Wait for ListenAndServe to return (should return http.ErrServerClosed)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("ListenAndServe returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return after shutdown")
	}
}

func TestPhase1bListenAndServe_AuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &Config{
		Port:               port,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
		APIKey:             "secret-key-abc",
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s.ListenAndServe(ctx)

	// Wait for server ready
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 50; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", port))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Request without auth to authenticated endpoint
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/patterns/latest", port))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: got %d, want %d. Body: %s", resp.StatusCode, http.StatusUnauthorized, string(body))
	}

	cancel()
}

// =============================================================================
// handleTelemetry (server.go:142) — test invalid JSON, method via mux, auth failure
// =============================================================================

func TestPhase1bHandleTelemetry_InvalidJSON(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader([]byte("not json at all")))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want %d. Body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["error"] != "invalid JSON" {
		t.Errorf("expected 'invalid JSON' error, got %q", body["error"])
	}
}

func TestPhase1bHandleTelemetry_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)

	// Use the mux directly — Go 1.22+ method routing returns 405 for wrong method
	mux := s.Mux()
	req := httptest.NewRequest("GET", "/api/v1/telemetry", nil)
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on POST endpoint: got %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestPhase1bHandleTelemetry_AuthFailureViaMux(t *testing.T) {
	s := newTestServer(t)
	mux := s.Mux()

	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:            "evt-1",
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
		},
	}
	body, _ := json.Marshal(batch)

	// No auth header
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no auth via mux: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Wrong auth
	req = httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong auth via mux: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestPhase1bHandleTelemetry_RejectedEvent(t *testing.T) {
	s := newTestServer(t)

	// Event with missing ID — should be rejected but still return 202
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				// ID intentionally empty
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
		},
	}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("rejected event: got %d, want %d. Body: %s", w.Code, http.StatusAccepted, w.Body.String())
	}

	var ack contracts.EventAcknowledgment
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Accepted != 0 {
		t.Errorf("expected 0 accepted, got %d", ack.Accepted)
	}
	if ack.Rejected != 1 {
		t.Errorf("expected 1 rejected, got %d", ack.Rejected)
	}
	if len(ack.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(ack.Errors))
	}
	if ack.Errors[0].Reason == "" {
		t.Error("expected non-empty error reason")
	}
}

func TestPhase1bHandleTelemetry_MixedBatch(t *testing.T) {
	s := newTestServer(t)

	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:            "good-1",
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
			{
				// Missing ID — should be rejected
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
			{
				ID:            "good-2",
				Source:        contracts.SourceLens,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
		},
	}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("mixed batch: got %d, want %d. Body: %s", w.Code, http.StatusAccepted, w.Body.String())
	}

	var ack contracts.EventAcknowledgment
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Accepted != 2 {
		t.Errorf("expected 2 accepted, got %d", ack.Accepted)
	}
	if ack.Rejected != 1 {
		t.Errorf("expected 1 rejected, got %d", ack.Rejected)
	}
}

func TestPhase1bHandleTelemetry_EmptyAPIKey(t *testing.T) {
	// Server with no API key — auth middleware should return 503
	tmpDir := t.TempDir()
	cfg := &Config{
		Port:               19091,
		APIKey:             "", // no API key
		EventRetentionDays: 90,
		StorePath:          tmpDir,
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := s.Mux()
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:            "evt-1",
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
		},
	}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("empty API key: got %d, want %d. Body: %s", w.Code, http.StatusServiceUnavailable, w.Body.String())
	}
}

// =============================================================================
// appendEvent (server.go:314) — test edge cases (bad store path)
// =============================================================================

func TestPhase1bAppendEvent_BadStorePath(t *testing.T) {
	s := newTestServer(t)

	// Override storePath to a non-existent directory
	s.storePath = "/nonexistent/path/that/does/not/exist"

	e := contracts.Event{
		ID:            "evt-bad-path",
		Source:        contracts.SourceScanner,
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
	}

	err := s.appendEvent(e)
	if err == nil {
		t.Fatal("expected error for bad store path, got nil")
	}
}

func TestPhase1bAppendEvent_MarshalSuccess(t *testing.T) {
	s := newTestServer(t)

	e := contracts.Event{
		ID:              "evt-marshal",
		Source:          contracts.SourceLens,
		SchemaVersion:   "v1",
		Timestamp:       time.Now().UTC(),
		TotalDetections: 5,
		Blocked:         true,
		Findings: []contracts.EventFinding{
			{RuleID: "rule1", Severity: "high", Category: "secrets"},
		},
	}

	if err := s.appendEvent(e); err != nil {
		t.Fatalf("appendEvent failed: %v", err)
	}

	// Verify the file was created
	path := filepath.Join(s.storePath, "events.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty store file")
	}

	// Verify it ends with newline
	if data[len(data)-1] != '\n' {
		t.Error("expected trailing newline in store file")
	}

	// Verify the content is valid JSON
	var stored contracts.Event
	if err := json.Unmarshal(data[:len(data)-1], &stored); err != nil {
		t.Fatalf("unmarshal stored event: %v", err)
	}
	if stored.ID != e.ID {
		t.Errorf("stored ID: got %q, want %q", stored.ID, e.ID)
	}
}

func TestPhase1bAppendEvent_AppendMultiple(t *testing.T) {
	s := newTestServer(t)

	for i := 0; i < 5; i++ {
		e := contracts.Event{
			ID:            fmt.Sprintf("evt-%d", i),
			Source:        contracts.SourceScanner,
			SchemaVersion: "v1",
			Timestamp:     time.Now().UTC(),
		}
		if err := s.appendEvent(e); err != nil {
			t.Fatalf("appendEvent[%d] failed: %v", i, err)
		}
	}

	// Verify 5 lines in the file
	path := filepath.Join(s.storePath, "events.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 lines, got %d", len(lines))
	}
}

// =============================================================================
// authMiddleware (server.go:337) — test empty API key (503)
// =============================================================================

func TestPhase1bAuthMiddleware_EmptyAPIKey(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		Port:               9091,
		APIKey:             "", // no API key configured
		EventRetentionDays: 90,
		StorePath:          tmpDir,
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/telemetry", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("empty API key: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(body["error"], "not configured") {
		t.Errorf("expected 'not configured' in error, got %q", body["error"])
	}
}

func TestPhase1bAuthMiddleware_EmptyAPIKeyWithAuthHeader(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		Port:               9091,
		APIKey:             "",
		EventRetentionDays: 90,
		StorePath:          tmpDir,
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Even with an auth header, if API key is empty, should return 503
	req := httptest.NewRequest("POST", "/api/v1/telemetry", nil)
	req.Header.Set("Authorization", "Bearer some-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("empty API key with auth header: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// =============================================================================
// Route with store error (routing.go) — test store error path
// =============================================================================

func TestPhase1bRoute_StoreError(t *testing.T) {
	// Create an adapter that always returns an error
	adapter := NewEventStorerAdapter(func(e contracts.Event) error {
		return fmt.Errorf("storage is down")
	})

	router := NewEventRouter(adapter)

	e := contracts.Event{
		ID:            "evt-store-err",
		Source:        contracts.SourceScanner,
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
	}

	err := router.Route(e)
	if err == nil {
		t.Fatal("expected error from store failure, got nil")
	}
	if !strings.Contains(err.Error(), "persist event") {
		t.Errorf("expected 'persist event' error, got %q", err.Error())
	}
}

// =============================================================================
// handleTelemetry via real HTTP — test the full stack with ListenAndServe
// =============================================================================

func TestPhase1bHandleTelemetry_FullHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &Config{
		Port:               port,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
		APIKey:             "full-http-key",
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s.ListenAndServe(ctx)

	// Wait for server
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 50; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/healthz", port))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Send a valid telemetry event
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:            "evt-http-1",
				Source:        contracts.SourceScanner,
				SchemaVersion: "v1",
				Timestamp:     time.Now().UTC(),
			},
		},
	}
	body, _ := json.Marshal(batch)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/telemetry", port), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer full-http-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("telemetry POST: got %d, want %d. Body: %s", resp.StatusCode, http.StatusAccepted, string(respBody))
	}

	var ack contracts.EventAcknowledgment
	if err := json.Unmarshal(respBody, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Accepted != 1 {
		t.Errorf("expected 1 accepted, got %d", ack.Accepted)
	}

	// Send invalid JSON
	req2, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/telemetry", port), bytes.NewReader([]byte("invalid")))
	req2.Header.Set("Authorization", "Bearer full-http-key")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid JSON POST: got %d, want %d", resp2.StatusCode, http.StatusBadRequest)
	}
}
