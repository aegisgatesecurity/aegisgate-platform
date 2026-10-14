// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := &Config{
		Port:               19091, // test port
		APIKey:             "test-api-key-12345",
		EventRetentionDays: 90,
		StorePath:          tmpDir,
		RateLimitPerMin:    10000,
		PatternsVersion:    "v1",
	}
	s, err := NewServer(cfg, "test")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthz: got %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status: got %q, want %q", body["status"], "ok")
	}
}

func TestAuthMiddleware(t *testing.T) {
	s := newTestServer(t)
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No auth header
	req := httptest.NewRequest("POST", "/api/v1/telemetry", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no auth: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Wrong key
	req = httptest.NewRequest("POST", "/api/v1/telemetry", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Correct key
	req = httptest.NewRequest("POST", "/api/v1/telemetry", nil)
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("correct key: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTelemetryAccept(t *testing.T) {
	s := newTestServer(t)

	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:              "evt-001",
				Source:          contracts.SourceScanner,
				SourceVersion:   "v0.3.0",
				SchemaVersion:   "v1",
				Timestamp:       mustParseTime("2026-10-14T15:30:00Z"),
				Direction:       contracts.DirectionScan,
				TotalDetections: 3,
				Blocked:         false,
				Action:          "logged",
				Artifact:        "src/handlers/secret.py",
				Categories:      []string{"secrets", "pii-us-core"},
				Severities:      []string{"critical", "high"},
				Rules:           []string{"secret_aws_key", "pii_ssn"},
			},
		},
	}

	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("telemetry: got %d, want %d. Body: %s", w.Code, http.StatusAccepted, w.Body.String())
	}

	var ack contracts.EventAcknowledgment
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Accepted != 1 {
		t.Errorf("accepted: got %d, want 1", ack.Accepted)
	}
	if ack.Rejected != 0 {
		t.Errorf("rejected: got %d, want 0", ack.Rejected)
	}
}

func TestTelemetryRejectBadSchemaVersion(t *testing.T) {
	s := newTestServer(t)

	batch := contracts.EventBatch{
		SchemaVersion: "v99", // unsupported
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:              "evt-bad",
				Source:          contracts.SourceScanner,
				SchemaVersion:   "v1",
				TotalDetections: 1,
			},
		},
	}

	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad schema: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTelemetryRejectEmptyBatch(t *testing.T) {
	s := newTestServer(t)

	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events:        []contracts.Event{},
	}

	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handleTelemetry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty batch: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestPatternPull(t *testing.T) {
	s := newTestServer(t)

	// Update patterns
	s.UpdatePatterns([]contracts.Pattern{
		{
			ID:       "secret_aws_key",
			Name:     "secret_aws_key",
			Regex:    `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
			Severity: contracts.SeverityCritical,
			Category: contracts.CategorySecrets,
			Version:  "v1",
		},
	})

	req := httptest.NewRequest("GET", "/api/v1/patterns/latest", nil)
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handlePatternPull(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("pattern pull: got %d, want %d", w.Code, http.StatusOK)
	}

	var resp contracts.PatternSetResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.APIVersion != "v1" {
		t.Errorf("api_version: got %q, want %q", resp.APIVersion, "v1")
	}
	if len(resp.PatternSet.Patterns) != 1 {
		t.Errorf("patterns: got %d, want 1", len(resp.PatternSet.Patterns))
	}
	if resp.PatternSet.Patterns[0].ID != "secret_aws_key" {
		t.Errorf("pattern id: got %q", resp.PatternSet.Patterns[0].ID)
	}
}

func TestPatternPullNotModified(t *testing.T) {
	s := newTestServer(t)
	s.UpdatePatterns([]contracts.Pattern{
		{ID: "test", Name: "test", Regex: "test", Severity: "low", Category: "secrets", Version: "v1"},
	})

	// First request to get the updated_at
	req := httptest.NewRequest("GET", "/api/v1/patterns/latest", nil)
	req.Header.Set("Authorization", "Bearer test-api-key-12345")
	w := httptest.NewRecorder()
	s.handlePatternPull(w, req)

	var resp contracts.PatternSetResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Second request with If-Modified-Since matching
	req2 := httptest.NewRequest("GET", "/api/v1/patterns/latest", nil)
	req2.Header.Set("Authorization", "Bearer test-api-key-12345")
	req2.Header.Set("If-Modified-Since", resp.UpdatedAt)
	w2 := httptest.NewRecorder()
	s.handlePatternPull(w2, req2)

	if w2.Code != http.StatusNotModified {
		t.Errorf("not modified: got %d, want %d", w2.Code, http.StatusNotModified)
	}
}

func TestEventStore(t *testing.T) {
	s := newTestServer(t)

	e := contracts.Event{
		ID:              "evt-store-test",
		Source:          contracts.SourceRampart,
		SchemaVersion:   "v1",
		Timestamp:       mustParseTime("2026-10-14T15:30:00Z"),
		TotalDetections: 1,
		Blocked:         true,
	}

	if err := s.appendEvent(e); err != nil {
		t.Fatalf("appendEvent: %v", err)
	}

	// Verify file exists and contains the event
	data, err := os.ReadFile(s.storePath + "/events.jsonl")
	if err != nil {
		t.Fatalf("read store: %v", err)
	}

	var stored contracts.Event
	if err := json.Unmarshal(data[:len(data)-1], &stored); err != nil {
		t.Fatalf("unmarshal stored: %v", err)
	}
	if stored.ID != e.ID {
		t.Errorf("stored ID: got %q, want %q", stored.ID, e.ID)
	}
}

func TestValidateEvent(t *testing.T) {
	s := newTestServer(t)

	tests := []struct {
		name    string
		event   contracts.Event
		wantErr bool
	}{
		{
			name: "valid event",
			event: contracts.Event{
				ID:              "evt-1",
				Source:          contracts.SourceLens,
				SchemaVersion:   "v1",
				Timestamp:       mustParseTime("2026-10-14T15:30:00Z"),
				TotalDetections: 1,
			},
			wantErr: false,
		},
		{
			name: "missing id",
			event: contracts.Event{
				Source:        contracts.SourceLens,
				SchemaVersion: "v1",
				Timestamp:     mustParseTime("2026-10-14T15:30:00Z"),
			},
			wantErr: true,
		},
		{
			name: "missing source",
			event: contracts.Event{
				ID:            "evt-2",
				SchemaVersion: "v1",
				Timestamp:     mustParseTime("2026-10-14T15:30:00Z"),
			},
			wantErr: true,
		},
		{
			name: "bad schema version",
			event: contracts.Event{
				ID:            "evt-3",
				Source:        contracts.SourceLens,
				SchemaVersion: "v99",
				Timestamp:     mustParseTime("2026-10-14T15:30:00Z"),
			},
			wantErr: true,
		},
		{
			name: "unknown source",
			event: contracts.Event{
				ID:            "evt-4",
				Source:        contracts.EventSource("unknown"),
				SchemaVersion: "v1",
				Timestamp:     mustParseTime("2026-10-14T15:30:00Z"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateEvent(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEvent(): err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func mustParseTime(s string) (t time.Time) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return
}

func TestLoadConfig(t *testing.T) {
	// Test with no env vars — should return defaults.
	os.Unsetenv("TELEMETRY_PORT")
	os.Unsetenv("TELEMETRY_TLS_CERT")
	os.Unsetenv("TELEMETRY_TLS_KEY")
	os.Unsetenv("TELEMETRY_API_KEY")
	os.Unsetenv("TELEMETRY_EVENT_RETENTION_DAYS")
	os.Unsetenv("TELEMETRY_STORE_PATH")
	os.Unsetenv("TELEMETRY_RATE_LIMIT_PER_MIN")
	os.Unsetenv("TELEMETRY_PATTERNS_VERSION")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Port != 9091 {
		t.Errorf("LoadConfig(): Port = %d, want 9091", cfg.Port)
	}
	if cfg.EventRetentionDays != 90 {
		t.Errorf("LoadConfig(): EventRetentionDays = %d, want 90", cfg.EventRetentionDays)
	}
	if cfg.StorePath != "/var/lib/aegisgate/telemetry" {
		t.Errorf("LoadConfig(): StorePath = %q, want default", cfg.StorePath)
	}
	if cfg.RateLimitPerMin != 10000 {
		t.Errorf("LoadConfig(): RateLimitPerMin = %d, want 10000", cfg.RateLimitPerMin)
	}
	if cfg.PatternsVersion != "v1" {
		t.Errorf("LoadConfig(): PatternsVersion = %q, want v1", cfg.PatternsVersion)
	}

	// Test with env vars.
	t.Setenv("TELEMETRY_PORT", "8080")
	t.Setenv("TELEMETRY_API_KEY", "secret123")
	t.Setenv("TELEMETRY_EVENT_RETENTION_DAYS", "30")
	t.Setenv("TELEMETRY_PATTERNS_VERSION", "v2")
	t.Setenv("TELEMETRY_RATE_LIMIT_PER_MIN", "5000")
	t.Setenv("TELEMETRY_STORE_PATH", "/tmp/telemetry")

	cfg2, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() with env: error: %v", err)
	}
	if cfg2.Port != 8080 {
		t.Errorf("LoadConfig() with env: Port = %d, want 8080", cfg2.Port)
	}
	if cfg2.APIKey != "secret123" {
		t.Errorf("LoadConfig() with env: APIKey = %q, want secret123", cfg2.APIKey)
	}
	if cfg2.EventRetentionDays != 30 {
		t.Errorf("LoadConfig() with env: EventRetentionDays = %d, want 30", cfg2.EventRetentionDays)
	}
	if cfg2.PatternsVersion != "v2" {
		t.Errorf("LoadConfig() with env: PatternsVersion = %q, want v2", cfg2.PatternsVersion)
	}
	if cfg2.RateLimitPerMin != 5000 {
		t.Errorf("LoadConfig() with env: RateLimitPerMin = %d, want 5000", cfg2.RateLimitPerMin)
	}
	if cfg2.StorePath != "/tmp/telemetry" {
		t.Errorf("LoadConfig() with env: StorePath = %q, want /tmp/telemetry", cfg2.StorePath)
	}
}

func TestGetenvIntInvalid(t *testing.T) {
	t.Setenv("TEST_TELEMETRY_BAD_INT", "not-a-number")
	got := getenvInt("TEST_TELEMETRY_BAD_INT", 42)
	if got != 42 {
		t.Errorf("getenvInt with invalid value: got %d, want default 42", got)
	}
}

func TestGetenvStr(t *testing.T) {
	t.Setenv("TEST_TELEMETRY_STR", "custom-value")
	got := getenvStr("TEST_TELEMETRY_STR", "default")
	if got != "custom-value" {
		t.Errorf("getenvStr: got %q, want custom-value", got)
	}

	got = getenvStr("TEST_TELEMETRY_NONEXISTENT", "fallback")
	if got != "fallback" {
		t.Errorf("getenvStr missing: got %q, want fallback", got)
	}
}

func TestGetTotalBlocks(t *testing.T) {
	router := NewEventRouter(nil)
	router.Route(contracts.Event{
		ID:            "e1",
		Source:        "test",
		SchemaVersion: "v1",
		Timestamp:     time.Now(),
		Blocked:       true,
	})
	router.Route(contracts.Event{
		ID:            "e2",
		Source:        "test",
		SchemaVersion: "v1",
		Timestamp:     time.Now(),
		Blocked:       false,
	})
	router.Route(contracts.Event{
		ID:            "e3",
		Source:        "test",
		SchemaVersion: "v1",
		Timestamp:     time.Now(),
		Blocked:       true,
	})
	if got := router.GetTotalBlocks(); got != 2 {
		t.Errorf("GetTotalBlocks() = %d, want 2", got)
	}
}

func TestServerMux(t *testing.T) {
	srv, err := NewServer(&Config{
		Port:               9091,
		EventRetentionDays: 90,
		StorePath:          t.TempDir(),
	}, "test")
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	mux := srv.Mux()
	if mux == nil {
		t.Fatal("Mux() returned nil")
	}
}

func TestHandleStats(t *testing.T) {
	srv, err := NewServer(&Config{Port: 9091, EventRetentionDays: 90, StorePath: t.TempDir()}, "test")
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	// Route an event so stats are non-empty.
	srv.router.Route(contracts.Event{
		ID:            "e1",
		Source:        "test",
		SchemaVersion: "v1",
		Timestamp:     time.Now(),
		Blocked:       true,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	srv.handleStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleStats: status = %d, want 200", rec.Code)
	}

	var summary map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("handleStats: failed to decode response: %v", err)
	}
	if summary["total_events"] == nil {
		t.Error("handleStats: response missing total_events")
	}
}

func TestLoadDefaultPatterns(t *testing.T) {
	srv, err := NewServer(&Config{Port: 9091, EventRetentionDays: 90, StorePath: t.TempDir()}, "test")
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	// Should not panic and should populate patterns.
	srv.LoadDefaultPatterns()

	// Verify patterns were loaded by checking the patterns endpoint.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/patterns/latest", nil)
	srv.handlePatternPull(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handlePatternPull after LoadDefaultPatterns: status = %d, want 200", rec.Code)
	}
}
