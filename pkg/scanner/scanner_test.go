package scanner

import (
	"testing"
	"time"
)

func TestDefaultScannerConfig(t *testing.T) {
	cfg := DefaultScannerConfig()

	if cfg == nil {
		t.Fatal("DefaultScannerConfig returned nil")
	}
	if cfg.Address != "localhost:8080" {
		t.Errorf("Address = %v, want localhost:8080", cfg.Address)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
	if cfg.Debug {
		t.Error("Debug should be false by default")
	}
}

func TestNewScanner(t *testing.T) {
	cfg := DefaultAegisGuardMCPConfig()
	scanner := NewScanner(cfg)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if _, ok := scanner.(*AegisGuardMCPScanner); !ok {
		t.Error("NewScanner should return *AegisGuardMCPScanner")
	}
}

func TestNewScanner_WithNilConfig(t *testing.T) {
	scanner := NewScanner(nil)
	if scanner == nil {
		t.Fatal("NewScanner with nil config should return default scanner")
	}
}

func TestDefaultAegisGuardMCPConfig(t *testing.T) {
	cfg := DefaultAegisGuardMCPConfig()

	if cfg == nil {
		t.Fatal("DefaultAegisGuardMCPConfig returned nil")
	}
	if cfg.Address == "" {
		t.Error("Address should not be empty")
	}
	if cfg.Timeout == 0 {
		t.Error("Timeout should not be 0")
	}
}

func TestScanResult_Type(t *testing.T) {
	result := &ScanResult{
		ID:         "test-id",
		Type:       "api_key",
		Severity:   "high",
		Message:    "Found API key",
		Confidence: 0.95,
	}

	if result.ID != "test-id" {
		t.Error("ID mismatch")
	}
	if result.Confidence != 0.95 {
		t.Error("Confidence mismatch")
	}
}

func TestScanRequest_Creation(t *testing.T) {
	req := &ScanRequest{
		Message:  "Hello world",
		Kind:     "chat",
		ToolName: "test-tool",
		Args:     map[string]any{"key": "value"},
		Prompt:   "test prompt",
	}

	if req.Message != "Hello world" {
		t.Error("Message mismatch")
	}
	if len(req.Args) != 1 {
		t.Error("Args mismatch")
	}
}

func TestAuditEntry_Creation(t *testing.T) {
	entry := &AuditEntry{
		Timestamp: time.Now(),
		Action:    "scan",
		Message:   "Scan completed",
		Context:   "test context",
	}

	if entry.Action != "scan" {
		t.Error("Action mismatch")
	}
}

func TestStatsResponse_Defaults(t *testing.T) {
	stats := &StatsResponse{}

	if stats.TotalRequests != 0 {
		t.Error("TotalRequests should be 0")
	}
	if stats.AvgLatencyMs != 0 {
		t.Error("AvgLatencyMs should be 0")
	}
}

func TestStatsResponse_WithValues(t *testing.T) {
	stats := &StatsResponse{
		TotalRequests:   100,
		SuccessfulScans: 90,
		FailedScans:     10,
		AvgLatencyMs:    50,
		P95LatencyMs:    100,
		P99LatencyMs:    150,
	}

	if stats.SuccessfulScans != 90 {
		t.Error("SuccessfulScans mismatch")
	}
	if stats.P95LatencyMs != 100 {
		t.Error("P95LatencyMs mismatch")
	}
}

func TestScanResponse_Defaults(t *testing.T) {
	resp := &ScanResponse{}

	if resp.IsCompliant {
		t.Error("IsCompliant should be false by default")
	}
	if resp.ScanResults != nil {
		t.Error("ScanResults should be nil by default")
	}
}

func TestScanResponse_WithResults(t *testing.T) {
	resp := &ScanResponse{
		ScanID:      "scan-123",
		IsCompliant: false,
		ScanResults: []ScanResult{
			{ID: "finding-1", Severity: "high"},
			{ID: "finding-2", Severity: "medium"},
		},
		ProcessingMs: 150,
	}

	if len(resp.ScanResults) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resp.ScanResults))
	}
	if resp.ScanID != "scan-123" {
		t.Error("ScanID mismatch")
	}
}

// ScannerConfig tests

func TestScannerConfig_WithOptions(t *testing.T) {
	cfg := &ScannerConfig{
		Address: "localhost:9090",
		Timeout: 10 * time.Second,
		Debug:   true,
	}

	if cfg.Address != "localhost:9090" {
		t.Error("Address mismatch")
	}
	if cfg.Timeout != 10*time.Second {
		t.Error("Timeout mismatch")
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
}

func TestScanResult_Severities(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		result := &ScanResult{
			ID:       "test",
			Severity: sev,
		}
		if result.Severity != sev {
			t.Errorf("Severity mismatch for %s", sev)
		}
	}
}

func TestAuditEntry_Actions(t *testing.T) {
	actions := []string{"scan", "block", "allow", "deny"}
	for _, action := range actions {
		entry := &AuditEntry{
			Action: action,
		}
		if entry.Action != action {
			t.Errorf("Action mismatch for %s", action)
		}
	}
}

// Content structures

func TestCallToolResult_Creation(t *testing.T) {
	result := &CallToolResult{
		Content: []ContentBlock{
			{Type: "text", Text: "Hello"},
		},
		IsError:    false,
		DurationMs: 100,
	}

	if len(result.Content) != 1 {
		t.Error("Content length mismatch")
	}
	if result.IsError {
		t.Error("IsError should be false")
	}
}

func TestContentBlock_Creation(t *testing.T) {
	block := &ContentBlock{
		Type: "text",
		Text: "Test content",
	}

	if block.Type != "text" {
		t.Error("Type mismatch")
	}
}

func TestJSONRPCResponse_Creation(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  map[string]any{"status": "ok"},
		ID:      123,
	}

	if resp.JSONRPC != "2.0" {
		t.Error("JSONRPC mismatch")
	}
}

func TestJSONRPCError_Creation(t *testing.T) {
	err := &JSONRPCError{
		Code:    -32600,
		Message: "Invalid Request",
		Data:    map[string]any{"details": "test"},
	}

	if err.Code != -32600 {
		t.Error("Code mismatch")
	}
}

func TestAegisGuardMCPScanner_WithConfig(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "localhost:9999",
		Timeout:      60 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Debug:        true,
	}

	scanner := NewAegisGuardMCPScanner(cfg)
	if scanner == nil {
		t.Fatal("NewAegisGuardMCPScanner returned nil")
	}
	if scanner.config == nil {
		t.Fatal("Scanner config is nil")
	}
	if scanner.config.Address != "localhost:9999" {
		t.Errorf("Address = %v, want localhost:9999", scanner.config.Address)
	}
}

func TestAegisGuardMCPScanner_DefaultConfig(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	if scanner == nil {
		t.Fatal("NewAegisGuardMCPScanner(nil) returned nil")
	}
	if scanner.config == nil {
		t.Fatal("Scanner config should use defaults")
	}
}
