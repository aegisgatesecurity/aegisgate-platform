package scanner

import (
	"testing"
)

// Test AegisGuardMCPConfig types and defaults
func TestAegisGuardMCPConfig_DefaultValues(t *testing.T) {
	cfg := DefaultAegisGuardMCPConfig()
	if cfg.Address != "localhost:8080" {
		t.Errorf("Default address should be localhost:8080, got %s", cfg.Address)
	}
	if cfg.Debug != false {
		t.Error("Default debug should be false")
	}
}

func TestAegisGuardMCPConfig_CustomValues(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "remote:9090",
		Timeout:      60e9,
		ReadTimeout:  30e9,
		WriteTimeout: 30e9,
		Debug:        true,
	}
	if cfg.Address != "remote:9090" {
		t.Errorf("Address should be remote:9090, got %s", cfg.Address)
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
}

// Test AegisGuardMCPScanner interface compliance
func TestNewAegisGuardMCPScanner_NilConfig(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	if scanner == nil {
		t.Fatal("Scanner should not be nil")
	}
}

func TestAegisGuardMCPScanner_InterfaceCompliance(t *testing.T) {
	var _ Scanner = (*AegisGuardMCPScanner)(nil)
}

// Test Health() on uninitialized scanner
func TestAegisGuardMCPScanner_Health_Uninitialized(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	_ = scanner.Health() // May or may not error
}

// Test Stats() on uninitialized scanner
func TestAegisGuardMCPScanner_Stats_Uninitialized(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	stats, err := scanner.Stats()
	if err != nil {
		t.Logf("Stats returned error: %v", err)
	}
	if stats != nil {
		if stats.TotalRequests != 0 {
			t.Errorf("TotalRequests should be 0, got %d", stats.TotalRequests)
		}
	}
}

// Test ScanRequest type
func TestScanRequest_AllFields(t *testing.T) {
	req := &ScanRequest{
		Message:  "test message",
		Kind:     "chat",
		ToolName: "web_search",
		Args:     map[string]any{"query": "test"},
		Prompt:   "test prompt",
	}
	if req.Message != "test message" {
		t.Errorf("Message should be 'test message', got '%s'", req.Message)
	}
	if req.Kind != "chat" {
		t.Errorf("Kind should be 'chat', got '%s'", req.Kind)
	}
	if req.ToolName != "web_search" {
		t.Errorf("ToolName should be 'web_search', got '%s'", req.ToolName)
	}
}

func TestScanResponse_AllFields(t *testing.T) {
	resp := &ScanResponse{
		ScanID:       "scan-123",
		IsCompliant:  true,
		ScanResults:  []ScanResult{},
		ProcessingMs: 50,
		AuditLog:     []AuditEntry{},
	}
	if resp.ScanID != "scan-123" {
		t.Errorf("ScanID should be 'scan-123', got '%s'", resp.ScanID)
	}
	if !resp.IsCompliant {
		t.Error("IsCompliant should be true")
	}
	if resp.ProcessingMs != 50 {
		t.Errorf("ProcessingMs should be 50, got %d", resp.ProcessingMs)
	}
}

func TestScanResult_AllFields(t *testing.T) {
	result := ScanResult{
		ID:          "result-1",
		Type:        "api_key",
		Severity:    "high",
		Message:     "API key detected",
		Remediation: "Remove the API key",
		Confidence:  0.95,
	}
	if result.Type != "api_key" {
		t.Errorf("Type should be 'api_key', got '%s'", result.Type)
	}
	if result.Severity != "high" {
		t.Errorf("Severity should be 'high', got '%s'", result.Severity)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence should be 0.95, got %f", result.Confidence)
	}
}

func TestAuditEntry_AllFields(t *testing.T) {
	entry := AuditEntry{
		Action:  "scan",
		Message: "Scanned request",
		Context: "context-1",
	}
	if entry.Action != "scan" {
		t.Errorf("Action should be 'scan', got '%s'", entry.Action)
	}
	if entry.Context != "context-1" {
		t.Errorf("Context should be 'context-1', got '%s'", entry.Context)
	}
}

func TestStatsResponse_AllFields(t *testing.T) {
	stats := &StatsResponse{
		TotalRequests:   100,
		SuccessfulScans: 95,
		FailedScans:     5,
		AvgLatencyMs:    10,
		P95LatencyMs:    25,
		P99LatencyMs:    50,
	}
	if stats.TotalRequests != 100 {
		t.Errorf("TotalRequests should be 100, got %d", stats.TotalRequests)
	}
	if stats.SuccessfulScans != 95 {
		t.Errorf("SuccessfulScans should be 95, got %d", stats.SuccessfulScans)
	}
	if stats.FailedScans != 5 {
		t.Errorf("FailedScans should be 5, got %d", stats.FailedScans)
	}
	if stats.AvgLatencyMs != 10 {
		t.Errorf("AvgLatencyMs should be 10, got %d", stats.AvgLatencyMs)
	}
	if stats.P95LatencyMs != 25 {
		t.Errorf("P95LatencyMs should be 25, got %d", stats.P95LatencyMs)
	}
	if stats.P99LatencyMs != 50 {
		t.Errorf("P99LatencyMs should be 50, got %d", stats.P99LatencyMs)
	}
}
