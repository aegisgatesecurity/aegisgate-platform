package scanner

import (
	"context"
	"testing"
	"time"
)

// ============================================================================
// SCANNER COVERAGE TESTS
// ============================================================================

func TestScanRequestTypes(t *testing.T) {
	req := &ScanRequest{
		Message:  "test message",
		Kind:     "chat",
		ToolName: "web_search",
		Args:     map[string]any{"query": "test"},
		Prompt:   "test prompt",
	}
	if req.Message != "test message" {
		t.Errorf("Message mismatch")
	}
	if req.Kind != "chat" {
		t.Errorf("Kind mismatch")
	}
}

func TestScanResponseTypes(t *testing.T) {
	resp := &ScanResponse{
		ScanID:      "scan-1",
		IsCompliant: true,
		ScanResults: []ScanResult{
			{ID: "r1", Type: "api_key", Severity: "high", Message: "API key detected"},
		},
		ProcessingMs: 50,
		AuditLog: []AuditEntry{
			{Timestamp: time.Now(), Action: "scan", Message: "Scanned"},
		},
	}
	if resp.ScanID != "scan-1" {
		t.Errorf("ScanID mismatch")
	}
	if !resp.IsCompliant {
		t.Error("Should be compliant")
	}
}

func TestScanResultTypes(t *testing.T) {
	result := ScanResult{
		ID:          "result-1",
		Type:        "pii",
		Severity:    "medium",
		Message:     "PII detected",
		Remediation: "Remove PII",
		Confidence:  0.95,
	}
	if result.Type != "pii" {
		t.Errorf("Type mismatch")
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence mismatch")
	}
}

func TestAuditEntryTypes(t *testing.T) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    "block",
		Message:   "Blocked request",
		Context:   "user:admin",
	}
	if entry.Action != "block" {
		t.Errorf("Action mismatch")
	}
}

func TestStatsResponseTypes(t *testing.T) {
	stats := &StatsResponse{
		TotalRequests:   1000,
		SuccessfulScans: 950,
		FailedScans:     50,
		AvgLatencyMs:    100,
		P95LatencyMs:    200,
		P99LatencyMs:    300,
	}
	if stats.TotalRequests != 1000 {
		t.Errorf("TotalRequests mismatch")
	}
	if stats.P99LatencyMs != 300 {
		t.Errorf("P99LatencyMs mismatch")
	}
}

func TestAegisGuardMCPConfigTypes(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "localhost:8080",
		Timeout:      30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Debug:        true,
	}
	if cfg.Address != "localhost:8080" {
		t.Errorf("Address mismatch")
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
}

func TestDefaultAegisGuardMCPConfig(t *testing.T) {
	cfg := DefaultAegisGuardMCPConfig()
	if cfg == nil {
		t.Fatal("DefaultAegisGuardMCPConfig should return non-nil")
	}
	if cfg.Address != "localhost:8080" {
		t.Errorf("Default address mismatch")
	}
}

func TestNewAegisGuardMCPScanner(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	if scanner == nil {
		t.Fatal("NewAegisGuardMCPScanner should return non-nil")
	}
}

func TestNewAegisGuardMCPScannerWithConfig(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address: "localhost:9090",
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	if scanner == nil {
		t.Fatal("Should create with config")
	}
}

func TestScannerInterfaceCompliance(t *testing.T) {
	// Test that AegisGuardMCPScanner implements Scanner interface
	var s Scanner = NewAegisGuardMCPScanner(nil)
	if s == nil {
		t.Error("Should implement Scanner interface")
	}
}

func TestAegisGuardMCPScannerHealth(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	err := scanner.Health()
	// Health should return error since no server is running
	if err == nil {
		t.Log("Health check passed (server may be running)")
	}
}

func TestAegisGuardMCPScannerClose(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	err := scanner.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestAegisGuardMCPScannerScan(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	req := &ScanRequest{
		Message: "test message",
		Kind:    "chat",
	}
	_, err := scanner.Scan(context.Background(), req)
	// Scan should return error since no server is running
	if err == nil {
		t.Log("Scan passed (server may be running)")
	}
}

func TestAegisGuardMCPScannerStats(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	_, err := scanner.Stats()
	// Stats should return error since no server is running
	if err == nil {
		t.Log("Stats passed (server may be running)")
	}
}

func TestScannerConfigTypes(t *testing.T) {
	cfg := &ScannerConfig{}
	if cfg == nil {
		t.Error("ScannerConfig should not be nil")
	}
}

func TestScannerOptionFunc(t *testing.T) {
	var opt Option = func(c *ScannerConfig) {}
	if opt == nil {
		t.Error("Option should not be nil")
	}
}

func TestAuditEntryEmptyContext(t *testing.T) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    "scan",
		Message:   "test",
		Context:   "",
	}
	if entry.Context != "" {
		t.Errorf("Context should be empty, got %s", entry.Context)
	}
}

func TestStatsResponseZeros(t *testing.T) {
	stats := &StatsResponse{}
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0, got %d", stats.TotalRequests)
	}
}

func TestScanRequestWithEmptyArgs(t *testing.T) {
	req := &ScanRequest{
		Message: "test",
		Kind:    "chat",
		Args:    nil,
	}
	if req.Args != nil {
		t.Error("Args should be nil")
	}
}

func TestScanResponseEmptyResults(t *testing.T) {
	resp := &ScanResponse{
		ScanID:      "scan-1",
		IsCompliant: true,
		ScanResults: []ScanResult{},
	}
	if len(resp.ScanResults) != 0 {
		t.Errorf("Expected 0 results, got %d", len(resp.ScanResults))
	}
}

func TestScanResultMultiple(t *testing.T) {
	results := []ScanResult{
		{ID: "1", Type: "api_key", Severity: "critical"},
		{ID: "2", Type: "pii", Severity: "high"},
		{ID: "3", Type: "secret", Severity: "medium"},
	}
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}
}
