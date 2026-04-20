// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Scanner Integration Tests
// =========================================================================
//
// Integration tests for AegisGuard MCP Scanner
// These tests verify the scanner interface implementation
// =========================================================================

package scanner

import (
	"context"
	"testing"
	"time"
)

// TestAegisGuardMCPScanner_Configuration tests that scanner configuration works correctly
func TestAegisGuardMCPScanner_Configuration(t *testing.T) {
	config := &AegisGuardMCPConfig{
		Address:      "localhost:8080",
		Timeout:      30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Debug:        true,
	}

	scanner := NewAegisGuardMCPScanner(config)

	if scanner == nil {
		t.Fatal("scanner should not be nil")
	}

	if scanner.config.Address != "localhost:8080" {
		t.Errorf("expected address localhost:8080, got %s", scanner.config.Address)
	}

	if scanner.config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", scanner.config.Timeout)
	}
}

// TestAegisGuardMCPScanner_Close tests that scanner closes properly
func TestAegisGuardMCPScanner_Close(t *testing.T) {
	config := &AegisGuardMCPConfig{
		Address: "localhost:8080",
	}

	scanner := NewAegisGuardMCPScanner(config)

	// Close should not panic even if not connected
	err := scanner.Close()
	if err != nil {
		t.Logf("Close returned error (expected for unconnected scanner): %v", err)
	}
}

// TestAegisGuardMCPScanner_DefaultConfig tests default configuration
func TestAegisGuardMCPScanner_DefaultConfig(t *testing.T) {
	defaultConfig := DefaultAegisGuardMCPConfig()

	if defaultConfig.Address != "localhost:8080" {
		t.Errorf("expected default address localhost:8080, got %s", defaultConfig.Address)
	}

	if defaultConfig.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", defaultConfig.Timeout)
	}
}

// TestAegisGuardMCPScanner_ScanRequest creates a scan request and verifies structure
func TestAegisGuardMCPScanner_ScanRequest(t *testing.T) {
	request := &ScanRequest{
		Kind:     "completion",
		ToolName: "test_tool",
		Args: map[string]any{
			"input": "test data",
		},
		Prompt: "test prompt",
	}

	if request.Kind != "completion" {
		t.Errorf("expected kind completion, got %s", request.Kind)
	}

	if request.ToolName != "test_tool" {
		t.Errorf("expected tool_name test_tool, got %s", request.ToolName)
	}

	if len(request.Args) != 1 {
		t.Errorf("expected 1 arg, got %d", len(request.Args))
	}
}

// TestAegisGuardMCPScanner_ScanResponse creates a scan response and verifies structure
func TestAegisGuardMCPScanner_ScanResponse(t *testing.T) {
	response := &ScanResponse{
		ScanID:      "test-scan-123",
		IsCompliant: true,
		ScanResults: []ScanResult{
			{
				ID:         "result-1",
				Type:       "api_key",
				Severity:   "high",
				Message:    "API key detected",
				Confidence: 0.95,
			},
		},
		ProcessingMs: 150,
	}

	if response.ScanID != "test-scan-123" {
		t.Errorf("expected scan_id test-scan-123, got %s", response.ScanID)
	}

	if !response.IsCompliant {
		t.Error("expected is_compliant to be true")
	}

	if len(response.ScanResults) != 1 {
		t.Errorf("expected 1 scan result, got %d", len(response.ScanResults))
	}
}

// TestAegisGuardMCPScanner_ScanResult creates a scan result and verifies structure
func TestAegisGuardMCPScanner_ScanResult(t *testing.T) {
	result := ScanResult{
		ID:          "result-1",
		Type:        "api_key",
		Severity:    "high",
		Message:     "API key detected",
		Remediation: "Remove or secure the API key",
		Confidence:  0.95,
	}

	if result.Type != "api_key" {
		t.Errorf("expected type api_key, got %s", result.Type)
	}

	if result.Severity != "high" {
		t.Errorf("expected severity high, got %s", result.Severity)
	}

	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.Confidence)
	}
}

// TestAegisGuardMCPScanner_AuditEntry creates an audit entry and verifies structure
func TestAegisGuardMCPScanner_AuditEntry(t *testing.T) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    "scan",
		Message:   "Scanned request",
		Context:   "test-context",
	}

	if entry.Action != "scan" {
		t.Errorf("expected action scan, got %s", entry.Action)
	}

	if entry.Message != "Scanned request" {
		t.Errorf("expected message 'Scanned request', got '%s'", entry.Message)
	}
}

// TestAegisGuardMCPScanner_StatsResponse creates a stats response and verifies structure
func TestAegisGuardMCPScanner_StatsResponse(t *testing.T) {
	stats := &StatsResponse{
		TotalRequests:   100,
		SuccessfulScans: 95,
		FailedScans:     5,
		AvgLatencyMs:    150,
		P95LatencyMs:    200,
		P99LatencyMs:    250,
	}

	if stats.TotalRequests != 100 {
		t.Errorf("expected total_requests 100, got %d", stats.TotalRequests)
	}

	if stats.SuccessfulScans != 95 {
		t.Errorf("expected successful_scans 95, got %d", stats.SuccessfulScans)
	}

	if stats.FailedScans != 5 {
		t.Errorf("expected failed_scans 5, got %d", stats.FailedScans)
	}
}

// TestAegisGuardMCPScanner_ScannerInterface verifies that AegisGuardMCPScanner implements Scanner interface
func TestAegisGuardMCPScanner_ScannerInterface(t *testing.T) {
	config := &AegisGuardMCPConfig{
		Address: "localhost:8080",
	}
	scanner := NewAegisGuardMCPScanner(config)

	// Verify it implements Scanner interface
	var _ Scanner = scanner

	// Verify the methods exist and can be called
	ctx := context.Background()

	// Test that Scan accepts a ScanRequest
	request := &ScanRequest{
		Kind:     "completion",
		ToolName: "test",
	}
	_, err := scanner.Scan(ctx, request)
	// Expected to fail connection (no AegisGuard running), but method should exist
	_ = err

	// Test that Health exists and returns error (no connection)
	err = scanner.Health()
	_ = err

	// Test that Stats exists
	_, err = scanner.Stats()
	_ = err

	// Test Close
	err = scanner.Close()
	_ = err
}

// TestAegisGuardMCPScanner_NewScanner verifies factory function
func TestAegisGuardMCPScanner_NewScanner(t *testing.T) {
	scanner := NewScanner(nil)

	if scanner == nil {
		t.Fatal("scanner should not be nil")
	}

	// Verify it implements Scanner
	var _ Scanner = scanner

	scanner.Close()
}
