// SPDX-License-Identifier: Apache-2.0
// Scanner coverage tests

package scanner

import (
	"context"

	"testing"
	"time"
)

func TestScan_WriteError(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected write error")
	}
	scanner.Close()
}

func TestScan_DialTimeout(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "10.255.255.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected dial error")
	}
	scanner.Close()
}

func TestStats_InitFails(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "10.255.255.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0, got %d", stats.TotalRequests)
	}
	scanner.Close()
}

func TestClose_NilConn(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	err := scanner.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestClose_AlreadyClosed(t *testing.T) {
	cfg := &AegisGuardMCPConfig{Address: "127.0.0.1:1"}
	scanner := NewAegisGuardMCPScanner(cfg)
	scanner.Close()
	err := scanner.Close()
	if err != nil {
		t.Errorf("Second close returned error: %v", err)
	}
}

func TestInitialize_DialTimeout(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "10.255.255.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Initialize()
	if err == nil {
		t.Error("Expected error for dial timeout")
	}
	scanner.Close()
}

func TestValidateResponse_Valid(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: map[string]any{"status": "ok"}, ID: 1}
	if !scanner.validateResponse(resp, 1) {
		t.Error("Expected valid response to pass")
	}
}

func TestValidateResponse_WrongVersion(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	resp := &JSONRPCResponse{JSONRPC: "1.0", Result: map[string]any{"status": "ok"}, ID: 1}
	if scanner.validateResponse(resp, 1) {
		t.Error("Expected invalid version to fail")
	}
}

func TestValidateResponse_MismatchedID(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: map[string]any{"status": "ok"}, ID: 2}
	if scanner.validateResponse(resp, 1) {
		t.Error("Expected mismatched ID to fail")
	}
}

func TestValidateResponse_WithError(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	resp := &JSONRPCResponse{JSONRPC: "2.0", Error: &JSONRPCError{Code: -32600, Message: "Invalid"}, ID: 1}
	if scanner.validateResponse(resp, 1) {
		t.Error("Expected error response to fail")
	}
}

func TestParseToolResult_Nil(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	results := scanner.parseToolResult(nil)
	if len(results) != 0 {
		t.Errorf("Expected 0 results for nil, got %d", len(results))
	}
}

func TestParseToolResult_Error(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	result := &CallToolResult{Content: []ContentBlock{{Type: "text", Text: "Error"}}, IsError: true, DurationMs: 50}
	results := scanner.parseToolResult(result)
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
	if results[0].Type != "tool_error" {
		t.Errorf("Expected tool_error, got %s", results[0].Type)
	}
}

func TestParseToolResult_NoError(t *testing.T) {
	scanner := NewAegisGuardMCPScanner(nil)
	result := &CallToolResult{Content: []ContentBlock{{Type: "text", Text: "Clean"}}, IsError: false, DurationMs: 25}
	results := scanner.parseToolResult(result)
	if len(results) != 0 {
		t.Errorf("Expected 0 results for non-error, got %d", len(results))
	}
}
