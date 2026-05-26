// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 AegisGate Security
// Scanner AegisGuard MCP Coverage Tests

package scanner

import (
	"context"
	"testing"
	"time"
)

func TestAegisGuardMCPScanner_Lifecycle(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	s.Initialize()
	s.Health()
	req := &ScanRequest{Message: "test", Kind: "chat"}
	s.Scan(context.Background(), req)
	s.Stats()
	s.Close()
}

func TestAegisGuardMCPScanner_InitializeTwice(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	s.Initialize()
	s.Initialize()
	s.Close()
}

func TestAegisGuardMCPScanner_ScanChat(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Scan(context.Background(), &ScanRequest{Message: "hello", Kind: "chat"})
}

func TestAegisGuardMCPScanner_ScanTool(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "tool", ToolName: "read_file"})
}

func TestAegisGuardMCPScanner_ScanEmpty(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Scan(context.Background(), &ScanRequest{Message: "", Kind: "chat"})
}

func TestAegisGuardMCPScanner_ScanWithArgs(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "tool", ToolName: "write", Args: map[string]any{"path": "/tmp/test.txt"}})
}

func TestAegisGuardMCPScanner_ScanWithPrompt(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "summarize", Prompt: "summarize this"})
}

func TestAegisGuardMCPScanner_StatsEmpty(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	stats, _ := s.Stats()
	t.Logf("Stats: total=%d, success=%d, failed=%d", stats.TotalRequests, stats.SuccessfulScans, stats.FailedScans)
}

func TestAegisGuardMCPScanner_CloseNil(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	s.Close()
}

func TestAegisGuardMCPScanner_CloseAfterInit(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 100 * time.Millisecond})
	s.Initialize()
	s.Close()
}

func TestAegisGuardMCPScanner_ValidateResponse(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	valid := s.validateResponse(&JSONRPCResponse{JSONRPC: "2.0", Result: "ok", ID: 1}, 1)
	t.Logf("Valid: %v", valid)
}

func TestAegisGuardMCPScanner_ValidateResponseError(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	valid := s.validateResponse(&JSONRPCResponse{JSONRPC: "2.0", Error: &JSONRPCError{Code: -32600, Message: "Invalid"}}, 1)
	if valid {
		t.Error("Should not be valid with error")
	}
}

func TestAegisGuardMCPScanner_ValidateResponseMalformed(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	valid := s.validateResponse(&JSONRPCResponse{JSONRPC: "2.0", ID: 1}, 2)
	if valid {
		t.Error("Should not be valid with wrong ID")
	}
}

func TestAegisGuardMCPScanner_ParseToolResult(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	result := s.parseToolResult(&CallToolResult{Content: []ContentBlock{{Type: "text", Text: "ok"}}})
	t.Logf("Result: %v", result)
}

func TestAegisGuardMCPScanner_ParseToolResultNil(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	result := s.parseToolResult(nil)
	t.Logf("Nil Result: %v", result)
}

func TestAegisGuardMCPScanner_ParseToolResultEmpty(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	result := s.parseToolResult(&CallToolResult{})
	t.Logf("Empty Result: %v", result)
}

func TestAegisGuardMCPScanner_HealthUnreachable(t *testing.T) {
	s := NewAegisGuardMCPScanner(&AegisGuardMCPConfig{Address: "localhost:9999", Timeout: 50 * time.Millisecond})
	err := s.Health()
	if err != nil {
		t.Logf("Health unreachable (expected): %v", err)
	}
}

func TestAegisGuardMCPScanner_StatsAfterClose(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	s.Close()
	stats, _ := s.Stats()
	t.Logf("Stats after close: total=%d", stats.TotalRequests)
}
