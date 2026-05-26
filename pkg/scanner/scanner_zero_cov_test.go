// SPDX-License-Identifier: Apache-2.0
// Tests for 0% coverage functions

package scanner

import (
	"context"
	"testing"
	"time"
)

func TestDefaultScannerConfig(t *testing.T) {
	cfg := DefaultScannerConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.Address != "localhost:8080" {
		t.Errorf("Expected localhost:8080, got %s", cfg.Address)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected 30s timeout, got %v", cfg.Timeout)
	}
}

func TestNewScanner_NilConfig(t *testing.T) {
	scanner := NewScanner(nil)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}
	scanner.Close()
}

func TestNewScanner_ValidConfig(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewScanner(cfg)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}
	scanner.Close()
}

func TestJSONRPCError_Error(t *testing.T) {
	err := &JSONRPCError{
		Code:    -32600,
		Message: "Invalid Request",
	}
	errStr := err.Error()
	if errStr == "" {
		t.Error("Expected non-empty error string")
	}
}

func TestJSONRPCError_ErrorNil(t *testing.T) {
	var err *JSONRPCError = nil
	errStr := err.Error()
	if errStr != "" {
		t.Errorf("Expected empty string for nil error")
	}
}

func TestNewScanner_Error(t *testing.T) {
	ctx := context.Background()
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewScanner(cfg)
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error")
	}
	scanner.Close()
}
