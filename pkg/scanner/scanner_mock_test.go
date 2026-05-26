// SPDX-License-Identifier: Apache-2.0
// Scanner Mock Server Tests - Uses existing mockServer

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestWriteJSONWithMock tests writeJSON using mock server
func TestWriteJSONWithMock(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	scanner.Close()
}

// TestReadJSONWithMock tests readJSON using mock server
func TestReadJSONWithMock(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		return map[string]interface{}{"status": "pong"}, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Health()
	if err != nil {
		t.Errorf("Health failed unexpectedly: %v", err)
	}
	scanner.Close()
}

// TestScanWithMockServer tests full Scan flow
func TestScanWithMockServer(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "clean"}},
				"isError":     false,
				"duration_ms": 50,
			}, nil
		}
		return nil, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	resp, err := scanner.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !resp.IsCompliant {
		t.Error("Expected compliant")
	}
	if resp.ProcessingMs != 50 {
		t.Errorf("Expected 50, got %d", resp.ProcessingMs)
	}
	scanner.Close()
}

// TestStatsWithMockServer tests Stats
func TestStatsWithMockServer(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/list" {
			return map[string]interface{}{
				"tools": []map[string]interface{}{
					{"name": "scan"},
					{"name": "detect"},
					{"name": "analyze"},
				},
			}, nil
		}
		return nil, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.TotalRequests != 3 {
		t.Errorf("Expected 3, got %d", stats.TotalRequests)
	}
	scanner.Close()
}

// TestScanNonCompliantWithMock tests Scan with security findings
func TestScanNonCompliantWithMock(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "API key detected"}},
				"isError":     true,
				"duration_ms": 30,
			}, nil
		}
		return nil, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	resp, err := scanner.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant")
	}
	scanner.Close()
}

// TestMultipleScansReuseConnection tests multiple scans
func TestMultipleScansReuseConnection(t *testing.T) {
	callCount := 0
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			callCount++
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "clean"}},
				"isError":     false,
				"duration_ms": 5,
			}, nil
		}
		return nil, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	for i := 0; i < 3; i++ {
		resp, err := scanner.Scan(context.Background(), &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
		if err != nil {
			t.Fatalf("Scan %d failed: %v", i+1, err)
		}
		if !resp.IsCompliant {
			t.Errorf("Scan %d expected compliant", i+1)
		}
	}

	if callCount != 3 {
		t.Errorf("Expected 3 tool calls, got %d", callCount)
	}
	scanner.Close()
}

// TestStatsErrorResponseWithMock tests Stats error handling
func TestStatsErrorResponseWithMock(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/list" {
			return nil, fmt.Errorf("method not found")
		}
		return nil, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	_, err := scanner.Stats()
	if err == nil {
		t.Error("Expected error for tools/list error")
	}
	scanner.Close()
}

// TestHealthUnexpectedResponse tests Health error handling
func TestHealthUnexpectedResponse(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		return map[string]interface{}{"status": "not-pong"}, nil
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Health()
	if err == nil {
		t.Error("Expected error for unexpected ping response")
	}
	scanner.Close()
}
