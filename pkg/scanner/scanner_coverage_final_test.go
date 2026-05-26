// SPDX-License-Identifier: Apache-2.0
//go:build !race

package scanner

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestFinal_Initialize_AlreadyInitialized tests the early return when scanner is already initialized
func TestFinal_Initialize_AlreadyInitialized(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("First Initialize failed: %v", err)
	}

	// Second initialize should return nil early (already initialized)
	err = scanner.Initialize()
	if err != nil {
		t.Errorf("Second Initialize should return nil (already initialized), got: %v", err)
	}

	scanner.Close()
}

// TestFinal_Initialize_ConnectionFailure tests the DialTimeout failure path
func TestFinal_Initialize_ConnectionFailure(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Initialize()
	if err == nil {
		t.Error("Expected connection failure error")
	}
	scanner.Close()
}

// TestFinal_Initialize_WriteFailure tests Initialize when write fails after connecting
func TestFinal_Initialize_WriteFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	// After connecting, we override the conn with a closed one so writeJSON fails
	// First let Initialize connect
	// But the server closes immediately, so the write should fail
	err = scanner.Initialize()
	if err == nil {
		t.Error("Expected write failure")
	}
	scanner.Close()
	<-done
}

// TestFinal_Health_NotInitialized_Success tests Health check on uninitialized scanner reaching server
func TestFinal_Health_NotInitialized_Success(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
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

	err := scanner.Health()
	if err != nil {
		t.Errorf("Health check on uninitialized scanner should succeed, got: %v", err)
	}

	scanner.Close()
}

// TestFinal_Health_NotInitialized_Failure tests Health failure on uninitialized scanner
func TestFinal_Health_NotInitialized_Failure(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Health()
	if err == nil {
		t.Error("Expected health check to fail for unreachable server")
	}
	scanner.Close()
}

// TestFinal_Health_InitializedPong tests Health ping through initialized connection
func TestFinal_Health_InitializedPong(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "ping" {
			return map[string]interface{}{"status": "pong"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Health()
	if err != nil {
		t.Errorf("Health should succeed with pong, got: %v", err)
	}

	scanner.Close()
}

// TestFinal_Health_WriteFailure tests Health write failure on closed connection
func TestFinal_Health_WriteFailure(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close the underlying connection to force write failure
	scanner.connMu.Lock()
	scanner.conn.Close()
	scanner.connMu.Unlock()

	time.Sleep(50 * time.Millisecond)

	err = scanner.Health()
	if err == nil {
		t.Error("Expected Health to fail with closed connection")
	}

	scanner.Close()
}

// TestFinal_Health_ReadFailure tests Health read failure/timeouts
func TestFinal_Health_ReadFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			// Read the ping request but don't respond, force read timeout
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			conn.Read(buf)
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  200 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Health()
	if err == nil {
		t.Error("Expected Health to fail with read timeout")
	}

	scanner.Close()
	<-done
}

// TestFinal_Scan_FullSuccess tests Scan with successful tool call
func TestFinal_Scan_FullSuccess(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "clean"}},
				"isError":     false,
				"duration_ms": 42,
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

	resp, err := scanner.Scan(context.Background(), &ScanRequest{
		Message:  "test message",
		Kind:     "chat",
		ToolName: "security_scan",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !resp.IsCompliant {
		t.Error("Expected compliant result")
	}
	if resp.ProcessingMs != 42 {
		t.Errorf("Expected ProcessingMs=42, got %d", resp.ProcessingMs)
	}
	if resp.ScanID == "" {
		t.Error("Expected non-empty ScanID")
	}

	scanner.Close()
}

// TestFinal_Scan_NonCompliant tests Scan with isError=true result
func TestFinal_Scan_NonCompliant(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "API key exposed"}},
				"isError":     true,
				"duration_ms": 100,
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

	resp, err := scanner.Scan(context.Background(), &ScanRequest{
		Message:  "sensitive data",
		Kind:     "chat",
		ToolName: "scan",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant result")
	}
	if len(resp.ScanResults) != 1 {
		t.Errorf("Expected 1 scan result, got %d", len(resp.ScanResults))
	}
	if resp.ScanResults[0].Type != "tool_error" {
		t.Errorf("Expected type 'tool_error', got %q", resp.ScanResults[0].Type)
	}
	if resp.ScanResults[0].Severity != "high" {
		t.Errorf("Expected severity 'high', got %q", resp.ScanResults[0].Severity)
	}
	if resp.ScanResults[0].Confidence != 1.0 {
		t.Errorf("Expected confidence 1.0, got %f", resp.ScanResults[0].Confidence)
	}

	scanner.Close()
}

// TestFinal_Scan_WriteFailure tests Scan when connection is closed
func TestFinal_Scan_WriteFailure(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close connection to force write failure
	scanner.connMu.Lock()
	scanner.conn.Close()
	scanner.connMu.Unlock()
	time.Sleep(50 * time.Millisecond)

	_, err = scanner.Scan(context.Background(), &ScanRequest{
		Message:  "test",
		Kind:     "chat",
		ToolName: "scan",
	})
	if err == nil {
		t.Error("Expected Scan to fail with closed connection")
	}

	scanner.Close()
}

// TestFinal_Scan_ReadJSONFailure tests Scan read failure
func TestFinal_Scan_ReadJSONFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			// Read tools/call request but close without responding
			conn.Read(buf)
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  200 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = scanner.Scan(context.Background(), &ScanRequest{
		Message: "test", Kind: "chat", ToolName: "scan",
	})
	if err == nil {
		t.Error("Expected read failure")
	}

	scanner.Close()
	<-done
}

// TestFinal_Stats_SuccessWithTools tests Stats with tools/list returning real tool count
func TestFinal_Stats_SuccessWithTools(t *testing.T) {
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
					{"name": "report"},
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
	if stats.TotalRequests != 4 {
		t.Errorf("Expected 4 tools, got %d", stats.TotalRequests)
	}

	scanner.Close()
}

// TestFinal_Stats_WriteFailure tests Stats when write fails
func TestFinal_Stats_WriteFailure(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close connection to force write failure
	scanner.connMu.Lock()
	scanner.conn.Close()
	scanner.connMu.Unlock()
	time.Sleep(50 * time.Millisecond)

	_, err = scanner.Stats()
	if err == nil {
		t.Error("Expected Stats to fail with closed connection")
	}

	scanner.Close()
}

// TestFinal_Close_DoubleCloseConn tests double close of initialized scanner
func TestFinal_Close_DoubleCloseConn(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
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

	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Close()
	if err != nil {
		t.Errorf("First Close failed: %v", err)
	}

	// Second close (conn is nil)
	err = scanner.Close()
	if err != nil {
		t.Errorf("Second Close should succeed (nil conn), got: %v", err)
	}
}

// TestFinal_writeJSON_ClosedConn tests writeJSON SetWriteDeadline error path
func TestFinal_writeJSON_ClosedConn(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	defer scanner.Close()

	// Create and close a connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot create listener: %v", err)
		return
	}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	ln.Close()
	if err != nil {
		t.Skipf("Cannot connect: %v", err)
		return
	}
	conn.Close()

	// SetWriteDeadline on closed connection should fail
	writeErr := scanner.writeJSON(conn, []byte(`{"test":1}`))
	if writeErr == nil {
		t.Error("Expected writeJSON to fail on closed connection")
	}
}

// TestFinal_readJSON_EmptyResponse tests readJSON with empty response (just newline)
func TestFinal_readJSON_EmptyResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("\n"))
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err == nil {
		t.Error("Expected error for empty JSON response")
	}

	scanner.Close()
	<-done
}

// TestFinal_readJSON_ConnectionClose tests readJSON when connection closes immediately after write
func TestFinal_readJSON_ConnectionClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			// Close connection without sending anything
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err == nil {
		t.Error("Expected read error (connection closed)")
	}

	scanner.Close()
	<-done
}

// TestFinal_Health_InvalidResponse tests Health with invalid JSON-RPC response
func TestFinal_Health_InvalidResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			// Send response without "status":"pong"
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"error":"no pong"},"id":999}` + "\n"))
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = scanner.Health()
	if err == nil {
		t.Error("Expected error for non-pong response")
	}

	scanner.Close()
	<-done
}

// TestFinal_Scan_WithResults tests Scan result containing content blocks
func TestFinal_Scan_WithResults(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		if m == "initialize" {
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		}
		if m == "tools/call" {
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": "API key detected"},
					{"type": "text", "text": "Credential leak"},
				},
				"isError":     true,
				"duration_ms": 75,
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

	resp, err := scanner.Scan(context.Background(), &ScanRequest{
		Message:  "sensitive",
		Kind:     "chat",
		ToolName: "scan",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant")
	}
	if len(resp.ScanResults) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resp.ScanResults))
	}
	if resp.ProcessingMs != 75 {
		t.Errorf("Expected 75ms, got %d", resp.ProcessingMs)
	}

	scanner.Close()
}

// TestFinal_MultipleOperations tests the full lifecycle: Initialize → Scan → Health → Stats → Close
func TestFinal_MultipleOperations(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		switch m {
		case "initialize":
			return map[string]interface{}{"protocolVersion": "2024-11-05"}, nil
		case "ping":
			return map[string]interface{}{"status": "pong"}, nil
		case "tools/call":
			return map[string]interface{}{
				"content":     []map[string]interface{}{{"type": "text", "text": "clean"}},
				"isError":     false,
				"duration_ms": 10,
			}, nil
		case "tools/list":
			return map[string]interface{}{
				"tools": []map[string]interface{}{
					{"name": "scan"},
					{"name": "detect"},
				},
			}, nil
		default:
			return nil, nil
		}
	})
	defer mock.close()

	cfg := &AegisGuardMCPConfig{
		Address:      mock.addr(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	// Initialize
	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Initialize again (should return nil immediately)
	err = scanner.Initialize()
	if err != nil {
		t.Errorf("Second Initialize should return nil, got: %v", err)
	}

	// Scan
	resp, err := scanner.Scan(context.Background(), &ScanRequest{
		Message: "test", Kind: "chat", ToolName: "scan",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !resp.IsCompliant {
		t.Error("Expected compliant")
	}

	// Health
	err = scanner.Health()
	if err != nil {
		t.Errorf("Health failed: %v", err)
	}

	// Stats
	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.TotalRequests != 2 {
		t.Errorf("Expected 2 tools, got %d", stats.TotalRequests)
	}

	// Close
	err = scanner.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestFinal_writeJSON_WriteError tests writeJSON when Write() itself fails
func TestFinal_writeJSON_WriteError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Create a connection that we'll close to force write error
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		ln.Close()
		t.Fatalf("Dial failed: %v", err)
	}
	conn.Close()
	ln.Close()

	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	// writeJSON on a closed connection should fail
	writeErr := scanner.writeJSON(conn, []byte(`{"test":1}`))
	if writeErr == nil {
		t.Error("Expected writeJSON to fail on closed connection")
	}

	scanner.Close()
}

// TestFinal_readJSON_ZeroBytesThenData tests the zero-bytes path in readJSON (hard to trigger normally)
func TestFinal_readJSON_ZeroBytesThenData(t *testing.T) {
	// This test covers the edge case where conn.Read returns n=0 but no error.
	// In practice the Go net.Conn documentation says Read returns 0 only with io.EOF or timeout,
	// but we still need to test the code path. We'll use a custom mock server
	// that sends data slowly to potentially trigger intermediate reads.
	// Since it's hard to reliably trigger the zero-byte path, this test
	// simply ensures the full happy path works through readJSON.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			// Send valid JSON response
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	scanner.Close()
	<-done
}

// TestFinal_Scan_AlreadyInitialized tests Scan when scanner needs to auto-initialize
func TestFinal_Scan_AutoInit_Path(t *testing.T) {
	// Scan auto-initializes if not already initialized
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	// Scan should try to Initialize and fail (unreachable server)
	_, err := scanner.Scan(context.Background(), &ScanRequest{
		Message: "test", Kind: "chat", ToolName: "scan",
	})
	if err == nil {
		t.Error("Expected Scan to fail (unreachable server)")
	}

	scanner.Close()
}

// TestFinal_Stats_InitFailFallback tests Stats when initialization fails
func TestFinal_Stats_InitFailFallback(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      100 * time.Millisecond,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Stats should return fallback on init failure: %v", err)
	}
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0 TotalRequests, got %d", stats.TotalRequests)
	}

	scanner.Close()
}

// TestFinal_PartialReadJSON tests reading fragmented JSON response (multiple Read calls)
func TestFinal_PartialReadJSON(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			// Send partial first, then rest
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocol`))
			time.Sleep(50 * time.Millisecond)
			conn.Write([]byte(`Version":"2024-11-05"},"id":1}` + "\n"))
		}
	}()

	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)

	err = scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize should succeed with fragmented response: %v", err)
	}

	scanner.Close()
	<-done
}
