// SPDX-License-Identifier: Apache-2.0
// Scanner comprehensive tests

package scanner

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

var testCtx = context.Background()

func TestAegisGuardMCPScanner_FullConversation(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			var req map[string]interface{}
			json.Unmarshal(buf[:n], &req)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			n, _ = conn.Read(buf)
			json.Unmarshal(buf[:n], &req)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"clean\"}],\"isError\":false,\"duration_ms\":50},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	resp, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !resp.IsCompliant {
		t.Error("Expected compliant")
	}
	scanner.Close()
	<-done
}

func TestAegisGuardMCPScanner_HealthPong(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"pong\"},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
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
		t.Errorf("Health failed: %v", err)
	}
	scanner.Close()
	<-done
}

func TestAegisGuardMCPScanner_StatsMultipleTools(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"},{\"name\":\"c\"}]},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
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
		t.Errorf("Expected 3 tools, got %d", stats.TotalRequests)
	}
	scanner.Close()
	<-done
}

func TestAegisGuardMCPScanner_ScanSecurityFinding(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"API key detected\"}],\"isError\":true,\"duration_ms\":100},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	resp, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant")
	}
	scanner.Close()
	<-done
}

func TestAegisGuardMCPScanner_writeJSONError(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected write error")
	}
	scanner.Close()
}

func TestAegisGuardMCPScanner_InvalidJSONRPCVersion(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"1.0\",\"result\":{},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error")
	}
	scanner.Close()
	<-done
}

func TestAegisGuardMCPScanner_CloseMultiple(t *testing.T) {
	cfg := &AegisGuardMCPConfig{Address: "localhost:99999"}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Close()
	if err != nil {
		t.Errorf("First close error: %v", err)
	}
	err = scanner.Close()
	if err != nil {
		t.Errorf("Second close error: %v", err)
	}
}

func TestAegisGuardMCPScanner_MultipleErrors(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"},\"id\":1}" + "\n"))
			conn.Read(buf)
			conn.Write([]byte("{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"API key detected\"},{\"type\":\"text\",\"text\":\"PII found\"}],\"isError\":true,\"duration_ms\":100},\"id\":999}" + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	resp, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant")
	}
	if len(resp.ScanResults) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resp.ScanResults))
	}
	scanner.Close()
	<-done
}
