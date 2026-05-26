// SPDX-License-Identifier: Apache-2.0
// Scanner comprehensive coverage tests

package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestInitialize_WriteError(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Initialize()
	if err == nil {
		t.Error("Expected write error")
	}
	scanner.Close()
}

func TestInitialize_ReadError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Initialize()
	if err == nil {
		t.Error("Expected read error")
	}
	scanner.Close()
	<-done
}

func TestInitialize_InvalidJSON(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("not json\n"))
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
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	scanner.Close()
	<-done
}

func TestInitialize_JSONRPCError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid"},"id":1}` + "\n"))
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
	if err == nil {
		t.Error("Expected error for JSON-RPC error response")
	}
	scanner.Close()
	<-done
}

func TestInitialize_InvalidJSONRPCVersion(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"1.0","result":{},"id":1}` + "\n"))
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
	if err == nil {
		t.Error("Expected error for invalid JSON-RPC version")
	}
	scanner.Close()
	<-done
}

func TestHealth_WriteError(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Health()
	if err == nil {
		t.Error("Expected write error")
	}
	scanner.Close()
}

func TestHealth_ReadError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	err = scanner.Health()
	if err == nil {
		t.Error("Expected read error")
	}
	scanner.Close()
	<-done
}

func TestHealth_InvalidJSON(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte("not json\n"))
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
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	scanner.Close()
	<-done
}

func TestHealth_MissingStatus(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{},"id":999}` + "\n"))
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
	if err == nil {
		t.Error("Expected error for missing status")
	}
	scanner.Close()
	<-done
}

func TestHealth_InvalidStatusType(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"status":123},"id":999}` + "\n"))
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
	if err == nil {
		t.Error("Expected error for invalid status type")
	}
	scanner.Close()
	<-done
}

func TestStats_AlreadyInitialized(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Expected no error when init fails: %v", err)
	}
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0 TotalRequests, got %d", stats.TotalRequests)
	}
	scanner.Close()
}

func TestStats_ReadError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Stats()
	if err == nil {
		t.Error("Expected read error")
	}
	scanner.Close()
	<-done
}

func TestStats_InvalidJSON(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte("not json\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Stats()
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	scanner.Close()
	<-done
}

func TestStats_NoToolsKey(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{}}` + "\n"))
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
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0, got %d", stats.TotalRequests)
	}
	scanner.Close()
	<-done
}

func TestStats_ToolsNotArray(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":"not-array"}}` + "\n"))
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
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0, got %d", stats.TotalRequests)
	}
	scanner.Close()
	<-done
}

func TestStats_JSONRPCErrorResponse(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":1}` + "\n"))
			conn.Read(buf)
			conn.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"Error"},"id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	_, err := scanner.Stats()
	if err == nil {
		t.Error("Expected error")
	}
	scanner.Close()
	<-done
}

func TestScan_WriteJSONError(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected write error")
	}
	scanner.Close()
}

func TestScan_ReadJSONError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected read error")
	}
	scanner.Close()
	<-done
}

func TestScan_InvalidJSONResponse(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte("not json\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	scanner.Close()
	<-done
}

func TestScan_InvalidJSONRPCVersion(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte(`{"jsonrpc":"1.0","result":{},"id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error for invalid JSON-RPC version")
	}
	scanner.Close()
	<-done
}

func TestScan_NullResult(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":null,"id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err != nil {
		t.Errorf("Expected no error for null result: %v", err)
	}
	scanner.Close()
	<-done
}

func TestScan_InvalidResultType(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":"string","id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error for invalid result type")
	}
	scanner.Close()
	<-done
}

func TestClose_PreviouslyInitialized(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
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
	err := scanner.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	err = scanner.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}
	scanner.Close()
	<-done
}

func TestClose_DoubleClose(t *testing.T) {
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

func TestScan_MultipleResults(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"API key detected"},{"type":"text","text":"PII found"},{"type":"text","text":"Secrets detected"}],"isError":true,"duration_ms":150},"id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	resp, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if resp.IsCompliant {
		t.Error("Expected non-compliant")
	}
	if len(resp.ScanResults) != 3 {
		t.Errorf("Expected 3 results, got %d", len(resp.ScanResults))
	}
	scanner.Close()
	<-done
}

func TestScan_EmptyContent(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[],"isError":false,"duration_ms":10},"id":999}` + "\n"))
		}
	}()
	cfg := &AegisGuardMCPConfig{
		Address:      ln.Addr().String(),
		Timeout:      2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx := context.Background()
	resp, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "scan"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !resp.IsCompliant {
		t.Error("Expected compliant with empty content")
	}
	scanner.Close()
	<-done
}
