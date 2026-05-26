// SPDX-License-Identifier: Apache-2.0
// Scanner tests for 95% coverage

package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestInitialize_ValidResponse(t *testing.T) {
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
	scanner.Close()
	<-done
}

func TestStats_ValidTools(t *testing.T) {
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[{"name":"a"},{"name":"b"}]},"id":999}` + "\n"))
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
	if stats.TotalRequests != 2 {
		t.Errorf("Expected 2, got %d", stats.TotalRequests)
	}
	scanner.Close()
	<-done
}

func TestScan_ValidCompliant(t *testing.T) {
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"clean"}],"isError":false,"duration_ms":50},"id":999}` + "\n"))
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

func TestHealth_Pong(t *testing.T) {
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"status":"pong"},"id":999}` + "\n"))
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

func TestWriteJSON_Error(t *testing.T) {
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

func TestReadJSON_Error(t *testing.T) {
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
	_, err := scanner.Scan(testCtx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected read error")
	}
	scanner.Close()
	<-done
}

func TestScan_NonCompliant(t *testing.T) {
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"API key detected"}],"isError":true,"duration_ms":100},"id":999}` + "\n"))
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

func TestHealth_NotPong(t *testing.T) {
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
			conn.Write([]byte(`{"jsonrpc":"2.0","result":{"status":"not-pong"},"id":999}` + "\n"))
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
		t.Error("Expected error for not-pong")
	}
	scanner.Close()
	<-done
}

func TestStats_JSONRPCError(t *testing.T) {
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

func TestScan_ContextTimeout(t *testing.T) {
	cfg := &AegisGuardMCPConfig{
		Address:      "127.0.0.1:1",
		Timeout:      50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
	}
	scanner := NewAegisGuardMCPScanner(cfg)
	ctx, cancel := context.WithTimeout(testCtx, 50*time.Millisecond)
	defer cancel()
	_, err := scanner.Scan(ctx, &ScanRequest{Message: "test", Kind: "chat", ToolName: "test"})
	if err == nil {
		t.Error("Expected error")
	}
	scanner.Close()
}
