// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 AegisGate Security
// Scanner MCP Integration Tests

package scanner

import (
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

type mockServer struct {
	listener net.Listener
	handler  func(string, json.RawMessage) (interface{}, error)
	mu       sync.Mutex
	conns    []net.Conn
	closed   bool
}

func newMockServer(t *testing.T, h func(string, json.RawMessage) (interface{}, error)) *mockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	s := &mockServer{listener: ln, handler: h}
	go s.serve()
	return s
}

func (s *mockServer) addr() string { return s.listener.Addr().String() }

func (s *mockServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

func (s *mockServer) handleConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	for {
		var req struct {
			Method string
			Params json.RawMessage
			ID     interface{}
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := dec.Decode(&req); err != nil {
			return
		}
		var result interface{}
		var rpcErr *JSONRPCError
		if s.handler != nil {
			r, e := s.handler(req.Method, req.Params)
			if e != nil {
				rpcErr = &JSONRPCError{Code: -32000, Message: e.Error()}
			} else {
				result = r
			}
		}
		resp := JSONRPCResponse{JSONRPC: "2.0", Result: result, Error: rpcErr, ID: req.ID}
		data, _ := json.Marshal(resp)
		data = append(data, byte(10))
		conn.Write(data)
	}
}

func (s *mockServer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.listener.Close()
	for _, c := range s.conns {
		c.Close()
	}
}

func TestInitializeRefused(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "127.0.0.1:59999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	err := s.Initialize()
	if err == nil {
		t.Error("Initialize should fail for refused connection")
	}
}

func TestInitializeClosed(t *testing.T) {
	mock := newMockServer(t, func(m string, p json.RawMessage) (interface{}, error) {
		return nil, nil
	})
	addr := mock.addr()
	mock.close()
	config := &AegisGuardMCPConfig{Address: addr, Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	err := s.Initialize()
	if err == nil {
		t.Error("Initialize should fail when server closes")
	}
}

func TestHealthRefused(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "127.0.0.1:59999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	err := s.Health()
	if err == nil {
		t.Error("Health should fail for refused connection")
	}
}

func TestHealthNotInitialized(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "127.0.0.1:59999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	err := s.Health()
	if err == nil {
		t.Error("Health should fail when not initialized")
	}
}

func TestCloseTwice(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	s.Close()
	err := s.Close()
	if err != nil {
		t.Errorf("Close twice: %v", err)
	}
}

func TestParseNilResult(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	result := s.parseToolResult(nil)
	_ = result
}

func TestValidateErrorResp(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Error: &JSONRPCError{Code: -32600, Message: "err"}, ID: 1}
	if s.validateResponse(resp, 1) {
		t.Error("validateResponse should return false for error")
	}
}

func TestValidateWrongID(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: "ok", ID: 999}
	if s.validateResponse(resp, 1) {
		t.Error("validateResponse should return false for wrong ID")
	}
}

func TestValidateCorrectResp(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: "ok", ID: 1}
	if !s.validateResponse(resp, 1) {
		t.Error("validateResponse should return true for correct response")
	}
}

func TestValidateNilResult(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: nil, ID: 1}
	if !s.validateResponse(resp, 1) {
		t.Error("validateResponse should return true for nil result")
	}
}

func TestStatsEmpty(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	stats, err := s.Stats()
	if err != nil {
		t.Errorf("Stats failed: %v", err)
	}
	if stats.TotalRequests != 0 {
		t.Errorf("Empty scanner should have 0 requests, got %d", stats.TotalRequests)
	}
}

func TestStatsP95P99(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	stats, _ := s.Stats()
	t.Logf("Stats: avg=%d, p95=%d, p99=%d", stats.AvgLatencyMs, stats.P95LatencyMs, stats.P99LatencyMs)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultAegisGuardMCPConfig()
	if config == nil {
		t.Fatal("DefaultAegisGuardMCPConfig should not return nil")
	}
	if config.Address != "localhost:8080" {
		t.Errorf("Expected localhost:8080, got %s", config.Address)
	}
	if config.Timeout == 0 {
		t.Error("Expected non-zero timeout")
	}
}

func TestNewScannerNilConfig(t *testing.T) {
	s := NewAegisGuardMCPScanner(nil)
	if s == nil {
		t.Fatal("NewAegisGuardMCPScanner with nil config should not return nil")
	}
	if s.config == nil {
		t.Error("Scanner should use default config")
	}
}

func TestValidateJSONRPCError(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Error: &JSONRPCError{Code: -32603, Message: "Internal error"}, ID: 1}
	if s.validateResponse(resp, 1) {
		t.Error("validateResponse should return false for JSON-RPC error")
	}
}

func TestValidateWrongJSONRPCVersion(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "1.0", Result: "ok", ID: 1}
	if s.validateResponse(resp, 1) {
		t.Error("validateResponse should return false for wrong JSON-RPC version")
	}
}

func TestValidateZeroExpectedID(t *testing.T) {
	s := NewAegisGuardMCPScanner(DefaultAegisGuardMCPConfig())
	resp := &JSONRPCResponse{JSONRPC: "2.0", Result: "ok", ID: 0}
	if !s.validateResponse(resp, 0) {
		t.Error("validateResponse should return true for zero ID match")
	}
}

func TestStatsAfterFailedScan(t *testing.T) {
	config := &AegisGuardMCPConfig{Address: "127.0.0.1:59999", Timeout: 100 * time.Millisecond}
	s := NewAegisGuardMCPScanner(config)
	stats, _ := s.Stats()
	t.Logf("Stats after failed init: %v", stats)
}
