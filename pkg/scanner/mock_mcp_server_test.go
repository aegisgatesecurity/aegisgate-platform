// SPDX-License-Identifier: Apache-2.0
//go:build !race

package scanner

import (
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// mockMCPServer is a minimal JSON-RPC TCP server for testing.
type mockMCPServer struct {
	listener net.Listener
	handler  func(method string, params json.RawMessage) (interface{}, error)
	mu       sync.Mutex
	conns    []net.Conn
	closed   bool
}

// newMockMCPServer starts a mock MCP server on a random port.
func newMockMCPServer(t *testing.T, handler func(string, json.RawMessage) (interface{}, error)) *mockMCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := &mockMCPServer{listener: ln, handler: handler}
	go s.serve()
	return s
}

func (s *mockMCPServer) addr() string { return s.listener.Addr().String() }

func (s *mockMCPServer) serve() {
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

func (s *mockMCPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	for {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
			ID      interface{}     `json:"id"`
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
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.Write(append(data, '\n'))
	}
}

func (s *mockMCPServer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.listener.Close()
	for _, c := range s.conns {
		c.Close()
	}
}