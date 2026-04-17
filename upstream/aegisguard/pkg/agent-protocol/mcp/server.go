// Package mcp - Model Context Protocol Server
// Implements the MCP protocol for AI agent communication
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server represents an MCP server instance
type Server struct {
	config      *ServerConfig
	listener    net.Listener
	handler     *RequestHandler
	connections map[string]*Connection
	connMu      sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Address      string
	Handler      *RequestHandler
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// Connection represents an active MCP connection
type Connection struct {
	ID         string
	Conn       net.Conn
	Server     *Server
	CreatedAt  time.Time
	LastSeen   time.Time
	Session    *Session
	ClientInfo *ClientInfo
	AgentID    string
	mu         sync.RWMutex
}

// NewServer creates a new MCP server
func NewServer(cfg *ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}

	return &Server{
		config:      cfg,
		handler:     cfg.Handler,
		connections: make(map[string]*Connection),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start begins listening for MCP connections
func (s *Server) Start() error {
	return s.StartContext(context.Background())
}

// StartContext begins listening with context support for graceful shutdown
func (s *Server) StartContext(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	ln, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Address, err)
	}

	s.listener = ln
	slog.Info("MCP server listening", "address", s.config.Address)

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	slog.Info("MCP server shutting down...")
	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.connMu.Lock()
	for id, conn := range s.connections {
		conn.Conn.Close()
		delete(s.connections, id)
	}
	s.connMu.Unlock()

	s.wg.Wait()

	slog.Info("MCP server stopped")
	return nil
}

// acceptLoop accepts new connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Error("MCP server accept error", "error", err)
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a new MCP connection
func (s *Server) handleConnection(nc net.Conn) {
	defer s.wg.Done()

	connID := fmt.Sprintf("conn-%d", time.Now().UnixNano())
	conn := &Connection{
		ID:        connID,
		Conn:      nc,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session: &Session{
			ID: connID,
		},
	}

	s.connMu.Lock()
	s.connections[connID] = conn
	s.connMu.Unlock()

	defer func() {
		s.connMu.Lock()
		delete(s.connections, connID)
		s.connMu.Unlock()
		nc.Close()
	}()

	slog.Info("MCP connection established", "conn_id", connID)

	s.handleMCPProtocol(conn)
}

// handleMCPProtocol handles the MCP JSON-RPC protocol
func (s *Server) handleMCPProtocol(conn *Connection) {
	decoder := json.NewDecoder(conn.Conn)
	encoder := json.NewEncoder(conn.Conn)

	for {
		conn.Conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				slog.Debug("MCP connection closed", "conn_id", conn.ID)
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				conn.mu.RLock()
				lastSeen := conn.LastSeen
				conn.mu.RUnlock()
				if time.Since(lastSeen) > s.config.IdleTimeout {
					slog.Debug("MCP connection idle timeout", "conn_id", conn.ID)
					return
				}
				continue
			}
			slog.Error("MCP decode error", "conn_id", conn.ID, "error", err)
			return
		}

		conn.mu.Lock()
		conn.LastSeen = time.Now()
		conn.mu.Unlock()

		resp := s.handler.HandleRequest(conn, &req)

		conn.Conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))

		if err := encoder.Encode(resp); err != nil {
			slog.Error("MCP encode error", "conn_id", conn.ID, "error", err)
			return
		}
	}
}
