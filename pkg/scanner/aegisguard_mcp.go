// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - AegisGuard MCP Scanner
// =========================================================================
//
// AegisGuard Scanner using MCP protocol (JSON-RPC over TCP)
// instead of HTTP REST API
// =========================================================================

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// AegisGuardMCPConfig holds configuration for the MCP-based AegisGuard scanner
type AegisGuardMCPConfig struct {
	// MCP server address (format: "host:port")
	Address string `json:"address"`

	// Connection timeout
	Timeout time.Duration `json:"timeout"`

	// Read/write timeouts for MCP protocol
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`

	// Enable verbose logging
	Debug bool `json:"debug"`
}

// AegisGuardMCPScanner implements the Scanner interface using MCP protocol
type AegisGuardMCPScanner struct {
	config      *AegisGuardMCPConfig
	logger      *slog.Logger
	conn        net.Conn
	connMu      sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	initialized bool
}

// NewAegisGuardMCPScanner creates a new AegisGuard scanner using MCP protocol
func NewAegisGuardMCPScanner(config *AegisGuardMCPConfig) *AegisGuardMCPScanner {
	if config == nil {
		config = DefaultAegisGuardMCPConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AegisGuardMCPScanner{
		config: config,
		logger: slog.Default(),
		ctx:    ctx,
		cancel: cancel,
	}
}

// DefaultAegisGuardMCPConfig returns default configuration for MCP-based scanner
func DefaultAegisGuardMCPConfig() *AegisGuardMCPConfig {
	return &AegisGuardMCPConfig{
		Address:      "localhost:8080", // MCP protocol port
		Timeout:      30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Debug:        false,
	}
}

// Initialize connects to AegisGuard MCP server and performs initialization
func (s *AegisGuardMCPScanner) Initialize() error {
	// Connect to MCP server
	conn, err := net.DialTimeout("tcp", s.config.Address, s.config.Timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to AegisGuard MCP server: %w", err)
	}

	s.connMu.Lock()
	s.conn = conn
	s.connMu.Unlock()

	// Send initialize request
	initRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{
					"listChanged": true,
				},
			},
			"clientInfo": map[string]string{
				"name":    "AegisGate-Platform",
				"version": "0.1.0",
			},
		},
		"id": 1,
	}

	reqBytes, err := json.Marshal(initRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal initialize request: %w", err)
	}

	s.connMu.Lock()
	if err := s.writeJSON(s.conn, reqBytes); err != nil {
		s.connMu.Unlock()
		return fmt.Errorf("failed to send initialize request: %w", err)
	}

	// Receive response
	resp, err := s.readJSON(s.conn)
	s.connMu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to receive initialize response: %w", err)
	}

	if !s.validateResponse(resp, 1) {
		return fmt.Errorf("invalid initialize response")
	}

	s.initialized = true
	s.logger.Info("AegisGuard MCP scanner initialized", "address", s.config.Address)

	return nil
}

// Scanner interface implementation

// Scan processes a request using AegisGuard's MCP protocol
func (s *AegisGuardMCPScanner) Scan(ctx context.Context, request *ScanRequest) (*ScanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Ensure initialized
	if !s.initialized {
		if err := s.Initialize(); err != nil {
			return nil, fmt.Errorf("failed to initialize scanner: %w", err)
		}
	}

	// Build tool call request
	toolCall := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      request.ToolName,
			"arguments": request.Args,
		},
		"id": time.Now().UnixNano(),
	}

	reqBytes, err := json.Marshal(toolCall)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tool call: %w", err)
	}

	s.connMu.Lock()
	defer s.connMu.Unlock()

	if err := s.writeJSON(s.conn, reqBytes); err != nil {
		return nil, fmt.Errorf("failed to send tool call: %w", err)
	}

	// Receive response
	resp, err := s.readJSON(s.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive tool call response: %w", err)
	}

	// Validate response format
	if !s.validateResponse(resp, 0) {
		return nil, fmt.Errorf("invalid tool call response")
	}

	// Parse response - Result is interface{} containing the tool result
	var toolResult CallToolResult
	// The result is typically a map[string]interface{}, we need to marshal then unmarshal
	resultBytes, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	if err := json.Unmarshal(resultBytes, &toolResult); err != nil {
		return nil, fmt.Errorf("failed to parse tool result: %w", err)
	}

	// Build scan response
	isCompliant := !toolResult.IsError
	scanResults := s.parseToolResult(&toolResult)

	return &ScanResponse{
		ScanID:       fmt.Sprintf("mcp-scan-%d", time.Now().UnixNano()),
		IsCompliant:  isCompliant,
		ScanResults:  scanResults,
		ProcessingMs: toolResult.DurationMs,
		AuditLog:     []AuditEntry{},
	}, nil
}

// Health checks AegisGuard MCP server health
func (s *AegisGuardMCPScanner) Health() error {
	// If not initialized, just test connection
	if !s.initialized {
		conn, err := net.DialTimeout("tcp", s.config.Address, 5*time.Second)
		if err != nil {
			return fmt.Errorf("health check failed: %w", err)
		}
		conn.Close()
		return nil
	}

	// Send ping request via MCP protocol
	pingRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "ping",
		"id":      time.Now().UnixNano(),
	}

	reqBytes, err := json.Marshal(pingRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal ping request: %w", err)
	}

	s.connMu.Lock()
	defer s.connMu.Unlock()

	if err := s.writeJSON(s.conn, reqBytes); err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	// Receive response
	resp, err := s.readJSON(s.conn)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !s.validateResponse(resp, 0) {
		return fmt.Errorf("health check failed: invalid response")
	}

	// Verify ping result contains "status": "pong"
	if result, ok := resp.Result.(map[string]interface{}); ok {
		if status, ok := result["status"].(string); ok && status == "pong" {
			return nil
		}
	}

	return fmt.Errorf("health check failed: unexpected response")
}

// Stats returns scanner statistics
func (s *AegisGuardMCPScanner) Stats() (*StatsResponse, error) {
	// AegisGuard doesn't expose stats via MCP protocol directly
	// We can request tools list to get some statistics

	// If not initialized, do it first
	if !s.initialized {
		if err := s.Initialize(); err != nil {
			s.logger.Warn("failed to initialize scanner for stats", "error", err)
			return &StatsResponse{
				TotalRequests:   0,
				SuccessfulScans: 0,
				FailedScans:     0,
			}, nil
		}
	}

	// Request tools list
	toolsRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      time.Now().UnixNano(),
	}

	reqBytes, err := json.Marshal(toolsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tools request: %w", err)
	}

	s.connMu.Lock()
	defer s.connMu.Unlock()

	if err := s.writeJSON(s.conn, reqBytes); err != nil {
		return nil, fmt.Errorf("failed to send tools request: %w", err)
	}

	// Receive response
	resp, err := s.readJSON(s.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive tools response: %w", err)
	}

	// Parse tools count
	if toolsList, ok := resp.Result.(map[string]interface{}); ok {
		if tools, ok := toolsList["tools"].([]interface{}); ok {
			return &StatsResponse{
				TotalRequests:   int64(len(tools)),
				SuccessfulScans: 0,
				FailedScans:     0,
			}, nil
		}
	}

	return &StatsResponse{
		TotalRequests:   0,
		SuccessfulScans: 0,
		FailedScans:     0,
	}, nil
}

// Close closes the MCP connection
func (s *AegisGuardMCPScanner) Close() error {
	s.cancel()

	s.connMu.Lock()
	defer s.connMu.Unlock()

	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		s.conn = nil
	}

	s.initialized = false
	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// validateResponse verifies JSON-RPC response format
func (s *AegisGuardMCPScanner) validateResponse(resp *JSONRPCResponse, expectedID interface{}) bool {
	if resp.JSONRPC != "2.0" {
		s.logger.Debug("invalid jsonrpc version", "got", resp.JSONRPC)
		return false
	}

	if resp.ID != expectedID && expectedID != 0 {
		s.logger.Debug("unexpected response ID", "got", resp.ID, "expected", expectedID)
		return false
	}

	if resp.Error != nil {
		s.logger.Debug("response contains error", "code", resp.Error.Code, "message", resp.Error.Message)
		return false
	}

	return true
}

// parseToolResult converts MCP tool result to scan results
func (s *AegisGuardMCPScanner) parseToolResult(result *CallToolResult) []ScanResult {
	if result == nil {
		return []ScanResult{}
	}

	var scanResults []ScanResult

	// Check if there's any error content
	if result.IsError {
		for _, block := range result.Content {
			if block.Type == "text" {
				scanResults = append(scanResults, ScanResult{
					ID:          fmt.Sprintf("result-%d", time.Now().UnixNano()),
					Type:        "tool_error",
					Severity:    "high",
					Message:     block.Text,
					Remediation: "Tool execution failed",
					Confidence:  1.0,
				})
			}
		}
	}

	return scanResults
}

// writeJSON writes JSON data to connection with timeout
func (s *AegisGuardMCPScanner) writeJSON(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))

	// Add newline separator for JSON-RPC protocol
	_, err := conn.Write(append(data, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	return nil
}

// readJSON reads JSON data from connection with timeout
func (s *AegisGuardMCPScanner) readJSON(conn net.Conn) (*JSONRPCResponse, error) {
	conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))

	// Read until newline (JSON-RPC protocol line-based)
	var jsonBytes []byte
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read JSON: %w", err)
		}

		jsonBytes = append(jsonBytes, buf[:n]...)

		// Check if we have complete message (ends with newline)
		if buf[n-1] == '\n' {
			break
		}
	}

	// Remove trailing newline and decode
	jsonBytes = bytes.TrimSpace(jsonBytes)

	var resp JSONRPCResponse
	if err := json.Unmarshal(jsonBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &resp, nil
}
