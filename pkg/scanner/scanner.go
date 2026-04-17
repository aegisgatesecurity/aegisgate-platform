// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - Scanner Interface
// =========================================================================
//
// Scanner interface for security scanning services
// Supports both local processing and remote scanners like AegisGuard
// =========================================================================

package scanner

import (
	"context"
	"time"
)

// ScanRequest represents a request to the security scanner
type ScanRequest struct {
	Message  string         `json:"message"`
	Kind     string         `json:"kind"` // e.g., "chat", "completion", "summarization"
	ToolName string         `json:"tool_name,omitempty"`
	Args     map[string]any `json:"args,omitempty"`
	Prompt   string         `json:"prompt,omitempty"`
}

// ScanResponse represents a response from the security scanner
type ScanResponse struct {
	ScanID       string       `json:"scan_id"`
	IsCompliant  bool         `json:"is_compliant"`
	ScanResults  []ScanResult `json:"scan_results"`
	ProcessingMs int64        `json:"processing_ms"`
	AuditLog     []AuditEntry `json:"audit_log,omitempty"`
}

// ScanResult represents a single scan finding
type ScanResult struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`     // e.g., "api_key", "pii", "secret", "auth_denied"
	Severity    string  `json:"severity"` // e.g., "critical", "high", "medium", "low"
	Message     string  `json:"message"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  float64 `json:"confidence"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // e.g., "scan", "block", "allow"
	Message   string    `json:"message"`
	Context   string    `json:"context,omitempty"`
}

// StatsResponse represents scanner/proxy statistics
type StatsResponse struct {
	TotalRequests   int64 `json:"total_requests"`
	SuccessfulScans int64 `json:"successful_scans"`
	FailedScans     int64 `json:"failed_scans"`
	AvgLatencyMs    int64 `json:"avg_latency_ms"`
	P95LatencyMs    int64 `json:"p95_latency_ms"`
	P99LatencyMs    int64 `json:"p99_latency_ms"`
}

// Scanner is the interface for security scanning services
//
// Implementations include:
// - Local scanner (inline processing)
// - AegisGuardMCPScanner (remote scanner using MCP protocol)
// - Future: HTTP-based remote scanner
type Scanner interface {
	// Scan processes a request and returns the scan result
	Scan(ctx context.Context, request *ScanRequest) (*ScanResponse, error)

	// Health returns the health status of the scanner
	Health() error

	// Stats returns statistics about the scanner
	Stats() (*StatsResponse, error)

	// Close cleans up resources
	Close() error
}

// Option func for scanner configuration
type Option func(*ScannerConfig)

// ScannerConfig holds configuration for scanner setup
type ScannerConfig struct {
	Address      string
	Timeout      time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Debug        bool
}

// DefaultScannerConfig returns default scanner configuration
func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		Address:      "localhost:8080",
		Timeout:      30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Debug:        false,
	}
}

// NewScanner creates a scanner based on configuration
// Currently only supports AegisGuardMCPScanner
func NewScanner(config *AegisGuardMCPConfig) Scanner {
	if config == nil {
		config = DefaultAegisGuardMCPConfig()
	}
	return NewAegisGuardMCPScanner(config)
}

// ============================================================================
// MCP Protocol Types (moved from aegisguard_mcp.go for consistency)
// ============================================================================

// CallToolResult represents the result of a tool execution
type CallToolResult struct {
	Content     []ContentBlock `json:"content"`
	IsError     bool           `json:"isError,omitempty"`
	DurationMs  int64          `json:"duration_ms,omitempty"`
}

// ContentBlock represents a content block in MCP response
type ContentBlock struct {
	Type  string `json:"type"`
	Text  string `json:"text,omitempty"`
	Data  string `json:"data,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id,omitempty"`
}

// JSONRPCError represents a JSON-RPC error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
