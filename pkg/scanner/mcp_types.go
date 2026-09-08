// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Scanner Types
// =========================================================================
// Type definitions required by aegisguard_mcp.go for the remote MCP scanner.
// These types mirror the structures used in the AegisGuard MCP protocol
// (JSON-RPC 2.0 over TCP) and are kept locally to avoid cross-module
// dependencies in the consolidated platform build.
// =========================================================================

package scanner

import "time"

import "fmt"

// ScanRequest is a scan request sent to the AegisGuard MCP scanner.
type ScanRequest struct {
	Message  string                 `json:"message,omitempty"`
	Kind     string                 `json:"kind"`
	ToolName string                 `json:"tool_name,omitempty"`
	Args     map[string]interface{} `json:"args,omitempty"`
	Prompt   string                 `json:"prompt,omitempty"`
}

// ScanResponse is the response from an AegisGuard MCP scan.
type ScanResponse struct {
	ScanID       string       `json:"scan_id"`
	IsCompliant  bool         `json:"is_compliant"`
	ScanResults  []ScanResult `json:"scan_results,omitempty"`
	ProcessingMs int64        `json:"processing_ms"`
	AuditLog     []AuditEntry `json:"audit_log,omitempty"`
}

// StatsResponse holds scanner statistics.
type StatsResponse struct {
	TotalRequests   int64 `json:"total_requests"`
	SuccessfulScans int64 `json:"successful_scans"`
	FailedScans     int64 `json:"failed_scans"`
	AvgLatencyMs    int64 `json:"avg_latency_ms,omitempty"`
	P95LatencyMs    int64 `json:"p95_latency_ms,omitempty"`
	P99LatencyMs    int64 `json:"p99_latency_ms,omitempty"`
}

// ScanResult represents a single finding from a scan.
type ScanResult struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Message     string  `json:"message"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  float64 `json:"confidence"`
}

// CallToolResult is the result of an MCP tools/call invocation.
type CallToolResult struct {
	Content    []ContentBlock `json:"content"`
	IsError    bool           `json:"isError,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
}

// ContentBlock is a content block within a tool result.
type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id,omitempty"`
}

// JSONRPCError is a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface for JSONRPCError.
func (e *JSONRPCError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Action       string                 `json:"action,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Context      string                 `json:"context,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	ConnectionID string                 `json:"connection_id"`
	SessionID    string                 `json:"session_id,omitempty"`
	AgentID      string                 `json:"agent_id,omitempty"`
	AgentName    string                 `json:"agent_name,omitempty"`
	AgentRole    string                 `json:"agent_role,omitempty"`
	ToolName     string                 `json:"tool_name,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Result       string                 `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RiskScore    int                    `json:"risk_score"`
	Duration     time.Duration          `json:"duration"`
	Allowed      bool                   `json:"allowed"`
}
