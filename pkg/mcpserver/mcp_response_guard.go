// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - MCP Server Response Guard
// =========================================================================
//
// Adds response security scanning to MCP sessions.
// Scans AI responses for PII, secrets, toxicity, and hallucinations
// before they are returned to MCP clients.
//
// Integration point: MCP response handlers
// =========================================================================

package mcpserver

import (
	"context"
	"log/slog"
	"sync"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// MCP Response Scanner
// ============================================================================

// MCPResponseScanner provides response security scanning for MCP sessions
type MCPResponseScanner struct {
	guard  *responseguard.ResponseGuard
	mu     sync.RWMutex
	logger *slog.Logger

	// Session-specific scanning state
	sessionScans map[string]*SessionScanStats
}

// SessionScanStats tracks scanning stats per MCP session
type SessionScanStats struct {
	SessionID              string
	PIIFound               int
	SecretsFound           int
	ToxicityDetected       int
	HallucinationsDetected int
	BlockedResponses       int
	AllowedResponses       int
}

// NewMCPResponseScanner creates a new MCP response scanner with default config
func NewMCPResponseScanner() *MCPResponseScanner {
	return &MCPResponseScanner{
		guard:        responseguard.NewResponseGuard(),
		logger:       slog.Default().With("component", "mcp-response-scanner"),
		sessionScans: make(map[string]*SessionScanStats),
	}
}

// NewMCPResponseScannerWithConfig creates scanner with custom configuration
func NewMCPResponseScannerWithConfig(config *responseguard.ResponseGuardConfig) *MCPResponseScanner {
	return &MCPResponseScanner{
		guard:        responseguard.NewResponseGuardWithConfig(config),
		logger:       slog.Default().With("component", "mcp-response-scanner"),
		sessionScans: make(map[string]*SessionScanStats),
	}
}

// ScanResponse scans an MCP response for security threats
func (rs *MCPResponseScanner) ScanResponse(ctx context.Context, response string, sessionID string) (*responseguard.ResponseScanResult, error) {
	scanCtx := responseguard.NewScanContext(sessionID, "")
	scanCtx.ScanType = "mcp_response"

	return rs.guard.ScanWithContext(ctx, response, scanCtx)
}

// ScanMCPMessage scans an MCP message response
func (rs *MCPResponseScanner) ScanMCPMessage(ctx context.Context, message interface{}, sessionID string) (*responseguard.ResponseScanResult, error) {
	// Extract text content from MCP message structure
	var content string

	switch msg := message.(type) {
	case string:
		content = msg
	case []byte:
		content = string(msg)
	case map[string]interface{}:
		// Try common response fields
		if text, ok := msg["text"].(string); ok {
			content = text
		} else if content, ok = msg["content"].(string); ok {
			content = content
		} else if content, ok = msg["message"].(string); ok {
			content = content
		}
	}

	if content == "" {
		// No scannable content
		return &responseguard.ResponseScanResult{Allowed: true}, nil
	}

	return rs.ScanResponse(ctx, content, sessionID)
}

// UpdateSessionStats updates scanning statistics for a session
func (rs *MCPResponseScanner) UpdateSessionStats(sessionID string, result *responseguard.ResponseScanResult) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	stats, exists := rs.sessionScans[sessionID]
	if !exists {
		stats = &SessionScanStats{SessionID: sessionID}
		rs.sessionScans[sessionID] = stats
	}

	// Update stats based on scan result
	if result.Allowed {
		stats.AllowedResponses++
	} else {
		stats.BlockedResponses++
	}

	stats.PIIFound += len(result.DetectedPII)
	stats.SecretsFound += len(result.DetectedSecrets)

	// Count threat types
	for _, threat := range result.Threats {
		switch threat.Type {
		case "toxicity":
			stats.ToxicityDetected++
		case "hallucination":
			stats.HallucinationsDetected++
		}
	}
}

// GetSessionStats returns scanning statistics for a session
func (rs *MCPResponseScanner) GetSessionStats(sessionID string) *SessionScanStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if stats, exists := rs.sessionScans[sessionID]; exists {
		return stats
	}
	return nil
}

// GetAllSessionStats returns all session scanning statistics
func (rs *MCPResponseScanner) GetAllSessionStats() []*SessionScanStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	stats := make([]*SessionScanStats, 0, len(rs.sessionScans))
	for _, s := range rs.sessionScans {
		stats = append(stats, s)
	}
	return stats
}

// ClearSessionStats clears statistics for a specific session
func (rs *MCPResponseScanner) ClearSessionStats(sessionID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.sessionScans, sessionID)
}

// ============================================================================
// MCP Session Guard Integration
// ============================================================================

// MCPSessionGuard provides security scanning for MCP sessions
type MCPSessionGuard struct {
	scanner    *MCPResponseScanner
	strictMode bool
	enabled    bool
}

// NewMCPSessionGuard creates a new MCP session guard
func NewMCPSessionGuard() *MCPSessionGuard {
	return &MCPSessionGuard{
		scanner:    NewMCPResponseScanner(),
		strictMode: false,
		enabled:    true,
	}
}

// NewMCPSessionGuardWithConfig creates guard with custom configuration
func NewMCPSessionGuardWithConfig(config *responseguard.ResponseGuardConfig) *MCPSessionGuard {
	guard := &MCPSessionGuard{
		scanner:    NewMCPResponseScannerWithConfig(config),
		strictMode: config.StrictMode,
		enabled:    true,
	}
	return guard
}

// Scan scans a response in the context of an MCP session
func (sg *MCPSessionGuard) Scan(ctx context.Context, response string, sessionID string) (*responseguard.ResponseScanResult, error) {
	if !sg.enabled {
		return &responseguard.ResponseScanResult{Allowed: true}, nil
	}

	result, err := sg.scanner.ScanResponse(ctx, response, sessionID)
	if err != nil {
		return nil, err
	}

	// Update session statistics
	sg.scanner.UpdateSessionStats(sessionID, result)

	return result, nil
}

// IsEnabled returns whether the session guard is enabled
func (sg *MCPSessionGuard) IsEnabled() bool {
	return sg.enabled
}

// SetEnabled enables or disables the session guard
func (sg *MCPSessionGuard) SetEnabled(enabled bool) {
	sg.enabled = enabled
}

// IsStrictMode returns whether strict mode is enabled
func (sg *MCPSessionGuard) IsStrictMode() bool {
	return sg.strictMode
}

// ============================================================================
// MCP Tool Response Scanning
// ============================================================================

// MCPResponseGuard middleware for scanning MCP tool responses
type MCPResponseGuard struct {
	sessionGuard *MCPSessionGuard
	logger       *slog.Logger
}

// NewMCPResponseGuard creates a new MCP response guard middleware
func NewMCPResponseGuard() *MCPResponseGuard {
	return &MCPResponseGuard{
		sessionGuard: NewMCPSessionGuard(),
		logger:       slog.Default().With("component", "mcp-response-guard"),
	}
}

// NewMCPResponseGuardWithConfig creates guard with custom configuration
func NewMCPResponseGuardWithConfig(config *responseguard.ResponseGuardConfig) *MCPResponseGuard {
	return &MCPResponseGuard{
		sessionGuard: NewMCPSessionGuardWithConfig(config),
		logger:       slog.Default().With("component", "mcp-response-guard"),
	}
}

// GuardResponse scans and guards an MCP response
// Returns (allowed, response, error)
func (gr *MCPResponseGuard) GuardResponse(ctx context.Context, response string, sessionID string) (bool, string, error) {
	if !gr.sessionGuard.enabled {
		return true, response, nil
	}

	result, err := gr.sessionGuard.Scan(ctx, response, sessionID)
	if err != nil {
		gr.logger.Error("MCP response guard scan failed", "error", err, "session_id", sessionID)
		return false, "", err
	}

	if !result.Allowed {
		gr.logger.Warn("MCP response blocked",
			"session_id", sessionID,
			"reason", result.BlockReason,
			"threats", len(result.Threats),
		)
		// In strict mode, return empty response
		// In non-strict mode, return response with warning
		if gr.sessionGuard.strictMode {
			return false, "", nil
		}
	}

	return true, response, nil
}

// GetSessionStats returns scanning statistics for an MCP session
func (gr *MCPResponseGuard) GetSessionStats(sessionID string) *SessionScanStats {
	return gr.sessionGuard.scanner.GetSessionStats(sessionID)
}

// ============================================================================
// EmbeddedServer Response Scanning Extension
// ============================================================================

// WithResponseScanning extends EmbeddedServer with response scanning
type EmbeddedServerWithResponse struct {
	*EmbeddedServer
	responseGuard *MCPResponseGuard
}

// NewEmbeddedServerWithResponse creates an embedded server with response scanning
func NewEmbeddedServerWithResponse(cfg *Config) *EmbeddedServerWithResponse {
	return &EmbeddedServerWithResponse{
		EmbeddedServer: NewEmbeddedServer(cfg),
		responseGuard:  NewMCPResponseGuard(),
	}
}

// GuardMCPResponse scans an MCP response through the embedded server
func (es *EmbeddedServerWithResponse) GuardMCPResponse(ctx context.Context, response string, sessionID string) (bool, string, error) {
	return es.responseGuard.GuardResponse(ctx, response, sessionID)
}
