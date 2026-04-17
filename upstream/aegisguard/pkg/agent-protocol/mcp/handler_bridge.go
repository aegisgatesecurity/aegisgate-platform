// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGuard Security - Bridge-Enabled MCP Handler
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file extends the AegisGuardHandler with AegisGate bridge integration.
// When an agent makes an LLM API call, it can be routed through AegisGate
// for defense-in-depth security scanning.
//
// =========================================================================

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// ============================================================================
// Bridge-Enabled Handler
// ============================================================================

// BridgeEnabledHandler extends AegisGuardHandler with bridge capabilities
type BridgeEnabledHandler struct {
	*AegisGuardHandler
	bridge *BridgeIntegration
	logger *slog.Logger
}

// NewBridgeEnabledHandler creates a new handler with bridge integration
func NewBridgeEnabledHandler(config *AegisGuardHandlerConfig, bridgeConfig *BridgeConfig) (*BridgeEnabledHandler, error) {
	// Create base handler
	baseHandler := NewAegisGuardHandler(config)

	// Create bridge integration
	bridgeIntegration, err := NewBridgeIntegration(bridgeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge integration: %w", err)
	}

	handler := &BridgeEnabledHandler{
		AegisGuardHandler: baseHandler,
		bridge:            bridgeIntegration,
		logger:            slog.Default(),
	}

	return handler, nil
}

// Close shuts down the handler and all sub-components
func (h *BridgeEnabledHandler) Close() error {
	if h.bridge != nil {
		if err := h.bridge.Close(); err != nil {
			h.logger.Error("Failed to close bridge integration", "error", err)
		}
	}
	return nil
}

// IsBridgeEnabled returns whether the bridge is enabled
func (h *BridgeEnabledHandler) IsBridgeEnabled() bool {
	return h.bridge != nil && h.bridge.IsEnabled()
}

// GetBridgeStats returns bridge statistics
func (h *BridgeEnabledHandler) GetBridgeStats() *BridgeStats {
	if h.bridge == nil || !h.bridge.IsEnabled() {
		return nil
	}

	stats := h.bridge.GetStats()
	if stats == nil {
		return nil
	}

	return &BridgeStats{
		TotalRequests:   stats.TotalRequests,
		AllowedRequests: stats.AllowedRequests,
		BlockedRequests: stats.BlockedRequests,
		FailedRequests:  stats.FailedRequests,
		ThreatsDetected: stats.ThreatsDetected,
	}
}

// BridgeStats holds bridge statistics
type BridgeStats struct {
	TotalRequests   int64 `json:"total_requests"`
	AllowedRequests int64 `json:"allowed_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	FailedRequests  int64 `json:"failed_requests"`
	ThreatsDetected int64 `json:"threats_detected"`
}

// ============================================================================
// Bridge-Enabled Tool Call Handling
// ============================================================================

// HandleCallToolWithBridge handles tool calls with optional bridge routing
func (h *BridgeEnabledHandler) HandleCallToolWithBridge(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	startTime := time.Now()

	// Parse tool call parameters
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments,omitempty"`
	}

	if req.Params != nil {
		json.Unmarshal(req.Params, &params)
	}

	if params.Name == "" {
		return h.handleToolError(req.ID, "Tool name is required", true)
	}

	// Get session info
	sessionID, agentID := h.getSessionInfo(conn)

	// Check if this is an LLM call that should be routed through bridge
	if h.IsBridgeEnabled() && h.bridge.ShouldIntercept(params.Name, params.Arguments) {
		return h.handleLLMToolCall(ctx, conn, req, params.Name, params.Arguments, sessionID, agentID, startTime)
	}

	// Normal tool call processing (no bridge)
	return h.handleToolCallDirect(ctx, conn, req, params.Name, params.Arguments, sessionID, agentID, startTime)
}

// handleLLMToolCall handles an LLM tool call through the bridge
func (h *BridgeEnabledHandler) handleLLMToolCall(
	ctx context.Context,
	conn *Connection,
	req *JSONRPCRequest,
	toolName string,
	args map[string]interface{},
	sessionID, agentID string,
	startTime time.Time,
) *JSONRPCResponse {
	// Log the LLM call attempt
	h.auditLogger.LogToolCall(ctx, conn.ID, sessionID, agentID, toolName, args)

	// Authorize the tool call (RBAC check)
	if sessionID != "" {
		decision, err := h.authorizer.Authorize(ctx, &AuthorizationCall{
			Name:       toolName,
			Parameters: args,
			SessionID:  sessionID,
			AgentID:    agentID,
		})
		if err != nil {
			return h.handleToolError(req.ID, fmt.Sprintf("Authorization error: %s", err.Error()), true)
		}
		if !decision.Allowed {
			reason := decision.Reason
			h.auditLogger.LogToolDenied(ctx, &AuditEntry{
				ConnectionID: conn.ID,
				SessionID:    sessionID,
				AgentID:      agentID,
				ToolName:     toolName,
				RiskScore:    decision.RiskScore,
			}, reason)

			return h.handleToolResult(req.ID, fmt.Sprintf("Tool call denied: %s", reason), true)
		}
	}

	// Route through AegisGate bridge
	result, err := h.bridge.ProcessLLMToolCall(ctx, conn.ID, sessionID, agentID, toolName, args)
	duration := time.Since(startTime)

	if err != nil {
		// Bridge error - log and fall back to direct execution
		h.logger.Error("Bridge routing failed, falling back to direct execution",
			"error", err,
			"tool", toolName,
		)
		h.auditLogger.LogToolError(ctx, &AuditEntry{
			ConnectionID: conn.ID,
			SessionID:    sessionID,
			AgentID:      agentID,
			ToolName:     toolName,
		}, err, duration)

		// Try direct execution as fallback
		return h.handleToolCallDirect(ctx, conn, req, toolName, args, sessionID, agentID, startTime)
	}

	// Check if blocked by AegisGate
	if result != nil && result.Blocked {
		h.auditLogger.LogToolDenied(ctx, &AuditEntry{
			ConnectionID: conn.ID,
			SessionID:    sessionID,
			AgentID:      agentID,
			ToolName:     toolName,
			RiskScore:    int(result.RiskScore * 100),
		}, result.BlockReason)

		// Log threats if any
		for _, threat := range result.Threats {
			h.logger.Info("Threat detected by AegisGate",
				"type", threat.Type,
				"severity", threat.Severity,
				"pattern", threat.Pattern,
			)
		}

		return h.handleToolResult(req.ID, fmt.Sprintf("LLM call blocked by AegisGate: %s", result.BlockReason), true)
	}

	// Success - return LLM response
	h.auditLogger.LogToolSuccess(ctx, &AuditEntry{
		ConnectionID: conn.ID,
		SessionID:    sessionID,
		AgentID:      agentID,
		ToolName:     toolName,
		RiskScore:    int(result.RiskScore * 100),
	}, formatResult(result), duration)

	return h.handleToolResult(req.ID, formatResult(result), result.IsError)
}

// handleToolCallDirect handles tool calls without bridge routing
func (h *BridgeEnabledHandler) handleToolCallDirect(
	ctx context.Context,
	conn *Connection,
	req *JSONRPCRequest,
	toolName string,
	args map[string]interface{},
	sessionID, agentID string,
	startTime time.Time,
) *JSONRPCResponse {
	// Log tool call attempt
	h.auditLogger.LogToolCall(ctx, conn.ID, sessionID, agentID, toolName, args)

	// Authorize the tool call
	if sessionID != "" {
		decision, err := h.authorizer.Authorize(ctx, &AuthorizationCall{
			Name:       toolName,
			Parameters: args,
			SessionID:  sessionID,
			AgentID:    agentID,
		})
		if err != nil {
			return h.handleToolError(req.ID, fmt.Sprintf("Authorization error: %s", err.Error()), true)
		}
		if !decision.Allowed {
			reason := decision.Reason
			h.auditLogger.LogToolDenied(ctx, &AuditEntry{
				ConnectionID: conn.ID,
				SessionID:    sessionID,
				AgentID:      agentID,
				ToolName:     toolName,
				RiskScore:    decision.RiskScore,
			}, reason)

			return h.handleToolResult(req.ID, fmt.Sprintf("Tool call denied: %s", reason), true)
		}
	}

	// Execute the tool
	result, err := h.toolRegistry.Execute(ctx, toolName, args)
	duration := time.Since(startTime)

	if err != nil {
		h.auditLogger.LogToolError(ctx, &AuditEntry{
			ConnectionID: conn.ID,
			SessionID:    sessionID,
			AgentID:      agentID,
			ToolName:     toolName,
		}, err, duration)

		return h.handleToolError(req.ID, fmt.Sprintf("Tool execution failed: %s", err.Error()), true)
	}

	// Log success
	h.auditLogger.LogToolSuccess(ctx, &AuditEntry{
		ConnectionID: conn.ID,
		SessionID:    sessionID,
		AgentID:      agentID,
		ToolName:     toolName,
		RiskScore:    h.toolRegistry.GetRiskLevel(toolName),
	}, formatResult(result), duration)

	return h.handleToolResult(req.ID, formatResult(result), false)
}

// ============================================================================
// Override HandleRequest to Use Bridge
// ============================================================================

// HandleRequest handles an MCP JSON-RPC request with bridge support
func (h *BridgeEnabledHandler) HandleRequest(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	ctx := context.Background()

	switch req.Method {
	case "initialize":
		return h.handleInitialize(ctx, conn, req)
	case "tools/list", "tool/list":
		return h.handleListTools(ctx, req)
	case "tools/call", "tool/call":
		// Use bridge-enabled tool call handler
		return h.HandleCallToolWithBridge(ctx, conn, req)
	case "resources/list", "resource/list":
		return h.handleListResources(ctx, req)
	case "prompts/list", "prompt/list":
		return h.handleListPrompts(ctx, req)
	case "ping":
		return h.handlePing(req)
	default:
		return h.handleError(req.ID, ErrorMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// ============================================================================
// Unified Health Check
// ============================================================================

// HealthStatus returns comprehensive health status including bridge
func (h *BridgeEnabledHandler) HealthStatus() map[string]string {
	status := make(map[string]string)

	// Core handler status
	status["handler"] = "healthy"
	status["bridge_enabled"] = fmt.Sprintf("%t", h.IsBridgeEnabled())

	if h.bridge != nil && h.IsBridgeEnabled() {
		status["bridge"] = "enabled"
		if h.bridge.GetGateway() != nil {
			status["aegisgate"] = "connected"
		}
		// Get bridge stats
		stats := h.GetBridgeStats()
		if stats != nil {
			status["total_requests"] = fmt.Sprintf("%d", stats.TotalRequests)
			status["blocked_requests"] = fmt.Sprintf("%d", stats.BlockedRequests)
			status["threats_detected"] = fmt.Sprintf("%d", stats.ThreatsDetected)
		}
	} else {
		status["bridge"] = "disabled"
	}

	return status
}

// ============================================================================
// Configuration Management
// ============================================================================

// EnableBridge enables or disables the bridge
func (h *BridgeEnabledHandler) EnableBridge(enabled bool) error {
	if h.bridge == nil {
		return fmt.Errorf("bridge integration not initialized")
	}

	if !enabled {
		h.bridge.enabled = false
		h.logger.Info("AegisGate bridge disabled")
		return nil
	}

	// Bridge cannot be re-enabled without recreation
	// In production, you'd want to reinitialize the gateway
	h.logger.Warn("Bridge re-enable requires handler recreation")
	return nil
}
