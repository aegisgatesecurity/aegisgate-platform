// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// AegisGuard MCP Handler - Complete implementation with RBAC, Audit, and Sessions
// =========================================================================

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	rbac "github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// AegisGuardHandler is the complete MCP request handler for AegisGuard
type AegisGuardHandler struct {
	authorizer   *RBACAuthorizer
	sessionMgr   *ConnectionSessionManager
	toolRegistry *ToolRegistry
	auditLogger  *AuditLogger
	logger       *slog.Logger
	serverInfo   ServerInfo
}

// AegisGuardHandlerConfig holds configuration for the handler
type AegisGuardHandlerConfig struct {
	RBACManager *rbac.Manager
	Logger      *slog.Logger
}

// NewAegisGuardHandler creates a new AegisGuard MCP handler
func NewAegisGuardHandler(config *AegisGuardHandlerConfig) *AegisGuardHandler {
	logger := slog.Default()
	if config != nil && config.Logger != nil {
		logger = config.Logger
	}

	h := &AegisGuardHandler{
		authorizer:   NewRBACAuthorizer(config.RBACManager),
		sessionMgr:   NewConnectionSessionManager(config.RBACManager),
		toolRegistry: NewToolRegistry(),
		auditLogger:  NewAuditLogger(logger),
		logger:       logger,
		serverInfo: ServerInfo{
			Name:        "AegisGuard",
			Version:     "0.1.0",
			Description: "AI Agent Security Platform - MCP Server",
		},
	}

	// Register default tools (metadata only)
	h.toolRegistry.RegisterDefaultTools()

	// Connect actual tool executor implementations
	executorAdapter := NewToolExecutorAdapter()
	executorAdapter.RegisterHandlersWithRegistry(h.toolRegistry)

	return h
}

// HandleRequest handles an MCP JSON-RPC request
func (h *AegisGuardHandler) HandleRequest(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	ctx := context.Background()

	switch req.Method {
	case "initialize":
		return h.handleInitialize(ctx, conn, req)
	case "tools/list", "tool/list":
		return h.handleListTools(ctx, req)
	case "tools/call", "tool/call":
		return h.handleCallTool(ctx, conn, req)
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

// handleInitialize handles the MCP initialize request
func (h *AegisGuardHandler) handleInitialize(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	var initParams struct {
		ProtocolVersion string             `json:"protocolVersion"`
		Capabilities    ClientCapabilities `json:"capabilities"`
		ClientInfo      ClientInfo         `json:"clientInfo"`
	}

	if req.Params != nil {
		json.Unmarshal(req.Params, &initParams)
	}

	// Log initialization
	h.auditLogger.LogInitialize(ctx, conn.ID, &initParams.ClientInfo)

	h.logger.Info("MCP client initialized",
		"conn_id", conn.ID,
		"client", initParams.ClientInfo.Name,
		"version", initParams.ClientInfo.Version,
		"protocol", initParams.ProtocolVersion,
	)

	// Update connection with client info
	if conn != nil {
		conn.ClientInfo = &initParams.ClientInfo
	}

	// Return server capabilities
	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: ServerCapabilities{
			Tools:     &ToolCapabilities{ListChanged: true},
			Resources: &ResourceCapabilities{Subscribe: true, ListChanged: true},
			Prompts:   &PromptCapabilities{ListChanged: true},
		},
		ServerInfo: h.serverInfo,
	}

	return h.handleSuccess(req.ID, result)
}

// handleListTools returns available tools
func (h *AegisGuardHandler) handleListTools(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	tools := h.toolRegistry.ToMCPFormat()
	result := ListToolsResult{Tools: tools}
	return h.handleSuccess(req.ID, result)
}

// handleCallTool handles tool execution requests
func (h *AegisGuardHandler) handleCallTool(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
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

	// Log tool call attempt
	h.auditLogger.LogToolCall(ctx, conn.ID, sessionID, agentID, params.Name, params.Arguments)

	// Authorize the tool call
	if sessionID != "" {
		decision, err := h.authorizer.Authorize(ctx, &AuthorizationCall{
			Name:       params.Name,
			Parameters: params.Arguments,
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
				ToolName:     params.Name,
				RiskScore:    decision.RiskScore,
			}, reason)

			return h.handleToolResult(req.ID, fmt.Sprintf("Tool call denied: %s", reason), true)
		}
	}

	// Execute the tool
	result, err := h.toolRegistry.Execute(ctx, params.Name, params.Arguments)
	duration := time.Since(startTime)

	if err != nil {
		h.auditLogger.LogToolError(ctx, &AuditEntry{
			ConnectionID: conn.ID,
			SessionID:    sessionID,
			AgentID:      agentID,
			ToolName:     params.Name,
		}, err, duration)

		return h.handleToolError(req.ID, fmt.Sprintf("Tool execution failed: %s", err.Error()), true)
	}

	// Log success
	h.auditLogger.LogToolSuccess(ctx, &AuditEntry{
		ConnectionID: conn.ID,
		SessionID:    sessionID,
		AgentID:      agentID,
		ToolName:     params.Name,
		RiskScore:    h.toolRegistry.GetRiskLevel(params.Name),
	}, formatResult(result), duration)

	return h.handleToolResult(req.ID, formatResult(result), false)
}

// handleListResources returns available resources
func (h *AegisGuardHandler) handleListResources(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	result := ListResourcesResult{Resources: []Resource{}}
	return h.handleSuccess(req.ID, result)
}

// handleListPrompts returns available prompts
func (h *AegisGuardHandler) handleListPrompts(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	result := ListPromptsResult{Prompts: []Prompt{}}
	return h.handleSuccess(req.ID, result)
}

// handlePing handles ping requests
func (h *AegisGuardHandler) handlePing(req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleSuccess(req.ID, map[string]string{"status": "pong"})
}

// getSessionInfo extracts session and agent IDs from connection
func (h *AegisGuardHandler) getSessionInfo(conn *Connection) (sessionID, agentID string) {
	if conn == nil || conn.Session == nil {
		return "", ""
	}

	sessionID = conn.Session.ID
	if conn.Session.AgentID != "" {
		agentID = conn.Session.AgentID
	}

	// Try to get from session manager if not set on connection
	if agentID == "" && sessionID != "" && h.sessionMgr != nil {
		if mcpSession, err := h.sessionMgr.GetSession(conn.ID); err == nil && mcpSession != nil {
			if mcpSession.Agent != nil {
				agentID = mcpSession.Agent.ID
			}
		}
	}

	return sessionID, agentID
}

// RegisterAgent registers an agent and creates a session bound to connection
func (h *AegisGuardHandler) RegisterAgent(ctx context.Context, connID, agentID string) error {
	_, err := h.sessionMgr.BindAgent(ctx, connID, agentID)
	return err
}

// GetAgentForConnection returns the agent for a connection
func (h *AegisGuardHandler) GetAgentForConnection(connID string) (*rbac.Agent, error) {
	return h.sessionMgr.GetAgentForConnection(connID)
}

// GetAuditStats returns audit statistics
func (h *AegisGuardHandler) GetAuditStats() *AuditStats {
	return h.auditLogger.GetStats()
}

// GetAuditEntries returns recent audit entries
func (h *AegisGuardHandler) GetAuditEntries(limit int) []*AuditEntry {
	return h.auditLogger.GetEntries(limit)
}

// GetToolCount returns the number of registered tools
func (h *AegisGuardHandler) GetToolCount() int {
	return h.toolRegistry.Count()
}

// Helper methods

func (h *AegisGuardHandler) handleSuccess(id interface{}, result interface{}) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
}

func (h *AegisGuardHandler) handleError(id interface{}, code int, message string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	}
}

func (h *AegisGuardHandler) handleToolResult(id interface{}, content string, isError bool) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result: CallToolResult{
			Content: []ContentBlock{
				{Type: "text", Text: content},
			},
			IsError: isError,
		},
	}
}

func (h *AegisGuardHandler) handleToolError(id interface{}, message string, isError bool) *JSONRPCResponse {
	return h.handleToolResult(id, message, isError)
}

// formatResult formats a tool result for JSON-RPC response
func formatResult(result interface{}) string {
	if result == nil {
		return ""
	}
	switch v := result.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}
