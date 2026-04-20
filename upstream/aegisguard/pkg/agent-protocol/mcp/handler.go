// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// Package mcp - AegisGuard MCP Protocol Handler
// Handles MCP protocol requests with RBAC integration
// =========================================================================

package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
)

// RequestHandler handles MCP protocol requests
type RequestHandler struct {
	Authorizer  ToolAuthorizer
	AuditLogger AuditLoggerImpl
	SessionMgr  SessionManager
	Registry    *ToolRegistry
}

// AuditLoggerImpl is the interface for audit logging
type AuditLoggerImpl interface {
	Log(ctx context.Context, entry *AuditEntry) error
}

// NewRequestHandler creates a new request handler
func NewRequestHandler(authorizer ToolAuthorizer, auditLogger AuditLoggerImpl, sessionMgr SessionManager) *RequestHandler {
	return &RequestHandler{
		Authorizer:  authorizer,
		AuditLogger: auditLogger,
		SessionMgr:  sessionMgr,
		Registry:    NewToolRegistry(),
	}
}

// HandleRequest handles an MCP JSON-RPC request
func (h *RequestHandler) HandleRequest(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	ctx := context.Background()

	switch req.Method {
	case "initialize":
		return h.handleInitialize(ctx, req)
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
		return h.handleError(req.ID, ErrorMethodNotFound, "Method not found: "+req.Method)
	}
}

func (h *RequestHandler) handleInitialize(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if h.AuditLogger != nil {
		h.AuditLogger.Log(ctx, &AuditEntry{Type: "initialize"})
	}
	return h.handleSuccess(req.ID, NewInitializeResult())
}

func (h *RequestHandler) handleListTools(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	names := h.Registry.ListTools()
	tools := make([]Tool, len(names))
	for i, name := range names {
		tools[i] = Tool{Name: name, Description: "Tool: " + name}
	}
	return h.handleSuccess(req.ID, ListToolsResult{Tools: tools})
}

func (h *RequestHandler) handleCallTool(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	toolName := ""
	toolParams := make(map[string]interface{})
	if req.Params != nil {
		var params map[string]interface{}
		if err := json.Unmarshal(req.Params, &params); err == nil {
			if n, ok := params["name"].(string); ok {
				toolName = n
			}
			if p, ok := params["arguments"].(map[string]interface{}); ok {
				toolParams = p
			}
		}
	}

	sessionID := "anonymous"
	agentID := ""
	if conn != nil && conn.Session != nil {
		sessionID = conn.Session.ID
		agentID = conn.Session.AgentID
	}

	// Authorize if we have an authorizer
	if h.Authorizer != nil {
		authz, err := h.Authorizer.Authorize(ctx, &AuthorizationCall{
			Name:       toolName,
			Parameters: toolParams,
			SessionID:  sessionID,
			AgentID:    agentID,
		})
		if err != nil {
			slog.Error("authorization error", "error", err)
			return h.handleToolResult(req.ID, "Authorization error", true)
		}
		if !authz.Allowed {
			if h.AuditLogger != nil {
				h.AuditLogger.Log(ctx, &AuditEntry{
					Type: "tool_denied", SessionID: sessionID, AgentID: agentID, ToolName: toolName, Error: authz.Reason,
				})
			}
			msg := "Tool call denied"
			if authz.Reason != "" {
				msg = msg + ": " + authz.Reason
			}
			return h.handleToolResult(req.ID, msg, true)
		}
	}

	// Get and execute handler
	handler, ok := h.Registry.GetHandler(toolName)
	if !ok {
		return h.handleToolResult(req.ID, "Tool not found: "+toolName, true)
	}

	result, err := handler(ctx, toolParams)
	if err != nil {
		if h.AuditLogger != nil {
			h.AuditLogger.Log(ctx, &AuditEntry{
				Type: "tool_error", SessionID: sessionID, AgentID: agentID, ToolName: toolName, Error: err.Error(),
			})
		}
		return h.handleToolResult(req.ID, err.Error(), true)
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(ctx, &AuditEntry{
			Type: "tool_success", SessionID: sessionID, AgentID: agentID, ToolName: toolName,
		})
	}

	content := formatResult(result)
	return h.handleToolResult(req.ID, content, false)
}

func (h *RequestHandler) handleListResources(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleSuccess(req.ID, ListResourcesResult{})
}

func (h *RequestHandler) handleListPrompts(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleSuccess(req.ID, ListPromptsResult{})
}

func (h *RequestHandler) handlePing(req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleSuccess(req.ID, nil)
}

func (h *RequestHandler) handleSuccess(id interface{}, result interface{}) *JSONRPCResponse {
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: id, Result: result}
}

func (h *RequestHandler) handleError(id interface{}, code int, message string) *JSONRPCResponse {
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: id, Error: &JSONRPCError{Code: code, Message: message}}
}

func (h *RequestHandler) handleToolResult(id interface{}, text string, isError bool) *JSONRPCResponse {
	content := []ContentBlock{{Type: "text", Text: text}}
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: id, Result: CallToolResult{Content: content, IsError: isError}}
}

// =============================================================================
// INTERFACES
// =============================================================================

// ToolAuthorizer defines the interface for tool authorization
type ToolAuthorizer interface {
	Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error)
}

// AuthorizationCall represents a tool authorization request
type AuthorizationCall struct {
	ID         string
	Name       string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
}

// AuthorizationDecision represents an authorization decision
type AuthorizationDecision struct {
	Allowed     bool
	Reason      string
	RiskScore   int
	MatchedRule string
}

// PolicyEngine defines the interface for policy evaluation
type PolicyEngine interface {
	Evaluate(ctx context.Context, eval *PolicyEvalContext) (*PolicyEvalResult, error)
}

// PolicyEvalContext represents policy evaluation context
type PolicyEvalContext struct {
	ToolName   string
	SessionID  string
	AgentID    string
	Parameters map[string]interface{}
}

// PolicyEvalResult represents policy evaluation result
type PolicyEvalResult struct {
	Allowed      bool
	Reason       string
	MatchedRules []string
	ModifiedRisk int
}

// SessionManager defines the interface for session management
type SessionManager interface {
	CreateSession(ctx context.Context, agentID string) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

// Session represents an MCP session
type Session struct {
	ID      string
	AgentID string
}

// ToolHandler is a function that executes a tool
type ToolHandler func(ctx context.Context, params map[string]interface{}) (interface{}, error)
