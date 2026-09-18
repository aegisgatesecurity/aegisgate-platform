// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Embedded Server Guardrail Wiring
// =========================================================================
//
// This file wires GuardrailMiddleware (request-side guards) and
// MCPResponseGuard (response-side scanning) into the EmbeddedServer's
// MCP handler. Without this wiring, the MCP server runs without:
//   - Session limits (Guard 1)
//   - Tool count limits + risk-based authorization (Guard 2)
//   - Execution timeouts (Guard 3)
//   - Rate limiting (Guard 5)
//   - STDIO command validation (Guard 6)
//   - Response scanning for PII, secrets, XSS, toxicity (Response Guard)
//
// Integration: call SetGuardrails() before Start().
// =========================================================================

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	mcp "github.com/aegisgatesecurity/aegisguard/pkg/agent-protocol/mcp"
)

// GuardrailConfig holds the guardrail and response guard to wire into the
// EmbeddedServer's handler.
type EmbeddedGuardrailConfig struct {
	Guardrails     *GuardrailMiddleware
	ResponseGuard  *MCPResponseGuard
	ResponseConfig *EmbeddedResponseConfig
}

// EmbeddedResponseConfig controls how tool responses are scanned.
type EmbeddedResponseConfig struct {
	// Enabled controls whether tool responses are scanned. Default: true
	Enabled bool

	// BlockOnPII blocks the response if PII is detected. Default: true
	BlockOnPII bool

	// BlockOnSecrets blocks the response if secrets are detected. Default: true
	BlockOnSecrets bool

	// BlockOnToxicity blocks the response if toxicity is detected. Default: false
	// (toxicity is subjective for tool output like logs or documentation)
	BlockOnToxicity bool

	// LogOnlyCategories logs but does not block for these threat types
	LogOnlyCategories []string
}

// DefaultEmbeddedResponseConfig returns sensible defaults.
// Conservative: block on PII and secrets, log-only on toxicity.
func DefaultEmbeddedResponseConfig() *EmbeddedResponseConfig {
	return &EmbeddedResponseConfig{
		Enabled:           true,
		BlockOnPII:        true,
		BlockOnSecrets:    true,
		BlockOnToxicity:   false,
		LogOnlyCategories: []string{"toxicity", "hallucination"},
	}
}

// SetGuardrails wires the guardrail middleware and response guard into the
// EmbeddedServer's handler. This must be called before Start().
//
// After calling this method, all MCP requests will pass through:
//  1. GuardrailMiddleware.GuardrailHandler (request-side guards)
//  2. The inner RequestHandler (tool execution)
//  3. Response scanning via MCPResponseGuard (response-side guards)
//
// If guardrails is nil, only response scanning is wired.
// If responseGuard is nil, only request guardrails are wired.
// If both are nil, this is a no-op.
func (es *EmbeddedServer) SetGuardrails(guardrails *GuardrailMiddleware, responseGuard *MCPResponseGuard, respCfg *EmbeddedResponseConfig) {
	if guardrails == nil && responseGuard == nil {
		return
	}

	if respCfg == nil {
		respCfg = DefaultEmbeddedResponseConfig()
	}

	innerHandler := es.handler

	// Build the handler chain:
	// 1. GuardrailHandler wraps the inner handler (request-side guards)
	// 2. Response scanning intercepts the response after tool execution
	var requestHandler mcp.HandlerFunc

	if guardrails != nil {
		requestHandler = guardrails.GuardrailHandler(innerHandler)
	} else {
		requestHandler = func(conn *mcp.Connection, req *mcp.JSONRPCRequest) *mcp.JSONRPCResponse {
			return innerHandler.HandleRequest(conn, req)
		}
	}

	// Wrap with response scanning
	wrapped := func(conn *mcp.Connection, req *mcp.JSONRPCRequest) *mcp.JSONRPCResponse {
		// Execute the request through guardrails + handler
		resp := requestHandler(conn, req)

		// Only scan tool call responses (not errors, not other methods)
		if responseGuard == nil || !respCfg.Enabled {
			return resp
		}
		if resp == nil || resp.Error != nil {
			return resp
		}
		if req.Method != "tools/call" && req.Method != "tool/call" {
			return resp
		}

		// Extract text content from the response
		textContent := extractToolResponseText(resp)
		if textContent == "" {
			return resp
		}

		// Get session ID for tracking
		sessionID := "anonymous"
		if conn != nil && conn.Session != nil {
			sessionID = conn.Session.ID
		}

		// Scan the response
		ctx := context.Background()
		allowed, scannedText, err := responseGuard.GuardResponse(ctx, textContent, sessionID)
		if err != nil {
			slog.Error("MCP response guard error",
				"session_id", sessionID,
				"error", err,
			)
			// Fail-open on scanner error: return original response
			// (the request was already authorized and executed)
			return resp
		}

		if !allowed {
			// Response was blocked by the guard
			slog.Warn("MCP tool response blocked by response guard",
				"session_id", sessionID,
				"tool_method", req.Method,
			)
			// Replace the response content with a blocked message
			return mcpBlockedToolResult(req.ID, "Response blocked: sensitive data detected in tool output")
		}

		// If the guard modified the text (e.g., redacted), update the response
		if scannedText != textContent && scannedText != "" {
			updateToolResponseText(resp, scannedText)
		}

		return resp
	}

	es.handlerFunc = wrapped
}

// handlerFunc is stored on EmbeddedServer so Start() can pass it to the Server
// via SetHandleFunc.
// We store it as an untyped interface{} to avoid import cycle issues.
// It's set by SetGuardrails and consumed by Start().

// extractToolResponseText extracts the text content from a tool call response.
func extractToolResponseText(resp *mcp.JSONRPCResponse) string {
	if resp == nil || resp.Result == nil {
		return ""
	}

	// The Result field is interface{} but it's typically a CallToolResult
	// We need to marshal and unmarshal to extract the text
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return ""
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return ""
	}

	var texts []byte
	for _, c := range result.Content {
		if c.Type == "text" && c.Text != "" {
			texts = append(texts, []byte(c.Text)...)
			texts = append(texts, '\n')
		}
	}
	return string(texts)
}

// updateToolResponseText replaces the text content in a tool call response.
func updateToolResponseText(resp *mcp.JSONRPCResponse, newText string) {
	if resp == nil || resp.Result == nil {
		return
	}

	data, err := json.Marshal(resp.Result)
	if err != nil {
		return
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
		IsError bool `json:"isError,omitempty"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	// Replace text in the first text content block
	for i, c := range result.Content {
		if c.Type == "text" {
			result.Content[i].Text = newText
			break
		}
	}

	resp.Result = result
}

// mcpBlockedToolResult creates a tool result response indicating the response
// was blocked by the response guard.
func mcpBlockedToolResult(id interface{}, reason string) *mcp.JSONRPCResponse {
	return &mcp.JSONRPCResponse{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      id,
		Result: mcp.CallToolResult{
			Content: []mcp.ContentBlock{
				{Type: "text", Text: fmt.Sprintf("Tool response blocked: %s", reason)},
			},
			IsError: true,
		},
	}
}
