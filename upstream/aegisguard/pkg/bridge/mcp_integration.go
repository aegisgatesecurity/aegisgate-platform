// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security - MCP Bridge Integration
//
// =========================================================================
//
// This file integrates the AegisGate bridge into the AegisGuard MCP handler,
// enabling LLM API calls from agents to be routed through AegisGate.
//
// =========================================================================

package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// ============================================================================
// MCP Integration
// ============================================================================

// MCPIntegration provides bridge integration for MCP tool calls
type MCPIntegration struct {
	gateway *Gateway
	logger  *slog.Logger
	enabled bool
}

// NewMCPIntegration creates a new MCP bridge integration
func NewMCPIntegration(gateway *Gateway) *MCPIntegration {
	return &MCPIntegration{
		gateway: gateway,
		logger:  slog.Default(),
		enabled: gateway != nil && gateway.config.Enabled,
	}
}

// NewMCPIntegrationWithConfig creates integration with config
func NewMCPIntegrationWithConfig(config *Config) (*MCPIntegration, error) {
	if !config.Enabled {
		return &MCPIntegration{
			gateway: nil,
			logger:  slog.Default(),
			enabled: false,
		}, nil
	}

	gateway, err := NewGateway(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway: %w", err)
	}

	return NewMCPIntegration(gateway), nil
}

// ============================================================================
// LLM Tool Detection
// ============================================================================

// Known LLM API endpoints that should be routed through AegisGate
var knownLLMEndpoints = []string{
	// OpenAI
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/embeddings",
	"/v1/images",
	"/v1/audio",

	// Anthropic
	"/v1/messages",
	"/v1/images",

	// Azure OpenAI
	"/openai/deployments/",
	"/chat/completions",

	// Cohere
	"/v1/generate",
	"/v1/embed",
	"/v1/classify",

	// Google AI
	"/v1beta/models/",
	"/v1/models/",

	// AWS Bedrock
	"/bedrock/",
	"/model-anthropic/",
	"/model-titan/",
	"/model-llama/",

	// Generic
	"/llm/",
	"/ai/",
	"/chatbot/",
	"/gpt/",
	"/claude/",
}

// IsLLMCall determines if a tool call is an LLM API call
func (m *MCPIntegration) IsLLMCall(toolName string, args map[string]interface{}) bool {
	// Check tool name
	toolNameLower := strings.ToLower(toolName)
	llmIndicators := []string{"llm", "openai", "anthropic", "chat", "gpt", "claude", "bedrock", "cohere", "ai", "chatbot"}

	for _, indicator := range llmIndicators {
		if strings.Contains(toolNameLower, indicator) {
			return true
		}
	}

	// Check arguments for URL patterns
	if url, ok := args["url"].(string); ok {
		return m.isLLMURL(url)
	}

	if endpoint, ok := args["endpoint"].(string); ok {
		return m.isLLMURL(endpoint)
	}

	// Check for OpenAI-compatible API patterns
	if model, ok := args["model"].(string); ok {
		// If model is specified, it's likely an LLM call
		modelLower := strings.ToLower(model)
		llmModels := []string{"gpt", "claude", "llama", "mistral", "gemini", "titan", "command"}

		for _, llm := range llmModels {
			if strings.Contains(modelLower, llm) {
				return true
			}
		}
	}

	// Check for messages/prompt patterns
	if _, hasMessages := args["messages"]; hasMessages {
		return true
	}
	if _, hasPrompt := args["prompt"]; hasPrompt {
		return true
	}

	return false
}

// isLLMURL checks if a URL is an LLM API endpoint
func (m *MCPIntegration) isLLMURL(url string) bool {
	urlLower := strings.ToLower(url)
	for _, endpoint := range knownLLMEndpoints {
		if strings.Contains(urlLower, strings.ToLower(endpoint)) {
			return true
		}
	}
	return false
}

// ============================================================================
// LLM Call Routing
// ============================================================================

// LLMToolContext contains context for an LLM tool call
type LLMToolContext struct {
	AgentID   string
	SessionID string
	ToolName  string
	ToolArgs  map[string]interface{}
}

// RouteLLMToolCall routes an LLM tool call through AegisGate
func (m *MCPIntegration) RouteLLMToolCall(ctx context.Context, toolCall *LLMToolContext) (*LLMResponse, error) {
	if !m.enabled {
		m.logger.Debug("Bridge disabled, skipping AegisGate routing")
		return nil, nil
	}

	// Build LLM request
	req, err := m.buildLLMRequest(toolCall)
	if err != nil {
		return nil, fmt.Errorf("failed to build LLM request: %w", err)
	}

	// Route through bridge
	m.logger.Info("Routing LLM tool call through AegisGate",
		"agent_id", toolCall.AgentID,
		"session_id", toolCall.SessionID,
		"tool_name", toolCall.ToolName,
		"target_url", req.TargetURL,
	)

	resp, err := m.gateway.RouteLLMCall(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("bridge routing failed: %w", err)
	}

	// Log result
	if resp.ScanResult != nil {
		if !resp.ScanResult.Allowed {
			m.logger.Warn("AegisGate blocked LLM call",
				"agent_id", toolCall.AgentID,
				"session_id", toolCall.SessionID,
				"reason", resp.ScanResult.BlockReason,
				"threats", len(resp.ScanResult.Threats),
			)
		} else if len(resp.ScanResult.Threats) > 0 {
			m.logger.Info("AegisGate allowed LLM call with threats",
				"agent_id", toolCall.AgentID,
				"session_id", toolCall.SessionID,
				"threats", len(resp.ScanResult.Threats),
			)
		}
	}

	return resp, nil
}

// buildLLMRequest builds a bridge LLM request from tool call context
func (m *MCPIntegration) buildLLMRequest(toolCall *LLMToolContext) (*LLMRequest, error) {
	req := &LLMRequest{
		RequestID: generateRequestID(),
		AgentID:   toolCall.AgentID,
		SessionID: toolCall.SessionID,
		ToolName:  toolCall.ToolName,
		Method:    "POST",
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	args := toolCall.ToolArgs

	// Determine target URL
	if url, ok := args["url"].(string); ok {
		req.TargetURL = url
	} else if endpoint, ok := args["endpoint"].(string); ok {
		req.TargetURL = endpoint
	} else if baseURL, ok := args["base_url"].(string); ok {
		// Build URL from base + path
		path := ""
		if p, ok := args["path"].(string); ok {
			path = p
		} else {
			path = "/v1/chat/completions" // Default to chat completions
		}
		req.TargetURL = strings.TrimSuffix(baseURL, "/") + path
	}

	// Add API key to headers
	if apiKey, ok := args["api_key"].(string); ok {
		req.Headers["Authorization"] = "Bearer " + apiKey
	}

	// Build request body from arguments
	body := m.buildRequestBody(args)
	req.Body = body

	return req, nil
}

// buildRequestBody builds JSON body from tool arguments
func (m *MCPIntegration) buildRequestBody(args map[string]interface{}) []byte {
	// Build OpenAI-compatible request body
	body := make(map[string]interface{})

	// Common fields
	if model, ok := args["model"].(string); ok {
		body["model"] = model
	}

	if messages, ok := args["messages"].([]interface{}); ok {
		body["messages"] = messages
	} else if prompt, ok := args["prompt"].(string); ok {
		// Convert prompt to messages format
		body["messages"] = []map[string]string{
			{"role": "user", "content": prompt},
		}
	}

	// Optional parameters
	if temp, ok := args["temperature"].(float64); ok {
		body["temperature"] = temp
	}
	if maxTokens, ok := args["max_tokens"].(int); ok {
		body["max_tokens"] = maxTokens
	}
	if topP, ok := args["top_p"].(float64); ok {
		body["top_p"] = topP
	}

	// Convert to JSON
	// In production, use json.Marshal
	return []byte(fmt.Sprintf("%v", body))
}

// ============================================================================
// LLM Call Interception Hook
// ============================================================================

// Interceptor provides hook points for LLM call interception
type Interceptor struct {
	integration *MCPIntegration
	preHooks    []PreLLMCallHook
	postHooks   []PostLLMCallHook
}

// PreLLMCallHook is called before routing to AegisGate
type PreLLMCallHook func(ctx context.Context, call *LLMToolContext) error

// PostLLMCallHook is called after receiving response from AegisGate
type PostLLMCallHook func(ctx context.Context, call *LLMToolContext, resp *LLMResponse)

// NewInterceptor creates a new LLM call interceptor
func NewInterceptor(integration *MCPIntegration) *Interceptor {
	return &Interceptor{
		integration: integration,
		preHooks:    make([]PreLLMCallHook, 0),
		postHooks:   make([]PostLLMCallHook, 0),
	}
}

// AddPreHook adds a pre-call hook
func (i *Interceptor) AddPreHook(hook PreLLMCallHook) {
	i.preHooks = append(i.preHooks, hook)
}

// AddPostHook adds a post-call hook
func (i *Interceptor) AddPostHook(hook PostLLMCallHook) {
	i.postHooks = append(i.postHooks, hook)
}

// Intercept runs pre-hooks, routes call, then runs post-hooks
func (i *Interceptor) Intercept(ctx context.Context, call *LLMToolContext) (*LLMResponse, error) {
	// Run pre-hooks
	for _, hook := range i.preHooks {
		if err := hook(ctx, call); err != nil {
			return nil, fmt.Errorf("pre-hook failed: %w", err)
		}
	}

	// Route through bridge
	resp, err := i.integration.RouteLLMToolCall(ctx, call)
	if err != nil {
		return nil, err
	}

	// Run post-hooks
	for _, hook := range i.postHooks {
		hook(ctx, call, resp)
	}

	return resp, nil
}

// ============================================================================
// Utilities
// ============================================================================

// generateRequestID generates a unique request ID
func generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// DetectLLMTool is a helper to detect common LLM tools
func DetectLLMTool(toolName string, args map[string]interface{}) bool {
	integration := &MCPIntegration{enabled: true}
	return integration.IsLLMCall(toolName, args)
}
