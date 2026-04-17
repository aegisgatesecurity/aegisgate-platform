// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGuard Security - AegisGate Bridge Integration
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file integrates the AegisGate bridge into the AegisGuard MCP handler,
// enabling LLM API calls from agents to be routed through AegisGate for
// defense-in-depth security scanning.
//
// Architecture:
// ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
// │  AI Agent   │ ──────▶ │ AegisGuard   │ ──────▶ │   Tools     │
// │  (Cursor,   │         │   (MCP)      │         │  (files,    │
// │  OpenClaw)  │         │              │         │   shell)    │
// └──────────────┘         └──────┬───────┘         └──────────────┘
//                                  │                          ▲
//                                  │ LLM API Calls            │
//                                  ▼                          │
//                        ┌──────────────────┐                 │
//                        │  Bridge Module   │ ◀────────────────┘
//                        │ (mcp_integration)│
//                        └────────┬────────┘
//                                 │
//                                 ▼
//                        ┌──────────────────┐
//                        │   AegisGate     │
//                        │ (HTTP Proxy)    │
//                        └────────┬────────┘
//                                 │
//                                 ▼
//                        ┌──────────────────┐
//                        │  LLM Provider   │
//                        │ (OpenAI, etc.)  │
//                        └──────────────────┘
// =========================================================================

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/bridge"
)

// ============================================================================
// Bridge Integration
// ============================================================================

// BridgeConfig holds bridge integration configuration
type BridgeConfig struct {
	// AegisGate endpoint
	AegisGateURL string

	// Enable/disable bridge
	Enabled bool

	// Timeout for AegisGate requests
	Timeout time.Duration

	// Retry configuration
	MaxRetries    int
	RetryInterval time.Duration

	// TLS skip verify (for development)
	SkipTLSVerify bool
}

// DefaultBridgeConfig returns default bridge configuration
func DefaultBridgeConfig() *BridgeConfig {
	return &BridgeConfig{
		AegisGateURL:  "http://localhost:8080",
		Enabled:       false, // Disabled by default until user enables
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
	}
}

// BridgeIntegration handles bridge functionality for MCP handler
type BridgeIntegration struct {
	gateway     *bridge.Gateway
	interceptor *bridge.Interceptor
	config      *BridgeConfig
	logger      *slog.Logger
	enabled     bool
}

// NewBridgeIntegration creates a new bridge integration
func NewBridgeIntegration(config *BridgeConfig) (*BridgeIntegration, error) {
	if config == nil {
		config = DefaultBridgeConfig()
	}

	logger := slog.Default()

	bi := &BridgeIntegration{
		config:  config,
		logger:  logger,
		enabled: config.Enabled,
	}

	if !config.Enabled {
		logger.Info("AegisGate bridge integration disabled")
		return bi, nil
	}

	// Convert to bridge config
	bridgeConfig := &bridge.Config{
		AegisGateURL:  config.AegisGateURL,
		Timeout:       config.Timeout,
		Enabled:       config.Enabled,
		MaxRetries:    config.MaxRetries,
		RetryInterval: config.RetryInterval,
		SkipTLSVerify: config.SkipTLSVerify,
		DefaultTarget: "https://api.openai.com/v1",
	}

	// Create gateway
	gateway, err := bridge.NewGateway(bridgeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge gateway: %w", err)
	}
	bi.gateway = gateway

	// Create MCP integration
	mcpIntegration := bridge.NewMCPIntegration(gateway)

	// Create interceptor with hooks
	interceptor := bridge.NewInterceptor(mcpIntegration)
	interceptor.AddPreHook(bi.preLLMCallHook)
	interceptor.AddPostHook(bi.postLLMCallHook)

	bi.interceptor = interceptor

	logger.Info("AegisGate bridge integration initialized",
		"aegisgate_url", config.AegisGateURL,
		"enabled", config.Enabled,
	)

	return bi, nil
}

// IsEnabled returns whether bridge is enabled
func (bi *BridgeIntegration) IsEnabled() bool {
	return bi.enabled
}

// GetGateway returns the bridge gateway
func (bi *BridgeIntegration) GetGateway() *bridge.Gateway {
	return bi.gateway
}

// GetStats returns bridge statistics
func (bi *BridgeIntegration) GetStats() *bridge.Stats {
	if bi.gateway == nil {
		return nil
	}
	return bi.gateway.GetStats()
}

// Close shuts down the bridge integration
func (bi *BridgeIntegration) Close() error {
	if bi.gateway != nil {
		return bi.gateway.Close()
	}
	return nil
}

// ============================================================================
// LLM Call Detection
// ============================================================================

// Known LLM endpoints for detection
var knownLLMEndpoints = []string{
	// OpenAI
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/embeddings",
	"/v1/images",
	"/v1/audio",

	// Anthropic
	"/v1/messages",

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
func IsLLMCall(toolName string, args map[string]interface{}) bool {
	// Check tool name
	toolNameLower := strings.ToLower(toolName)
	llmIndicators := []string{"llm", "openai", "anthropic", "chat", "gpt", "claude",
		"bedrock", "cohere", "ai", "chatbot", "azure", "gemini", "mistral"}

	for _, indicator := range llmIndicators {
		if strings.Contains(toolNameLower, indicator) {
			return true
		}
	}

	// Check arguments for URL patterns
	if url, ok := args["url"].(string); ok {
		return isLLMURL(url)
	}

	if endpoint, ok := args["endpoint"].(string); ok {
		return isLLMURL(endpoint)
	}

	// Check for OpenAI-compatible API patterns
	if model, ok := args["model"].(string); ok {
		modelLower := strings.ToLower(model)
		llmModels := []string{"gpt", "claude", "llama", "mistral", "gemini", "titan",
			"command", "cohere", "palm", "bard"}

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
func isLLMURL(url string) bool {
	urlLower := strings.ToLower(url)
	for _, endpoint := range knownLLMEndpoints {
		if strings.Contains(urlLower, strings.ToLower(endpoint)) {
			return true
		}
	}
	return false
}

// ============================================================================
// Hook Implementations
// ============================================================================

// preLLMCallHook is called before routing to AegisGate
func (bi *BridgeIntegration) preLLMCallHook(ctx context.Context, call *bridge.LLMToolContext) error {
	bi.logger.Debug("Pre-LLM call hook",
		"agent_id", call.AgentID,
		"session_id", call.SessionID,
		"tool_name", call.ToolName,
	)

	// Could add additional validation or transformation here
	return nil
}

// postLLMCallHook is called after receiving response from AegisGate
func (bi *BridgeIntegration) postLLMCallHook(ctx context.Context, call *bridge.LLMToolContext, resp *bridge.LLMResponse) {
	if resp == nil {
		return
	}

	bi.logger.Debug("Post-LLM call hook",
		"agent_id", call.AgentID,
		"session_id", call.SessionID,
		"status_code", resp.StatusCode,
	)

	// Log scan results
	if resp.ScanResult != nil {
		if !resp.ScanResult.Allowed {
			bi.logger.Warn("AegisGate blocked LLM call",
				"agent_id", call.AgentID,
				"session_id", call.SessionID,
				"tool_name", call.ToolName,
				"reason", resp.ScanResult.BlockReason,
				"threats", len(resp.ScanResult.Threats),
			)
		}
	}
}

// ============================================================================
// Tool Call Routing
// ============================================================================

// RouteLLMToolCall routes an LLM tool call through AegisGate
func (bi *BridgeIntegration) RouteLLMToolCall(ctx context.Context, toolCall *bridge.LLMToolContext) (*bridge.LLMResponse, error) {
	if !bi.enabled {
		return nil, nil
	}

	if bi.interceptor == nil {
		return nil, fmt.Errorf("interceptor not initialized")
	}

	return bi.interceptor.Intercept(ctx, toolCall)
}

// ShouldIntercept returns whether a tool call should be routed through the bridge
func (bi *BridgeIntegration) ShouldIntercept(toolName string, args map[string]interface{}) bool {
	if !bi.enabled {
		return false
	}
	return IsLLMCall(toolName, args)
}

// BuildLLMToolContext builds bridge context from MCP tool call
func (bi *BridgeIntegration) BuildLLMToolContext(connID, sessionID, agentID, toolName string, args map[string]interface{}) *bridge.LLMToolContext {
	return &bridge.LLMToolContext{
		AgentID:   agentID,
		SessionID: sessionID,
		ToolName:  toolName,
		ToolArgs:  args,
	}
}

// ============================================================================
// MCP Handler Bridge Extension
// ============================================================================

// LLMToolResult represents the result of an LLM tool call with bridge metadata
type LLMToolResult struct {
	// Raw response from LLM
	Content []ContentBlock
	IsError bool

	// Bridge metadata
	Blocked      bool
	BlockReason  string
	Threats      []bridge.Threat
	RiskScore    float64
	ScannedBy    string // "aegisgate"
	ScanDuration time.Duration
}

// ProcessLLMToolCall processes an LLM tool call through the bridge
func (bi *BridgeIntegration) ProcessLLMToolCall(
	ctx context.Context,
	connID, sessionID, agentID string,
	toolName string,
	args map[string]interface{},
) (*LLMToolResult, error) {
	result := &LLMToolResult{
		ScannedBy: "aegisgate",
	}

	// Build tool context
	toolCtx := bi.BuildLLMToolContext(connID, sessionID, agentID, toolName, args)

	// Route through bridge
	startTime := time.Now()
	resp, err := bi.RouteLLMToolCall(ctx, toolCtx)
	result.ScanDuration = time.Since(startTime)

	if err != nil {
		return nil, fmt.Errorf("bridge routing failed: %w", err)
	}

	// Process response
	if resp == nil {
		// Bridge not enabled or bypassed
		return nil, nil
	}

	// Extract scan result
	if resp.ScanResult != nil {
		result.Threats = resp.ScanResult.Threats
		result.RiskScore = resp.ScanResult.RiskScore
		result.Blocked = !resp.ScanResult.Allowed
		result.BlockReason = resp.ScanResult.BlockReason
	}

	// Check if blocked
	if result.Blocked {
		result.Content = []ContentBlock{
			{
				Type: "text",
				Text: fmt.Sprintf("LLM call blocked by AegisGate: %s", result.BlockReason),
			},
		}
		result.IsError = true
		return result, nil
	}

	// Return LLM response
	result.Content = []ContentBlock{
		{
			Type: "text",
			Text: string(resp.Body),
		},
	}
	result.IsError = resp.StatusCode >= 400

	return result, nil
}

// ============================================================================
// Unified Audit Integration
// ============================================================================

// AuditBridgeEvent logs a bridge event to the unified audit trail
func (bi *BridgeIntegration) AuditBridgeEvent(ctx context.Context, eventType string, call *bridge.LLMToolContext, resp *bridge.LLMResponse) {
	if !bi.enabled {
		return
	}

	// Build audit event
	action := "bridge:" + eventType
	allowed := true
	reason := ""

	if resp != nil && resp.ScanResult != nil {
		allowed = resp.ScanResult.Allowed
		if !allowed {
			reason = resp.ScanResult.BlockReason
		}
	}

	bi.logger.Info("Bridge audit event",
		"action", action,
		"agent_id", call.AgentID,
		"session_id", call.SessionID,
		"tool_name", call.ToolName,
		"allowed", allowed,
		"reason", reason,
	)
}

func BuildLLMRequestBody(args map[string]interface{}) ([]byte, string, error) {
	body := make(map[string]interface{})

	// Common fields
	if model, ok := args["model"].(string); ok {
		body["model"] = model
	}

	// Messages or prompt
	if messages, ok := args["messages"].([]interface{}); ok {
		body["messages"] = messages
	} else if prompt, ok := args["prompt"].(string); ok {
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
	if stop, ok := args["stop"].([]string); ok {
		body["stop"] = stop
	}
	if stream, ok := args["stream"].(bool); ok {
		body["stream"] = stream
	}

	// Serialize to JSON
	data, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}

	// Determine content type
	contentType := "application/json"

	return data, contentType, nil
}
