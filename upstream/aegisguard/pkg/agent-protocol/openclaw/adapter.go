// Package openclaw provides OpenClaw protocol adapters
package openclaw

import (
	"context"
	"fmt"

	agentprotocol "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol"
)

// Adapter converts between OpenClaw and MCP protocols
type Adapter struct {
	parser *Parser
}

// NewAdapter creates a new OpenClaw to MCP adapter
func NewAdapter() *Adapter {
	return &Adapter{
		parser: NewParser(),
	}
}

// ToMCP converts an OpenClaw message to MCP format
func (a *Adapter) ToMCP(ctx context.Context, msg *OpenClawMessage) (*agentprotocol.ToolCall, error) {
	if msg.Action != "tool.call" {
		return nil, fmt.Errorf("unsupported action: %s", msg.Action)
	}

	toolCall := &agentprotocol.ToolCall{
		ID:         getString(msg.Payload, "id"),
		Name:       getString(msg.Payload, "name"),
		Parameters: msg.Payload["args"].(map[string]interface{}),
		SessionID:  getString(msg.Meta, "session_id"),
		AgentID:    getString(msg.Meta, "agent_id"),
	}

	return toolCall, nil
}

// FromMCP converts an MCP message to OpenClaw format
func (a *Adapter) FromMCP(ctx context.Context, call *agentprotocol.ToolCall) (*OpenClawMessage, error) {
	msg := &OpenClawMessage{
		Type:    "tool",
		Action:  "tool.call",
		Payload: call.Parameters,
		Meta: map[string]interface{}{
			"session_id": call.SessionID,
			"agent_id":   call.AgentID,
			"tool_name":  call.Name,
		},
	}

	return msg, nil
}

// ConvertToolCall converts a tool call between protocols
func (a *Adapter) ConvertToolCall(toolCall *ToolCall) (*agentprotocol.ToolCall, error) {
	return &agentprotocol.ToolCall{
		ID:         toolCall.Name + "-converted",
		Name:       toolCall.Name,
		Parameters: toolCall.Args,
		SessionID:  toolCall.SessionID,
	}, nil
}

// GetCapabilities returns the adapter's supported capabilities
func (a *Adapter) GetCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"protocol_version": "1.0",
		"supported_actions": []string{
			"tool.call",
			"tool.list",
			"resource.list",
			"session.create",
			"session.end",
		},
	}
}

// Helper to safely get string from map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
