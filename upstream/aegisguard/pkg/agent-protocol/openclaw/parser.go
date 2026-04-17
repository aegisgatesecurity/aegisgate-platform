// Package openclaw provides OpenClaw agent protocol support
package openclaw

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenClawMessage represents an OpenClaw protocol message
type OpenClawMessage struct {
	Type    string                 `json:"type"`
	Action  string                 `json:"action"`
	Payload map[string]interface{} `json:"payload"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// Parser parses OpenClaw protocol messages
type Parser struct{}

// NewParser creates a new OpenClaw parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseMessage parses an OpenClaw message from JSON bytes
func (p *Parser) ParseMessage(data []byte) (*OpenClawMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message data")
	}

	// Try to parse as OpenClaw format first
	var msg OpenClawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse OpenClaw message: %w", err)
	}

	// Validate required fields
	if err := p.validateMessage(&msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// validateMessage ensures required fields are present
func (p *Parser) validateMessage(msg *OpenClawMessage) error {
	if msg.Type == "" {
		return fmt.Errorf("missing required field: type")
	}
	if msg.Action == "" {
		return fmt.Errorf("missing required field: action")
	}
	if msg.Payload == nil {
		return fmt.Errorf("missing required field: payload")
	}
	return nil
}

// ParseToolCall extracts a tool call from an OpenClaw message
func (p *Parser) ParseToolCall(msg *OpenClawMessage) (*ToolCall, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message")
	}

	// Validate message type for tool call
	validTypes := map[string]bool{
		"tool":    true,
		"action":  true,
		"request": true,
	}
	if !validTypes[msg.Type] {
		return nil, fmt.Errorf("invalid message type for tool call: %s", msg.Type)
	}

	// Validate action
	validActions := map[string]bool{
		"tool.call":    true,
		"tool.execute": true,
		"execute":      true,
		"call":         true,
	}
	if !validActions[msg.Action] {
		return nil, fmt.Errorf("invalid action for tool call: %s", msg.Action)
	}

	// Extract tool name
	toolName := extractString(msg.Payload, "name")
	if toolName == "" {
		// Try alternate field names
		toolName = extractString(msg.Payload, "tool")
		if toolName == "" {
			toolName = extractString(msg.Payload, "tool_name")
		}
	}
	if toolName == "" {
		return nil, fmt.Errorf("missing tool name in payload")
	}

	// Extract arguments
	args := extractMap(msg.Payload, "args")
	if args == nil {
		// Try alternate field names
		args = extractMap(msg.Payload, "arguments")
		if args == nil {
			args = extractMap(msg.Payload, "params")
		}
	}

	// Extract session ID
	sessionID := extractString(msg.Meta, "session_id")
	if sessionID == "" {
		sessionID = extractString(msg.Meta, "sessionId")
	}

	// Extract context ID
	contextID := extractString(msg.Meta, "context_id")
	if contextID == "" {
		contextID = extractString(msg.Meta, "contextId")
	}

	return &ToolCall{
		Name:       toolName,
		Args:       args,
		SessionID:  sessionID,
		ContextID:  contextID,
		ActionType: msg.Action,
	}, nil
}

// ParseBatch parses multiple OpenClaw messages from a batch request
func (p *Parser) ParseBatch(data []byte) ([]*OpenClawMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty batch data")
	}

	// Check if it's a batch (array) or single message
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var messages []*OpenClawMessage
		if err := json.Unmarshal(data, &messages); err != nil {
			return nil, fmt.Errorf("failed to parse batch: %w", err)
		}
		return messages, nil
	}

	// Single message
	msg, err := p.ParseMessage(data)
	if err != nil {
		return nil, err
	}
	return []*OpenClawMessage{msg}, nil
}

// ValidatePayload checks if payload contains required tool call fields
func (p *Parser) ValidatePayload(payload map[string]interface{}, requiredFields []string) error {
	if payload == nil {
		return fmt.Errorf("payload is nil")
	}

	for _, field := range requiredFields {
		if _, exists := payload[field]; !exists {
			return fmt.Errorf("missing required payload field: %s", field)
		}
	}
	return nil
}

// ToolCall represents an OpenClaw tool call
type ToolCall struct {
	Name       string
	Args       map[string]interface{}
	SessionID  string
	ContextID  string
	ActionType string
}

// ToJSON serializes the tool call back to JSON
func (tc *ToolCall) ToJSON() ([]byte, error) {
	msg := &OpenClawMessage{
		Type:    "tool",
		Action:  tc.ActionType,
		Payload: tc.Args,
		Meta: map[string]interface{}{
			"session_id": tc.SessionID,
			"context_id": tc.ContextID,
			"name":       tc.Name,
		},
	}
	return json.Marshal(msg)
}

// GetArg retrieves a typed argument from the tool call
func (tc *ToolCall) GetArg(key string) (interface{}, bool) {
	if tc.Args == nil {
		return nil, false
	}
	val, ok := tc.Args[key]
	return val, ok
}

// GetStringArg retrieves a string argument
func (tc *ToolCall) GetStringArg(key string) (string, bool) {
	val, ok := tc.GetArg(key)
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetIntArg retrieves an integer argument
func (tc *ToolCall) GetIntArg(key string) (int, bool) {
	val, ok := tc.GetArg(key)
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

// GetBoolArg retrieves a boolean argument
func (tc *ToolCall) GetBoolArg(key string) (bool, bool) {
	val, ok := tc.GetArg(key)
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// Helper to safely extract string from map
func extractString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Helper to safely extract map from map
func extractMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}
