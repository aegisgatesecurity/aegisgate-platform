// Package agentprotocol - Common types for AI agent protocols
package agentprotocol

import (
	"time"
)

// ToolCall represents an agent tool invocation
type ToolCall struct {
	ID          string
	Name        string
	Parameters  map[string]interface{}
	SessionID   string
	Timestamp   time.Time
	AgentID     string
	RiskScore   int
	Approved    bool
	PolicyMatch []string
}

// ToolResult represents the result of a tool call
type ToolResult struct {
	ToolCall *ToolCall
	Success  bool
	Output   interface{}
	Error    error
	Duration time.Duration
}

// SessionInfo contains information about an agent session
type SessionInfo struct {
	ID           string
	AgentID      string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ToolCount    int
	LastActivity time.Time
	Tags         map[string]string
}
