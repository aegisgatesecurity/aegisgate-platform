// Package tool-executor - Tool execution service for AegisGuard
// Provides secure execution of AI agent tool calls with authorization
package toolexecutor

import (
	"context"
	"time"
)

// ToolExecutor is the interface for executing tools
type ToolExecutor interface {
	// Name returns the tool name this executor handles
	Name() string

	// Execute runs the tool with given parameters
	Execute(ctx context.Context, params map[string]interface{}) (interface{}, error)

	// Validate checks if parameters are valid before execution
	Validate(params map[string]interface{}) error

	// Timeout returns the maximum execution time allowed
	Timeout() time.Duration

	// RiskLevel returns the risk level (1-100)
	RiskLevel() int

	// Description returns a human-readable description
	Description() string
}

// ExecutionRequest represents a tool execution request
type ExecutionRequest struct {
	ToolName   string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
	RequestID  string
}

// ExecutionResult represents the result of tool execution
type ExecutionResult struct {
	RequestID string
	ToolName  string
	Success   bool
	Result    interface{}
	Error     string
	ErrorCode string
	Duration  time.Duration
	Timestamp time.Time
}

// ExecutionContext contains context for tool execution
type ExecutionContext struct {
	SessionID string
	AgentID   string
	RequestID string
	Timeout   time.Duration
	Metadata  map[string]interface{}
}

// ToolCategory categorizes tools by type
type ToolCategory string

const (
	CategoryFile     ToolCategory = "file"
	CategoryWeb      ToolCategory = "web"
	CategoryShell    ToolCategory = "shell"
	CategoryCode     ToolCategory = "code"
	CategoryDatabase ToolCategory = "database"
	CategorySystem   ToolCategory = "system"
)

// RiskLevel represents tool risk levels
type RiskLevel int

const (
	RiskLow      RiskLevel = 25
	RiskMedium   RiskLevel = 50
	RiskHigh     RiskLevel = 75
	RiskCritical RiskLevel = 100
)

// DefaultTimeouts returns default timeouts by risk level
func DefaultTimeout(risk RiskLevel) time.Duration {
	switch risk {
	case RiskLow:
		return 30 * time.Second
	case RiskMedium:
		return 60 * time.Second
	case RiskHigh:
		return 120 * time.Second
	case RiskCritical:
		return 180 * time.Second
	default:
		return 60 * time.Second
	}
}
