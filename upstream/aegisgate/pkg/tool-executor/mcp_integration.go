// Package tool-executor - Tool executor integration for MCP
package toolexecutor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// MCPIntegration provides integration between MCP handler and tool executor
type MCPIntegration struct {
	manager    *Manager
	logger     *slog.Logger
	registered map[string]bool
}

// NewMCPIntegration creates a new MCP integration
func NewMCPIntegration(manager *Manager) *MCPIntegration {
	return &MCPIntegration{
		manager:    manager,
		logger:     slog.Default(),
		registered: make(map[string]bool),
	}
}

// RegisterAllTools registers all built-in tool executors
func (m *MCPIntegration) RegisterAllTools() error {
	// File tools
	fileTools := NewFileTools([]string{}, 10*1024*1024) // 10MB default

	fileToolsExecutors := []ToolExecutor{
		NewFileReadExecutor(fileTools),
		NewFileWriteExecutor(fileTools),
		NewFileDeleteExecutor(fileTools),
		NewFileExistsExecutor(fileTools),
	}

	for _, exec := range fileToolsExecutors {
		if err := m.manager.Register(exec); err != nil {
			return fmt.Errorf("failed to register %s: %w", exec.Name(), err)
		}
		m.registered[exec.Name()] = true
	}

	// Web tools
	webTools := NewWebTools([]string{}, 30*1024*1024) // 30MB default

	webToolsExecutors := []ToolExecutor{
		NewHTTPToolExecutor(webTools),
		NewWebSearchExecutor(webTools),
		NewJSONFetchExecutor(webTools),
	}

	for _, exec := range webToolsExecutors {
		if err := m.manager.Register(exec); err != nil {
			return fmt.Errorf("failed to register %s: %w", exec.Name(), err)
		}
		m.registered[exec.Name()] = true
	}

	// Shell tools (HIGH RISK - defaults blocked)
	shellTools := NewShellTools([]string{}, []string{"rm -rf", "dd if=", "mkfs"}, 120*1024*1024)

	shellToolsExecutors := []ToolExecutor{
		NewShellCommandExecutor(shellTools),
		NewBashExecutor(shellTools),
		NewPingExecutor(shellTools),
	}

	for _, exec := range shellToolsExecutors {
		if err := m.manager.Register(exec); err != nil {
			return fmt.Errorf("failed to register %s: %w", exec.Name(), err)
		}
		m.registered[exec.Name()] = true
	}

	// Code tools
	codeTools := NewCodeTools("", 60*1024*1024) // 60MB default

	codeToolsExecutors := []ToolExecutor{
		NewGoExecutor(codeTools),
		NewPythonExecutor(codeTools),
		NewJavaScriptExecutor(codeTools),
		NewCodeSearchExecutor(),
	}

	for _, exec := range codeToolsExecutors {
		if err := m.manager.Register(exec); err != nil {
			return fmt.Errorf("failed to register %s: %w", exec.Name(), err)
		}
		m.registered[exec.Name()] = true
	}

	// Database tools
	dbTools := NewDatabaseTools(30 * 1024 * 1024) // 30MB default

	dbToolsExecutors := []ToolExecutor{
		NewDatabaseQueryExecutor(dbTools),
		NewDatabaseListExecutor(dbTools),
		NewDatabaseSchemaExecutor(dbTools),
	}

	for _, exec := range dbToolsExecutors {
		if err := m.manager.Register(exec); err != nil {
			return fmt.Errorf("failed to register %s: %w", exec.Name(), err)
		}
		m.registered[exec.Name()] = true
	}

	m.logger.Info("all tool executors registered", "count", m.manager.Count())
	return nil
}

// ExecuteTool executes a tool and returns MCP-formatted result
func (m *MCPIntegration) ExecuteTool(ctx context.Context, req *MCPExecutionRequest) (*MCPExecutionResult, error) {
	execReq := &ExecutionRequest{
		ToolName:   req.ToolName,
		Parameters: req.Parameters,
		SessionID:  req.SessionID,
		AgentID:    req.AgentID,
		RequestID:  req.RequestID,
	}

	result := m.manager.Execute(ctx, execReq)

	// Format as MCP response
	mcpResult := &MCPExecutionResult{
		RequestID: result.RequestID,
		ToolName:  result.ToolName,
		Success:   result.Success,
		Error:     result.Error,
		ErrorCode: result.ErrorCode,
		Duration:  result.Duration,
		Timestamp: result.Timestamp,
	}

	if result.Success {
		mcpResult.Content = []MCPContentBlock{
			{Type: "text", Text: formatResult(result.Result)},
		}
	} else {
		mcpResult.IsError = true
		mcpResult.Content = []MCPContentBlock{
			{Type: "text", Text: result.Error},
		}
	}

	return mcpResult, nil
}

// GetRegisteredTools returns all registered tool names
func (m *MCPIntegration) GetRegisteredTools() []string {
	return m.manager.List()
}

// GetToolInfo returns information about a specific tool
func (m *MCPIntegration) GetToolInfo(name string) (*ToolExecutorInfo, bool) {
	exec, exists := m.manager.Get(name)
	if !exists {
		return nil, false
	}

	return &ToolExecutorInfo{
		Name:        exec.Name(),
		RiskLevel:   exec.RiskLevel(),
		Timeout:     exec.Timeout(),
		Description: exec.Description(),
	}, true
}

// ListTools returns all tools formatted for MCP
func (m *MCPIntegration) ListTools() []MCPTool {
	tools := make([]MCPTool, 0)
	for _, name := range m.manager.List() {
		info, exists := m.GetToolInfo(name)
		if !exists {
			continue
		}

		tools = append(tools, MCPTool{
			Name:        info.Name,
			Description: info.Description,
			InputSchema: m.buildInputSchema(info.Name),
		})
	}
	return tools
}

// buildInputSchema creates an input schema for a tool
func (m *MCPIntegration) buildInputSchema(toolName string) map[string]interface{} {
	schemas := map[string]map[string]interface{}{
		"file_read": {
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file to read",
				},
			},
			"required": []string{"path"},
		},
		"file_write": {
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to write to",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content to write",
				},
			},
			"required": []string{"path", "content"},
		},
		"file_delete": {
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to delete",
				},
			},
			"required": []string{"path"},
		},
		"file_exists": {
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to check",
				},
			},
			"required": []string{"path"},
		},
		"http_request": {
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "URL to request",
				},
				"method": map[string]interface{}{
					"type":        "string",
					"description": "HTTP method",
					"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
				},
				"body": map[string]interface{}{
					"type":        "string",
					"description": "Request body",
				},
			},
			"required": []string{"url"},
		},
		"web_search": {
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Search query",
				},
			},
			"required": []string{"query"},
		},
		"shell_command": {
			"type": "object",
			"properties": map[string]interface{}{
				"command": map[string]interface{}{
					"type":        "string",
					"description": "Shell command to execute",
				},
			},
			"required": []string{"command"},
		},
		"code_execute_go": {
			"type": "object",
			"properties": map[string]interface{}{
				"code": map[string]interface{}{
					"type":        "string",
					"description": "Go code to execute",
				},
			},
			"required": []string{"code"},
		},
		"code_execute_python": {
			"type": "object",
			"properties": map[string]interface{}{
				"code": map[string]interface{}{
					"type":        "string",
					"description": "Python code to execute",
				},
			},
			"required": []string{"code"},
		},
		"code_execute_javascript": {
			"type": "object",
			"properties": map[string]interface{}{
				"code": map[string]interface{}{
					"type":        "string",
					"description": "JavaScript code to execute",
				},
			},
			"required": []string{"code"},
		},
		"database_query": {
			"type": "object",
			"properties": map[string]interface{}{
				"connection": map[string]interface{}{
					"type":        "string",
					"description": "Database connection name",
				},
				"query": map[string]interface{}{
					"type":        "string",
					"description": "SQL query",
				},
			},
			"required": []string{"connection", "query"},
		},
	}

	if schema, ok := schemas[toolName]; ok {
		return schema
	}

	// Default schema
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

// MCP types for integration
type MCPExecutionRequest struct {
	ToolName   string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
	RequestID  string
}

type MCPExecutionResult struct {
	RequestID string
	ToolName  string
	Success   bool
	Content   []MCPContentBlock
	IsError   bool
	Error     string
	ErrorCode string
	Duration  interface{}
	Timestamp interface{}
}

type MCPContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

type ToolExecutorInfo struct {
	Name        string
	RiskLevel   int
	Timeout     interface{}
	Description string
}

// formatResult formats a result for MCP response
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
