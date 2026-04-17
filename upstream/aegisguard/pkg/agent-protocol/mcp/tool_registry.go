// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// MCP Tool Registry - Manages MCP tools and tool handlers
// =========================================================================

package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ToolRegistry manages MCP tools and their handlers
type ToolRegistry struct {
	mu       sync.RWMutex
	tools    map[string]*registryTool
	handlers map[string]ToolHandlerFunc
	logger   *slog.Logger
}

// registryTool represents an internal tool with risk level
type registryTool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	RiskLevel   int
	Executor    string
}

// ToolHandlerFunc is a function that executes a tool
type ToolHandlerFunc func(ctx context.Context, params map[string]interface{}) (interface{}, error)

// NewToolRegistry creates a new MCP tool registry
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools:    make(map[string]*registryTool),
		handlers: make(map[string]ToolHandlerFunc),
		logger:   slog.Default(),
	}
}

// Register registers a tool with metadata
func (r *ToolRegistry) Register(name string, desc string, riskLevel int, inputSchema map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if name == "" {
		return fmt.Errorf("tool name is required")
	}
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool already registered: %s", name)
	}

	r.tools[name] = &registryTool{
		Name:        name,
		Description: desc,
		RiskLevel:   riskLevel,
		InputSchema: inputSchema,
		Executor:    name,
	}
	r.logger.Debug("MCP tool registered", "name", name, "risk", riskLevel)

	return nil
}

// RegisterHandler registers a tool handler
func (r *ToolRegistry) RegisterHandler(name string, handler ToolHandlerFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if name == "" {
		return fmt.Errorf("tool name is required")
	}
	r.handlers[name] = handler
	return nil
}

// ListTools returns all registered tool names
func (r *ToolRegistry) ListTools() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// GetTool returns a tool by name
func (r *ToolRegistry) GetTool(name string) (*registryTool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	return tool, ok
}

// GetHandler returns a tool handler by name
func (r *ToolRegistry) GetHandler(name string) (ToolHandlerFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	handler, ok := r.handlers[name]
	return handler, ok
}

// Execute executes a tool by name
func (r *ToolRegistry) Execute(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	handler, ok := r.GetHandler(name)
	if !ok {
		return nil, fmt.Errorf("tool handler not found: %s", name)
	}
	return handler(ctx, params)
}

// ToMCPFormat converts tools to MCP Tool format
func (r *ToolRegistry) ToMCPFormat() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return tools
}

// GetRiskLevel returns the risk level for a tool
func (r *ToolRegistry) GetRiskLevel(name string) int {
	tool, ok := r.GetTool(name)
	if !ok {
		return 100 // Unknown tools are high risk
	}
	return tool.RiskLevel
}

// Count returns the number of registered tools
func (r *ToolRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// RegisterDefaultTools registers the default set of tools
func (r *ToolRegistry) RegisterDefaultTools() {
	defaults := []struct {
		name    string
		desc    string
		risk    int
		schema  map[string]interface{}
		handler ToolHandlerFunc
	}{
		{"file_read", "Read contents of a file", 10, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "Path to the file"},
			},
			"required": []string{"path"},
		}, nil},
		{"file_write", "Write content to a file", 30, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":    map[string]interface{}{"type": "string", "description": "Path to the file"},
				"content": map[string]interface{}{"type": "string", "description": "Content to write"},
			},
			"required": []string{"path", "content"},
		}, nil},
		{"file_exists", "Check if a file exists", 5, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "Path to check"},
			},
			"required": []string{"path"},
		}, nil},
		{"web_search", "Search the web", 10, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{"type": "string", "description": "Search query"},
			},
			"required": []string{"query"},
		}, nil},
		{"http_request", "Make an HTTP request", 40, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"method": map[string]interface{}{"type": "string", "description": "HTTP method"},
				"url":    map[string]interface{}{"type": "string", "description": "Request URL"},
			},
			"required": []string{"method", "url"},
		}, nil},
		{"shell_command", "Execute a shell command", 90, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"command": map[string]interface{}{"type": "string", "description": "Command to execute"},
			},
			"required": []string{"command"},
		}, nil},
		{"code_search", "Search code in files", 10, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pattern": map[string]interface{}{"type": "string", "description": "Search pattern"},
				"path":    map[string]interface{}{"type": "string", "description": "Path to search"},
			},
			"required": []string{"pattern"},
		}, nil},
		{"ping", "Ping a host", 5, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host": map[string]interface{}{"type": "string", "description": "Host to ping"},
			},
			"required": []string{"host"},
		}, nil},

		// ===== DATABASE TOOLS (risk 30-60) =====
		{"db_query", "Execute a database query", 60, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"connection": map[string]interface{}{"type": "string", "description": "Database connection string"},
				"query":      map[string]interface{}{"type": "string", "description": "SQL query to execute"},
				"timeout":    map[string]interface{}{"type": "number", "description": "Query timeout in seconds"},
			},
			"required": []string{"connection", "query"},
		}, nil},
		{"db_list", "List databases or tables", 35, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"connection": map[string]interface{}{"type": "string", "description": "Database connection string"},
				"type":       map[string]interface{}{"type": "string", "description": "Type: databases or tables", "enum": []string{"databases", "tables"}},
				"database":   map[string]interface{}{"type": "string", "description": "Database name (for tables)"},
			},
			"required": []string{"connection", "type"},
		}, nil},
		{"db_schema", "Get database schema information", 30, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"connection": map[string]interface{}{"type": "string", "description": "Database connection string"},
				"database":   map[string]interface{}{"type": "string", "description": "Database name"},
				"table":      map[string]interface{}{"type": "string", "description": "Table name (optional)"},
			},
			"required": []string{"connection", "database"},
		}, nil},

		// ===== CODE EXECUTION TOOLS (risk 60-80) =====
		{"code_execute_go", "Execute Go code in a sandboxed environment", 70, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"code":    map[string]interface{}{"type": "string", "description": "Go code to execute"},
				"timeout": map[string]interface{}{"type": "number", "description": "Execution timeout in seconds (default: 30)"},
			},
			"required": []string{"code"},
		}, nil},
		{"code_execute_py", "Execute Python code in a sandboxed environment", 65, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"code":    map[string]interface{}{"type": "string", "description": "Python code to execute"},
				"timeout": map[string]interface{}{"type": "number", "description": "Execution timeout in seconds (default: 30)"},
			},
			"required": []string{"code"},
		}, nil},
		{"code_execute_js", "Execute JavaScript code in a sandboxed environment", 60, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"code":    map[string]interface{}{"type": "string", "description": "JavaScript code to execute"},
				"timeout": map[string]interface{}{"type": "number", "description": "Execution timeout in seconds (default: 30)"},
			},
			"required": []string{"code"},
		}, nil},

		// ===== SYSTEM TOOLS (risk 30-70) =====
		{"process_list", "List running processes", 40, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"filter": map[string]interface{}{"type": "string", "description": "Filter processes by name"},
				"limit":  map[string]interface{}{"type": "number", "description": "Maximum number of processes to return"},
			},
		}, nil},
		{"memory_stats", "Get system memory statistics", 30, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"detailed": map[string]interface{}{"type": "boolean", "description": "Include detailed breakdown"},
			},
		}, nil},
		{"network_connections", "List active network connections", 50, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"protocol": map[string]interface{}{"type": "string", "description": "Filter by protocol (tcp, udp, all)", "default": "all"},
				"state":    map[string]interface{}{"type": "string", "description": "Filter by connection state"},
			},
		}, nil},
		{"system_info", "Get system information", 25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"info_type": map[string]interface{}{"type": "string", "description": "Type of info (os, cpu, disk, all)", "default": "all"},
			},
		}, nil},

		// ===== FILE MANAGEMENT TOOLS (risk 20-40) =====
		{"file_copy", "Copy a file or directory", 20, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source":      map[string]interface{}{"type": "string", "description": "Source path"},
				"destination": map[string]interface{}{"type": "string", "description": "Destination path"},
			},
			"required": []string{"source", "destination"},
		}, nil},
		{"file_move", "Move or rename a file or directory", 25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source":      map[string]interface{}{"type": "string", "description": "Source path"},
				"destination": map[string]interface{}{"type": "string", "description": "Destination path"},
			},
			"required": []string{"source", "destination"},
		}, nil},
		{"file_delete", "Delete a file or directory", 35, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":      map[string]interface{}{"type": "string", "description": "Path to delete"},
				"recursive": map[string]interface{}{"type": "boolean", "description": "Delete directories recursively"},
			},
			"required": []string{"path"},
		}, nil},
		{"file_mkdir", "Create a directory", 25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":      map[string]interface{}{"type": "string", "description": "Directory path to create"},
				"recursive": map[string]interface{}{"type": "boolean", "description": "Create parent directories if needed"},
			},
			"required": []string{"path"},
		}, nil},

		// ===== GIT TOOLS (risk 20-50) =====
		{"git_status", "Get git repository status", 15, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "Repository path"},
			},
			"required": []string{"path"},
		}, nil},
		{"git_log", "Get git commit history", 15, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":   map[string]interface{}{"type": "string", "description": "Repository path"},
				"limit":  map[string]interface{}{"type": "number", "description": "Maximum commits to return"},
				"branch": map[string]interface{}{"type": "string", "description": "Branch name"},
			},
			"required": []string{"path"},
		}, nil},
		{"git_diff", "Get git diff between commits or files", 20, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "Repository path"},
				"from": map[string]interface{}{"type": "string", "description": "Start commit/branch"},
				"to":   map[string]interface{}{"type": "string", "description": "End commit/branch"},
				"file": map[string]interface{}{"type": "string", "description": "Specific file to diff"},
			},
			"required": []string{"path"},
		}, nil},
	}

	for _, d := range defaults {
		if err := r.Register(d.name, d.desc, d.risk, d.schema); err != nil {
			r.logger.Error("failed to register default tool", "name", d.name, "error", err)
		}
	}
}

func generateRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano()%1000000)
}
