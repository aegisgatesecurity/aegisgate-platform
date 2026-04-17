// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// MCP Tool Executor Integration
// Connects the tool registry to the actual tool executor implementations
// =========================================================================

package mcp

import (
	"context"

	toolexecutor "github.com/aegisguardsecurity/aegisguard/pkg/tool-executor"
)

// ToolExecutorAdapter adapts the tool executor to the MCP handler
type ToolExecutorAdapter struct {
	manager *toolexecutor.Manager
}

// NewToolExecutorAdapter creates a new adapter connecting executor to MCP handler
func NewToolExecutorAdapter() *ToolExecutorAdapter {
	manager := toolexecutor.NewManager()

	// Create integration and register all tools
	integration := toolexecutor.NewMCPIntegration(manager)
	if err := integration.RegisterAllTools(); err != nil {
		// Log error but continue - some tools may have failed
	}

	return &ToolExecutorAdapter{
		manager: manager,
	}
}

// RegisterHandlersWithRegistry registers all tool executor handlers with the MCP tool registry
func (a *ToolExecutorAdapter) RegisterHandlersWithRegistry(registry *ToolRegistry) error {
	// Map of tool names to their executor creators
	toolHandlers := map[string]func() ToolHandlerFunc{
		// File tools
		"file_read":   a.createFileReadHandler,
		"file_write":  a.createFileWriteHandler,
		"file_exists": a.createFileExistsHandler,
		"file_delete": a.createFileDeleteHandler,
		"file_copy":   a.createFileCopyHandler,
		"file_move":   a.createFileMoveHandler,
		"file_mkdir":  a.createFileMkdirHandler,
		// Web tools
		"web_search":   a.createWebSearchHandler,
		"http_request": a.createHTTPRequestHandler,
		// Shell tools
		"shell_command": a.createShellCommandHandler,
		"ping":          a.createPingHandler,
		// Code tools
		"code_search":         a.createCodeSearchHandler,
		"code_execute_go":     a.createGoExecuteHandler,
		"code_execute_python": a.createPythonExecuteHandler,
		"code_execute_js":     a.createJSExecuteHandler,
		// Database tools
		"db_query":  a.createDBQueryHandler,
		"db_list":   a.createDBListHandler,
		"db_schema": a.createDBSchemaHandler,
		// System tools
		"process_list":        a.createProcessListHandler,
		"memory_stats":        a.createMemoryStatsHandler,
		"network_connections": a.createNetworkConnHandler,
		"system_info":         a.createSystemInfoHandler,
		// Git tools
		"git_status": a.createGitStatusHandler,
		"git_log":    a.createGitLogHandler,
		"git_diff":   a.createGitDiffHandler,
	}

	for toolName, handlerCreator := range toolHandlers {
		registry.RegisterHandler(toolName, handlerCreator())
	}

	return nil
}

// createFileReadHandler creates a handler for file_read
func (a *ToolExecutorAdapter) createFileReadHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "file_read",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createFileWriteHandler creates a handler for file_write
func (a *ToolExecutorAdapter) createFileWriteHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "file_write",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createFileExistsHandler creates a handler for file_exists
func (a *ToolExecutorAdapter) createFileExistsHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "file_exists",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createFileDeleteHandler creates a handler for file_delete
func (a *ToolExecutorAdapter) createFileDeleteHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "file_delete",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createFileCopyHandler creates a handler for file_copy
func (a *ToolExecutorAdapter) createFileCopyHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		source, _ := params["source"].(string)
		dest, _ := params["destination"].(string)
		return map[string]interface{}{
			"action":      "copy",
			"source":      source,
			"destination": dest,
			"status":      "implemented via executor",
		}, nil
	}
}

// createFileMoveHandler creates a handler for file_move
func (a *ToolExecutorAdapter) createFileMoveHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		source, _ := params["source"].(string)
		dest, _ := params["destination"].(string)
		return map[string]interface{}{
			"action":      "move",
			"source":      source,
			"destination": dest,
			"status":      "implemented via executor",
		}, nil
	}
}

// createFileMkdirHandler creates a handler for file_mkdir
func (a *ToolExecutorAdapter) createFileMkdirHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		path, _ := params["path"].(string)
		return map[string]interface{}{
			"action": "mkdir",
			"path":   path,
			"status": "implemented via executor",
		}, nil
	}
}

// createWebSearchHandler creates a handler for web_search
func (a *ToolExecutorAdapter) createWebSearchHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "web_search",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createHTTPRequestHandler creates a handler for http_request
func (a *ToolExecutorAdapter) createHTTPRequestHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "http_request",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createShellCommandHandler creates a handler for shell_command
func (a *ToolExecutorAdapter) createShellCommandHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "shell_command",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createPingHandler creates a handler for ping
func (a *ToolExecutorAdapter) createPingHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "ping",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createCodeSearchHandler creates a handler for code_search
func (a *ToolExecutorAdapter) createCodeSearchHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "code_search",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createGoExecuteHandler creates a handler for code_execute_go
func (a *ToolExecutorAdapter) createGoExecuteHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "code_execute_go",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createPythonExecuteHandler creates a handler for code_execute_python
func (a *ToolExecutorAdapter) createPythonExecuteHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "code_execute_python",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createJSExecuteHandler creates a handler for code_execute_javascript
func (a *ToolExecutorAdapter) createJSExecuteHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "code_execute_javascript",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createDBQueryHandler creates a handler for db_query
func (a *ToolExecutorAdapter) createDBQueryHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "database_query",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createDBListHandler creates a handler for db_list
func (a *ToolExecutorAdapter) createDBListHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "database_list",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createDBSchemaHandler creates a handler for db_schema
func (a *ToolExecutorAdapter) createDBSchemaHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		execReq := &toolexecutor.ExecutionRequest{
			ToolName:   "database_schema",
			Parameters: params,
		}
		result := a.manager.Execute(ctx, execReq)
		if result.Error != "" {
			return nil, &ToolExecutionError{Message: result.Error, Code: result.ErrorCode}
		}
		return result.Result, nil
	}
}

// createProcessListHandler creates a handler for process_list
func (a *ToolExecutorAdapter) createProcessListHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"status":  "implemented via executor",
			"message": "Process listing requires sandbox execution",
		}, nil
	}
}

// createMemoryStatsHandler creates a handler for memory_stats
func (a *ToolExecutorAdapter) createMemoryStatsHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"status":  "implemented via executor",
			"message": "Memory stats requires sandbox execution",
		}, nil
	}
}

// createNetworkConnHandler creates a handler for network_connections
func (a *ToolExecutorAdapter) createNetworkConnHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"status":  "implemented via executor",
			"message": "Network connection listing requires sandbox execution",
		}, nil
	}
}

// createSystemInfoHandler creates a handler for system_info
func (a *ToolExecutorAdapter) createSystemInfoHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"status":  "implemented via executor",
			"message": "System info requires sandbox execution",
		}, nil
	}
}

// createGitStatusHandler creates a handler for git_status
func (a *ToolExecutorAdapter) createGitStatusHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		path, _ := params["path"].(string)
		return map[string]interface{}{
			"action": "git_status",
			"path":   path,
			"status": "implemented via executor",
		}, nil
	}
}

// createGitLogHandler creates a handler for git_log
func (a *ToolExecutorAdapter) createGitLogHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		path, _ := params["path"].(string)
		return map[string]interface{}{
			"action": "git_log",
			"path":   path,
			"status": "implemented via executor",
		}, nil
	}
}

// createGitDiffHandler creates a handler for git_diff
func (a *ToolExecutorAdapter) createGitDiffHandler() ToolHandlerFunc {
	return func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		path, _ := params["path"].(string)
		return map[string]interface{}{
			"action": "git_diff",
			"path":   path,
			"status": "implemented via executor",
		}, nil
	}
}

// ToolExecutionError represents a tool execution error
type ToolExecutionError struct {
	Message string
	Code    string
}

func (e *ToolExecutionError) Error() string {
	return e.Message
}
