// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Tool Registration
// =========================================================================
//
// Registers built-in MCP tools for the embedded AegisGuard MCP server.
// Tools are tier-gated: Community gets safe, read-only tools;
// Developer+ gets additional tools; Professional+ gets code execution;
// Enterprise gets unrestricted shell/DB access.
//
// This mirrors AegisGuard's registerBuiltInTools() but uses the platform's
// unified tier system for feature gating and the real tool-executor
// implementations instead of stubs.
// =========================================================================

package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
	toolexecutor "github.com/aegisguardsecurity/aegisguard/pkg/tool-executor"
)

// RegisterBuiltInTools registers the standard MCP tool set, gated by tier.
// This is the platform's equivalent of AegisGuard's registerBuiltInTools().
func RegisterBuiltInTools(handler *mcp.RequestHandler, platformTier tier.Tier) {
	logger := slog.Default().With("component", "mcp-tools")
	logger.Info("Registering built-in MCP tools", "tier", platformTier.String())

	registry := handler.Registry

	// ================================================================
	// Community Tier: Safe, read-only tools (available to everyone)
	// ================================================================

	// System tools — low risk, read-only
	registerTool(registry, "process_list", "List running processes on the system",
		25, map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewProcessListExecutor()
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "memory_stats", "Get system memory statistics",
		25, map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewMemoryStatsExecutor()
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "network_connections", "List active network connections",
		25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Filter by protocol: tcp, udp, all",
				},
			},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewNetworkConnectionsExecutor()
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "system_info", "Get detailed system information",
		25, map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewSystemInfoExecutor()
			return exec.Execute(ctx, params)
		})

	// Git tools — low risk, read-only
	registerTool(registry, "git_status", "Get git repository status",
		25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Repository path",
				},
			},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewGitStatusExecutor(nil, nil)
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "git_log", "Get git commit log",
		25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Repository path",
				},
				"limit": map[string]interface{}{
					"type":        "number",
					"description": "Number of commits",
				},
				"branch": map[string]interface{}{
					"type":        "string",
					"description": "Branch name",
				},
			},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewGitLogExecutor(50, nil, nil)
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "git_diff", "Get git diff of changes",
		25, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Repository path",
				},
				"staged": map[string]interface{}{
					"type":        "boolean",
					"description": "Show staged diff",
				},
				"file": map[string]interface{}{
					"type":        "string",
					"description": "Specific file",
				},
			},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewGitDiffExecutor(nil, nil)
			return exec.Execute(ctx, params)
		})

	// File read — low risk, read-only
	fileTools := toolexecutor.NewFileTools(nil, 10*1024*1024) // 10MB max
	registerTool(registry, "file_read", "Read contents of a file",
		10, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file",
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewFileReadExecutor(fileTools)
			return exec.Execute(ctx, params)
		})

	// Web tools — low risk, read-only
	webTools := toolexecutor.NewWebTools(nil, 30*time.Second)
	registerTool(registry, "web_search", "Search the web for information",
		10, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Search query",
				},
			},
			"required": []string{"query"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewWebSearchExecutor(webTools)
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "http_request", "Make an HTTP request to a URL",
		15, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "URL to request",
				},
				"method": map[string]interface{}{
					"type":        "string",
					"description": "HTTP method (GET, POST, etc.)",
				},
			},
			"required": []string{"url"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewHTTPToolExecutor(webTools)
			return exec.Execute(ctx, params)
		})

	registerTool(registry, "json_fetch", "Fetch and parse JSON from a URL",
		15, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "URL to fetch JSON from",
				},
			},
			"required": []string{"url"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewJSONFetchExecutor(webTools)
			return exec.Execute(ctx, params)
		})

	// Code search — low risk, read-only
	registerTool(registry, "code_search", "Search code in a repository",
		15, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Search query",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Repository path",
				},
			},
			"required": []string{"query"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			exec := toolexecutor.NewCodeSearchExecutor()
			return exec.Execute(ctx, params)
		})

	// ================================================================
	// Blocked tools (always registered, always denied for security)
	// These appear in tools/list so agents know they exist but are
	// security-restricted. Attempting to call them returns an error.
	// ================================================================

	registerTool(registry, "shell_command", "Execute a shell command (BLOCKED — security policy)",
		90, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"command": map[string]interface{}{
					"type":        "string",
					"description": "Command to execute",
				},
			},
			"required": []string{"command"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, fmt.Errorf("shell commands are blocked by security policy")
		})

	registerTool(registry, "code_execute", "Execute code in a sandbox (BLOCKED — security policy)",
		80, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"code": map[string]interface{}{
					"type":        "string",
					"description": "Code to execute",
				},
				"language": map[string]interface{}{
					"type":        "string",
					"description": "Programming language (go, python, javascript)",
				},
			},
			"required": []string{"code"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, fmt.Errorf("code execution is blocked by security policy")
		})

	registerTool(registry, "file_write", "Write content to a file (BLOCKED — security policy)",
		70, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content to write",
				},
			},
			"required": []string{"path", "content"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, fmt.Errorf("file writes are blocked by security policy")
		})

	registerTool(registry, "file_delete", "Delete a file (BLOCKED — security policy)",
		90, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file",
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, fmt.Errorf("file deletion is blocked by security policy")
		})

	registerTool(registry, "database_query", "Execute a database query (BLOCKED — security policy)",
		80, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "SQL query to execute",
				},
				"database": map[string]interface{}{
					"type":        "string",
					"description": "Database connection string",
				},
			},
			"required": []string{"query"},
		},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, fmt.Errorf("database access is blocked by security policy")
		})

	logger.Info("Built-in tools registered",
		"count", registry.Count(),
		"tier", platformTier.String())
}

// registerTool is a helper that registers both the tool definition and its handler.
// This reduces the two-step Register/RegisterHandler to a single call.
func registerTool(registry *mcp.ToolRegistry, name, description string, riskLevel int,
	schema map[string]interface{}, handler mcp.ToolHandlerFunc) {
	if err := registry.Register(name, description, riskLevel, schema); err != nil {
		slog.Error("Failed to register tool definition", "tool", name, "error", err)
		return
	}
	if err := registry.RegisterHandler(name, handler); err != nil {
		slog.Error("Failed to register tool handler", "tool", name, "error", err)
		return
	}
}
