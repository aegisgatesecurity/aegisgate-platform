// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - MCP (Model Context Protocol) Server
// =========================================================================
//
// Model Context Protocol server. The MCP protocol is the standard
// way for AI agents to invoke tools and access resources; this
// package provides the security guardrails for MCP sessions.
//
// Architecture:
//   - server.go:              wraps AegisGuard's MCP server for in-process use
//                             (standalone mode); the platform starts the MCP
//                             server directly so agents can connect without
//                             a separate AegisGuard process
//   - guardrails.go:          tier-based limits (max sessions, max tools/session,
//                             exec timeout, sandbox memory advisory)
//   - mcp_response_guard.go:  response security scanning (PII, secrets, toxicity,
//                             hallucination) before returning to MCP clients
//
// Tier-based guardrails (enforced in pkg/mcpserver/guardrails.go):
//   - MaxConcurrentMCP:         max simultaneous MCP sessions per tier
//   - MaxMCPToolsPerSession:    max tool calls within a single session
//   - MCPExecTimeoutSeconds:    max execution time per tool call
//   - MaxMCPSandboxMemoryMB:    advisory memory limit (logged, not enforced)
//
// When a limit is exceeded, returns a JSON-RPC error response immediately.
//
// Reference: https://modelcontextprotocol.io/
//            plans/THREAT-MODEL.md Section 2.2 (MCP STRIDE threats)
//
// =========================================================================

package mcpserver
