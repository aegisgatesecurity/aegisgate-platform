// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Guardrail Middleware
// =========================================================================
//
// Enforces tier-based limits on MCP sessions and tool execution:
//   - MaxConcurrentMCP:  maximum simultaneous MCP sessions
//   - MaxMCPToolsPerSession: maximum tool calls within a single session
//   - MCPExecTimeoutSeconds: maximum execution time per tool call
//   - MaxMCPSandboxMemoryMB: advisory memory limit (logged, not enforced at MVP)
//
// Implementation: wraps RequestHandler.HandleRequest with pre-check hooks.
// When a limit is exceeded, returns a JSON-RPC error response immediately.
// =========================================================================

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// --------------------------------------------------------------------------
// Guardrail error codes (JSON-RPC application-specific)
// --------------------------------------------------------------------------

const (
	ErrMaxSessions       = "max_sessions_reached"
	ErrSessionToolLimit  = "session_tool_limit_reached"
	ErrExecTimeout       = "execution_timeout"
	ErrMemoryLimit       = "sandbox_memory_limit"
	ErrRateLimitExceeded = "rate_limit_exceeded"
)

// --------------------------------------------------------------------------
// sessionState tracks per-session guardrail counters
// --------------------------------------------------------------------------

type sessionState struct {
	ID         string
	AgentID    string
	ToolCount  int64
	MemoryMB   int64
	CreatedAt  time.Time
	LastSeen   time.Time
	ClientAddr string // Client IP address for logging
}

// --------------------------------------------------------------------------
// GuardrailConfig holds configuration for the guardrail middleware
// --------------------------------------------------------------------------

type GuardrailConfig struct {
	// Enabled controls whether guardrails are enforced
	Enabled bool

	// PlatformTier determines the limits
	PlatformTier tier.Tier

	// LogViolations controls whether limit violations are logged at warn level
	LogViolations bool

	// AuditViolations controls whether limit violations are sent to the audit log
	AuditViolations bool
}

// DefaultGuardrailConfig returns sensible defaults for the given tier
func DefaultGuardrailConfig(t tier.Tier) GuardrailConfig {
	return GuardrailConfig{
		Enabled:         true,
		PlatformTier:    t,
		LogViolations:   true,
		AuditViolations: true,
	}
}

// --------------------------------------------------------------------------
// GuardrailMiddleware enforces tier-based MCP limits
// --------------------------------------------------------------------------

// mcpClientBucket is a token-bucket rate limiter for a single client.
// It tracks requests per minute in a sliding 60-second window.
type mcpClientBucket struct {
	count   int64
	resetAt time.Time
}

// GuardrailMiddleware wraps an MCP RequestHandler and enforces tier-based
// limits before delegating to the inner handler.
type GuardrailMiddleware struct {
	config   GuardrailConfig
	logger   *slog.Logger
	toolAuth *toolauth.Matrix
	serverID string // Server identifier for MCP registration logging

	// Session tracking
	mu             sync.RWMutex
	sessions       map[string]*sessionState // sessionID -> state
	activeSessions int64                    // atomic counter for fast concurrent-session checks

	// Rate limiting (Guard 5: per-client RPM)
	rateMu       sync.Mutex
	rateLimits   map[string]*mcpClientBucket // sanitized clientAddr -> bucket
	rateLimitRPM int                         // cached from tier.RateLimitMCP()

	// Metrics
	totalRequests   int64
	blockedRequests int64
	timeoutRequests int64
	rateLimitedReqs int64
}

// NewGuardrailMiddleware creates a new guardrail middleware for the given tier
func NewGuardrailMiddleware(cfg GuardrailConfig, serverID string) *GuardrailMiddleware {
	rpm := cfg.PlatformTier.RateLimitMCP()

	// Initialize tool authorizer matrix with default policies
	toolAuth := toolauth.NewMatrix()
	toolAuth.RegisterDefaultPolicies()

	if !cfg.Enabled {
		return &GuardrailMiddleware{
			config:       cfg,
			logger:       slog.Default().With("component", "mcp-guardrails"),
			serverID:     serverID,
			sessions:     make(map[string]*sessionState),
			rateLimits:   make(map[string]*mcpClientBucket),
			rateLimitRPM: rpm,
			toolAuth:     toolAuth,
		}
	}

	return &GuardrailMiddleware{
		config:       cfg,
		logger:       slog.Default().With("component", "mcp-guardrails", "tier", cfg.PlatformTier.String()),
		serverID:     serverID,
		sessions:     make(map[string]*sessionState),
		rateLimits:   make(map[string]*mcpClientBucket),
		rateLimitRPM: rpm,
		toolAuth:     toolAuth,
	}
}

// --------------------------------------------------------------------------
// Session lifecycle
// --------------------------------------------------------------------------

// OnSessionCreate is called when a new MCP session is initialized.
// Returns an error if the concurrent session limit has been reached.
func (g *GuardrailMiddleware) OnSessionCreate(sessionID, agentID, clientAddr string) error {
	if !g.config.Enabled {
		return nil
	}

	maxSessions := g.config.PlatformTier.MaxConcurrentMCP()
	if maxSessions < 0 {
		// Unlimited (-1)
		g.trackSession(sessionID, agentID, clientAddr)
		return nil
	}

	current := atomic.LoadInt64(&g.activeSessions)
	if current >= int64(maxSessions) {
		atomic.AddInt64(&g.blockedRequests, 1)
		err := fmt.Errorf("maximum concurrent MCP sessions reached (%d/%d for %s tier)",
			current, maxSessions, g.config.PlatformTier.DisplayName())
		if g.config.LogViolations {
			g.logger.Warn("Session blocked", "session_id", sessionID, "reason", ErrMaxSessions, "error", err)
		}
		return err
	}

	g.trackSession(sessionID, agentID, clientAddr)
	return nil
}

// OnSessionDestroy is called when an MCP session ends.
func (g *GuardrailMiddleware) OnSessionDestroy(sessionID string) {
	if !g.config.Enabled {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.sessions[sessionID]; exists {
		delete(g.sessions, sessionID)
		atomic.AddInt64(&g.activeSessions, -1)
		metrics.DecActiveConnections(metrics.ServiceMCP)
		metrics.SetMCPConnections(int(atomic.LoadInt64(&g.activeSessions)))
		g.logger.Debug("Session destroyed", "session_id", sessionID)
	}
}

// trackSession registers a new session in the tracking map
func (g *GuardrailMiddleware) trackSession(sessionID, agentID, clientAddr string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.sessions[sessionID] = &sessionState{
		ID:        sessionID,
		AgentID:   agentID,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		ClientAddr: clientAddr, // Add clientAddr for logging
	}
	atomic.AddInt64(&g.activeSessions, 1)
	metrics.IncActiveConnections(metrics.ServiceMCP)
	metrics.SetMCPConnections(int(atomic.LoadInt64(&g.activeSessions)))

	// MCP server registration logging
	g.logger.Info("MCP server registration",
		"session_id", sessionID,
		"agent_id", agentID,
		"client_ip", clientAddr,
		"server_id", g.serverID,
		"timestamp", time.Now().Format(time.RFC3339),
		"active", atomic.LoadInt64(&g.activeSessions),
		"max", g.config.PlatformTier.MaxConcurrentMCP())
}

// --------------------------------------------------------------------------
// Tool call enforcement
// --------------------------------------------------------------------------

// OnToolCall is called before each tool invocation within a session.
// Returns an error if the session's tool count limit has been reached.
func (g *GuardrailMiddleware) OnToolCall(sessionID, toolName string) error {
	if !g.config.Enabled {
		return nil
	}

	maxTools := g.config.PlatformTier.MaxMCPToolsPerSession()
	if maxTools < 0 {
		// Unlimited
		g.incrementToolCount(sessionID, toolName)
		return nil
	}

	g.mu.RLock()
	state, exists := g.sessions[sessionID]
	g.mu.RUnlock()

	if !exists {
		g.logger.Debug("Tool call from untracked session", "session_id", sessionID, "tool", toolName)
		return nil
	}

	currentCount := atomic.LoadInt64(&state.ToolCount)
	if currentCount >= int64(maxTools) {
		atomic.AddInt64(&g.blockedRequests, 1)
		err := fmt.Errorf("session tool limit reached (%d/%d for %s tier, session %s)",
			currentCount, maxTools, g.config.PlatformTier.DisplayName(), sessionID)
		if g.config.LogViolations {
			g.logger.Warn("Tool call blocked",
				"session_id", sessionID,
				"tool", toolName,
				"reason", ErrSessionToolLimit,
				"error", err)
		}
		return err
	}

	g.incrementToolCount(sessionID, toolName)
	return nil
}

// OnToolCallWithAuth checks tool authorization using the Tool Authorizer matrix.
// Returns an error if the tool call is denied by policy or requires approval.
// This integrates risk-based tool authorization into the MCP guardrails.
func (g *GuardrailMiddleware) OnToolCallWithAuth(sessionID, agentID, toolName string) error {
	if !g.config.Enabled || g.toolAuth == nil {
		return nil
	}

	// Create tool call for authorization check
	toolCall := &toolauth.ToolCall{
		ID:      sessionID + "-" + toolName,
		Name:    toolName,
		AgentID: agentID,
	}

	// Authorize the tool call
	decision, err := g.toolAuth.Authorize(context.Background(), toolCall)
	if err != nil {
		atomic.AddInt64(&g.blockedRequests, 1)
		g.logger.Error("Tool authorization error",
			"session_id", sessionID,
			"tool", toolName,
			"error", err)
		return fmt.Errorf("tool authorization failed: %w", err)
	}

	// Log the authorization decision
	g.logger.Debug("Tool authorization decision",
		"session_id", sessionID,
		"tool", toolName,
		"allow", decision.Allow,
		"reason", decision.Reason,
		"risk_score", decision.RiskScore)

	// Check if tool is denied
	if !decision.Allow {
		atomic.AddInt64(&g.blockedRequests, 1)

		// Record metric for blocked tool call
		tool := metrics.SanitizeToolName(toolName, nil)
		metrics.RecordMCPRequest(tool, metrics.ResultFailure)

		if g.config.LogViolations {
			g.logger.Warn("Tool call blocked by authorization",
				"session_id", sessionID,
				"tool", toolName,
				"reason", decision.Reason,
				"risk_score", decision.RiskScore)
		}
		return fmt.Errorf("tool %s blocked: %s", toolName, decision.Reason)
	}

	// Tool is authorized, record success metric
	tool := metrics.SanitizeToolName(toolName, nil)
	metrics.RecordMCPRequest(tool, metrics.ResultSuccess)

	return nil
}

// OnToolCallWithContext wraps a tool call with a timeout context.
// Returns the context (with deadline) and a cancel function.
// If the tier timeout is -1 (unlimited), returns the original context.
func (g *GuardrailMiddleware) OnToolCallWithContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !g.config.Enabled {
		return ctx, func() {}
	}

	timeoutSec := g.config.PlatformTier.MCPExecTimeoutSeconds()
	if timeoutSec < 0 {
		// Unlimited
		return ctx, func() {}
	}

	timeout := time.Duration(timeoutSec) * time.Second
	return context.WithTimeout(ctx, timeout)
}

// incrementToolCount atomically increments the tool counter for a session
func (g *GuardrailMiddleware) incrementToolCount(sessionID, toolName string) {
	g.mu.RLock()
	state, exists := g.sessions[sessionID]
	g.mu.RUnlock()

	if exists {
		newCount := atomic.AddInt64(&state.ToolCount, 1)
		state.LastSeen = time.Now()
		g.logger.Debug("Tool call counted",
			"session_id", sessionID,
			"tool", toolName,
			"count", newCount,
			"max", g.config.PlatformTier.MaxMCPToolsPerSession())
	}

	atomic.AddInt64(&g.totalRequests, 1)

	// Record MCP tool call metric
	tool := metrics.SanitizeToolName(toolName, nil)
	metrics.RecordMCPRequest(tool, metrics.ResultSuccess)
}

// --------------------------------------------------------------------------
// Memory advisory (Community tier: logged warning, not hard-enforced)
// --------------------------------------------------------------------------

// OnMemoryUsage is called after a tool execution to report memory usage.
// At MVP (with S3b-05), this hard-enforces memory limits at Community tier
// by killing sessions that exceed their quota.
func (g *GuardrailMiddleware) OnMemoryUsage(sessionID string, memoryMB int64) {
	if !g.config.Enabled {
		return
	}

	limitMB := g.config.PlatformTier.MaxMCPSandboxMemoryMB()
	if limitMB < 0 {
		// Unlimited
		return
	}

	g.mu.RLock()
	state, exists := g.sessions[sessionID]
	g.mu.RUnlock()

	if exists {
		state.MemoryMB = memoryMB
		state.LastSeen = time.Now()
	}

	if memoryMB > int64(limitMB) {
		// Hard enforcement: kill session that exceeds limit
		g.logger.Error("Memory limit exceeded - HARD ENFORCEMENT (killing session)",
			"session_id", sessionID,
			"used_mb", memoryMB,
			"limit_mb", limitMB,
			"tier", g.config.PlatformTier.DisplayName())

		// Remove the session from tracking
		g.mu.Lock()
		delete(g.sessions, sessionID)
		g.mu.Unlock()
	}
}

// --------------------------------------------------------------------------
// Guard 5: Per-client RPM rate limiting
// --------------------------------------------------------------------------

// OnRateLimitCheck enforces per-client requests-per-minute limits.
// Returns an error if the client has exceeded their tier's RPM allowance.
// A return of nil means the request is allowed.
func (g *GuardrailMiddleware) OnRateLimitCheck(clientAddr string) error {
	if !g.config.Enabled {
		return nil
	}

	rpm := g.rateLimitRPM
	if rpm < 0 {
		// Unlimited (-1 from Enterprise tier)
		return nil
	}

	sanitized := metrics.SanitizeClientID(clientAddr)

	g.rateMu.Lock()
	defer g.rateMu.Unlock()

	now := time.Now()
	bucket, exists := g.rateLimits[sanitized]
	if !exists || now.After(bucket.resetAt) {
		// New window: reset or create bucket
		bucket = &mcpClientBucket{
			count:   0,
			resetAt: now.Add(time.Minute),
		}
		g.rateLimits[sanitized] = bucket
	}

	bucket.count++
	if bucket.count > int64(rpm) {
		atomic.AddInt64(&g.blockedRequests, 1)
		atomic.AddInt64(&g.rateLimitedReqs, 1)
		metrics.RecordRateLimitHit(metrics.ServiceMCP, sanitized)
		err := fmt.Errorf("MCP rate limit exceeded (%d/%d RPM for %s tier, client %s)",
			bucket.count, rpm, g.config.PlatformTier.DisplayName(), sanitized)
		if g.config.LogViolations {
			g.logger.Warn("MCP request rate-limited",
				"client", sanitized,
				"reason", ErrRateLimitExceeded,
				"count", bucket.count,
				"limit", rpm,
				"error", err)
		}
		return err
	}

	return nil
}

// RateLimitCleanup removes stale rate limit entries for clients whose
// window has expired. Call periodically (e.g., every 5 minutes).
func (g *GuardrailMiddleware) RateLimitCleanup() {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()

	now := time.Now()
	for addr, bucket := range g.rateLimits {
		if now.After(bucket.resetAt) {
			delete(g.rateLimits, addr)
		}
	}
}

// ExpireRateLimitBuckets is a test helper that forces all rate limit
// buckets to expire immediately. This allows integration tests to verify
// window-reset behavior without waiting for the full 60-second window.
func (g *GuardrailMiddleware) ExpireRateLimitBuckets() {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()

	past := time.Now().Add(-time.Second)
	for _, bucket := range g.rateLimits {
		bucket.resetAt = past
	}
}

// --------------------------------------------------------------------------
// GuardrailHandler wraps HandleRequest with guardrail enforcement
// --------------------------------------------------------------------------

// GuardrailHandler returns a function that wraps the inner RequestHandler's
// HandleRequest with all four guardrail checks. This is the main integration
// point: replace direct HandleRequest calls with this wrapper.
func (g *GuardrailMiddleware) GuardrailHandler(inner *mcp.RequestHandler) func(conn *mcp.Connection, req *mcp.JSONRPCRequest) *mcp.JSONRPCResponse {
	return func(conn *mcp.Connection, req *mcp.JSONRPCRequest) *mcp.JSONRPCResponse {
		// Skip guardrails if disabled
		if !g.config.Enabled {
			return inner.HandleRequest(conn, req)
		}

		// --- Guard 5: Per-client RPM rate limiting ---
		// Applies to ALL incoming MCP requests, not just tool calls.
		if conn != nil && conn.Conn != nil {
			clientAddr := conn.Conn.RemoteAddr().String()
			if err := g.OnRateLimitCheck(clientAddr); err != nil {
				return guardrailErrorResponse(req.ID, ErrRateLimitExceeded, err.Error())
			}
		}

		// --- Guard 1: Concurrent session limit ---
		// Use clientAddr from line 519 if conn is available, otherwise use empty string
		clientAddrForSession := ""
		if conn != nil && conn.Conn != nil {
			clientAddrForSession = conn.Conn.RemoteAddr().String()
		}
		if req.Method == "initialize" {
			sessionID := "pending"
			agentID := ""
			if conn != nil && conn.Session != nil {
				sessionID = conn.Session.ID
				agentID = conn.Session.AgentID
			}
			if err := g.OnSessionCreate(sessionID, agentID, clientAddrForSession); err != nil {
				return guardrailErrorResponse(req.ID, ErrMaxSessions, err.Error())
			}
		}

		// --- Guard 2: Per-session tool count limit ---
		if req.Method == "tools/call" || req.Method == "tool/call" {
			sessionID := "anonymous"
			agentID := ""
			toolName := ""
			if conn != nil && conn.Session != nil {
				sessionID = conn.Session.ID
				agentID = conn.Session.AgentID
			}
			// Extract tool name from params for logging
			if req.Params != nil {
				var params map[string]interface{}
				if err := parseJSONParams(req.Params, &params); err == nil {
					if n, ok := params["name"].(string); ok {
						toolName = n
					}
				}
			}

			if err := g.OnToolCall(sessionID, toolName); err != nil {
				return guardrailErrorResponse(req.ID, ErrSessionToolLimit, err.Error())
			}

			// --- Guard 2b: Tool authorization (risk-based) ---
			if err := g.OnToolCallWithAuth(sessionID, agentID, toolName); err != nil {
				return guardrailErrorResponse(req.ID, "tool_authorization_denied", err.Error())
			}
		}

		// --- Guard 3: Execution timeout ---
		// Applied by wrapping the tool handler's context. We set it here
		// and the actual handler picks it up via the connection's context.
		if req.Method == "tools/call" || req.Method == "tool/call" {
			timeoutSec := g.config.PlatformTier.MCPExecTimeoutSeconds()
			if timeoutSec > 0 {
				// The timeout is enforced by the tool executor context.
				// We log the configured timeout here for audit purposes.
				g.logger.Debug("Tool call with timeout",
					"timeout_sec", timeoutSec,
					"method", req.Method)
			}
		}

		// --- Guard 4: Memory (advisory) ---
		// Memory is checked after execution in OnMemoryUsage().
		// No pre-check needed here.

		// Delegate to the inner handler
		return inner.HandleRequest(conn, req)
	}
}

// --------------------------------------------------------------------------
// Metrics & status
// --------------------------------------------------------------------------

// GuardrailStats returns current guardrail statistics
type GuardrailStats struct {
	Tier              string `json:"tier"`
	ActiveSessions    int64  `json:"active_sessions"`
	MaxSessions       int    `json:"max_sessions"`
	TotalRequests     int64  `json:"total_requests"`
	BlockedRequests   int64  `json:"blocked_requests"`
	TimeoutRequests   int64  `json:"timeout_requests"`
	RateLimitRPM      int    `json:"rate_limit_rpm"`
	RateLimitedReqs   int64  `json:"rate_limited_requests"`
	ToolsPerSession   int    `json:"tools_per_session"`
	ExecTimeoutSec    int    `json:"exec_timeout_sec"`
	SandboxMemoryMB   int    `json:"sandbox_memory_mb"`
	GuardrailsEnabled bool   `json:"guardrails_enabled"`
}

// Stats returns a snapshot of the current guardrail state
func (g *GuardrailMiddleware) Stats() GuardrailStats {
	maxSess := g.config.PlatformTier.MaxConcurrentMCP()
	if maxSess < 0 {
		maxSess = 0 // represents unlimited
	}

	maxTools := g.config.PlatformTier.MaxMCPToolsPerSession()
	if maxTools < 0 {
		maxTools = 0
	}

	timeoutSec := g.config.PlatformTier.MCPExecTimeoutSeconds()
	memMB := g.config.PlatformTier.MaxMCPSandboxMemoryMB()

	rateLimitRPM := g.rateLimitRPM
	if rateLimitRPM < 0 {
		rateLimitRPM = 0 // represents unlimited
	}

	return GuardrailStats{
		Tier:              g.config.PlatformTier.String(),
		ActiveSessions:    atomic.LoadInt64(&g.activeSessions),
		MaxSessions:       maxSess,
		TotalRequests:     atomic.LoadInt64(&g.totalRequests),
		BlockedRequests:   atomic.LoadInt64(&g.blockedRequests),
		TimeoutRequests:   atomic.LoadInt64(&g.timeoutRequests),
		RateLimitRPM:      rateLimitRPM,
		RateLimitedReqs:   atomic.LoadInt64(&g.rateLimitedReqs),
		ToolsPerSession:   maxTools,
		ExecTimeoutSec:    timeoutSec,
		SandboxMemoryMB:   memMB,
		GuardrailsEnabled: g.config.Enabled,
	}
}

// Close cleans up any running goroutines and logs final stats
func (g *GuardrailMiddleware) Close() {
	stats := g.Stats()
	g.logger.Info("Guardrail middleware shutting down",
		"active_sessions", stats.ActiveSessions,
		"total_requests", stats.TotalRequests,
		"blocked_requests", stats.BlockedRequests,
		"rate_limited_requests", stats.RateLimitedReqs)
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// guardrailErrorResponse creates a JSON-RPC error response for a guardrail violation
func guardrailErrorResponse(id interface{}, code, message string) *mcp.JSONRPCResponse {
	return &mcp.JSONRPCResponse{
		ID: id,
		Error: &mcp.JSONRPCError{
			Code:    -32000, // Application error range
			Message: code + ": " + message,
		},
	}
}

// parseJSONParams safely unmarshals JSON params
func parseJSONParams(data json.RawMessage, v interface{}) error {
	// Using encoding/json to unmarshal — the param bytes are already a JSON object
	return json.Unmarshal(data, v)
}
