// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - Embedded MCP Server
// =========================================================================
//
// Wraps AegisGuard's MCP server for in-process use in the unified platform.
// When the platform runs in "standalone" mode, it starts the MCP server
// directly so agents can connect without a separate AegisGuard process.
//
// When AegisGuard is already running externally, the platform just uses
// the scanner client to connect to it.
// =========================================================================

package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
	"github.com/aegisguardsecurity/aegisguard/pkg/audit"
	"github.com/aegisguardsecurity/aegisguard/pkg/authorization"
	"github.com/aegisguardsecurity/aegisguard/pkg/context-isolator"
	"github.com/aegisguardsecurity/aegisguard/pkg/policy"
)

// Config holds configuration for the embedded MCP server
type Config struct {
	// Address to listen on (e.g., ":8081")
	Address string

	// Read timeout for MCP connections
	ReadTimeout time.Duration

	// Write timeout for MCP connections
	WriteTimeout time.Duration

	// Idle timeout for MCP connections
	IdleTimeout time.Duration
}

// DefaultConfig returns default MCP server configuration
func DefaultConfig() *Config {
	return &Config{
		Address:      ":8081",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  5 * time.Minute,
	}
}

// EmbeddedServer wraps AegisGuard's MCP server for in-process use
type EmbeddedServer struct {
	config  *Config
	server  *mcp.Server
	handler *mcp.RequestHandler
	logger  *slog.Logger
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewEmbeddedServer creates a new embedded MCP server
func NewEmbeddedServer(cfg *Config) *EmbeddedServer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create the platform-adapted handler components
	authz := authorization.NewAuthorizer()
	auditLogger := audit.NewLogger()
	sessionMgr := contextisolator.NewSessionManager()
	policyEngine := policy.NewEngine()

	// Add common policy rules
	for _, rule := range policy.CommonRules() {
		policyEngine.AddRule(rule)
	}

	// Create adapters that implement MCP handler interfaces
	authzAdapter := &authorizerAdapter{authz: authz}
	auditAdapter := &auditLoggerAdapter{logger: auditLogger}
	sessionAdapter := &sessionManagerAdapter{mgr: sessionMgr}

	// Create the MCP request handler
	handler := mcp.NewRequestHandler(authzAdapter, auditAdapter, sessionAdapter)

	return &EmbeddedServer{
		config:  cfg,
		handler: handler,
		logger:  slog.Default(),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Handler returns the MCP request handler for tool registration
func (es *EmbeddedServer) Handler() *mcp.RequestHandler {
	return es.handler
}

// Start begins listening for MCP connections
func (es *EmbeddedServer) Start() error {
	serverCfg := &mcp.ServerConfig{
		Address:      es.config.Address,
		Handler:      es.handler,
		ReadTimeout:  es.config.ReadTimeout,
		WriteTimeout: es.config.WriteTimeout,
		IdleTimeout:  es.config.IdleTimeout,
	}

	es.server = mcp.NewServer(serverCfg)

	es.logger.Info("Starting embedded MCP server", "address", es.config.Address)

	if err := es.server.StartContext(es.ctx); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	es.logger.Info("Embedded MCP server listening", "address", es.config.Address)
	return nil
}

// Stop gracefully shuts down the MCP server
func (es *EmbeddedServer) Stop() error {
	es.cancel()
	if es.server != nil {
		es.server.Stop()
	}
	es.logger.Info("Embedded MCP server stopped")
	return nil
}

// ============================================================================
// Adapter types — bridge platform components to MCP handler interfaces
// ============================================================================

// authorizerAdapter adapts authorization.Authorizer to mcp.ToolAuthorizer
type authorizerAdapter struct {
	authz *authorization.Authorizer
}

func (a *authorizerAdapter) Authorize(ctx context.Context, call *mcp.AuthorizationCall) (*mcp.AuthorizationDecision, error) {
	authzCall := &authorization.ToolCallRequest{
		ID:         call.ID,
		Name:       call.Name,
		Parameters: call.Parameters,
		SessionID:  call.SessionID,
		AgentID:    call.AgentID,
	}

	result, err := a.authz.Authorize(ctx, authzCall)
	if err != nil {
		return nil, err
	}

	return &mcp.AuthorizationDecision{
		Allowed:     result.Allow,
		Reason:      result.Reason,
		RiskScore:   result.RiskScore,
		MatchedRule: result.MatchedRule,
	}, nil
}

// auditLoggerAdapter adapts audit.Logger to mcp.AuditLoggerImpl
type auditLoggerAdapter struct {
	logger *audit.Logger
}

func (a *auditLoggerAdapter) Log(ctx context.Context, entry *mcp.AuditEntry) error {
	allowed := entry.Error == "" && entry.Type != "tool_denied" && entry.Type != "tool_error"
	reason := entry.Error
	if reason == "" && entry.Type == "tool_denied" {
		reason = "Tool denied by policy"
	}

	return a.logger.LogAction(ctx, &audit.Action{
		Type:      entry.Type,
		SessionID: entry.SessionID,
		AgentID:   entry.AgentID,
		ToolName:  entry.ToolName,
		Allowed:   allowed,
		Reason:    reason,
		RiskScore: entry.RiskScore,
	})
}

// sessionManagerAdapter adapts contextisolator.SessionManager to mcp.SessionManager
type sessionManagerAdapter struct {
	mgr *contextisolator.SessionManager
}

func (s *sessionManagerAdapter) CreateSession(ctx context.Context, agentID string) (*mcp.Session, error) {
	session, err := s.mgr.CreateSession(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return &mcp.Session{
		ID:      session.ID,
		AgentID: session.AgentID,
	}, nil
}

func (s *sessionManagerAdapter) GetSession(ctx context.Context, sessionID string) (*mcp.Session, error) {
	session, err := s.mgr.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return &mcp.Session{
		ID:      session.ID,
		AgentID: session.AgentID,
	}, nil
}

func (s *sessionManagerAdapter) DeleteSession(ctx context.Context, sessionID string) error {
	return s.mgr.DeleteSession(ctx, sessionID)
}