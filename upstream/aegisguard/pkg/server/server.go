// Package server - Integration layer for AegisGuard security components
// Orchestrates all security components into a unified service
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	agentcomm "github.com/aegisguardsecurity/aegisguard/pkg/agent-comm"
	mcpserver "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
	audit "github.com/aegisguardsecurity/aegisguard/pkg/audit"
	contextisolator "github.com/aegisguardsecurity/aegisguard/pkg/context-isolator"
	policyengine "github.com/aegisguardsecurity/aegisguard/pkg/policy"
	ratelimit "github.com/aegisguardsecurity/aegisguard/pkg/ratelimit"
	toolregistry "github.com/aegisguardsecurity/aegisguard/pkg/tool-registry"
)

// ServerConfig holds all configuration for the AegisGuard server
type ServerConfig struct {
	Server          ServerBasicConfig      `json:"server"`
	Policy          policyConfig           `json:"policy"`
	RateLimit       ratelimit.Config       `json:"rate_limit"`
	Channels        []ChannelConfig        `json:"channels"`
	Audit           auditConfig            `json:"audit"`
	ContextIsolator isolatorConfig         `json:"context_isolator"`
	ToolRegistry    toolregistryConfig     `json:"tool_registry"`
	MCP             mcpserver.ServerConfig `json:"mcp"`
}

type policyConfig struct {
	MaxPriority int `json:"max_priority"`
}

type auditConfig struct {
	LogFile    string `json:"log_file"`
	MaxEntries int    `json:"max_entries"`
	Retention  string `json:"retention"` // duration string like "24h"
}

type isolatorConfig struct {
	Enabled bool `json:"enabled"`
}

type toolregistryConfig struct {
	MaxTools int `json:"max_tools"`
}

// ServerBasicConfig holds basic server settings
type ServerBasicConfig struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ConfigFile   string `json:"config_file"`
	LogFile      string `json:"log_file"`
	MaxChannels  int    `json:"max_channels"`
	MessageQueue int    `json:"message_queue"`
}

// ChannelConfig configures communication channels
type ChannelConfig struct {
	Name           string   `json:"name"`
	AgentIDs       []string `json:"agent_ids"`
	MaxMessages    int      `json:"max_messages"`
	PriorityEnable bool     `json:"priority_enable"`
}

// Server orchestrates all AegisGuard security components
type Server struct {
	config          *ServerConfig
	toolRegistry    *toolregistry.Registry
	policyEngine    *policyengine.Engine
	auditLogger     *audit.Logger
	rateLimiter     *ratelimit.Limiter
	contextIsolator *contextisolator.SessionManager
	commChannels    map[string]*agentcomm.Channel
	mcpServer       *mcpserver.Server
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	wg              sync.WaitGroup
	startTime       time.Time
}

// NewServer creates a new AegisGuard server with all components initialized
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:       config,
		commChannels: make(map[string]*agentcomm.Channel),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize audit logger
	var auditLogger *audit.Logger
	if config.Audit.LogFile != "" {
		// Configure with custom settings if needed
		retention := 30 * 24 * time.Hour
		if config.Audit.Retention != "" {
			if d, err := time.ParseDuration(config.Audit.Retention); err == nil {
				retention = d
			}
		}
		auditLogger = audit.NewLoggerWithConfig(config.Audit.MaxEntries, retention)
	} else {
		auditLogger = audit.NewLogger()
	}
	s.auditLogger = auditLogger
	s.auditLogger.LogAction(context.Background(), &audit.Action{
		Type:    "server_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "AegisGuard server initializing",
	})

	// Initialize policy engine - add common rules
	policyEngine := policyengine.NewEngine()
	for _, rule := range policyengine.CommonRules() {
		policyEngine.AddRule(rule)
	}
	s.policyEngine = policyEngine
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "component_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "Policy engine initialized",
	})

	// Initialize rate limiter
	rateLimiter := ratelimit.NewLimiterWithConfig(&config.RateLimit)
	s.rateLimiter = rateLimiter
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "component_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "Rate limiter initialized",
	})

	// Initialize context isolator (using session-based isolation)
	contextIsolator := contextisolator.NewSessionManager()
	s.contextIsolator = contextIsolator
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "component_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "Context isolator initialized",
	})

	// Pre-create default session for server
	_, _ = contextIsolator.CreateSession(context.Background(), "server")

	// Initialize tool registry
	toolRegistry := toolregistry.NewRegistry()
	s.toolRegistry = toolRegistry
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "component_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "Tool registry initialized",
	})

	// Initialize MCP server
	mcpServer := mcpserver.NewServer(&config.MCP)
	s.mcpServer = mcpServer
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "component_init",
		AgentID: "server",
		Allowed: true,
		Reason:  "MCP server initialized",
	})

	// Initialize communication channels
	for _, chCfg := range config.Channels {
		channel, err := agentcomm.NewChannel(chCfg.Name, agentcomm.WithMaxMessages(chCfg.MaxMessages))
		if err != nil {
			return nil, fmt.Errorf("failed to create channel %s: %w", chCfg.Name, err)
		}
		s.commChannels[chCfg.Name] = channel
		for _, agentID := range chCfg.AgentIDs {
			channel.Subscribe(agentID)
		}
		s.auditLogger.LogAction(ctx, &audit.Action{
			Type:    "channel_init",
			AgentID: "server",
			Allowed: true,
			Reason:  "Communication channel initialized: " + chCfg.Name,
		})
	}

	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "server_ready",
		AgentID: "server",
		Allowed: true,
		Reason:  "All components initialized successfully",
	})
	return s, nil
}

// LoadConfig loads server configuration from a JSON file
func LoadConfig(path string) (*ServerConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Start starts all server components and begins accepting requests
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server is already running")
	}

	s.running = true
	s.startTime = time.Now()

	ctx := s.ctx
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "server_start",
		AgentID: "server",
		Allowed: true,
		Reason:  "Server starting",
	})

	// Start MCP server
	if err := s.mcpServer.Start(); err != nil {
		s.auditLogger.LogAction(ctx, &audit.Action{
			Type:    "server_error",
			AgentID: "server",
			Allowed: false,
			Reason:  "MCP server start failed: " + err.Error(),
		})
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:      "server_started",
		AgentID:   "server",
		Allowed:   true,
		Reason:    fmt.Sprintf("Server started on %s:%d", s.config.Server.Host, s.config.Server.Port),
		Timestamp: time.Now(),
	})

	s.wg.Add(1)
	go s.runEventLoop()

	return nil
}

// Stop gracefully shuts down all server components
func (s *Server) Stop() error {
	s.mu.Lock()

	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("server is not running")
	}

	ctx := s.ctx
	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "server_stop",
		AgentID: "server",
		Allowed: true,
		Reason:  "Server stopping",
	})

	// Stop accepting new requests
	s.running = false

	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Stop MCP server
	if err := s.mcpServer.Stop(); err != nil {
		s.auditLogger.LogAction(ctx, &audit.Action{
			Type:    "server_error",
			AgentID: "server",
			Allowed: false,
			Reason:  "MCP server stop failed: " + err.Error(),
		})
		s.mu.Unlock()
		return fmt.Errorf("failed to stop MCP server: %w", err)
	}

	// Release the lock before waiting for goroutines
	s.mu.Unlock()

	// Wait for all goroutines to finish (runEventLoop calls Done when ctx is cancelled)
	s.wg.Wait()

	s.auditLogger.LogAction(ctx, &audit.Action{
		Type:    "server_stopped",
		AgentID: "server",
		Allowed: true,
		Reason:  "Server stopped",
	})
	return nil
}

// Run starts the server and blocks until stopped
func (s *Server) Run() error {
	if err := s.Start(); err != nil {
		return err
	}

	<-s.ctx.Done()
	return s.Stop()
}

// runEventLoop processes messages from communication channels
func (s *Server) runEventLoop() {
	defer s.wg.Done()

	ctx := s.ctx
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processChannelMessages()
		}
	}
}

// processChannelMessages processes pending messages across all channels
func (s *Server) processChannelMessages() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, channel := range s.commChannels {
		messages := channel.Peek()
		if len(messages) == 0 {
			continue
		}

		// Process all pending messages
		for _, msg := range messages {
			// Check rate limit
			decision := s.rateLimiter.Allow(s.ctx, msg.Sender)
			if !decision.Allowed {
				s.auditLogger.LogAction(s.ctx, &audit.Action{
					Type:    "rate_limit",
					AgentID: msg.Sender,
					Allowed: false,
					Reason:  fmt.Sprintf("Rate limit exceeded for agent: %s", msg.Sender),
				})
				_, _ = channel.Receive(s.ctx)
				continue
			}

			// Validate against policy
			evalCtx := &policyengine.EvaluationContext{
				AgentID:   msg.Sender,
				ToolName:  string(msg.Type),
				RiskScore: msg.Priority,
			}
			policyDecision := s.policyEngine.Evaluate(context.Background(), evalCtx)
			if !policyDecision.Allowed {
				s.auditLogger.LogAction(s.ctx, &audit.Action{
					Type:    "policy_denial",
					AgentID: msg.Sender,
					Allowed: false,
					Reason:  policyDecision.Reason,
				})
				if _, err := channel.Receive(s.ctx); err == nil {
					// Message consumed
				}
				continue
			}

			// Validate context isolation - check session exists
			_, err := s.contextIsolator.GetSession(context.Background(), msg.Sender)
			if err != nil {
				// Create new session if not found
				_, createErr := s.contextIsolator.CreateSession(context.Background(), msg.Sender)
				if createErr != nil {
					s.auditLogger.LogAction(s.ctx, &audit.Action{
						Type:    "context_violation",
						AgentID: msg.Sender,
						Allowed: false,
						Reason:  fmt.Sprintf("Context isolation violation: %s", createErr.Error()),
					})
					if _, err := channel.Receive(s.ctx); err == nil {
						// Message consumed
					}
					continue
				}
			}

			// Process the message
			s.processMessage(msg)
			_, _ = channel.Receive(s.ctx)
		}
	}
}

// processMessage handles a validated message
func (s *Server) processMessage(msg *agentcomm.Message) {
	switch msg.Type {
	case agentcomm.MessageTypeRequest:
		s.handleRequest(msg)
	case agentcomm.MessageTypeCommand:
		s.handleCommand(msg)
	case agentcomm.MessageTypeEvent:
		s.handleEvent(msg)
	case agentcomm.MessageTypeHeartbeat:
		s.auditLogger.LogAction(s.ctx, &audit.Action{
			Type:      "heartbeat",
			AgentID:   msg.Sender,
			Allowed:   true,
			Reason:    "Heartbeat received",
			Timestamp: time.Now(),
		})
	case agentcomm.MessageTypeError:
		s.handleError(msg)
	default:
		s.auditLogger.LogAction(s.ctx, &audit.Action{
			Type:      "unknown_message",
			AgentID:   msg.Sender,
			Allowed:   false,
			Reason:    fmt.Sprintf("Unhandled message type: %s", msg.Type),
			Timestamp: time.Now(),
		})
	}
}

// handleRequest processes request messages
func (s *Server) handleRequest(msg *agentcomm.Message) {
	s.auditLogger.LogAction(s.ctx, &audit.Action{
		Type:      "request",
		AgentID:   msg.Sender,
		Allowed:   true,
		Reason:    fmt.Sprintf("Processing request from %s", msg.Sender),
		Metadata:  map[string]interface{}{"payload": msg.Payload},
		Timestamp: time.Now(),
	})
}

// handleCommand processes command messages
func (s *Server) handleCommand(msg *agentcomm.Message) {
	s.auditLogger.LogAction(s.ctx, &audit.Action{
		Type:      "command",
		AgentID:   msg.Sender,
		Allowed:   true,
		Reason:    fmt.Sprintf("Processing command from %s", msg.Sender),
		Metadata:  map[string]interface{}{"payload": msg.Payload},
		Timestamp: time.Now(),
	})
}

// handleEvent processes event messages
func (s *Server) handleEvent(msg *agentcomm.Message) {
	s.auditLogger.LogAction(s.ctx, &audit.Action{
		Type:      "event",
		AgentID:   msg.Sender,
		Allowed:   true,
		Reason:    fmt.Sprintf("Processing event from %s", msg.Sender),
		Metadata:  map[string]interface{}{"payload": msg.Payload},
		Timestamp: time.Now(),
	})
}

func (s *Server) handleError(msg *agentcomm.Message) {
	s.auditLogger.LogAction(s.ctx, &audit.Action{
		Type:      "error_forwarded",
		AgentID:   msg.Sender,
		Allowed:   false,
		Reason:    fmt.Sprintf("Error from %s: %v", msg.Sender, msg.Payload),
		Timestamp: time.Now(),
	})
}

// GetToolRegistry returns the server's tool registry
func (s *Server) GetToolRegistry() *toolregistry.Registry {
	return s.toolRegistry
}

// GetPolicyEngine returns the server's policy engine
func (s *Server) GetPolicyEngine() *policyengine.Engine {
	return s.policyEngine
}

// GetCommChannel returns a communication channel by name
func (s *Server) GetCommChannel(name string) (*agentcomm.Channel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.commChannels[name]
	return ch, ok
}

// ListCommChannels returns all channel names
func (s *Server) ListCommChannels() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.commChannels))
	for name := range s.commChannels {
		names = append(names, name)
	}
	return names
}

// IsRunning returns true if the server is running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Uptime returns the server's uptime duration
func (s *Server) Uptime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.running {
		return 0
	}
	return time.Since(s.startTime)
}

// GetAuditLogger returns the server's audit logger
func (s *Server) GetAuditLogger() *audit.Logger {
	return s.auditLogger
}

// GetRateLimiter returns the server's rate limiter
func (s *Server) GetRateLimiter() *ratelimit.Limiter {
	return s.rateLimiter
}

// GetContextIsolator returns the server's context isolator
func (s *Server) GetContextIsolator() *contextisolator.SessionManager {
	return s.contextIsolator
}

// GetMCPServer returns the server's MCP server
func (s *Server) GetMCPServer() *mcpserver.Server {
	return s.mcpServer
}

// HealthStatus returns a map of component health statuses
func (s *Server) HealthStatus() map[string]string {
	status := make(map[string]string)

	// Check if server is running
	if s.IsRunning() {
		status["server"] = "healthy"
	} else {
		status["server"] = "stopped"
	}

	// Check audit logger
	if s.auditLogger != nil {
		status["audit"] = "healthy"
	}

	// Check policy engine
	if s.policyEngine != nil {
		status["policy"] = "healthy"
	}

	// Check rate limiter
	if s.rateLimiter != nil {
		status["rate_limiter"] = "healthy"
	}

	// Check context isolator
	if s.contextIsolator != nil {
		status["context_isolator"] = "healthy"
	}

	// Check MCP server
	if s.mcpServer != nil {
		status["mcp"] = "healthy"
	}

	return status
}
