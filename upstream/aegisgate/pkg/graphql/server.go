// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package graphql provides GraphQL API support for AegisGate
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
	"github.com/aegisgatesecurity/aegisgate/pkg/sso"
	"github.com/aegisgatesecurity/aegisgate/pkg/tls"
	"github.com/aegisgatesecurity/aegisgate/pkg/webhook"
)

// Server represents the GraphQL server
type Server struct {
	http.Server
	logger         *slog.Logger
	authManager    *auth.Manager
	ssomanager     *sso.Manager
	complianceMgr  *compliance.Manager
	proxyServer    *proxy.Proxy
	siemManager    *siem.Manager
	webhookManager *webhook.Manager
	tlsManager     *tls.Manager
	coreRegistry   *core.Registry
	metricsMgr     *metrics.Manager
	resolver       *Resolver
	subscriptions  *SubscriptionManager
	mu             sync.RWMutex
	config         *ServerConfig
}

// ServerConfig holds GraphQL server configuration
type ServerConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ListenAddress   string        `yaml:"listen_address"`
	Port            int           `yaml:"port"`
	Playground      bool          `yaml:"playground"`
	DepthLimit      int           `yaml:"depth_limit"`
	ComplexityLimit int           `yaml:"complexity_limit"`
	Timeout         time.Duration `yaml:"timeout"`
}

// DefaultServerConfig returns default configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Enabled:         true,
		ListenAddress:   "127.0.0.1",
		Port:            4000,
		Playground:      true,
		DepthLimit:      10,
		ComplexityLimit: 100,
		Timeout:         30 * time.Second,
	}
}

// NewServer creates a new GraphQL server
func NewServer(cfg *ServerConfig, logger *slog.Logger) *Server {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		logger:        logger,
		config:        cfg,
		subscriptions: NewSubscriptionManager(),
	}

	// Set up HTTP handler
	s.Handler = s.handleRequest()

	return s
}

// RegisterModules registers all AegisGate modules with the GraphQL server
func (s *Server) RegisterModules(
	authMgr *auth.Manager,
	ssoMgr *sso.Manager,
	complianceMgr *compliance.Manager,
	proxySrv *proxy.Proxy,
	siemMgr *siem.Manager,
	webhookMgr *webhook.Manager,
	tlsMgr *tls.Manager,
	coreReg *core.Registry,
	metricsMgr *metrics.Manager,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authManager = authMgr
	s.ssomanager = ssoMgr
	s.complianceMgr = complianceMgr
	s.proxyServer = proxySrv
	s.siemManager = siemMgr
	s.webhookManager = webhookMgr
	s.tlsManager = tlsMgr
	s.coreRegistry = coreReg
	s.metricsMgr = metricsMgr

	// Initialize resolver with all managers
	s.resolver = NewResolver(s)
}

// handleRequest handles incoming GraphQL requests
func (s *Server) handleRequest() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Set up timeout
		ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()

		// Add request info to context
		ctx = WithRequestInfo(ctx, &RequestInfo{
			StartTime: time.Now(),
			RemoteIP:  getRemoteIP(r),
		})

		// Set headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Handle CORS if enabled
		if s.config.Playground {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		// Parse request
		var req map[string]interface{}
		contentType := r.Header.Get("Content-Type")

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			return
		}

		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if contentType != "application/json" && contentType != "application/graphql" {
			s.writeError(w, http.StatusBadRequest, "invalid content type")
			return
		}

		// Get query from body or URL
		var query string
		if contentType == "application/graphql" {
			body, err := readBody(r)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			query = string(body)
		} else {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			query, _ = req["query"].(string)
			_ = req
		}

		if query == "" {
			s.writeError(w, http.StatusBadRequest, "query is required")
			return
		}

		// Parse variables and operation name
		variables, _ := req["variables"].(map[string]interface{})
		operationName, _ := req["operationName"].(string)

		// Execute query
		result := s.executeQuery(ctx, query, variables, operationName)

		// Write response
		s.writeResponse(w, result)
	})
}

// executeQuery executes a GraphQL query
func (s *Server) executeQuery(ctx context.Context, query string, variables map[string]interface{}, operationName string) *Response {
	startTime := time.Now()

	// Check depth limit
	if s.config.DepthLimit > 0 {
		ctx = WithDepthLimit(ctx, s.config.DepthLimit)
	}

	// Check complexity limit
	if s.config.ComplexityLimit > 0 {
		ctx = WithComplexityLimit(ctx, s.config.ComplexityLimit)
	}

	// Execute query through resolver if available
	var result *Response
	if s.resolver != nil {
		result = s.resolver.Execute(ctx, query, variables)
	} else {
		result = &Response{
			Errors: []*Error{{
				Message: "resolver not initialized",
			}},
		}
	}

	// Add extensions
	result.Extensions = map[string]interface{}{
		"tracing": map[string]interface{}{
			"version":    "1.0.0",
			"duration":   time.Since(startTime).Nanoseconds(),
			"parsing":    map[string]interface{}{"duration": 0},
			"validation": map[string]interface{}{"duration": 0},
			"execution":  map[string]interface{}{"duration": time.Since(startTime).Nanoseconds()},
		},
	}

	return result
}

// writeResponse writes a GraphQL response
func (s *Server) writeResponse(w http.ResponseWriter, result *Response) {
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(result); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}
}

// writeError writes a GraphQL error
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	resp := &Response{
		Errors: []*Error{{
			Message: message,
		}},
	}
	s.writeResponse(w, resp)
}

// Start starts the GraphQL server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)
	s.Addr = addr

	s.logger.Info("starting GraphQL server", "address", addr)
	return s.ListenAndServe()
}

// Stop stops the GraphQL server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping GraphQL server")
	s.subscriptions.Cleanup()
	return s.Shutdown(ctx)
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handleRequest().ServeHTTP(w, r)
}

// RequestInfo holds information about the current request
type RequestInfo struct {
	StartTime time.Time
	RemoteIP  string
}

// contextKey is a type for context keys
type contextKey string

const (
	requestInfoKey contextKey = "graphql_request_info"
	depthLimitKey  contextKey = "graphql_depth_limit"
	complexityKey  contextKey = "graphql_complexity"
)

// WithRequestInfo adds request info to context
func WithRequestInfo(ctx context.Context, info *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey, info)
}

// GetRequestInfo gets request info from context
func GetRequestInfo(ctx context.Context) *RequestInfo {
	if info, ok := ctx.Value(requestInfoKey).(*RequestInfo); ok {
		return info
	}
	return nil
}

// WithDepthLimit adds depth limit to context
func WithDepthLimit(ctx context.Context, limit int) context.Context {
	return context.WithValue(ctx, depthLimitKey, limit)
}

// GetDepthLimit gets depth limit from context
func GetDepthLimit(ctx context.Context) int {
	if limit, ok := ctx.Value(depthLimitKey).(int); ok {
		return limit
	}
	return 0
}

// WithComplexityLimit adds complexity limit to context
func WithComplexityLimit(ctx context.Context, limit int) context.Context {
	return context.WithValue(ctx, complexityKey, limit)
}

// GetComplexityLimit gets complexity limit from context
func GetComplexityLimit(ctx context.Context) int {
	if limit, ok := ctx.Value(complexityKey).(int); ok {
		return limit
	}
	return 0
}

// Helper functions
func getRemoteIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	// Check X-Real-IP header
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Use RemoteAddr
	return r.RemoteAddr
}

func readBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	return make([]byte, 0), nil
}
