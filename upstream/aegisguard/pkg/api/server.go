// Package api - REST API server for AegisGuard
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/api/handlers"
	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// Server represents the REST API server
type Server struct {
	addr       string
	manager    *rbac.Manager
	mux        *http.ServeMux
	shutdown   chan struct{}
	shutdownFn func() error
	version    string
	startTime  time.Time

	// Handlers
	agentHandler   *handlers.AgentHandler
	sessionHandler *handlers.SessionHandler
	authHandler    *handlers.AuthHandler
	toolsHandler   *handlers.ToolsHandler
	rolesHandler   *handlers.RolesHandler
	metricsHandler *handlers.MetricsHandler
}

// Config holds API server configuration
type Config struct {
	Addr    string
	Manager *rbac.Manager
	Version string
}

// NewServer creates a new API server
func NewServer(cfg *Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8082"
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}

	s := &Server{
		addr:      cfg.Addr,
		manager:   cfg.Manager,
		mux:       http.NewServeMux(),
		shutdown:  make(chan struct{}),
		version:   cfg.Version,
		startTime: time.Now(),
	}

	// Initialize handlers
	s.initHandlers()

	// Setup routes
	s.setupRoutes()

	return s
}

// initHandlers initializes all API handlers
func (s *Server) initHandlers() {
	s.agentHandler = handlers.NewAgentHandler(s.manager)
	s.sessionHandler = handlers.NewSessionHandler(s.manager)
	s.authHandler = handlers.NewAuthHandler(s.manager)
	s.toolsHandler = handlers.NewToolsHandler(s.manager)
	s.rolesHandler = handlers.NewRolesHandler(s.manager)
	s.metricsHandler = handlers.NewMetricsHandler(s.manager, s.version)
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// CORS middleware wrapper
	withCORS := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			handler(w, r)
		}
	}

	// Health check endpoints
	s.mux.HandleFunc("/health", withCORS(s.handleHealth))
	s.mux.HandleFunc("/healthz", withCORS(s.handleHealth))
	s.mux.HandleFunc("/ready", withCORS(s.handleReady))

	// API v1 routes
	v1 := "/api/v1"

	// Agent routes
	s.mux.HandleFunc(v1+"/agents", withCORS(s.agentHandler.HandleAgents))
	s.mux.HandleFunc(v1+"/agents/", withCORS(s.agentHandler.HandleAgentByID))
	s.mux.HandleFunc(v1+"/agents/health", withCORS(s.agentHandler.HandleAgentHealth))

	// Agent sessions route (nested under agents)
	s.mux.HandleFunc(v1+"/agents/.*/sessions", withCORS(s.agentHandler.HandleAgentSessions))

	// Session routes
	s.mux.HandleFunc(v1+"/sessions", withCORS(s.sessionHandler.HandleSessions))
	s.mux.HandleFunc(v1+"/sessions/", withCORS(s.sessionHandler.HandleSessionByID))
	s.mux.HandleFunc(v1+"/sessions/stats", withCORS(s.sessionHandler.HandleSessionStats))

	// Authorization routes
	s.mux.HandleFunc(v1+"/authorize", withCORS(s.authHandler.HandleAuthorize))
	s.mux.HandleFunc(v1+"/authorize/batch", withCORS(s.authHandler.HandleBatchAuthorize))

	// Tools route
	s.mux.HandleFunc(v1+"/tools", withCORS(s.toolsHandler.HandleTools))

	// Roles routes
	s.mux.HandleFunc(v1+"/roles", withCORS(s.rolesHandler.HandleRoles))
	s.mux.HandleFunc(v1+"/roles/", withCORS(s.rolesHandler.HandleRoleByName))

	// Metrics route
	s.mux.HandleFunc(v1+"/metrics", withCORS(s.metricsHandler.HandleMetrics))
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Start starts the API server
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.shutdownFn = srv.Close

	go func() {
		<-s.shutdown
		srv.Shutdown(context.Background())
	}()

	return srv.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	close(s.shutdown)
	if s.shutdownFn != nil {
		return s.shutdownFn()
	}
	return nil
}

// handleHealth returns basic health info
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/health" && r.URL.Path != "/healthz" {
		return
	}

	health := handlers.HealthResponse{
		Status:    "ok",
		Service:   "aegisguard-api",
		Version:   s.version,
		Timestamp: time.Now().Format(time.RFC3339),
		Checks: map[string]string{
			"api": "ok",
		},
	}

	handlers.WriteJSON(w, http.StatusOK, health)
}

// handleReady returns readiness status
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if manager is responsive
	agents := s.manager.ListAgents()

	ready := true
	checks := map[string]string{
		"api":    "ok",
		"rbac":   "ok",
		"agents": fmt.Sprintf("%d", len(agents)),
	}

	if !ready {
		handlers.WriteJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":  "not_ready",
			"service": "aegisguard-api",
			"version": s.version,
			"checks":  checks,
		})
		return
	}

	handlers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ready",
		"service": "aegisguard-api",
		"version": s.version,
		"checks":  checks,
	})
}
