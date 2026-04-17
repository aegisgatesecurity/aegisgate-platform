// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ServerConfig contains server configuration
type ServerConfig struct {
	Host            string
	Port            int
	TLSEnabled      bool
	TLSCertFile     string
	TLSKeyFile      string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	MaxHeaderBytes  int
	ShutdownTimeout time.Duration

	// Feature flags
	EnableVersioning bool
	EnableCaching    bool
	EnableMetrics    bool
	EnableGraphQL    bool
	EnableHealth     bool

	// Versioning config
	VersionConfig *VersionConfig

	// Cache config
	CacheConfig *CacheConfig

	// Optional interfaces (using any to avoid import issues)
	MetricsMgr interface {
		ServeHTTP(http.ResponseWriter, *http.Request)
	}
	ProxySrv interface {
		Start() error
		Stop()
	}
}

// VersionConfig contains versioning configuration
type VersionConfig struct {
	Enable         bool
	StrictMode     bool
	Negotiator     string // "header", "query", "path", "content-type"
	DefaultVersion string
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:             "0.0.0.0",
		Port:             8080,
		TLSEnabled:       false,
		TLSCertFile:      "server.crt",
		TLSKeyFile:       "server.key",
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		IdleTimeout:      60 * time.Second,
		MaxHeaderBytes:   1 << 20, // 1MB
		ShutdownTimeout:  30 * time.Second,
		EnableVersioning: true,
		EnableCaching:    true,
		EnableMetrics:    true,
		EnableGraphQL:    true,
		EnableHealth:     true,
		VersionConfig: &VersionConfig{
			Enable:         true,
			StrictMode:     false,
			Negotiator:     "header",
			DefaultVersion: "v2",
		},
		CacheConfig: DefaultCacheConfig(),
	}
}

// Server is the main API server
type Server struct {
	cfg        *ServerConfig
	httpServer *http.Server
	versionMgr *VersionManager
	cacheMgr   *CacheHandler
	router     *VersionedRouter
	logger     *slog.Logger
	mu         sync.RWMutex
	running    bool
	ready      bool
}

// NewServer creates a new API server
func NewServer(cfg *ServerConfig) *Server {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}

	s := &Server{
		cfg:    cfg,
		logger: slog.Default(),
	}

	// Initialize version manager
	if cfg.EnableVersioning {
		s.versionMgr = DefaultVersionManager()
	}

	// Initialize cache handler
	if cfg.EnableCaching {
		s.cacheMgr = NewCacheHandler(cfg.CacheConfig)
	}

	// Initialize router
	s.router = NewVersionedRouter(s.versionMgr)

	// Set up HTTP server
	s.setupHTTPServer()

	return s
}

// setupHTTPServer configures the HTTP server
func (s *Server) setupHTTPServer() {
	// Create main router
	mux := http.NewServeMux()

	// Apply middleware stack
	handler := s.middlewareChain(mux)

	s.httpServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:        handler,
		ReadTimeout:    s.cfg.ReadTimeout,
		WriteTimeout:   s.cfg.WriteTimeout,
		IdleTimeout:    s.cfg.IdleTimeout,
		MaxHeaderBytes: s.cfg.MaxHeaderBytes,
		TLSConfig:      s.getTLSConfig(),
	}
}

// middlewareChain applies all middleware
func (s *Server) middlewareChain(handler http.Handler) http.Handler {
	// Recovery middleware
	handler = s.recoveryMiddleware(handler)

	// Logging middleware
	handler = s.loggingMiddleware(handler)

	// Versioning middleware
	if s.cfg.EnableVersioning && s.versionMgr != nil {
		handler = VersionMiddleware(s.versionMgr)(handler)
	}

	// Caching middleware
	if s.cfg.EnableCaching && s.cacheMgr != nil {
		handler = s.cacheMgr.Handle(handler)
	}

	// CORS middleware (if needed)
	handler = s.corsMiddleware(handler)

	// Rate limiting (if needed)
	// handler = s.rateLimitMiddleware(handler)

	return handler
}

// loggingMiddleware logs all requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		rec := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rec, r)

		duration := time.Since(start)

		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode,
			"duration", duration,
			"client", r.RemoteAddr,
		)
	})
}

// recoveryMiddleware recovers from panics
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.logger.Error("panic recovered", "error", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal Server Error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles CORS
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept-Version")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getTLSConfig returns TLS configuration
func (s *Server) getTLSConfig() *tls.Config {
	if !s.cfg.TLSEnabled {
		return nil
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
	}
}

// Start starts the server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Register routes
	s.registerRoutes()

	// Start server
	addr := s.httpServer.Addr
	s.logger.Info("starting server", "address", addr, "tls", s.cfg.TLSEnabled)

	go func() {
		var err error
		if s.cfg.TLSEnabled {
			err = s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("server error", "error", err)
		}
	}()

	// Mark as ready
	s.ready = true
	s.logger.Info("server started successfully")

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("server not running")
	}

	s.logger.Info("shutting down server")
	s.ready = false

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// registerRoutes registers all API routes
func (s *Server) registerRoutes() {
	// Health endpoint
	if s.cfg.EnableHealth {
		s.router.AddRoute("v1", "GET", "/health", s.handleHealth())
		s.router.AddRoute("v2", "GET", "/health", s.handleHealthV2())
	}

	// Metrics endpoint
	if s.cfg.EnableMetrics {
		s.router.AddRoute("v1", "GET", "/metrics", s.handleMetrics())
		s.router.AddRoute("v2", "GET", "/metrics", s.handleMetrics())
	}

	// API info
	s.router.AddRoute("v1", "GET", "/api/info", s.handleAPIInfo())
	s.router.AddRoute("v2", "GET", "/api/info", s.handleAPIInfo())

	// Version endpoints
	if s.cfg.EnableVersioning {
		s.router.AddRoute("v1", "GET", "/api/versions", s.handleListVersions())
		s.router.AddRoute("v2", "GET", "/api/versions", s.handleListVersions())
	}

	// Cache endpoints
	if s.cfg.EnableCaching {
		s.router.AddRoute("v1", "GET", "/api/cache/stats", s.handleCacheStats())
		s.router.AddRoute("v1", "DELETE", "/api/cache", s.handleCacheClear())
		s.router.AddRoute("v2", "GET", "/api/cache/stats", s.handleCacheStats())
		s.router.AddRoute("v2", "DELETE", "/api/cache", s.handleCacheClear())
	}
}

// Handlers

func (s *Server) handleHealth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
		})
	})
}

func (s *Server) handleHealthV2() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get cache stats if available
		var cacheStats map[string]interface{}
		if s.cacheMgr != nil {
			stats, _ := s.cfg.CacheConfig.Store.Stats(r.Context())
			cacheStats = map[string]interface{}{
				"hits":      stats.Hits,
				"misses":    stats.Misses,
				"items":     stats.Items,
				"memory_mb": stats.MemoryBytes / (1024 * 1024),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"version":   "v2",
			"timestamp": time.Now().Unix(),
			"cache":     cacheStats,
		})
	})
}

func (s *Server) handleMetrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If metrics manager is provided, use it
		if s.cfg.MetricsMgr != nil {
			s.cfg.MetricsMgr.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "# AegisGate Metrics")
		_, _ = fmt.Fprintf(w, "aegisgate_requests_total 0\n")
	})
}

func (s *Server) handleAPIInfo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := map[string]interface{}{
			"name":        "AegisGate API",
			"version":     "0.36.0",
			"description": "Enterprise Security Platform",
			"features": map[string]bool{
				"versioning": s.cfg.EnableVersioning,
				"caching":    s.cfg.EnableCaching,
				"metrics":    s.cfg.EnableMetrics,
				"graphql":    s.cfg.EnableGraphQL,
			},
		}

		// Add version info if available
		if s.versionMgr != nil {
			info["supported_versions"] = s.versionMgr.GetSupportedVersions()
			info["default_version"] = s.versionMgr.GetDefaultVersion()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(info)
	})
}

func (s *Server) handleListVersions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.versionMgr == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Versioning not enabled",
			})
			return
		}

		versions := s.versionMgr.GetSupportedVersions()

		// Build version info
		type VersionInfo struct {
			Version     string `json:"version"`
			Deprecated  bool   `json:"deprecated,omitempty"`
			Sunset      string `json:"sunset,omitempty"`
			Unsupported bool   `json:"unsupported,omitempty"`
		}

		result := make([]VersionInfo, len(versions))
		for i, v := range versions {
			ver, _ := s.versionMgr.GetVersion(v)
			info := VersionInfo{Version: v}
			if ver != nil {
				info.Deprecated = ver.Deprecated
				info.Unsupported = ver.Unsupported
				if ver.Sunset != nil {
					info.Sunset = ver.Sunset.Format(time.RFC3339)
				}
			}
			result[i] = info
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"versions":           result,
			"default_version":    s.versionMgr.GetDefaultVersion(),
			"supported_versions": versions,
		})
	})
}

func (s *Server) handleCacheStats() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cacheMgr == nil || s.cfg.CacheConfig == nil || s.cfg.CacheConfig.Store == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Caching not enabled",
			})
			return
		}

		stats, err := s.cfg.CacheConfig.Store.Stats(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Calculate hit rate
		hitRate := float64(0)
		total := stats.Hits + stats.Misses
		if total > 0 {
			hitRate = float64(stats.Hits) / float64(total) * 100
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hits":         stats.Hits,
			"misses":       stats.Misses,
			"hit_rate":     fmt.Sprintf("%.2f%%", hitRate),
			"items":        stats.Items,
			"evictions":    stats.Evictions,
			"memory_bytes": stats.MemoryBytes,
			"uptime":       stats.Uptime.String(),
		})
	})
}

func (s *Server) handleCacheClear() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cacheMgr == nil || s.cfg.CacheConfig == nil || s.cfg.CacheConfig.Store == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Caching not enabled",
			})
			return
		}

		err := s.cfg.CacheConfig.Store.Clear(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "cleared",
		})
	})
}

// AddRoute adds a route to the server
func (s *Server) AddRoute(version, method, path string, handler http.Handler) {
	s.router.AddRoute(version, method, path, handler)
}

// AddRouteFunc adds a route with a handler function
func (s *Server) AddRouteFunc(version, method, path string, fn func(http.ResponseWriter, *http.Request)) {
	s.router.AddRoute(version, method, path, http.HandlerFunc(fn))
}

// UseMiddleware adds middleware to all routes
func (s *Server) UseMiddleware(middleware func(http.Handler) http.Handler) {
	s.router.Use(middleware)
}

// Router returns the underlying router
func (s *Server) Router() *VersionedRouter {
	return s.router
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.ready {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Server not ready",
		})
		return
	}

	s.router.Handler().ServeHTTP(w, r)
}

// statusResponseWriter wraps http.ResponseWriter to capture status code
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// RunServer runs the server with signal handling
func RunServer(cfg *ServerConfig) error {
	server := NewServer(cfg)

	if err := server.Start(); err != nil {
		return err
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")

	return server.Stop()
}

// Ensure strconv is used for conversion
var _ = strconv.Itoa
