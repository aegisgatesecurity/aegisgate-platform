// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package dashboard provides HTTP handlers and API endpoints for AegisGate's
// real-time monitoring interface.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/i18n"
	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate/pkg/websocket"

	// Security imports
	"github.com/aegisgatesecurity/aegisgate/pkg/security"
)

// version represents the current dashboard API version.
const version = "1.0.0"

// Config holds the dashboard configuration.
type Config struct {
	Port              int      `json:"port"`
	StaticDir         string   `json:"static_dir"`
	AuthToken         string   `json:"auth_token,omitempty"`
	CORSEnabled       bool     `json:"cors_enabled"`
	CORSOrigins       []string `json:"cors_origins,omitempty"`
	RateLimitRequests int      `json:"rate_limit_requests"`
	RateLimitBurst    int      `json:"rate_limit_burst"`
	LogLevel          string   `json:"log_level"`
	// Security configuration
	EnableCSRF            bool          `json:"enable_csrf,omitempty"`
	CSRFTokenLifetime     time.Duration `json:"csrf_token_lifetime,omitempty"`
	EnableAudit           bool          `json:"enable_audit,omitempty"`
	AuditLevel            string        `json:"audit_level,omitempty"`
	EnableSecurityHeaders bool          `json:"enable_security_headers,omitempty"`
	CSPPolicy             string        `json:"csp_policy,omitempty"`
	EnablePanicRecovery   bool          `json:"enable_panic_recovery,omitempty"`
	SecretsProvider       string        `json:"secrets_provider,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Port:              8080,
		StaticDir:         "./static",
		CORSEnabled:       true,
		CORSOrigins:       []string{"*"},
		RateLimitRequests: 100,
		RateLimitBurst:    150,
		LogLevel:          "INFO",
	}
}

type StatsFilter struct {
	Severity    string    `json:"severity,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Since       time.Time `json:"since,omitempty"`
	Until       time.Time `json:"until,omitempty"`
	PatternType string    `json:"pattern_type,omitempty"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type DashboardData struct {
	Version      string                 `json:"version"`
	ServerTime   time.Time              `json:"server_time"`
	Uptime       time.Duration          `json:"uptime"`
	Config       Config                 `json:"config"`
	Stats        map[string]interface{} `json:"stats"`
	WebSocketURL string                 `json:"websocket_url"`
}

type Route struct {
	Path        string
	Method      string
	Handler     HandlerFunc
	RequireAuth bool
	RateLimited bool
}

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

type Dashboard struct {
	config      Config
	server      *http.Server
	metrics     *metrics.MetricsCollector
	sseServer   *websocket.SSEServer
	routes      []Route
	startTime   time.Time
	logger      *slog.Logger
	rateLimiter *RateLimiter
	i18n        *i18n.Manager
	csrfHandler *security.CSRFMiddleware
	auditLogger *security.AuditLogger
}

type RateLimiter struct {
	requests int
	burst    int
	clients  map[string]*clientLimit
	mu       sync.Mutex
}

type clientLimit struct {
	tokens    int
	lastCheck time.Time
}

func NewRateLimiter(requests, burst int) *RateLimiter {
	return &RateLimiter{
		requests: requests,
		burst:    burst,
		clients:  make(map[string]*clientLimit),
	}
}

func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cl, exists := rl.clients[clientIP]
	if !exists {
		rl.clients[clientIP] = &clientLimit{
			tokens:    rl.burst - 1,
			lastCheck: now,
		}
		return true
	}
	elapsed := now.Sub(cl.lastCheck).Seconds()
	cl.tokens = min(cl.tokens+int(elapsed*float64(rl.requests)), rl.burst)
	cl.lastCheck = now
	if cl.tokens > 0 {
		cl.tokens--
		return true
	}
	return false
}

// New creates a new Dashboard without i18n support (backward compatible)
func New(cfg Config) *Dashboard {

	// Security is initialized after Dashboard struct is created
	logger := slog.Default().WithGroup("dashboard")
	sseServer := websocket.NewDefaultSSEServer()
	return &Dashboard{
		config:      cfg,
		startTime:   time.Now(),
		logger:      logger,
		metrics:     metrics.GlobalCollector(),
		sseServer:   sseServer,
		rateLimiter: NewRateLimiter(cfg.RateLimitRequests, cfg.RateLimitBurst),
		routes:      make([]Route, 0),
	}
}

// NewWithI18n creates a new Dashboard with i18n support
func NewWithI18n(cfg Config, i18nManager *i18n.Manager) *Dashboard {
	d := New(cfg)
	d.i18n = i18nManager
	return d
}

// getLocaleFromRequest extracts the locale from the Accept-Language header

// initSecurity initializes all security components

func (d *Dashboard) getLocaleFromRequest(r *http.Request) i18n.Locale {
	acceptLanguage := r.Header.Get("Accept-Language")
	if acceptLanguage == "" {
		if d.i18n != nil {
			return d.i18n.GetCurrent()
		}
		return i18n.DefaultLocale
	}

	// Parse Accept-Language header (simple implementation)
	// Format: "en-US,en;q=0.9,fr;q=0.8"
	parts := strings.Split(acceptLanguage, ",")
	if len(parts) > 0 {
		// Take the first language
		lang := strings.TrimSpace(parts[0])
		// Remove region suffix (e.g., "en-US" -> "en")
		if idx := strings.Index(lang, "-"); idx > 0 {
			lang = lang[:idx]
		}
		locale := i18n.ParseLocale(lang)
		if i18n.IsValidLocale(locale) {
			return locale
		}
	}

	if d.i18n != nil {
		return d.i18n.GetCurrent()
	}
	return i18n.DefaultLocale
}

// t translates a message key for the given locale
func (d *Dashboard) t(locale i18n.Locale, key string) string {
	if d.i18n == nil {
		return key
	}
	return d.i18n.TLocale(locale, key)
}

// tWith translates a message key with variables for the given locale
func (d *Dashboard) tWith(locale i18n.Locale, key string, vars map[string]interface{}) string {
	if d.i18n == nil {
		return key
	}
	return d.i18n.TLocaleWith(locale, key, vars)
}

func (d *Dashboard) Start() error {
	d.setupRoutes()
	mux := http.NewServeMux()
	for _, route := range d.routes {
		handler := d.middleware(route.Handler, route.RequireAuth, route.RateLimited)
		mux.HandleFunc(route.Path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != route.Method && route.Method != "" {
				locale := d.getLocaleFromRequest(r)
				d.errorResponse(w, http.StatusMethodNotAllowed, d.t(locale, "error.method_not_allowed"))
				return
			}
			handler(w, r)
		})
	}
	mux.HandleFunc("/static/", d.serveStatic)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := d.serveIndex(w, r); err != nil {
			locale := d.getLocaleFromRequest(r)
			d.errorResponse(w, http.StatusInternalServerError, d.tWith(locale, "error.internal", map[string]interface{}{"Error": err.Error()}))
		}
	})
	d.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", d.config.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	d.logger.Info("Starting dashboard server", "port", d.config.Port)
	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			d.logger.Error("Dashboard server failed", "error", err)
		}
	}()
	return nil
}

func (d *Dashboard) Stop(ctx context.Context) error {
	if d.server == nil {
		return nil
	}
	d.logger.Info("Stopping dashboard server")
	return d.server.Shutdown(ctx)
}

func (d *Dashboard) setupRoutes() {
	d.routes = append(d.routes, Route{Path: "/api/stats", Method: http.MethodGet, Handler: d.handleAPIStats, RequireAuth: false, RateLimited: true})
	d.routes = append(d.routes, Route{Path: "/api/history", Method: http.MethodGet, Handler: d.handleAPIHistory, RequireAuth: false, RateLimited: true})
	d.routes = append(d.routes, Route{Path: "/api/violations", Method: http.MethodGet, Handler: d.handleAPIViolations, RequireAuth: false, RateLimited: true})
	d.routes = append(d.routes, Route{Path: "/api/patterns", Method: http.MethodGet, Handler: d.handleAPIPatterns, RequireAuth: false, RateLimited: true})
	d.routes = append(d.routes, Route{Path: "/api/health", Method: http.MethodGet, Handler: d.handleAPIHealth, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/api/version", Method: http.MethodGet, Handler: d.handleAPIVersion, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/api/health/detailed", Method: http.MethodGet, Handler: d.handleDetailedHealth, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/health/live", Method: http.MethodGet, Handler: d.handleLiveness, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/health/ready", Method: http.MethodGet, Handler: d.handleReadiness, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/health", Method: http.MethodGet, Handler: d.handleEnhancedHealth, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/health/components", Method: http.MethodGet, Handler: d.handleComponentHealth, RequireAuth: false, RateLimited: false})
	d.routes = append(d.routes, Route{Path: "/metrics", Method: http.MethodGet, Handler: d.handlePrometheusMetrics, RequireAuth: false, RateLimited: false})

	d.routes = append(d.routes, Route{Path: "/api/config", Method: http.MethodGet, Handler: d.handleAPIConfig, RequireAuth: true, RateLimited: true})
	d.routes = append(d.routes, Route{Path: "/events", Method: http.MethodGet, Handler: d.sseHandler, RequireAuth: false, RateLimited: false})
}

func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := DashboardData{
		Version:      version,
		ServerTime:   time.Now(),
		Uptime:       time.Since(d.startTime),
		WebSocketURL: fmt.Sprintf("ws://%s/events", r.Host),
	}
	if d.metrics != nil {
		stats := d.metrics.GetStats()
		data.Stats = map[string]interface{}{
			"requests":   stats.Requests,
			"responses":  stats.Responses,
			"blocked":    stats.Blocked,
			"violations": stats.Violations,
			"errors":     stats.Errors,
		}
	}
	tmpl := `<!DOCTYPE html><html><head><title>AegisGate</title></head><body>Dashboard</body></html>`
	_, _ = fmt.Fprint(w, tmpl)
	return nil
}

func (d *Dashboard) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		locale := d.getLocaleFromRequest(r)
		http.Error(w, d.t(locale, "error.method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	path = filepath.Clean(path)
	if strings.Contains(path, "..") {
		locale := d.getLocaleFromRequest(r)
		d.errorResponse(w, http.StatusNotFound, d.t(locale, "error.not_found"))
		return
	}
	fullPath := filepath.Join(d.config.StaticDir, path)
	ext := filepath.Ext(fullPath)
	switch ext {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	}
	http.ServeFile(w, r, fullPath)
}

func (d *Dashboard) handleAPIStats(w http.ResponseWriter, r *http.Request) error {
	if d.metrics == nil {
		d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: make(map[string]interface{}), Timestamp: time.Now()})
		return nil
	}
	stats := d.metrics.GetStats()
	d.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"requests":   stats.Requests,
			"responses":  stats.Responses,
			"blocked":    stats.Blocked,
			"violations": stats.Violations,
			"errors":     stats.Errors,
		},
		Timestamp: time.Now(),
	})
	return nil
}

func (d *Dashboard) handleAPIHistory(w http.ResponseWriter, r *http.Request) error {
	filter := d.parseHistoryFilter(r)
	data := map[string]interface{}{
		"type":   filter.PatternType,
		"since":  filter.Since,
		"until":  filter.Until,
		"values": []interface{}{},
	}
	if d.metrics != nil {
		history := d.metrics.GetRequestHistory()
		if len(history) > 0 {
			data["values"] = history
		}
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: data, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) handleAPIViolations(w http.ResponseWriter, r *http.Request) error {
	violations := []map[string]interface{}{}
	if d.metrics != nil {
		sc := d.metrics.GetSeverityCounts()
		violations = append(violations, map[string]interface{}{
			"critical": sc.Critical,
			"high":     sc.High,
			"medium":   sc.Medium,
			"low":      sc.Low,
			"info":     sc.Info,
		})
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: violations, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) handleAPIPatterns(w http.ResponseWriter, r *http.Request) error {
	patterns := map[string]interface{}{
		"total_patterns": 0,
		"matches":        map[string]int{},
	}
	if d.metrics != nil {
		pm := d.metrics.GetPatternMatches()
		matches := make(map[string]int)
		for name, p := range pm {
			matches[name] = int(p.GetCount())
		}
		patterns["matches"] = matches
		patterns["total_patterns"] = len(pm)
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: patterns, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) handleAPIHealth(w http.ResponseWriter, r *http.Request) error {
	locale := d.getLocaleFromRequest(r)
	health := map[string]interface{}{
		"status":    d.t(locale, "health.status_healthy"),
		"uptime":    time.Since(d.startTime).Seconds(),
		"timestamp": time.Now(),
	}
	if d.metrics != nil {
		health["metrics_status"] = d.t(locale, "health.connected")
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: health, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) handleAPIVersion(w http.ResponseWriter, r *http.Request) error {
	versionInfo := map[string]interface{}{
		"version":       version,
		"api_version":   "v1",
		"build_time":    "unknown",
		"go_version":    "unknown",
		"server_time":   time.Now(),
		"server_uptime": time.Since(d.startTime).Seconds(),
	}
	// Add locale info if i18n is enabled
	if d.i18n != nil {
		versionInfo["locale"] = string(d.i18n.GetCurrent())
		versionInfo["supported_locales"] = []string{"en", "fr", "de", "es", "ja", "zh"}
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: versionInfo, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) handleAPIConfig(w http.ResponseWriter, r *http.Request) error {
	safeConfig := map[string]interface{}{
		"port":           d.config.Port,
		"static_dir":     d.config.StaticDir,
		"cors_enabled":   d.config.CORSEnabled,
		"rate_limit_req": d.config.RateLimitRequests,
		"log_level":      d.config.LogLevel,
	}
	if d.i18n != nil {
		safeConfig["locale"] = string(d.i18n.GetCurrent())
	}
	d.writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: safeConfig, Timestamp: time.Now()})
	return nil
}

func (d *Dashboard) sseHandler(w http.ResponseWriter, r *http.Request) error {
	if d.sseServer == nil {
		locale := d.getLocaleFromRequest(r)
		return errors.New(d.t(locale, "error.websocket_unavailable"))
	}
	d.sseServer.HandleSSE(w, r)
	return nil
}

func (d *Dashboard) middleware(next HandlerFunc, requireAuth, rateLimited bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create base handler from next
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = next(w, r)
		})

		// Apply panic recovery
		if d.config.EnablePanicRecovery {
			recovery := security.NewPanicRecoveryMiddleware()
			handler = recovery.Handler(handler)
		}

		// Apply security headers - creates middleware function
		if d.config.EnableSecurityHeaders {
			config := security.SecurityHeadersConfig{
				ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'unsafe-inline'",
			}
			headersMiddleware := security.SecurityHeadersMiddleware(config)
			handler = headersMiddleware(handler)
		}

		// Apply CSRF protection
		if d.csrfHandler != nil {
			originalHandler := handler
			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Skip CSRF for safe methods
				if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
					originalHandler.ServeHTTP(w, r)
					return
				}
				d.csrfHandler.Handler(originalHandler).ServeHTTP(w, r)
			})
		}

		// Apply audit logging
		if d.auditLogger != nil {
			handler = security.AuditMiddleware(d.auditLogger, handler)
		}

		// Execute handler chain
		handler.ServeHTTP(w, r)
	}
}

func (d *Dashboard) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := false
	if len(d.config.CORSOrigins) == 0 || (len(d.config.CORSOrigins) == 1 && d.config.CORSOrigins[0] == "*") {
		allowed = true
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else {
		for _, o := range d.config.CORSOrigins {
			if o == origin {
				allowed = true
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}
	if allowed {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (d *Dashboard) checkAuth(r *http.Request) bool {
	if d.config.AuthToken == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1] == d.config.AuthToken
	}
	return authHeader == d.config.AuthToken
}

func (d *Dashboard) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (d *Dashboard) errorResponse(w http.ResponseWriter, status int, message string) {
	d.writeJSON(w, status, APIResponse{Success: false, Error: message, Timestamp: time.Now()})
}

func (d *Dashboard) parseStatsFilter(r *http.Request) StatsFilter {
	filter := StatsFilter{Limit: 100}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = strings.ToUpper(severity)
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = min(limit, 1000)
		}
	}
	return filter
}

func (d *Dashboard) parseHistoryFilter(r *http.Request) StatsFilter {
	filter := d.parseStatsFilter(r)
	if filterType := r.URL.Query().Get("type"); filterType != "" {
		filter.PatternType = filterType
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = t
		}
	}
	return filter
}

func (d *Dashboard) RegisterEventChannel(events <-chan metrics.MetricEvent) {
	go func() {
		for event := range events {
			if d.sseServer != nil {
				d.sseServer.BroadcastEvent(context.Background(), websocket.Event{
					Event: "metric",
					Data:  event,
				})
			}
		}
	}()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
