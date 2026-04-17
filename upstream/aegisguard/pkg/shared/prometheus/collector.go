// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package prometheus provides Prometheus metrics integration for AegisGuard.
// Based on AegisGate Security observability implementation.
package prometheus

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ============================================================================
// CORE METRICS
// ============================================================================

var (
	// Tool call metrics
	toolCallsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisguard_tool_calls_total",
			Help: "Total number of tool calls processed",
		},
		[]string{"tool_name", "status"},
	)

	toolCallDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisguard_tool_call_duration_seconds",
			Help:    "Tool call processing duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"tool_name"},
	)

	toolErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisguard_tool_errors_total",
			Help: "Total number of tool errors",
		},
		[]string{"tool_name", "error_type"},
	)

	// Session metrics
	sessionsCreatedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisguard_sessions_created_total",
			Help: "Total number of sessions created",
		},
	)

	sessionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_sessions_active",
			Help: "Number of active sessions",
		},
	)

	sessionsDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aegisguard_session_duration_seconds",
			Help:    "Session duration in seconds",
			Buckets: []float64{60, 300, 900, 1800, 3600, 7200, 14400, 28800, 86400},
		},
	)

	// Agent metrics
	agentsRegisteredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisguard_agents_registered_total",
			Help: "Total number of agents registered",
		},
	)

	agentsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_agents_active",
			Help: "Number of active agents",
		},
	)

	// Authorization metrics
	authDecisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisguard_auth_decisions_total",
			Help: "Total number of authorization decisions",
		},
		[]string{"decision", "tool_name"},
	)

	authLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisguard_auth_latency_seconds",
			Help:    "Authorization decision latency in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		},
		[]string{"decision"},
	)

	// Audit metrics
	auditEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisguard_audit_events_total",
			Help: "Total number of audit events",
		},
		[]string{"event_type", "severity"},
	)

	// Risk score metrics
	toolRiskScores = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisguard_tool_risk_scores",
			Help:    "Distribution of tool risk scores",
			Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
		[]string{"tool_name"},
	)

	blockedToolsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisguard_tools_blocked_total",
			Help: "Total number of tools blocked by risk level",
		},
		[]string{"tool_name", "reason"},
	)

	// System metrics
	goGoroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_goroutines",
			Help: "Number of goroutines",
		},
	)

	goMemoryAlloc = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_memory_alloc_bytes",
			Help: "Memory allocated in bytes",
		},
	)

	goMemoryHeap = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_memory_heap_bytes",
			Help: "Heap memory allocated in bytes",
		},
	)

	// Connection metrics
	connectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisguard_connections_active",
			Help: "Number of active MCP connections",
		},
	)

	connectionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisguard_connections_total",
			Help: "Total number of MCP connections established",
		},
	)

	connectionsClosed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisguard_connections_closed_total",
			Help: "Total number of MCP connections closed",
		},
	)
)

// ============================================================================
// COLLECTOR
// ============================================================================

// Collector manages Prometheus metrics collection
type Collector struct {
	mu         sync.RWMutex
	startTime  time.Time
	subsystems map[string]*SubsystemMetrics
}

// SubsystemMetrics holds metrics for a specific subsystem
type SubsystemMetrics struct {
	RequestsTotal  prometheus.Counter
	RequestLatency prometheus.Histogram
	ErrorsTotal    prometheus.Counter
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		startTime:  time.Now(),
		subsystems: make(map[string]*SubsystemMetrics),
	}
}

// RegisterSubsystem registers a new subsystem with its own metrics
func (c *Collector) RegisterSubsystem(name string) *SubsystemMetrics {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.subsystems[name]; exists {
		return c.subsystems[name]
	}

	metrics := &SubsystemMetrics{
		RequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "aegisguard_" + name + "_requests_total",
			Help: "Total requests for " + name,
		}),
		RequestLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "aegisguard_" + name + "_latency_seconds",
			Help:    "Request latency for " + name,
			Buckets: prometheus.DefBuckets,
		}),
		ErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "aegisguard_" + name + "_errors_total",
			Help: "Total errors for " + name,
		}),
	}

	c.subsystems[name] = metrics
	return metrics
}

// UpdateSystemMetrics updates Go runtime metrics
func (c *Collector) UpdateSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	goGoroutines.Set(float64(runtime.NumGoroutine()))
	goMemoryAlloc.Set(float64(memStats.Alloc))
	goMemoryHeap.Set(float64(memStats.HeapAlloc))
}

// Uptime returns the collector uptime
func (c *Collector) Uptime() time.Duration {
	return time.Since(c.startTime)
}

// ============================================================================
// TOOL METRICS HELPERS
// ============================================================================

// RecordToolCall records a tool call metric
func RecordToolCall(toolName string, status string, duration time.Duration) {
	toolCallsTotal.WithLabelValues(toolName, status).Inc()
	toolCallDuration.WithLabelValues(toolName).Observe(duration.Seconds())
}

// RecordToolError records a tool error
func RecordToolError(toolName, errorType string) {
	toolErrorsTotal.WithLabelValues(toolName, errorType).Inc()
}

// RecordToolRiskScore records the risk score for a tool call
func RecordToolRiskScore(toolName string, score int) {
	toolRiskScores.WithLabelValues(toolName).Observe(float64(score))
}

// RecordToolBlocked records a blocked tool call
func RecordToolBlocked(toolName, reason string) {
	blockedToolsTotal.WithLabelValues(toolName, reason).Inc()
}

// ============================================================================
// SESSION METRICS HELPERS
// ============================================================================

// RecordSessionCreated records a new session creation
func RecordSessionCreated() {
	sessionsCreatedTotal.Inc()
	sessionsActive.Inc()
}

// RecordSessionEnded records a session ending
func RecordSessionEnded(duration time.Duration) {
	sessionsActive.Dec()
	sessionsDuration.Observe(duration.Seconds())
}

// ============================================================================
// AGENT METRICS HELPERS
// ============================================================================

// RecordAgentRegistered records a new agent registration
func RecordAgentRegistered() {
	agentsRegisteredTotal.Inc()
	agentsActive.Inc()
}

// RecordAgentUnregistered records an agent unregistration
func RecordAgentUnregistered() {
	agentsActive.Dec()
}

// ============================================================================
// AUTHORIZATION METRICS HELPERS
// ============================================================================

// RecordAuthDecision records an authorization decision
func RecordAuthDecision(decision, toolName string, latency time.Duration) {
	authDecisionsTotal.WithLabelValues(decision, toolName).Inc()
	authLatency.WithLabelValues(decision).Observe(latency.Seconds())
}

// RecordAuthAllowed records an allowed authorization
func RecordAuthAllowed(toolName string, latency time.Duration) {
	RecordAuthDecision("allowed", toolName, latency)
}

// RecordAuthDenied records a denied authorization
func RecordAuthDenied(toolName string, latency time.Duration) {
	RecordAuthDecision("denied", toolName, latency)
}

// ============================================================================
// AUDIT METRICS HELPERS
// ============================================================================

// RecordAuditEvent records an audit event
func RecordAuditEvent(eventType, severity string) {
	auditEventsTotal.WithLabelValues(eventType, severity).Inc()
}

// ============================================================================
// CONNECTION METRICS HELPERS
// ============================================================================

// RecordConnectionOpened records a new connection
func RecordConnectionOpened() {
	connectionsTotal.Inc()
	connectionsActive.Inc()
}

// RecordConnectionClosed records a closed connection
func RecordConnectionClosed() {
	connectionsActive.Dec()
	connectionsClosed.Inc()
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// Handler returns an HTTP handler for Prometheus metrics
func Handler() http.Handler {
	return promhttp.Handler()
}

// HandlerWithCollector returns an HTTP handler that also updates system metrics
func HandlerWithCollector(c *Collector) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.UpdateSystemMetrics()
		promhttp.Handler().ServeHTTP(w, r)
	})
}

// ServeMetrics is a convenience function to add /metrics endpoint to an existing server
func ServeMetrics(mux *http.ServeMux, collector *Collector) {
	if collector == nil {
		collector = NewCollector()
	}

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		collector.UpdateSystemMetrics()
		promhttp.Handler().ServeHTTP(w, r)
	})
}

// ============================================================================
// GLOBAL COLLECTOR
// ============================================================================

var (
	globalCollector     *Collector
	globalCollectorOnce sync.Once
)

// Global returns the global metrics collector
func Global() *Collector {
	globalCollectorOnce.Do(func() {
		globalCollector = NewCollector()
	})
	return globalCollector
}

// RecordToolCallGlobal is a convenience wrapper for Global().RecordToolCall
func RecordToolCallGlobal(toolName, status string, duration time.Duration) {
	RecordToolCall(toolName, status, duration)
}

// RecordSessionCreatedGlobal is a convenience wrapper for Global().RecordSessionCreated
func RecordSessionCreatedGlobal() {
	RecordSessionCreated()
}

// RecordAgentRegisteredGlobal is a convenience wrapper for Global().RecordAgentRegistered
func RecordAgentRegisteredGlobal() {
	RecordAgentRegistered()
}

// RecordConnectionOpenedGlobal is a convenience wrapper for Global().RecordConnectionOpened
func RecordConnectionOpenedGlobal() {
	RecordConnectionOpened()
}

// ============================================================================
// STATS COLLECTOR (for periodic updates)
// ============================================================================

// StartStatsCollector starts a background goroutine that periodically updates system metrics
func StartStatsCollector(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			goGoroutines.Set(float64(runtime.NumGoroutine()))
			goMemoryAlloc.Set(float64(memStats.Alloc))
			goMemoryHeap.Set(float64(memStats.HeapAlloc))
		}
	}()
}

// ============================================================================
// HELPERS
// ============================================================================

// LatencyToFloat converts a duration to seconds for Prometheus
func LatencyToFloat(d time.Duration) float64 {
	return d.Seconds()
}

// StatusCodeToString converts an int status code to string
func StatusCodeToString(code int) string {
	return strconv.Itoa(code)
}
