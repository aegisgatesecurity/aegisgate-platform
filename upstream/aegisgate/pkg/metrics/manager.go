// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package metrics provides metrics collection for AegisGate
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// Manager wraps MetricsCollector for compatibility
type Manager struct {
	collector *MetricsCollector
	logger    *slog.Logger
	server    *http.Server
	startTime time.Time
}

// NewManager creates a new metrics manager
func NewManager(cfg interface{}) *Manager {
	opts, ok := cfg.(CollectorOptions)
	if !ok {
		opts = DefaultCollectorOptions()
	}

	return &Manager{
		collector: NewCollector(&opts),
		logger:    slog.Default(),
		startTime: time.Now(),
	}
}

// Start starts the metrics server
func (m *Manager) Start(addr string) error {
	m.logger.Info("starting metrics server", "address", addr)

	m.server = &http.Server{
		Addr:         addr,
		Handler:      m,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return m.server.ListenAndServe()
}

// Stop stops the metrics server
func (m *Manager) Stop() error {
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return m.server.Shutdown(ctx)
	}
	return nil
}

// ServeHTTP serves metrics in Prometheus format
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stats := m.collector.GetStats()

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	// Output Prometheus format
	_, _ = w.Write([]byte("# HELP aegisgate_requests_total Total requests\n"))
	_, _ = w.Write([]byte("# TYPE aegisgate_requests_total counter\n"))
	_, _ = w.Write([]byte("aegisgate_requests_total " + string(rune(stats.Requests)) + "\n"))

	w.Write([]byte("# HELP aegisgate_responses_total Total responses\n"))
	w.Write([]byte("# TYPE aegisgate_responses_total counter\n"))
	w.Write([]byte("aegisgate_responses_total " + string(rune(stats.Responses)) + "\n"))

	w.Write([]byte("# HELP aegisgate_blocked_total Total blocked requests\n"))
	w.Write([]byte("# TYPE aegisgate_blocked_total counter\n"))
	w.Write([]byte("aegisgate_blocked_total " + string(rune(stats.Blocked)) + "\n"))

	w.Write([]byte("# HELP aegisgate_violations_total Total violations\n"))
	w.Write([]byte("# TYPE aegisgate_violations_total counter\n"))
	w.Write([]byte("aegisgate_violations_total " + string(rune(stats.Violations)) + "\n"))

	w.Write([]byte("# HELP aegisgate_errors_total Total errors\n"))
	w.Write([]byte("# TYPE aegisgate_errors_total counter\n"))
	w.Write([]byte("aegisgate_errors_total " + string(rune(stats.Errors)) + "\n"))
}

// GetCollector returns the underlying collector
func (m *Manager) GetCollector() *MetricsCollector {
	return m.collector
}

// GetHealth returns health status
func (m *Manager) GetHealth() map[string]interface{} {
	stats := m.collector.GetStats()
	return map[string]interface{}{
		"status":           "healthy",
		"uptime":           time.Since(m.startTime).Seconds(),
		"total_requests":   stats.Requests,
		"total_responses":  stats.Responses,
		"total_blocked":    stats.Blocked,
		"total_violations": stats.Violations,
	}
}

// GetStats returns statistics
func (m *Manager) GetStats() map[string]interface{} {
	stats := m.collector.GetStats()
	return map[string]interface{}{
		"total_requests":     stats.Requests,
		"blocked_requests":   stats.Blocked,
		"active_users":       int64(0),
		"active_connections": int64(0),
		"uptime":             time.Since(m.startTime).Seconds(),
	}
}

// GetUptime returns uptime in seconds
func (m *Manager) GetUptime() float64 {
	return time.Since(m.startTime).Seconds()
}
