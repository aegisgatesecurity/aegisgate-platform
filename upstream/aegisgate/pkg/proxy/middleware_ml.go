// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Copyright 2024 AegisGate, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/ml"
)

// logger is the package-level logger
var logger = slog.Default()

// getClientIP extracts the client IP from the request, considering proxies
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// MLMiddlewareConfig holds configuration for ML anomaly detection middleware
type MLMiddlewareConfig struct {
	// Enabled toggles ML anomaly detection on/off
	Enabled bool `json:"enabled"`

	// Sensitivity determines the threshold for anomaly detection
	// Options: "low", "medium", "high", "paranoid"
	Sensitivity string `json:"sensitivity"`

	// BlockOnHighSeverity determines if high-severity anomalies should be blocked
	BlockOnHighSeverity bool `json:"block_on_high_severity"`

	// BlockOnCriticalSeverity determines if critical-severity anomalies should be blocked
	BlockOnCriticalSeverity bool `json:"block_on_critical_severity"`

	// MinScoreToBlock minimum score to trigger blocking
	MinScoreToBlock float64 `json:"min_score_to_block"`

	// LogAllAnomalies whether to log all anomalies or only blocked ones
	LogAllAnomalies bool `json:"log_all_anomalies"`

	// SampleRate percentage of requests to analyze (0-100)
	// Use for high-throughput environments
	SampleRate int `json:"sample_rate"`

	// ExcludedPaths URL paths to exclude from ML analysis
	ExcludedPaths []string `json:"excluded_paths"`

	// ExcludedMethods HTTP methods to exclude from ML analysis
	ExcludedMethods []string `json:"excluded_methods"`

	// Detector holds the ML detector instance (set automatically)
	Detector *ml.Detector `json:"-"`
}

// DefaultMLMiddlewareConfig returns sensible defaults for ML middleware
func DefaultMLMiddlewareConfig() *MLMiddlewareConfig {
	return &MLMiddlewareConfig{
		Enabled:                 true,
		Sensitivity:             "medium",
		BlockOnHighSeverity:     false,
		BlockOnCriticalSeverity: true,
		MinScoreToBlock:         3.0,
		LogAllAnomalies:         true,
		SampleRate:              100,
		ExcludedPaths:           []string{"/health", "/ready", "/metrics"},
		ExcludedMethods:         []string{"OPTIONS", "HEAD"},
	}
}

// MLAnomalyResult holds the result of ML anomaly detection
type MLAnomalyResult struct {
	Anomalies        []ml.Anomaly   `json:"anomalies"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	ShouldBlock      bool           `json:"should_block"`
	BlockingReason   string         `json:"blocking_reason"`
	AnalysisDuration time.Duration  `json:"analysis_duration_ms"`
	Method           string         `json:"method"`
	Path             string         `json:"path"`
	Size             int64          `json:"size"`
}

// MLMiddleware provides ML-based anomaly detection for HTTP traffic
type MLMiddleware struct {
	config *MLMiddlewareConfig
	mu     sync.RWMutex
	stats  *MLStats
}

// MLStats holds statistics about ML detection
type MLStats struct {
	TotalRequests    int64            `json:"total_requests"`
	AnalyzedRequests int64            `json:"analyzed_requests"`
	BlockedRequests  int64            `json:"blocked_requests"`
	AnomalyCounts    map[string]int64 `json:"anomaly_counts"`
	LastUpdate       time.Time        `json:"last_update"`
	mu               sync.Mutex
}

// NewMLMiddleware creates a new ML middleware instance
func NewMLMiddleware(config *MLMiddlewareConfig) (*MLMiddleware, error) {
	if config == nil {
		config = DefaultMLMiddlewareConfig()
	}

	// Validate sensitivity
	switch config.Sensitivity {
	case "low", "medium", "high", "paranoid":
		// Valid
	default:
		config.Sensitivity = "medium"
	}

	// Validate sample rate
	if config.SampleRate < 0 || config.SampleRate > 100 {
		config.SampleRate = 100
	}

	// Create ML detector with config
	mlSensitivity := ml.Sensitivity(config.Sensitivity)

	detectorConfig := ml.Config{
		Sensitivity:      mlSensitivity,
		WindowSize:       1000,
		ZThreshold:       3.0,
		MinSamples:       10,
		EntropyThreshold: 4.5,
	}
	detector := ml.New(detectorConfig)

	middleware := &MLMiddleware{
		config: config,
		stats: &MLStats{
			AnomalyCounts: make(map[string]int64),
			LastUpdate:    time.Now(),
		},
	}

	// Store detector reference
	middleware.config.Detector = detector

	return middleware, nil
}

// Middleware returns the HTTP middleware handler
func (m *MLMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if disabled
		if !m.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Update stats
		m.stats.mu.Lock()
		m.stats.TotalRequests++
		m.stats.mu.Unlock()

		// Check exclusions
		if m.isExcluded(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Sample rate check
		if !m.shouldSample() {
			next.ServeHTTP(w, r)
			return
		}

		// Perform ML analysis
		result := m.analyzeRequest(r)

		// Update analyzed count
		m.stats.mu.Lock()
		m.stats.AnalyzedRequests++
		m.stats.mu.Unlock()

		// Handle anomalies
		if len(result.Anomalies) > 0 {
			// Update anomaly type counts
			m.stats.mu.Lock()
			for _, anomaly := range result.Anomalies {
				m.stats.AnomalyCounts[string(anomaly.Type)]++
			}
			m.stats.mu.Unlock()

			// Log if enabled
			if m.config.LogAllAnomalies {
				m.logAnomalies(r, result)
			}

			// Block if necessary
			if result.ShouldBlock {
				m.stats.mu.Lock()
				m.stats.BlockedRequests++
				m.stats.mu.Unlock()

				m.blockRequest(w, r, result)
				return
			}
		}

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// isExcluded checks if the request should be excluded from ML analysis
func (m *MLMiddleware) isExcluded(r *http.Request) bool {
	// Check path exclusions
	path := r.URL.Path
	for _, excluded := range m.config.ExcludedPaths {
		if strings.HasPrefix(path, excluded) {
			return true
		}
	}

	// Check method exclusions
	method := r.Method
	for _, excluded := range m.config.ExcludedMethods {
		if method == excluded {
			return true
		}
	}

	return false
}

// shouldSample determines if this request should be analyzed
func (m *MLMiddleware) shouldSample() bool {
	if m.config.SampleRate >= 100 {
		return true
	}

	// Simple deterministic sampling based on time
	now := time.Now()
	second := now.Unix()
	return int(second)%100 < m.config.SampleRate
}

// analyzeRequest performs ML anomaly detection on the request
func (m *MLMiddleware) analyzeRequest(r *http.Request) *MLAnomalyResult {
	startTime := time.Now()

	// Get request info
	method := r.Method
	path := r.URL.Path
	contentLength := r.ContentLength
	if contentLength < 0 {
		contentLength = 0
	}

	// Create traffic sample
	sample := ml.TrafficSample{
		Timestamp:  time.Now(),
		Volume:     1,
		Size:       contentLength,
		Violations: 0,
	}

	// Record traffic in detector
	m.config.Detector.RecordTraffic(sample)

	// Run ML analysis - returns (Anomaly, bool)
	anomaly, detected := m.config.Detector.AnalyzeRequest(method, path, contentLength)

	// Collect anomalies
	var anomalies []ml.Anomaly
	if detected {
		anomalies = append(anomalies, anomaly)
	}

	// Calculate severity counts
	severityCounts := make(map[string]int)
	for _, a := range anomalies {
		severityCounts[fmt.Sprintf("%d", a.Severity)]++
	}

	// Determine if we should block
	shouldBlock, blockingReason := m.shouldBlock(anomalies)

	// Add high-severity indicators check
	if m.containsHighRiskIndicators(r) {
		shouldBlock = true
		blockingReason = "high_risk_indicators"
		anomalies = append(anomalies, ml.Anomaly{
			Type:        "high_risk_indicators",
			Severity:    ml.Severity(5),
			Score:       5.0,
			Timestamp:   time.Now(),
			Description: "Request contains high-risk indicators",
		})
	}

	return &MLAnomalyResult{
		Anomalies:        anomalies,
		SeverityCounts:   severityCounts,
		ShouldBlock:      shouldBlock,
		BlockingReason:   blockingReason,
		AnalysisDuration: time.Since(startTime),
		Method:           method,
		Path:             path,
		Size:             contentLength,
	}
}

// shouldBlock determines if the anomalies should result in blocking
func (m *MLMiddleware) shouldBlock(anomalies []ml.Anomaly) (bool, string) {
	if len(anomalies) == 0 {
		return false, ""
	}

	for _, anomaly := range anomalies {
		// Check severity-based blocking
		// Severity is int: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
		if anomaly.Severity >= ml.Severity(4) && m.config.BlockOnCriticalSeverity {
			if anomaly.Score >= m.config.MinScoreToBlock {
				return true, fmt.Sprintf("severity_%d_%s", anomaly.Severity, anomaly.Type)
			}
		}
		if anomaly.Severity >= ml.Severity(3) && m.config.BlockOnHighSeverity {
			if anomaly.Score >= m.config.MinScoreToBlock {
				return true, fmt.Sprintf("severity_%d_%s", anomaly.Severity, anomaly.Type)
			}
		}
	}

	return false, ""
}

// containsHighRiskIndicators checks for high-risk patterns in the request
func (m *MLMiddleware) containsHighRiskIndicators(r *http.Request) bool {
	// This is a placeholder for additional high-risk checks
	// Can be extended with:
	// - Known malicious patterns
	// - Suspicious payload signatures
	// - Behavioral anomalies
	return false
}

// logAnomalies logs detected anomalies to the appropriate channels
func (m *MLMiddleware) logAnomalies(r *http.Request, result *MLAnomalyResult) {
	// Format log message
	logMsg := fmt.Sprintf("[ML_ANOMALY] Path: %s %s | Client: %s | Anomalies: %d | Blocked: %v",
		r.Method,
		r.URL.Path,
		getClientIP(r),
		len(result.Anomalies),
		result.ShouldBlock,
	)

	// Log each anomaly
	for _, anomaly := range result.Anomalies {
		logMsg += fmt.Sprintf("\n  - Type: %s | Severity: %d | Score: %.2f",
			anomaly.Type,
			anomaly.Severity,
			anomaly.Score,
		)
	}

	// Log at appropriate level
	if result.ShouldBlock {
		logger.Warn(logMsg)
	} else {
		logger.Info(logMsg)
	}
}

// blockRequest handles blocking a request due to ML detection
func (m *MLMiddleware) blockRequest(w http.ResponseWriter, r *http.Request, result *MLAnomalyResult) {
	// Set security headers
	w.Header().Set("X-Blocked-By", "AegisGate-ML")
	w.Header().Set("X-Block-Reason", result.BlockingReason)
	w.Header().Set("X-Anomaly-Count", fmt.Sprintf("%d", len(result.Anomalies)))

	// Return blocked response
	w.WriteHeader(http.StatusForbidden)

	// Write response body
	blockResponse := map[string]interface{}{
		"status":        "blocked",
		"reason":        result.BlockingReason,
		"anomaly_count": len(result.Anomalies),
		"anomalies":     result.Anomalies,
		"severity":      result.SeverityCounts,
		"analysis_time": result.AnalysisDuration.Milliseconds(),
	}

	if m.config.Sensitivity == "paranoid" {
		// In paranoid mode, don't reveal details
		blockResponse = map[string]interface{}{
			"status": "blocked",
			"reason": "security_policy",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockResponse)
}

// UpdateConfig updates the ML middleware configuration
func (m *MLMiddleware) UpdateConfig(config *MLMiddlewareConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config.Sensitivity != m.config.Sensitivity {
		// Sensitivity changed, recreate detector
		mlSensitivity := ml.Sensitivity(config.Sensitivity)

		detectorConfig := ml.Config{
			Sensitivity:      mlSensitivity,
			WindowSize:       1000,
			ZThreshold:       3.0,
			MinSamples:       10,
			EntropyThreshold: 4.5,
		}
		detector := ml.New(detectorConfig)
		config.Detector = detector
	}

	m.config = config
	return nil
}

// GetStats returns current ML statistics
func (m *MLMiddleware) GetStats() *MLStats {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	// Return pointer to current stats (don't copy)
	return &MLStats{
		TotalRequests:    m.stats.TotalRequests,
		AnalyzedRequests: m.stats.AnalyzedRequests,
		BlockedRequests:  m.stats.BlockedRequests,
		AnomalyCounts:    m.stats.AnomalyCounts,
		LastUpdate:       time.Now(),
	}
}

// ResetStats resets ML statistics
func (m *MLMiddleware) ResetStats() {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	m.stats.TotalRequests = 0
	m.stats.AnalyzedRequests = 0
	m.stats.BlockedRequests = 0
	m.stats.AnomalyCounts = make(map[string]int64)
	m.stats.LastUpdate = time.Now()
}

// Config returns the ML middleware configuration
func (m *MLMiddleware) Config() *MLMiddlewareConfig {
	return m.config
}

// MLMiddlewareFromPolicy creates ML middleware from policy configuration
// Note: This is a placeholder for future policy integration
func MLMiddlewareFromPolicy(policyData map[string]interface{}) (*MLMiddleware, error) {
	if policyData == nil {
		return NewMLMiddleware(DefaultMLMiddlewareConfig())
	}

	// Extract ML configuration from policy map
	mlConfig := &MLMiddlewareConfig{
		Enabled:                 true,
		Sensitivity:             "medium",
		BlockOnHighSeverity:     false,
		BlockOnCriticalSeverity: true,
		MinScoreToBlock:         3.0,
		LogAllAnomalies:         true,
		SampleRate:              100,
	}

	// Parse policy data if provided
	if enabled, ok := policyData["ml_enabled"].(bool); ok {
		mlConfig.Enabled = enabled
	}
	if sensitivity, ok := policyData["ml_sensitivity"].(string); ok {
		mlConfig.Sensitivity = sensitivity
	}
	if blockHigh, ok := policyData["ml_block_on_high"].(bool); ok {
		mlConfig.BlockOnHighSeverity = blockHigh
	}
	if blockCritical, ok := policyData["ml_block_on_critical"].(bool); ok {
		mlConfig.BlockOnCriticalSeverity = blockCritical
	}
	if minScore, ok := policyData["ml_min_score"].(float64); ok {
		mlConfig.MinScoreToBlock = minScore
	}
	if sampleRate, ok := policyData["ml_sample_rate"].(float64); ok {
		mlConfig.SampleRate = int(sampleRate)
	}

	return NewMLMiddleware(mlConfig)
}

// MiddlewareWithContext returns an ML middleware that uses context for configuration
func MiddlewareWithContext(ctx context.Context, config *MLMiddlewareConfig) func(http.Handler) http.Handler {
	middleware, err := NewMLMiddleware(config)
	if err != nil {
		slog.Error("Failed to create ML middleware", "error", err.Error())
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return middleware.Middleware
}
