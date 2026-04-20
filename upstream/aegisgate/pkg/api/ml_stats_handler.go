// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
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

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
)

// MLStatsHandler handles ML anomaly detection statistics API requests
type MLStatsHandler struct {
	proxyWithML *proxy.ProxyWithML
}

// NewMLStatsHandler creates a new ML stats handler
func NewMLStatsHandler(p *proxy.ProxyWithML) *MLStatsHandler {
	return &MLStatsHandler{
		proxyWithML: p,
	}
}

// MLStatsResponse represents the ML statistics API response
type MLStatsResponse struct {
	Middleware         *MiddlewareStats         `json:"middleware,omitempty"`
	PromptInjection    *PromptInjectionStats    `json:"prompt_injection,omitempty"`
	ContentAnalysis    *ContentAnalysisStats    `json:"content_analysis,omitempty"`
	BehavioralAnalysis *BehavioralAnalysisStats `json:"behavioral_analysis,omitempty"`
	Sensitivity        string                   `json:"sensitivity"`
	Enabled            bool                     `json:"enabled"`
	RecentAnomalies    []AnomalySummary         `json:"recent_anomalies"`
}

// MiddlewareStats holds middleware statistics
type MiddlewareStats struct {
	TotalRequests    int64            `json:"total_requests"`
	AnalyzedRequests int64            `json:"analyzed_requests"`
	BlockedRequests  int64            `json:"blocked_requests"`
	AnomalyCounts    map[string]int64 `json:"anomaly_counts"`
	LastUpdate       time.Time        `json:"last_update"`
}

// PromptInjectionStats holds prompt injection detection stats
type PromptInjectionStats struct {
	TotalScanned    int64            `json:"total_scanned"`
	ThreatsDetected int64            `json:"threats_detected"`
	BlockedCount    int64            `json:"blocked_count"`
	Sensitivity     int              `json:"sensitivity"`
	ByPattern       map[string]int64 `json:"by_pattern"`
}

// ContentAnalysisStats holds content analysis stats
type ContentAnalysisStats struct {
	TotalAnalyzed   int64            `json:"total_analyzed"`
	ViolationsFound int64            `json:"violations_found"`
	ByType          map[string]int64 `json:"by_type"`
}

// BehavioralAnalysisStats holds behavioral analysis stats
type BehavioralAnalysisStats struct {
	TotalClients     int64 `json:"total_clients"`
	AnomalousClients int64 `json:"anomalous_clients"`
	TotalAnomalies   int64 `json:"total_anomalies"`
	ActiveClients    int   `json:"active_clients"`
}

// AnomalySummary represents a summary of a detected anomaly
type AnomalySummary struct {
	Type      string    `json:"type"`
	Severity  int       `json:"severity"`
	Score     float64   `json:"score"`
	ClientIP  string    `json:"client_ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	Timestamp time.Time `json:"timestamp"`
	Blocked   bool      `json:"blocked"`
}

// HandleGetStats handles GET /api/v1/ml/stats
func (h *MLStatsHandler) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	// Get stats from proxy
	stats := h.proxyWithML.GetMLStats()

	// Build response
	response := MLStatsResponse{
		Enabled:     true,
		Sensitivity: "medium",
	}

	// Extract middleware stats
	if ms, ok := stats["middleware"].(map[string]interface{}); ok {
		response.Middleware = &MiddlewareStats{}
		if v, ok := ms["total_requests"].(int64); ok {
			response.Middleware.TotalRequests = v
		}
		if v, ok := ms["analyzed_requests"].(int64); ok {
			response.Middleware.AnalyzedRequests = v
		}
		if v, ok := ms["blocked_requests"].(int64); ok {
			response.Middleware.BlockedRequests = v
		}
		if v, ok := ms["anomaly_counts"].(map[string]int64); ok {
			response.Middleware.AnomalyCounts = v
		}
		response.Middleware.LastUpdate = time.Now()
	}

	// Extract prompt injection stats
	if pis, ok := stats["prompt_injection"].(map[string]interface{}); ok {
		response.PromptInjection = &PromptInjectionStats{}
		if v, ok := pis["total_scanned"].(int64); ok {
			response.PromptInjection.TotalScanned = v
		}
		if v, ok := pis["threats_detected"].(int64); ok {
			response.PromptInjection.ThreatsDetected = v
		}
		if v, ok := pis["blocked_count"].(int64); ok {
			response.PromptInjection.BlockedCount = v
		}
		if v, ok := pis["sensitivity"].(int); ok {
			response.PromptInjection.Sensitivity = v
		}
		if v, ok := pis["by_pattern"].(map[string]int64); ok {
			response.PromptInjection.ByPattern = v
		}
	}

	// Extract content analysis stats
	if cas, ok := stats["content_analysis"].(map[string]interface{}); ok {
		response.ContentAnalysis = &ContentAnalysisStats{}
		if v, ok := cas["total_analyzed"].(int64); ok {
			response.ContentAnalysis.TotalAnalyzed = v
		}
		if v, ok := cas["violations_found"].(int64); ok {
			response.ContentAnalysis.ViolationsFound = v
		}
		if v, ok := cas["by_type"].(map[string]int64); ok {
			response.ContentAnalysis.ByType = v
		}
	}

	// Extract behavioral analysis stats
	if bas, ok := stats["behavioral_analysis"].(map[string]interface{}); ok {
		response.BehavioralAnalysis = &BehavioralAnalysisStats{}
		if v, ok := bas["total_clients"].(int64); ok {
			response.BehavioralAnalysis.TotalClients = v
		}
		if v, ok := bas["anomalous_clients"].(int64); ok {
			response.BehavioralAnalysis.AnomalousClients = v
		}
		if v, ok := bas["total_anomalies"].(int64); ok {
			response.BehavioralAnalysis.TotalAnomalies = v
		}
		if v, ok := bas["active_clients"].(int); ok {
			response.BehavioralAnalysis.ActiveClients = v
		}
	}

	// Add recent anomalies from middleware if available
	if response.Middleware != nil {
		response.RecentAnomalies = h.getRecentAnomalies(10)
	}

	// Write response
	json.NewEncoder(w).Encode(response)
}

// HandleResetStats handles POST /api/v1/ml/stats/reset
func (h *MLStatsHandler) HandleResetStats(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reset stats
	h.proxyWithML.ResetMLStats()

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "ML statistics reset successfully",
	})
}

// HandleUpdateConfig handles PUT /api/v1/ml/config
func (h *MLStatsHandler) HandleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// Only allow PUT
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var config proxy.MLOptions
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Update configuration would require reconstructing the middleware
	// For now, just return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Configuration update not implemented yet",
	})
}

// HandleHealth handles GET /api/v1/ml/health
func (h *MLStatsHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":     "healthy",
		"ml_enabled": h.proxyWithML != nil && h.proxyWithML.MLMiddleware != nil,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	if h.proxyWithML != nil && h.proxyWithML.MLMiddleware != nil {
		health["sensitivity"] = h.proxyWithML.MLMiddleware.Config().Sensitivity
		stats := h.proxyWithML.MLMiddleware.GetStats()
		if stats != nil {
			health["total_requests"] = stats.TotalRequests
		}
	}

	json.NewEncoder(w).Encode(health)
}

// getRecentAnomalies returns recent anomaly summaries
func (h *MLStatsHandler) getRecentAnomalies(limit int) []AnomalySummary {
	// This would typically come from a stored log or buffer
	// For now, return empty slice
	return []AnomalySummary{}
}

// RegisterRoutes registers ML stats API routes
func (h *MLStatsHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/ml/stats", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleGetStats(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/ml/stats/reset", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			h.HandleResetStats(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/ml/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			h.HandleUpdateConfig(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/ml/health", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleHealth(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
