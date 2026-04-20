// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security - AegisGate Bridge Gateway
//
// =========================================================================
//
// This file implements the bridge gateway that routes agent LLM calls
// through AegisGate for additional security scanning.
//
// =========================================================================

package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Gateway
// ============================================================================

// Gateway handles routing of LLM calls from agents through AegisGate
type Gateway struct {
	config    *Config
	client    *http.Client
	logger    *slog.Logger
	stats     *GatewayStats
	upstream  *url.URL
	transport *http.Transport
	mu        sync.RWMutex
}

// GatewayStats holds gateway statistics
type GatewayStats struct {
	Requests     atomic.Int64
	Allowed      atomic.Int64
	Blocked      atomic.Int64
	Failed       atomic.Int64
	ThreatsFound atomic.Int64
}

// NewGateway creates a new bridge gateway
func NewGateway(config *Config) (*Gateway, error) {
	if config == nil {
		config = DefaultConfig()
	}

	logger := slog.Default()

	// Parse upstream URL
	upstream, err := url.Parse(config.AegisGateURL)
	if err != nil {
		return nil, fmt.Errorf("invalid AegisGate URL: %w", err)
	}

	// Create HTTP client with timeouts
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	gw := &Gateway{
		config:    config,
		client:    client,
		logger:    logger,
		stats:     &GatewayStats{},
		upstream:  upstream,
		transport: transport,
	}

	logger.Info("AegisGate bridge gateway initialized",
		"aegisgate_url", config.AegisGateURL,
		"enabled", config.Enabled,
		"timeout", config.Timeout,
	)

	return gw, nil
}

// ============================================================================
// Core Routing
// ============================================================================

// RouteLLMCall routes an LLM API call through AegisGate
func (g *Gateway) RouteLLMCall(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	startTime := time.Now()

	g.stats.Requests.Add(1)

	// Check if bridge is enabled
	if !g.config.Enabled {
		g.logger.Debug("Bridge disabled, passing through directly")
		return g.passThrough(ctx, req)
	}

	// Check if AegisGate is reachable
	if !g.isAegisGateReachable(ctx) {
		g.logger.Warn("AegisGate unreachable, falling back to direct call")
		g.stats.Failed.Add(1)
		return g.passThrough(ctx, req)
	}

	// Route through AegisGate
	resp, err := g.proxyThroughAegisGate(ctx, req)
	if err != nil {
		g.logger.Error("AegisGate proxy failed", "error", err)
		g.stats.Failed.Add(1)
		// Fall back to direct call on proxy failure
		return g.passThrough(ctx, req)
	}

	// Record stats
	resp.Duration = time.Since(startTime)
	if resp.ScanResult != nil {
		if !resp.ScanResult.Allowed {
			g.stats.Blocked.Add(1)
		} else {
			g.stats.Allowed.Add(1)
		}
		g.stats.ThreatsFound.Add(int64(len(resp.ScanResult.Threats)))
	} else {
		g.stats.Allowed.Add(1)
	}

	return resp, nil
}

// proxyThroughAegisGate routes the request through AegisGate proxy
func (g *Gateway) proxyThroughAegisGate(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	// Determine target URL
	targetURL := req.TargetURL
	if targetURL == "" {
		targetURL = g.config.DefaultTarget
	}

	// Create proxy URL (AegisGate acts as reverse proxy)
	proxyURL := fmt.Sprintf("%s/proxy/%s", strings.TrimSuffix(g.config.AegisGateURL, "/"), targetURL)

	g.logger.Debug("Routing through AegisGate",
		"proxy_url", proxyURL,
		"target", targetURL,
		"request_id", req.RequestID,
	)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, proxyURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Add agent context headers for audit trail
	httpReq.Header.Set("X-AegisGuard-Agent-ID", req.AgentID)
	httpReq.Header.Set("X-AegisGuard-Session-ID", req.SessionID)
	httpReq.Header.Set("X-AegisGuard-Request-ID", req.RequestID)
	httpReq.Header.Set("X-AegisGuard-Tool-Name", req.ToolName)
	httpReq.Header.Set("X-AegisGuard-Source", "aegisguard-bridge")

	// Set content type if body present
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Execute request with retries
	var lastErr error
	for attempt := 0; attempt <= g.config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(g.config.RetryInterval * time.Duration(attempt))
			g.logger.Debug("Retrying request", "attempt", attempt+1)
		}

		resp, err := g.client.Do(httpReq)
		if err != nil {
			lastErr = err
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		// Extract AegisGate scan result from headers
		scanResult := g.extractScanResult(resp.Header)

		// Check if request was blocked
		if resp.StatusCode == http.StatusForbidden {
			return &LLMResponse{
				RequestID:  req.RequestID,
				StatusCode: http.StatusForbidden,
				Body:       body,
				ScanResult: scanResult,
			}, nil
		}

		// Build response
		llmResp := &LLMResponse{
			RequestID:  req.RequestID,
			StatusCode: resp.StatusCode,
			Body:       body,
			Headers:    extractHeaders(resp.Header),
			ScanResult: scanResult,
		}

		return llmResp, nil
	}

	return nil, fmt.Errorf("all retries exhausted: %w", lastErr)
}

// passThrough makes a direct call without AegisGate proxying
func (g *Gateway) passThrough(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	targetURL := req.TargetURL
	if targetURL == "" {
		targetURL = g.config.DefaultTarget
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("direct call failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &LLMResponse{
		RequestID:  req.RequestID,
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    extractHeaders(resp.Header),
	}, nil
}

// ============================================================================
// Health & Status
// ============================================================================

// isAegisGateReachable checks if AegisGate is reachable
func (g *Gateway) isAegisGateReachable(ctx context.Context) bool {
	healthURL := g.config.AegisGateURL + "/health"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false
	}

	// Use a short timeout for health check
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		g.logger.Debug("AegisGate health check failed", "error", err)
		return false
	}
	resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetStats returns current gateway statistics
func (g *Gateway) GetStats() *Stats {
	return &Stats{
		TotalRequests:   g.stats.Requests.Load(),
		AllowedRequests: g.stats.Allowed.Load(),
		BlockedRequests: g.stats.Blocked.Load(),
		FailedRequests:  g.stats.Failed.Load(),
		ThreatsDetected: g.stats.ThreatsFound.Load(),
		MaxLatency:      0, // Would need to track per-request
		MinLatency:      0,
		AvgLatency:      0,
	}
}

// Close shuts down the gateway
func (g *Gateway) Close() error {
	g.transport.CloseIdleConnections()
	g.logger.Info("AegisGate bridge gateway closed")
	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// extractScanResult extracts AegisGate scan result from response headers
func (g *Gateway) extractScanResult(header http.Header) *ScanResult {
	// AegisGate may add headers with scan results
	threatHeader := header.Get("X-AegisGate-Threats")
	blockReason := header.Get("X-AegisGate-Block-Reason")
	allowed := header.Get("X-AegisGate-Allowed")

	// Also try to get from response body (JSON format)
	// This is a simplified version - full implementation would parse body

	result := &ScanResult{
		Allowed:     allowed != "false",
		BlockReason: blockReason,
	}

	// Parse threats if present
	if threatHeader != "" {
		threats := strings.Split(threatHeader, ",")
		for _, t := range threats {
			if t != "" {
				result.Threats = append(result.Threats, Threat{
					Type:     strings.TrimSpace(t),
					Severity: SeverityHigh, // Default severity from header
				})
			}
		}
	}

	return result
}

// extractHeaders converts http.Header to map[string]string
func extractHeaders(header http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range header {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}
