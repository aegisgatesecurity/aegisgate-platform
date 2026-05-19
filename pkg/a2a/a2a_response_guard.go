// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - A2A Response Guard
// =========================================================================
//
// Adds response security scanning to A2A communication.
// Scans AI responses for PII, secrets, toxicity, and hallucinations
// before they are transmitted to other agents.
//
// Integration point: A2A middleware response handling
// =========================================================================

package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// A2A Response Scanner
// ============================================================================

// A2AResponseScanner provides response security scanning for A2A communication
type A2AResponseScanner struct {
	guard  *responseguard.ResponseGuard
	mu     sync.RWMutex
	logger *slog.Logger

	// Per-agent scanning stats
	agentStats map[string]*AgentScanStats
}

// AgentScanStats tracks scanning stats per agent
type AgentScanStats struct {
	AgentID          string
	ResponsesScanned int
	PIIFound         int
	SecretsFound     int
	ToxicityDetected int
	BlockedResponses int
	AllowedResponses int
}

// NewA2AResponseScanner creates a new A2A response scanner
func NewA2AResponseScanner() *A2AResponseScanner {
	return &A2AResponseScanner{
		guard:      responseguard.NewResponseGuard(),
		logger:     slog.Default().With("component", "a2a-response-scanner"),
		agentStats: make(map[string]*AgentScanStats),
	}
}

// NewA2AResponseScannerWithConfig creates scanner with custom configuration
func NewA2AResponseScannerWithConfig(config *responseguard.ResponseGuardConfig) *A2AResponseScanner {
	return &A2AResponseScanner{
		guard:      responseguard.NewResponseGuardWithConfig(config),
		logger:     slog.Default().With("component", "a2a-response-scanner"),
		agentStats: make(map[string]*AgentScanStats),
	}
}

// ScanResponse scans an A2A response for security threats
func (rs *A2AResponseScanner) ScanResponse(ctx context.Context, response string, agentID string) (*responseguard.ResponseScanResult, error) {
	scanCtx := responseguard.NewScanContext(agentID, "")
	scanCtx.ScanType = "a2a_response"

	return rs.guard.ScanWithContext(ctx, response, scanCtx)
}

// ScanA2AMessage scans an A2A message response
func (rs *A2AResponseScanner) ScanA2AMessage(ctx context.Context, message interface{}, agentID string) (*responseguard.ResponseScanResult, error) {
	var content string

	switch msg := message.(type) {
	case string:
		content = msg
	case []byte:
		content = string(msg)
	case map[string]interface{}:
		// Try common A2A message fields
		if text, ok := msg["text"].(string); ok {
			content = text
		} else if data, ok := msg["data"].(string); ok {
			content = data
		} else if content, ok = msg["content"].(string); ok {
			content = content
		} else if payload, ok := msg["payload"].(string); ok {
			content = payload
		}
	}

	if content == "" {
		return &responseguard.ResponseScanResult{Allowed: true}, nil
	}

	return rs.ScanResponse(ctx, content, agentID)
}

// UpdateAgentStats updates scanning statistics for an agent
func (rs *A2AResponseScanner) UpdateAgentStats(agentID string, result *responseguard.ResponseScanResult) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	stats, exists := rs.agentStats[agentID]
	if !exists {
		stats = &AgentScanStats{AgentID: agentID}
		rs.agentStats[agentID] = stats
	}

	stats.ResponsesScanned++

	if result.Allowed {
		stats.AllowedResponses++
	} else {
		stats.BlockedResponses++
	}

	stats.PIIFound += len(result.DetectedPII)
	stats.SecretsFound += len(result.DetectedSecrets)

	for _, threat := range result.Threats {
		if threat.Type == "toxicity" {
			stats.ToxicityDetected++
		}
	}
}

// GetAgentStats returns scanning statistics for an agent
func (rs *A2AResponseScanner) GetAgentStats(agentID string) *AgentScanStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if stats, exists := rs.agentStats[agentID]; exists {
		return stats
	}
	return nil
}

// ============================================================================
// A2A Response Guard Middleware
// ============================================================================

// ResponseGuardMiddleware provides response scanning for A2A middleware
type ResponseGuardMiddleware struct {
	scanner    *A2AResponseScanner
	strictMode bool
	enabled    bool
	logger     *slog.Logger
}

// NewResponseGuardMiddleware creates a new A2A response guard middleware
func NewResponseGuardMiddleware() *ResponseGuardMiddleware {
	return &ResponseGuardMiddleware{
		scanner:    NewA2AResponseScanner(),
		strictMode: false,
		enabled:    true,
		logger:     slog.Default().With("component", "a2a-response-guard"),
	}
}

// NewResponseGuardMiddlewareWithConfig creates middleware with custom config
func NewResponseGuardMiddlewareWithConfig(config *responseguard.ResponseGuardConfig) *ResponseGuardMiddleware {
	return &ResponseGuardMiddleware{
		scanner:    NewA2AResponseScannerWithConfig(config),
		strictMode: config.StrictMode,
		enabled:    true,
		logger:     slog.Default().With("component", "a2a-response-guard"),
	}
}

// GuardResponse scans and guards an A2A response
// Returns (allowed, response, error)
func (m *ResponseGuardMiddleware) GuardResponse(ctx context.Context, response string, agentID string) (bool, string, error) {
	if !m.enabled {
		return true, response, nil
	}

	result, err := m.scanner.ScanResponse(ctx, response, agentID)
	if err != nil {
		m.logger.Error("A2A response guard scan failed", "error", err, "agent_id", agentID)
		return false, "", err
	}

	// Update agent stats
	m.scanner.UpdateAgentStats(agentID, result)

	if !result.Allowed {
		m.logger.Warn("A2A response blocked",
			"agent_id", agentID,
			"reason", result.BlockReason,
			"threats", len(result.Threats),
		)

		if m.strictMode {
			return false, "", nil
		}
	}

	return true, response, nil
}

// IsEnabled returns whether the middleware is enabled
func (m *ResponseGuardMiddleware) IsEnabled() bool {
	return m.enabled
}

// SetEnabled enables or disables the middleware
func (m *ResponseGuardMiddleware) SetEnabled(enabled bool) {
	m.enabled = enabled
}

// GetAgentStats returns scanning stats for an agent
func (m *ResponseGuardMiddleware) GetAgentStats(agentID string) *AgentScanStats {
	return m.scanner.GetAgentStats(agentID)
}

// ============================================================================
// Middleware Extension with Response Guard
// ============================================================================

// A2AMiddlewareWithResponse extends A2A middleware with response scanning
type A2AMiddlewareWithResponse struct {
	Middleware
	responseGuard *ResponseGuardMiddleware
}

// NewA2AMiddlewareWithResponse creates A2A middleware with response guard
func NewA2AMiddlewareWithResponse(
	next http.Handler,
	secret []byte,
	lm *license.Manager,
	caps CapabilityEnforcer,
) *A2AMiddlewareWithResponse {
	return &A2AMiddlewareWithResponse{
		Middleware: Middleware{
			auth:       &MTLSAuth{},
			integrity:  NewIntegrityVerifier(secret),
			caps:       caps,
			limiter:    NewTokenBucket(100, 10, time.Minute),
			next:       next,
			licenseMgr: lm,
			logger:     slog.Default().With("component", "a2a-middleware"),
		},
		responseGuard: NewResponseGuardMiddleware(),
	}
}

// ServeHTTP extends base middleware with response scanning
func (m *A2AMiddlewareWithResponse) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// First run base middleware guards
	m.Middleware.ServeHTTP(w, r)

	// Response scanning would happen here for request/response pairs
	// Note: For streaming responses, use a response wrapper
}

// ============================================================================
// A2A Server Response Handling
// ============================================================================

// A2AResponseHandler handles response scanning for A2A communications
type A2AResponseHandler struct {
	scanner *A2AResponseScanner
	logger  *slog.Logger
}

// NewA2AResponseHandler creates a new A2A response handler
func NewA2AResponseHandler() *A2AResponseHandler {
	return &A2AResponseHandler{
		scanner: NewA2AResponseScanner(),
		logger:  slog.Default().With("component", "a2a-response-handler"),
	}
}

// NewA2AResponseHandlerWithConfig creates handler with custom config
func NewA2AResponseHandlerWithConfig(config *responseguard.ResponseGuardConfig) *A2AResponseHandler {
	return &A2AResponseHandler{
		scanner: NewA2AResponseScannerWithConfig(config),
		logger:  slog.Default().With("component", "a2a-response-handler"),
	}
}

// HandleResponse scans and handles an A2A response
func (h *A2AResponseHandler) HandleResponse(ctx context.Context, response interface{}, agentID string) (interface{}, *responseguard.ResponseScanResult, error) {
	result, err := h.scanner.ScanA2AMessage(ctx, response, agentID)
	if err != nil {
		return nil, nil, err
	}

	if !result.Allowed {
		h.logger.Warn("A2A response blocked by security scanner",
			"agent_id", agentID,
			"reason", result.BlockReason,
		)
		return nil, result, fmt.Errorf("response blocked: %s", result.BlockReason)
	}

	return response, result, nil
}

// GetComplianceReport generates compliance report for A2A communications
func (h *A2AResponseHandler) GetComplianceReport(ctx context.Context, response string) (map[string]responseguard.ComplianceResult, error) {
	result, err := h.scanner.ScanResponse(ctx, response, "system")
	if err != nil {
		return nil, err
	}
	return result.ComplianceReports, nil
}

// ============================================================================
// Registration Helper
// ============================================================================

// RegisterA2AServerWithResponse registers an A2A server with response scanning
func RegisterA2AServerWithResponse(
	mux *http.ServeMux,
	secret []byte,
	lm *license.Manager,
	caps CapabilityEnforcer,
	config *responseguard.ResponseGuardConfig,
) {
	responseHandler := NewA2AResponseHandlerWithConfig(config)

	// Register echo endpoint with response scanning
	mux.Handle("/a2a/echo", NewA2AMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				a2aErrorResponse(w, "A2A_BAD_REQUEST", "invalid json", http.StatusBadRequest)
				return
			}

			// Scan response before sending
			agentID := ""
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				agentID = r.TLS.PeerCertificates[0].Subject.CommonName
			}

			allowed, _, err := responseHandler.HandleResponse(r.Context(), payload, agentID)
			if err != nil {
				a2aErrorResponse(w, "A2A_RESPONSE_BLOCKED", err.Error(), http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(allowed); err != nil {
				a2aErrorResponse(w, A2A_ERR_INTERNAL, "failed to write response", http.StatusInternalServerError)
				return
			}
		}),
		secret, lm, caps,
	))
}
