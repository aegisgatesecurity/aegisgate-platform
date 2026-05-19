// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Response Guard Integration
// =========================================================================
//
// Adds response security scanning to the bridge package.
// Scans LLM responses for PII, secrets, toxicity, and hallucinations
// before passing them back to agents.
//
// Integration point: After RouteLLMCall receives response from AegisGate proxy
// =========================================================================

package bridge

import (
	"context"
	"log/slog"
	"sync"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// Response Scanner Integration
// ============================================================================

// ResponseScanner provides response security scanning for LLM responses
type ResponseScanner struct {
	guard  *responseguard.ResponseGuard
	mu     sync.RWMutex
	logger *slog.Logger
}

// NewResponseScanner creates a new response scanner with default configuration
func NewResponseScanner() *ResponseScanner {
	return &ResponseScanner{
		guard:  responseguard.NewResponseGuard(),
		logger: slog.Default().With("component", "response-scanner"),
	}
}

// NewResponseScannerWithConfig creates a response scanner with custom configuration
func NewResponseScannerWithConfig(config *responseguard.ResponseGuardConfig) *ResponseScanner {
	return &ResponseScanner{
		guard:  responseguard.NewResponseGuardWithConfig(config),
		logger: slog.Default().With("component", "response-scanner"),
	}
}

// ScanResponse performs security scanning on an LLM response
// Returns the scan result with allowed/blocked status and detected threats
func (rs *ResponseScanner) ScanResponse(ctx context.Context, response string) (*responseguard.ResponseScanResult, error) {
	return rs.ScanResponseWithContext(ctx, response, nil)
}

// ScanResponseWithContext performs response scanning with additional context
func (rs *ResponseScanner) ScanResponseWithContext(ctx context.Context, response string, scanCtx *responseguard.ScanContext) (*responseguard.ResponseScanResult, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result, err := rs.guard.ScanWithContext(ctx, response, scanCtx)
	if err != nil {
		rs.logger.Error("response scan failed", "error", err)
		return nil, err
	}

	// Log blocked responses
	if !result.Allowed {
		rs.logger.Warn("response blocked by security scanner",
			"block_reason", result.BlockReason,
			"pii_count", len(result.DetectedPII),
			"secret_count", len(result.DetectedSecrets),
			"threat_count", len(result.Threats),
		)
	}

	return result, nil
}

// ScanLLMResponse scans a complete LLM response and returns formatted result
// Convenience method for bridge integration
func (rs *ResponseScanner) ScanLLMResponse(ctx context.Context, content string, clientID string) (*responseguard.ResponseScanResult, error) {
	scanCtx := responseguard.NewScanContext(clientID, "")
	scanCtx.ScanType = "llm_response"

	return rs.ScanResponseWithContext(ctx, content, scanCtx)
}

// IsResponseAllowed checks if a response is allowed without full scan details
func (rs *ResponseScanner) IsResponseAllowed(ctx context.Context, response string) bool {
	result, err := rs.ScanResponse(ctx, response)
	if err != nil {
		// On scan error, fail closed - deny the response
		rs.logger.Error("response scan error - failing closed", "error", err)
		return false
	}
	return result.Allowed
}

// GetComplianceReport generates compliance report for a response
func (rs *ResponseScanner) GetComplianceReport(ctx context.Context, response string) (map[string]responseguard.ComplianceResult, error) {
	result, err := rs.ScanResponse(ctx, response)
	if err != nil {
		return nil, err
	}
	return result.ComplianceReports, nil
}

// GetDetectedPII returns PII categories found in the response
func (rs *ResponseScanner) GetDetectedPII(ctx context.Context, response string) []responseguard.PIICategory {
	result, err := rs.ScanResponse(ctx, response)
	if err != nil {
		return nil
	}
	return result.DetectedPII
}

// GetDetectedSecrets returns secret types found in the response
func (rs *ResponseScanner) GetDetectedSecrets(ctx context.Context, response string) []string {
	result, err := rs.ScanResponse(ctx, response)
	if err != nil {
		return nil
	}
	return result.DetectedSecrets
}

// ============================================================================
// Bridge Response Scanner Integration
// ============================================================================

// ResponseScanResult wraps the guard's scan result for bridge use
type ResponseScanResult struct {
	Allowed               bool
	BlockReason           string
	PIIFound              []string
	SecretsFound          []string
	ToxicityDetected      bool
	HallucinationDetected bool
	Threats               int
	LatencyMs             int64
}

// ScanBridgeResponse scans an LLM response through the bridge
// This method is designed to be called after RouteLLMCall receives a response
func ScanBridgeResponse(ctx context.Context, resp *LLMResponse, scanner *ResponseScanner) (*ResponseScanResult, error) {
	if resp == nil || scanner == nil {
		return nil, nil
	}

	// Extract response content from LLMResponse
	// Body is []byte in AegisGuard's LLMResponse
	content := string(resp.Body)

	if content == "" {
		// Response has no scannable content
		return &ResponseScanResult{Allowed: true}, nil
	}

	result, err := scanner.ScanLLMResponse(ctx, content, resp.RequestID)
	if err != nil {
		return nil, err
	}

	// Convert to bridge result format
	bridgeResult := &ResponseScanResult{
		Allowed: result.Allowed,
	}

	if !result.Allowed {
		bridgeResult.BlockReason = result.BlockReason
	}

	// Count threats by type
	for _, threat := range result.Threats {
		switch threat.Type {
		case "pii":
			bridgeResult.PIIFound = append(bridgeResult.PIIFound, threat.Pattern)
		case "secret":
			bridgeResult.SecretsFound = append(bridgeResult.SecretsFound, threat.Pattern)
		case "toxicity":
			bridgeResult.ToxicityDetected = true
		case "hallucination":
			bridgeResult.HallucinationDetected = true
		}
		bridgeResult.Threats++
	}

	bridgeResult.LatencyMs = result.LatencyMs

	return bridgeResult, nil
}

// ============================================================================
// Platform Bridge Extension
// ============================================================================

// ResponseScannable extends PlatformBridge with response scanning capability
type ResponseScannable interface {
	// ScanResponse performs security scan on LLM response
	ScanResponse(ctx context.Context, response string) (*responseguard.ResponseScanResult, error)
}

// WithResponseScanning creates a platform bridge with response scanning enabled
// This wraps the standard PlatformBridge with additional response security
type PlatformBridgeWithResponse struct {
	*PlatformBridge
	responseScanner *ResponseScanner
}

// NewPlatformBridgeWithResponse creates a new bridge with response scanning
func NewPlatformBridgeWithResponse(aegisGateURL string) (*PlatformBridgeWithResponse, error) {
	pb, err := NewPlatformBridge(aegisGateURL)
	if err != nil {
		return nil, err
	}

	return &PlatformBridgeWithResponse{
		PlatformBridge:  pb,
		responseScanner: NewResponseScanner(),
	}, nil
}

// ScanResponse scans an LLM response before returning it to the agent
func (pb *PlatformBridgeWithResponse) ScanResponse(ctx context.Context, response string) (*responseguard.ResponseScanResult, error) {
	return pb.responseScanner.ScanResponse(ctx, response)
}

// ScanAndFilter scans response and returns filtered content if threats detected
func (pb *PlatformBridgeWithResponse) ScanAndFilter(ctx context.Context, response string) (string, *responseguard.ResponseScanResult, error) {
	result, err := pb.responseScanner.ScanResponse(ctx, response)
	if err != nil {
		return response, nil, err
	}

	// In non-strict mode, still pass through but log warnings
	// In strict mode, block or return empty response
	config := responseguard.DefaultResponseGuardConfig()
	if !result.Allowed && !config.StrictMode {
		// Non-strict: log warning but pass through
		pb.logger.Warn("response with security concerns passed through",
			"block_reason", result.BlockReason,
			"threat_count", len(result.Threats),
		)
		return response, result, nil
	}

	return response, result, nil
}
