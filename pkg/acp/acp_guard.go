// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Response Guard
// =========================================================================
//
// Core ACP response scanner that adds security scanning to ACP messages.
// Follows the same pattern as MCP and A2A response guards.
//
// =========================================================================

package acp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// ACP Response Scanner
// ============================================================================

// ACPResponseScanner provides response security scanning for ACP communication
type ACPResponseScanner struct {
	guard *responseguard.ResponseGuard
	mu    sync.RWMutex
	cfg   *ACPGuardConfig

	// Per-session scanning stats
	stats map[string]*ACPScanStats

	// Rate limiting state
	rateLimitBuckets map[string]*rateBucket

	// Blocked methods tracking
	blockedMethods map[string]bool
}

// ACPScanStats tracks scanning statistics per ACP session
type ACPScanStats struct {
	SessionID              string
	MessagesScanned        int
	PIIFound               int
	SecretsFound           int
	ToxicityDetected       int
	HallucinationsDetected int
	BlockedMessages        int
	AllowedMessages        int
	RateLimitHits          int
	AuthFailures           int
}

// rateBucket implements a simple token bucket for rate limiting
type rateBucket struct {
	tokens     int
	lastRefill time.Time
	maxTokens  int
	refillRate int // tokens per minute
}

// NewACPScanStats creates a new scan stats tracker
func NewACPScanStats() *ACPScanStats {
	return &ACPScanStats{}
}

// NewACPResponseScanner creates a new ACP response scanner
func NewACPResponseScanner() *ACPResponseScanner {
	return NewACPResponseScannerWithConfig(DefaultACPGuardConfig())
}

// NewACPResponseScannerWithConfig creates scanner with custom configuration
func NewACPResponseScannerWithConfig(cfg *ACPGuardConfig) *ACPResponseScanner {
	if cfg == nil {
		cfg = DefaultACPGuardConfig()
	}
	if cfg.ResponseGuardConfig == nil {
		cfg.ResponseGuardConfig = responseguard.DefaultResponseGuardConfig()
	}

	return &ACPResponseScanner{
		guard:            responseguard.NewResponseGuardWithConfig(cfg.ResponseGuardConfig),
		cfg:              cfg,
		stats:            make(map[string]*ACPScanStats),
		rateLimitBuckets: make(map[string]*rateBucket),
		blockedMethods:   make(map[string]bool),
	}
}

// EnsureLogger sets up the logger if not configured
func (rs *ACPResponseScanner) EnsureLogger() {
	if rs.cfg.Logger == nil {
		rs.cfg.Logger = slog.Default().With("component", "acp-response-scanner")
	}
}

// ============================================================================
// Core Scanning Functions
// ============================================================================

// ScanResponse scans an ACP response for security threats
func (rs *ACPResponseScanner) ScanResponse(ctx context.Context, response string, sessionID string) (*responseguard.ResponseScanResult, error) {
	rs.EnsureLogger()

	// Create scan context
	scanCtx := responseguard.NewScanContext(sessionID, "")
	scanCtx.ScanType = "acp_response"

	// Perform the scan
	result, err := rs.guard.ScanWithContext(ctx, response, scanCtx)
	if err != nil {
		return nil, err
	}

	// Update stats
	rs.updateStats(sessionID, result)

	return result, nil
}

// ScanACPMessage scans an ACP message (structured format)
func (rs *ACPResponseScanner) ScanACPMessage(ctx context.Context, msg *ACPMessage, sessionID string) (*responseguard.ResponseScanResult, error) {
	rs.EnsureLogger()

	// Extract content from message for scanning
	content := extractContentFromACPMessage(msg)

	result, err := rs.ScanResponse(ctx, content, sessionID)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ScanAgentResponse scans an agent response message
func (rs *ACPResponseScanner) ScanAgentResponse(ctx context.Context, resp *AgentResponse, sessionID string) (*responseguard.ResponseScanResult, error) {
	rs.EnsureLogger()

	content := extractContentFromACPMessage(&ACPMessage{
		ID:     resp.ID,
		Method: "",
		Result: resp.Result,
		Error:  resp.Error,
	})

	return rs.ScanResponse(ctx, content, sessionID)
}

// ============================================================================
// Input Validation
// ============================================================================

// ValidateACPMessage validates an ACP message structure
func (rs *ACPResponseScanner) ValidateACPMessage(msg *ACPMessage) error {
	if msg == nil {
		return ErrNilMessage
	}

	// Check for blocked methods
	rs.mu.RLock()
	isBlocked := rs.blockedMethods[msg.Method]
	rs.mu.RUnlock()

	if isBlocked {
		return ErrMethodBlocked
	}

	// Check method name
	if msg.Method == "" {
		return ErrInvalidMethod
	}

	return nil
}

// BlockMethod adds a method to the blocked list
func (rs *ACPResponseScanner) BlockMethod(method string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.blockedMethods[method] = true
}

// UnblockMethod removes a method from the blocked list
func (rs *ACPResponseScanner) UnblockMethod(method string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.blockedMethods, method)
}

// IsMethodBlocked checks if a method is blocked
func (rs *ACPResponseScanner) IsMethodBlocked(method string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.blockedMethods[method]
}

// ============================================================================
// Rate Limiting
// ============================================================================

// CheckRateLimit checks if a request is within rate limits
func (rs *ACPResponseScanner) CheckRateLimit(identity string) error {
	if !rs.cfg.EnableRateLimiting {
		return nil
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	bucket, exists := rs.rateLimitBuckets[identity]
	if !exists {
		bucket = &rateBucket{
			tokens:     rs.cfg.RateLimitBurst,
			lastRefill: time.Now(),
			maxTokens:  rs.cfg.RateLimitBurst,
			refillRate: rs.cfg.RateLimitPerMinute,
		}
		rs.rateLimitBuckets[identity] = bucket
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	newTokens := int(elapsed.Seconds()) * bucket.refillRate / 60
	if newTokens > 0 {
		bucket.tokens = min(bucket.tokens+newTokens, bucket.maxTokens)
		bucket.lastRefill = now
	}

	// Check if we have tokens
	if bucket.tokens <= 0 {
		rs.updateRateLimitStats(identity)
		return ErrRateLimited
	}

	bucket.tokens--
	return nil
}

// GetRateLimitRemaining returns remaining rate limit tokens for an identity
func (rs *ACPResponseScanner) GetRateLimitRemaining(identity string) int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	bucket, exists := rs.rateLimitBuckets[identity]
	if !exists {
		return rs.cfg.RateLimitBurst
	}

	return bucket.tokens
}

// ============================================================================
// Session Statistics
// ============================================================================

// GetSessionStats returns statistics for a session
func (rs *ACPResponseScanner) GetSessionStats(sessionID string) *ACPScanStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.stats[sessionID]
}

// ResetAllSessionStats returns all session statistics
func (rs *ACPResponseScanner) ResetAllSessionStats() []*ACPScanStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make([]*ACPScanStats, 0, len(rs.stats))
	for _, s := range rs.stats {
		result = append(result, s)
	}
	return result
}

// ClearSessionStats clears statistics for a session
func (rs *ACPResponseScanner) ClearSessionStats(sessionID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.stats, sessionID)
}

// ClearAllStats clears all statistics
func (rs *ACPResponseScanner) ClearAllStats() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.stats = make(map[string]*ACPScanStats)
	rs.rateLimitBuckets = make(map[string]*rateBucket)
}

// ============================================================================
// Helper Methods
// ============================================================================

func (rs *ACPResponseScanner) updateStats(sessionID string, result *responseguard.ResponseScanResult) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	stats, exists := rs.stats[sessionID]
	if !exists {
		stats = NewACPScanStats()
		stats.SessionID = sessionID
		rs.stats[sessionID] = stats
	}

	stats.MessagesScanned++

	if result.Allowed {
		stats.AllowedMessages++
	} else {
		stats.BlockedMessages++
	}

	// Count detections from result
	stats.PIIFound += len(result.DetectedPII)
	stats.SecretsFound += len(result.DetectedSecrets)
}

func (rs *ACPResponseScanner) updateRateLimitStats(identity string) {
	// Note: Lock is already held by caller (CheckRateLimit)
	if stats, exists := rs.stats[identity]; exists {
		stats.RateLimitHits++
	}
}

func extractContentFromACPMessage(msg *ACPMessage) string {
	if msg == nil {
		return ""
	}

	var content string

	switch v := msg.Result.(type) {
	case string:
		content = v
	case []byte:
		content = string(v)
	case map[string]interface{}:
		// Try to extract text content from result
		if text, ok := v["text"].(string); ok {
			content = text
		} else if contentStr, ok := v["content"].(string); ok {
			content = contentStr
		}
	}

	// Also check params if content is empty
	if content == "" {
		if msg.Params != nil {
			if text, ok := msg.Params["text"].(string); ok {
				content = text
			}
		}
	}

	return content
}
