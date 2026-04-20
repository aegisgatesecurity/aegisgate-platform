// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security - AegisGate Bridge

// =========================================================================
//
// This package provides the bridge between AegisGuard and AegisGate,
// enabling unified AI security coverage.
//
// Architecture:
// ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
// │  AI Agent    │ ──────▶ │ AegisGuard   │ ──────▶ │   Tools     │
// │  (Cursor,   │         │   (MCP)      │         │  (files,    │
// │  OpenClaw)  │         │              │         │   shell)    │
// └──────────────┘         └──────┬───────┘         └──────────────┘
//                                 │                          ▲
//                                 │ LLM API Calls            │
//                                 ▼                          │
//                        ┌──────────────────┐                 │
//                        │   AegisGate     │ ◀────────────────┘
//                        │   Bridge        │
//                        └────────┬────────┘
//                                 │
//                                 ▼
//                        ┌──────────────────┐
//                        │   AegisGate     │
//                        │   (HTTP Proxy)  │
//                        └────────┬────────┘
//                                 │
//                                 ▼
//                        ┌──────────────────┐
//                        │  LLM Provider   │
//                        │ (OpenAI, etc.)  │
//                        └──────────────────┘
//
// Key Features:
// - Transparent proxy for LLM API calls from agents
// - Shared audit trail format
// - Defense in depth (AegisGuard + AegisGate scanning)
// =========================================================================

package bridge

import (
	"time"
)

// ============================================================================
// Bridge Types
// ============================================================================

// Config holds bridge configuration
type Config struct {
	// AegisGate endpoint (e.g., "http://localhost:8080")
	AegisGateURL string

	// Timeout for AegisGate requests
	Timeout time.Duration

	// Whether to enable AegisGate scanning
	Enabled bool

	// Retry configuration
	MaxRetries    int
	RetryInterval time.Duration

	// TLS configuration (for production)
	SkipTLSVerify bool

	// Default target for LLM calls when not specified
	DefaultTarget string

	// API key for AegisGate (if authentication required)
	APIKey string
}

// DefaultConfig returns a default bridge configuration
func DefaultConfig() *Config {
	return &Config{
		AegisGateURL:  "http://localhost:8080",
		Timeout:       30 * time.Second,
		Enabled:       true,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true, // For local development
		DefaultTarget: "https://api.openai.com",
	}
}

// ============================================================================
// LLM Request/Response Types
// ============================================================================

// LLMRequest represents an LLM API request from an agent
type LLMRequest struct {
	// Request identification
	RequestID string `json:"request_id"`

	// Agent information
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`

	// Target LLM endpoint
	TargetURL string `json:"target_url"`

	// HTTP details
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`

	// Original tool call context
	ToolName    string                 `json:"tool_name,omitempty"`
	ToolContext map[string]interface{} `json:"tool_context,omitempty"`

	// Timing
	Timestamp time.Time `json:"timestamp"`
}

// LLMResponse represents an LLM API response
type LLMResponse struct {
	// Response identification
	RequestID string `json:"request_id"`

	// HTTP response details
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body,omitempty"`

	// AegisGate scan results
	ScanResult *ScanResult `json:"scan_result,omitempty"`

	// Timing
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

// ScanResult contains AegisGate's security scan results
type ScanResult struct {
	// Scan decision
	Allowed bool `json:"allowed"`

	// Threats detected
	Threats []Threat `json:"threats,omitempty"`

	// Compliance violations
	Violations []ComplianceViolation `json:"violations,omitempty"`

	// Risk score (0.0 - 1.0)
	RiskScore float64 `json:"risk_score"`

	// Block reason if denied
	BlockReason string `json:"block_reason,omitempty"`
}

// Threat represents a detected security threat
type Threat struct {
	// Threat identification
	Type    string `json:"type"`
	Pattern string `json:"pattern"`

	// Severity
	Severity ThreatSeverity `json:"severity"`

	// MITRE ATLAS mapping
	TechniqueID string `json:"technique_id,omitempty"`
	Framework   string `json:"framework,omitempty"`

	// Detection details
	Confidence float64 `json:"confidence"`
	Position   int     `json:"position,omitempty"`
	Context    string  `json:"context,omitempty"`
}

// ThreatSeverity levels
type ThreatSeverity int

const (
	SeverityInfo     ThreatSeverity = 0
	SeverityLow      ThreatSeverity = 1
	SeverityMedium   ThreatSeverity = 2
	SeverityHigh     ThreatSeverity = 3
	SeverityCritical ThreatSeverity = 4
)

// String returns the string representation of severity
func (s ThreatSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ComplianceViolation represents a compliance framework violation
type ComplianceViolation struct {
	// Violation identification
	Framework string `json:"framework"`
	Control   string `json:"control"`

	// Description
	Description string `json:"description"`

	// Severity
	Severity ThreatSeverity `json:"severity"`
}

// ============================================================================
// Bridge Statistics
// ============================================================================

// Stats holds bridge statistics
type Stats struct {
	// Request counts
	TotalRequests   int64 `json:"total_requests"`
	AllowedRequests int64 `json:"allowed_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	FailedRequests  int64 `json:"failed_requests"`

	// Threat statistics
	ThreatsDetected   int64            `json:"threats_detected"`
	ThreatsByType     map[string]int64 `json:"threats_by_type"`
	ThreatsBySeverity map[string]int64 `json:"threats_by_severity"`

	// Performance
	AvgLatency time.Duration `json:"avg_latency_ms"`
	MaxLatency time.Duration `json:"max_latency_ms"`
	MinLatency time.Duration `json:"min_latency_ms"`
}

// NewStats creates a new stats instance
func NewStats() *Stats {
	return &Stats{
		ThreatsByType:     make(map[string]int64),
		ThreatsBySeverity: make(map[string]int64),
	}
}

// RecordRequest records a request result
func (s *Stats) RecordRequest(req *LLMRequest, resp *LLMResponse, err error) {
	// This would update internal counters
	// Implementation depends on atomic operations
}
