// Package proxy provides proxy server capabilities for AegisGate
// This file adds types needed by the grpc package
package proxy

import "time"

// Stats represents proxy statistics
type Stats struct {
	RequestsTotal     int64   `json:"requests_total"`
	RequestsBlocked   int64   `json:"requests_blocked"`
	RequestsAllowed   int64   `json:"requests_allowed"`
	BytesIn           int64   `json:"bytes_in"`
	BytesOut          int64   `json:"bytes_out"`
	ActiveConnections int32   `json:"active_connections"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	P99LatencyMs      float64 `json:"p99_latency_ms"`
	Errors            int64   `json:"errors"`
}

// Health represents proxy health status
type Health struct {
	Status      string  `json:"status"`
	Uptime      float64 `json:"uptime"`
	MemoryUsage int64   `json:"memory_usage"`
	Goroutines  int32   `json:"goroutines"`
}

// ViolationType represents types of security violations
type ViolationType string

// ViolationType constants
const (
	ViolationTypeMaliciousRequest ViolationType = "malicious_request"
	ViolationTypeSQLInjection     ViolationType = "sql_injection"
	ViolationTypeXSS              ViolationType = "xss"
	ViolationTypeCSRF             ViolationType = "csrf"
	ViolationTypePathTraversal    ViolationType = "path_traversal"
	ViolationTypeCommandInjection ViolationType = "command_injection"
	ViolationTypeAtlasTechnique   ViolationType = "atlas_technique"
	ViolationTypeCustomPattern    ViolationType = "custom_pattern"
)

// Severity represents violation severity levels
type Severity string

// Severity constants
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ProxyViolation represents a detailed security violation
type ProxyViolation struct {
	ID        string        `json:"id"`
	Type      ViolationType `json:"type"`
	Severity  Severity      `json:"severity"`
	Message   string        `json:"message"`
	ClientIP  string        `json:"client_ip"`
	Method    string        `json:"method"`
	Path      string        `json:"path"`
	Blocked   bool          `json:"blocked"`
	Timestamp time.Time     `json:"timestamp"`
}

// ProxyOptions represents proxy options (alias for Options for grpc compatibility)
type ProxyOptions = Options
