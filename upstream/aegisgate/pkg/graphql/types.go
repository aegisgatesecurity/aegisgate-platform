// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package graphql provides GraphQL API support for AegisGate
package graphql

import (
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
	"github.com/aegisgatesecurity/aegisgate/pkg/webhook"
)

// Time is a custom scalar for time
type Time time.Time

// MarshalJSON implements json.Marshaler
func (t Time) MarshalJSON() ([]byte, error) {
	return time.Time(t).MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler
func (t *Time) UnmarshalJSON(data []byte) error {
	var ts time.Time
	if err := ts.UnmarshalJSON(data); err != nil {
		return err
	}
	*t = Time(ts)
	return nil
}

// FrameworkType represents compliance framework types
type FrameworkType string

// Severity represents finding severity levels
type Severity string

// ComplianceStatus represents compliance check status
type ComplianceStatus string

// ViolationType represents proxy violation types
type ViolationType string

// LogLevel represents logging levels
type LogLevel string

// AuthProvider represents authentication providers
type AuthProvider string

// Role represents user roles
type Role string

// Permission represents user permissions
type Permission string

// ModuleTier represents module tiers
type ModuleTier string

// ModuleStatus represents module statuses
type ModuleStatus string

// Framework represents a compliance framework
type Framework struct {
	ID            FrameworkType    `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	Version       string           `json:"version"`
	Status        ComplianceStatus `json:"status"`
	FindingsCount int              `json:"findingsCount"`
}

// ComplianceFinding represents a compliance finding
type ComplianceFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Timestamp   Time     `json:"timestamp"`
}

// User represents a user
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      Role   `json:"role"`
	Enabled   bool   `json:"enabled"`
	LastLogin *Time  `json:"lastLogin"`
	CreatedAt Time   `json:"createdAt"`
	UpdatedAt Time   `json:"updatedAt"`
}

// Session represents a user session
type Session struct {
	ID        string `json:"id"`
	UserID    string `json:"userId"`
	Token     string `json:"token"`
	ExpiresAt Time   `json:"expiresAt"`
	CreatedAt Time   `json:"createdAt"`
	IPAddress string `json:"ipAddress"`
	UserAgent string `json:"userAgent"`
}

// AuthResult represents authentication result
type AuthResult struct {
	Success      bool   `json:"success"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    Time   `json:"expiresAt"`
	User         *User  `json:"user"`
	Error        string `json:"error"`
}

// ProxyStats represents proxy statistics
type ProxyStats struct {
	RequestsTotal     int64   `json:"requestsTotal"`
	RequestsBlocked   int64   `json:"requestsBlocked"`
	RequestsAllowed   int64   `json:"requestsAllowed"`
	BytesIn           int64   `json:"bytesIn"`
	BytesOut          int64   `json:"bytesOut"`
	ActiveConnections int     `json:"activeConnections"`
	AvgLatencyMs      float64 `json:"avgLatencyMs"`
}

// Violation represents a proxy violation
type Violation struct {
	ID        string        `json:"id"`
	Type      ViolationType `json:"type"`
	Severity  Severity      `json:"severity"`
	Message   string        `json:"message"`
	Timestamp Time          `json:"timestamp"`
	ClientIP  string        `json:"clientIP"`
	Method    string        `json:"method"`
	Path      string        `json:"path"`
	Blocked   bool          `json:"blocked"`
}

// ProxyHealth represents proxy health
type ProxyHealth struct {
	Status      string  `json:"status"`
	Uptime      float64 `json:"uptime"`
	MemoryUsage int64   `json:"memoryUsage"`
}

// SIEMEvent represents SIEM event
type SIEMEvent struct {
	ID         string                 `json:"id"`
	Timestamp  Time                   `json:"timestamp"`
	Source     string                 `json:"source"`
	Category   string                 `json:"category"`
	Severity   Severity               `json:"severity"`
	Message    string                 `json:"message"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Webhook represents a webhook
type Webhook struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
	CreatedAt Time     `json:"createdAt"`
	UpdatedAt Time     `json:"updatedAt"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled      bool     `json:"enabled"`
	MinVersion   string   `json:"minVersion"`
	MaxVersion   string   `json:"maxVersion"`
	CipherSuites []string `json:"cipherSuites"`
	CertFile     string   `json:"certFile"`
	KeyFile      string   `json:"keyFile"`
	AutoGenerate bool     `json:"autoGenerate"`
}

// Certificate represents a certificate
type Certificate struct {
	ID           string   `json:"id"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serialNumber"`
	NotBefore    Time     `json:"notBefore"`
	NotAfter     Time     `json:"notAfter"`
	DNSNames     []string `json:"dnsNames"`
	Fingerprint  string   `json:"fingerprint"`
	IsCA         bool     `json:"isCA"`
	Status       string   `json:"status"`
}

// MTLSConfig represents mTLS configuration
type MTLSConfig struct {
	Enabled          bool   `json:"enabled"`
	CertFile         string `json:"certFile"`
	KeyFile          string `json:"keyFile"`
	CACertFile       string `json:"caCertFile"`
	CAKeyFile        string `json:"caKeyFile"`
	ClientAuth       string `json:"clientAuth"`
	VerifyClientCert bool   `json:"verifyClientCert"`
}

// Module represents a module
type Module struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Tier        ModuleTier   `json:"tier"`
	Status      ModuleStatus `json:"status"`
}

// ModuleHealth represents module health
type ModuleHealth struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	LastCheck Time   `json:"lastCheck"`
}

// License represents a license
type License struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Valid     bool     `json:"valid"`
	ExpiresAt *Time    `json:"expiresAt"`
	Features  []string `json:"features"`
}

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	TotalRequests     int64   `json:"totalRequests"`
	BlockedRequests   int64   `json:"blockedRequests"`
	ActiveUsers       int     `json:"activeUsers"`
	ActiveConnections int     `json:"activeConnections"`
	Uptime            float64 `json:"uptime"`
}

// Health represents health status
type Health struct {
	Status    string         `json:"status"`
	Checks    []*HealthCheck `json:"checks"`
	Timestamp Time           `json:"timestamp"`
}

// HealthCheck represents a health check
type HealthCheck struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Timestamp Time   `json:"timestamp"`
}

// CounterMetric represents counter metric
type CounterMetric struct {
	Name   string                 `json:"name"`
	Value  int64                  `json:"value"`
	Labels map[string]interface{} `json:"labels"`
}

// GaugeMetric represents gauge metric
type GaugeMetric struct {
	Name   string                 `json:"name"`
	Value  float64                `json:"value"`
	Labels map[string]interface{} `json:"labels"`
}

// MetricSnapshot represents metrics snapshot
type MetricSnapshot struct {
	Timestamp Time             `json:"timestamp"`
	Counters  []*CounterMetric `json:"counters"`
	Gauges    []*GaugeMetric   `json:"gauges"`
}

// ComplianceReportSummary represents compliance report summary
type ComplianceReportSummary struct {
	TotalChecks   int     `json:"totalChecks"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	Warnings      int     `json:"warnings"`
	NotApplicable int     `json:"notApplicable"`
	Score         float64 `json:"score"`
}

// ComplianceStatusSummary represents overall compliance status
type ComplianceStatusSummary struct {
	Overall    ComplianceStatus   `json:"overall"`
	Frameworks []*FrameworkStatus `json:"frameworks"`
	LastCheck  Time               `json:"lastCheck"`
}

// FrameworkStatus represents framework status
type FrameworkStatus struct {
	Framework FrameworkType    `json:"framework"`
	Status    ComplianceStatus `json:"status"`
	Score     float64          `json:"score"`
	LastCheck *Time            `json:"lastCheck"`
}

// ConfigValidationResult represents config validation result
type ConfigValidationResult struct {
	Valid  bool           `json:"valid"`
	Errors []*ConfigError `json:"errors"`
}

// ConfigError represents config error
type ConfigError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// LoginInput represents login input
type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfaCode"`
}

// CreateUserInput represents create user input
type CreateUserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     Role   `json:"role"`
}

// PageInfo represents page info
type PageInfo struct {
	HasNextPage     bool   `json:"hasNextPage"`
	HasPreviousPage bool   `json:"hasPreviousPage"`
	StartCursor     string `json:"startCursor"`
	EndCursor       string `json:"endCursor"`
}

// Placeholder types for unexported fields
func init() {
	// Suppress unused import warnings
	_ = proxy.Violation{}
	_ = compliance.Finding{}
	_ = siem.Event{}
	_ = webhook.Webhook{}
	_ = auth.User{}
	_ = auth.Session{}
}
