// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// Common types for compliance framework implementations
// =========================================================================

package common

import (
	"context"
	"time"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Framework interface that all compliance frameworks must implement
type Framework interface {
	GetName() string
	GetVersion() string
	GetDescription() string
	Check(ctx context.Context, input CheckInput) (*CheckResult, error)
	Configure(config map[string]interface{}) error
	IsEnabled() bool
	Enable()
	Disable()
	GetFrameworkID() string
	GetPatternCount() int
	GetSeverityLevels() []Severity
	GetTier() TierInfo
	GetConfig() *FrameworkConfig
	SupportsTier(tier string) bool
	GetPricing() PricingInfo
}

// CheckInput represents input for compliance checks
type CheckInput struct {
	Content   string
	Metadata  map[string]string
	Headers   map[string]string
	Timestamp time.Time
}

// CheckResult represents the result of a compliance check
type CheckResult struct {
	Framework       string
	Passed          bool
	Findings        []Finding
	CheckedAt       time.Time
	Duration        time.Duration
	TotalPatterns   int
	MatchedPatterns int
}

// Finding represents a compliance finding
type Finding struct {
	Framework   string
	Severity    Severity
	Description string
	Timestamp   time.Time
}

// HTTPRequest represents an HTTP request for checking
type HTTPRequest struct {
	Method    string
	URL       string
	Path      string
	Headers   map[string]string
	Body      string
	SourceIP  string
	UserAgent string
}

// HTTPResponse represents an HTTP response for checking
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// FrameworkConfig holds framework configuration
type FrameworkConfig struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

// TierInfo holds tier information
type TierInfo struct {
	Name        string
	Pricing     string
	Description string
}

// PricingInfo holds pricing details
type PricingInfo struct {
	Tier        string
	MonthlyCost float64
	Description string
	Features    []string
}
