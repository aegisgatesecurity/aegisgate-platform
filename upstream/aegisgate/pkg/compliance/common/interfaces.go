// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package common

import (
	"context"
	"time"
)

// Severity represents compliance finding severity
type Severity int

const (
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

func (s Severity) String() string {
	switch s {
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

// Finding represents a compliance violation or finding
type Finding struct {
	ID          string                 `json:"id"`
	Framework   string                 `json:"framework"`
	Rule        string                 `json:"rule"`
	Severity    Severity               `json:"severity"`
	Description string                 `json:"description"`
	Evidence    string                 `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Location    string                 `json:"location,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// Framework is the interface that all compliance frameworks must implement
type Framework interface {
	// Identity information
	GetName() string
	GetVersion() string
	GetDescription() string

	// Core functionality
	Check(ctx context.Context, input CheckInput) (*CheckResult, error)
	CheckRequest(ctx context.Context, req *HTTPRequest) ([]Finding, error)
	CheckResponse(ctx context.Context, resp *HTTPResponse) ([]Finding, error)

	// Configuration
	Configure(config map[string]interface{}) error
	IsEnabled() bool
	Enable()
	Disable()

	// Metadata
	GetFrameworkID() string
	GetPatternCount() int
	GetSeverityLevels() []Severity
}

// CheckInput represents input to a compliance check
type CheckInput struct {
	Content  string
	Headers  map[string]string
	Metadata map[string]interface{}
}

// CheckResult represents the result of a compliance check
type CheckResult struct {
	Framework       string        `json:"framework"`
	Passed          bool          `json:"passed"`
	Findings        []Finding     `json:"findings,omitempty"`
	CheckedAt       time.Time     `json:"checked_at"`
	Duration        time.Duration `json:"duration"`
	TotalPatterns   int           `json:"total_patterns"`
	MatchedPatterns int           `json:"matched_patterns"`
}

// HTTPRequest represents an HTTP request for compliance checking
type HTTPRequest struct {
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	RemoteAddr string              `json:"remote_addr"`
	Timestamp  time.Time           `json:"timestamp"`
}

// HTTPResponse represents an HTTP response for compliance checking
type HTTPResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	Timestamp  time.Time           `json:"timestamp"`
}

// Report represents a comprehensive compliance report
type Report struct {
	ID          string        `json:"id"`
	GeneratedAt time.Time     `json:"generated_at"`
	Frameworks  []string      `json:"frameworks"`
	Findings    []Finding     `json:"findings"`
	Summary     ReportSummary `json:"summary"`
}

type ReportSummary struct {
	TotalChecks   int `json:"total_checks"`
	PassedChecks  int `json:"passed_checks"`
	FailedChecks  int `json:"failed_checks"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
}

// Pattern defines a detection pattern
type Pattern struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Regex       string   `json:"regex,omitempty"`
	Semantics   []string `json:"semantics,omitempty"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
}
