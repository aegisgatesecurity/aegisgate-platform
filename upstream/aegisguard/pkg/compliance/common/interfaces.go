// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package common

import (
	"time"
)

// Note: Framework interface, Severity types, Finding, CheckInput, CheckResult,
// HTTPRequest, HTTPResponse, FrameworkConfig, TierInfo, and PricingInfo are
// defined in framework.go. This file contains additional types used across
// compliance packages.

// ============================================================================
// REPORT TYPES
// ============================================================================

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

// TechniqueFinding represents a technique check result
type TechniqueFinding struct {
	ID          string
	Name        string
	Tactic      string
	Severity    Severity
	Status      string
	Description string
}

// Findings is a collection of Finding
type Findings struct {
	Framework       string
	Version         string
	Timestamp       interface{} // time.Time
	Status          string
	Techniques      []TechniqueFinding
	Recommendations []string
}

// ITierManager interface for tier checking
type ITierManager interface {
	GetCurrentTier() string
	ValidateLicense() bool
}

// AgentCheckInput extends CheckInput for agent-specific checks
type AgentCheckInput struct {
	CheckInput
	AgentID    string                 `json:"agent_id"`
	SessionID  string                 `json:"session_id"`
	ToolName   string                 `json:"tool_name"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ToolFinding represents a tool call finding
type ToolFinding struct {
	ID          string                 `json:"id"`
	ToolName    string                 `json:"tool_name"`
	Action      string                 `json:"action"`
	Severity    Severity               `json:"severity"`
	Description string                 `json:"description"`
	RiskScore   int                    `json:"risk_score"`
	Blocked     bool                   `json:"blocked"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context,omitempty"`
}
