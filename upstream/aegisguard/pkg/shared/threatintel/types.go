// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package threatintel provides threat intelligence for AI agent security
package threatintel

import (
	"time"
)

// ThreatType represents types of agent-specific threats
type ThreatType string

const (
	ThreatTypePromptInjection    ThreatType = "prompt_injection"
	ThreatTypeToolAbuse          ThreatType = "tool_abuse"
	ThreatTypeContextPoisoning   ThreatType = "context_poisoning"
	ThreatTypeDataExfiltration   ThreatType = "data_exfiltration"
	ThreatTypeUnauthorizedAccess ThreatType = "unauthorized_access"
)

// Severity represents threat severity
type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
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

// Threat represents an agent security threat
type Threat struct {
	ID          string                 `json:"id"`
	Type        ThreatType             `json:"type"`
	Severity    Severity               `json:"severity"`
	AgentID     string                 `json:"agent_id"`
	SessionID   string                 `json:"session_id"`
	ToolName    string                 `json:"tool_name,omitempty"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Blocked     bool                   `json:"blocked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// ThreatIndicator represents a pattern to detect threats
type ThreatIndicator struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Type        ThreatType `json:"type"`
	Pattern     string     `json:"pattern"` // regex or semantic pattern
	Severity    Severity   `json:"severity"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	MITREATLAS  string     `json:"mitre_atlas,omitempty"` // ATLAS technique ID
}

// AgentThreatFeed represents a feed of threats for agents
type AgentThreatFeed struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Indicators []ThreatIndicator `json:"indicators"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Source     string            `json:"source"`
}

// DetectionResult represents the result of threat detection
type DetectionResult struct {
	Threats    []Threat `json:"threats"`
	Blocked    bool     `json:"blocked"`
	RiskScore  int      `json:"risk_score"` // 0-100
	Confidence float64  `json:"confidence"` // 0.0-1.0
}

// ToolCallThreatAnalysis represents analysis of a tool call
type ToolCallThreatAnalysis struct {
	ToolName   string                 `json:"tool_name"`
	Parameters map[string]interface{} `json:"parameters"`
	Threats    []Threat               `json:"threats"`
	RiskLevel  Severity               `json:"risk_level"`
	Approved   bool                   `json:"approved"`
	Reason     string                 `json:"reason,omitempty"`
}
