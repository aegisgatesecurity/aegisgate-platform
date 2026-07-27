// Package compliance provides compliance checking capabilities for AegisGate
// This file adds backward compatibility types for the grpc package
package compliance

import (
	"time"
)

// ComplianceStatus represents the status of a compliance check
// (alias for ControlCheckStatus for backward compatibility)
type ComplianceStatus = ControlCheckStatus

// CheckResult represents the result of a compliance check
type CheckResult struct {
	ID        string           `json:"id"`
	Framework Framework        `json:"framework"`
	Status    ComplianceStatus `json:"status"`
	Summary   CheckSummary     `json:"summary"`
	Findings  []Finding        `json:"findings"`
	Timestamp time.Time        `json:"timestamp"`
}

// CheckSummary contains summary statistics
type CheckSummary struct {
	TotalChecks   int     `json:"total_checks"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	Warnings      int     `json:"warnings"`
	NotApplicable int     `json:"not_applicable"`
	Score         float64 `json:"score"`
}
