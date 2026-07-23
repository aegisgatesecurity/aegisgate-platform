// SPDX-FileCopyrightText: 2025 AegisGate Security
// SPDX-License-Identifier: MIT

// Package soc2 provides types and utilities for SOC 2 audit automation,
// covering trust service categories, evidence collection, compliance status
// tracking, and report generation aligned with AICPA TSC criteria.
package soc2

import (
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// TrustServiceCategory represents a SOC 2 trust service category.
type TrustServiceCategory string

const (
	TSCSecurity            TrustServiceCategory = "security"
	TSCAvailability        TrustServiceCategory = "availability"
	TSCProcessingIntegrity TrustServiceCategory = "processing_integrity"
	TSCConfidentiality     TrustServiceCategory = "confidentiality"
	TSCPrivacy             TrustServiceCategory = "privacy"
)

// String returns the string representation of the trust service category.
func (c TrustServiceCategory) String() string { return string(c) }

// AllTrustServiceCategories returns all defined SOC 2 trust service categories.
func AllTrustServiceCategories() []TrustServiceCategory {
	return []TrustServiceCategory{TSCSecurity, TSCAvailability, TSCProcessingIntegrity, TSCConfidentiality, TSCPrivacy}
}

// EvidenceSource identifies the origin of compliance evidence.
type EvidenceSource string

const (
	EvidenceSourceCompliance  EvidenceSource = "compliance_scan"
	EvidenceSourceAttestation EvidenceSource = "attestation"
	EvidenceSourceBenchmark   EvidenceSource = "benchmark"
	EvidenceSourceManual      EvidenceSource = "manual"
	EvidenceSourceAuditLog    EvidenceSource = "audit_log"
	EvidenceSourcePolicy      EvidenceSource = "policy_template"
)

// ComplianceStatus indicates whether a control meets its criteria.
type ComplianceStatus string

const (
	StatusMet          ComplianceStatus = "met"
	StatusNotMet       ComplianceStatus = "not_met"
	StatusPartiallyMet ComplianceStatus = "partially_met"
	StatusNotApplicable ComplianceStatus = "not_applicable"
)

// AuditType distinguishes between SOC 2 Type I and Type II examinations.
type AuditType string

const (
	AuditType1 AuditType = "type1"
	AuditType2 AuditType = "type2"
)

// EvidenceRef is a reference to a specific piece of evidence supporting a control.
type EvidenceRef struct {
	Source      EvidenceSource `json:"source"`
	ReferenceID string         `json:"reference_id"`
	Description string         `json:"description"`
	Timestamp   time.Time      `json:"timestamp,omitempty"`
}

// ControlEvidence maps a SOC 2 control to its supporting evidence and compliance status.
type ControlEvidence struct {
	ControlID    string                `json:"control_id"`
	ControlName  string                `json:"control_name"`
	Category     TrustServiceCategory   `json:"category"`
	Status       ComplianceStatus       `json:"status"`
	Sources      []EvidenceRef          `json:"sources"`
	Findings     []string               `json:"findings,omitempty"`
	Remediation  string                 `json:"remediation,omitempty"`
	LastAssessed time.Time              `json:"last_assessed"`
}

// AuditSummary provides aggregate statistics across all evaluated controls.
type AuditSummary struct {
	TotalControls int     `json:"total_controls"`
	ControlsMet   int     `json:"controls_met"`
	ControlsNotMet  int   `json:"controls_not_met"`
	ControlsPartial int   `json:"controls_partial"`
	ControlsNA      int   `json:"controls_not_applicable"`
	ScorePct        float64 `json:"score_pct"`
}

// AuditProcedure represents a single step in an audit workpaper.
type AuditProcedure struct {
	Step        int      `json:"step"`
	Description string   `json:"description"`
	Method      string   `json:"method"`
	Evidence    []string `json:"evidence_refs,omitempty"`
}

// ControlResult captures the compliance result for a single control within a workpaper.
type ControlResult struct {
	ControlID   string           `json:"control_id"`
	ControlName string           `json:"control_name"`
	Status      ComplianceStatus `json:"status"`
	Details     string           `json:"details"`
}

// Workpaper documents the audit procedures, evidence, and results for a trust service category.
type Workpaper struct {
	WorkpaperID string               `json:"workpaper_id"`
	Category   TrustServiceCategory  `json:"category"`
	Title       string               `json:"title"`
	Objective   string               `json:"objective"`
	Scope       string               `json:"scope"`
	Procedures  []AuditProcedure     `json:"procedures"`
	Results     []ControlResult       `json:"results"`
	Conclusion  string               `json:"conclusion"`
	PreparedBy  string               `json:"prepared_by"`
	ReviewedBy  string               `json:"reviewed_by,omitempty"`
	Date        time.Time            `json:"date"`
}

// PolicyDocument represents a policy template document mapped to SOC 2 controls.
type PolicyDocument struct {
	ID          string               `json:"id"`
	Title       string               `json:"title"`
	Category    TrustServiceCategory  `json:"category"`
	Version     string               `json:"version"`
	Content     string               `json:"content"`
	Controls    []string             `json:"controls"`
	LastUpdated time.Time            `json:"last_updated"`
}

// SOC2AuditReport is the top-level audit report aggregating controls, summary,
// policies, workpapers, and an optional attestation envelope for signing.
type SOC2AuditReport struct {
	ReportID     string                `json:"report_id"`
	Organization string                `json:"organization"`
	Auditor      string                `json:"auditor"`
	PeriodStart  time.Time             `json:"period_start"`
	PeriodEnd    time.Time             `json:"period_end"`
	GeneratedAt  time.Time             `json:"generated_at"`
	Type         AuditType              `json:"type"`
	Controls     []ControlEvidence      `json:"controls"`
	Summary      AuditSummary           `json:"summary"`
	Policies     []PolicyDocument       `json:"policies,omitempty"`
	Workpapers   []Workpaper            `json:"workpapers,omitempty"`
	Attestation  *attestation.Envelope  `json:"attestation,omitempty"`
}