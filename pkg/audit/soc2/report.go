// SPDX-FileCopyrightText: 2025 AegisGate Security
// SPDX-License-Identifier: MIT

// Package soc2 provides types and utilities for SOC 2 audit automation,
// covering trust service categories, evidence collection, compliance status
// tracking, and report generation aligned with AICPA TSC criteria.
//
// This file implements the SOC 2 audit report builder. The ReportBuilder
// composes evidence, policies, and workpapers into a final SOC2AuditReport,
// computes summary statistics, and can sign the report using the attestation
// envelope system for tamper-evidence.
package soc2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// ReportConfig holds the configuration for building a SOC 2 audit report.
type ReportConfig struct {
	// Organization is the name of the entity being audited.
	Organization string
	// Auditor is the person or firm conducting the audit.
	Auditor string
	// PeriodStart is the start date of the audit period.
	PeriodStart time.Time
	// PeriodEnd is the end date of the audit period.
	PeriodEnd time.Time
	// Type indicates whether this is a Type I or Type II examination.
	Type AuditType
	// Categories filters which trust service categories to include.
	// Empty means all categories.
	Categories []TrustServiceCategory
}

// ReportBuilder constructs a SOC2AuditReport from evidence, policies, and
// workpapers. Use NewReportBuilder to create an instance, then call Build
// to produce the final report.
type ReportBuilder struct {
	config    ReportConfig
	collector *EvidenceCollector
}

// NewReportBuilder creates a new ReportBuilder with the given configuration
// and evidence collector.
func NewReportBuilder(config ReportConfig, collector *EvidenceCollector) *ReportBuilder {
	return &ReportBuilder{
		config:    config,
		collector: collector,
	}
}

// Build constructs the full SOC 2 audit report. It collects evidence from the
// configured collector, generates policies and workpapers, computes summary
// statistics, and assembles the final report with a deterministic report ID.
func (rb *ReportBuilder) Build(ctx context.Context) (*SOC2AuditReport, error) {
	// Collect evidence using the collector.
	evidence, err := rb.collector.Collect(ctx, rb.config.PeriodStart, rb.config.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("soc2 report: collect evidence: %w", err)
	}

	// Determine which categories to include.
	categories := rb.config.Categories
	if len(categories) == 0 {
		categories = AllTrustServiceCategories()
	}

	// Generate policies for the relevant categories.
	var policies []PolicyDocument
	for _, cat := range categories {
		catPolicies, err := PolicyForCategory(cat)
		if err != nil {
			return nil, fmt.Errorf("soc2 report: generate policies for %s: %w", cat, err)
		}
		policies = append(policies, catPolicies...)
	}

	// Generate workpapers for the evidence.
	workpapers, err := GenerateWorkpapers(evidence, rb.config.PeriodStart, rb.config.PeriodEnd, rb.config.Organization, rb.config.Auditor)
	if err != nil {
		return nil, fmt.Errorf("soc2 report: generate workpapers: %w", err)
	}

	// Compute summary statistics.
	summary := computeSummary(evidence)

	// Generate deterministic report ID: SOC2-{YYYYMMDD}-{org_hash8}
	orgHash := sha256.Sum256([]byte(rb.config.Organization))
	orgHash8 := hex.EncodeToString(orgHash[:])[:8]
	periodStartStr := rb.config.PeriodStart.Format("20060102")
	reportID := fmt.Sprintf("SOC2-%s-%s", periodStartStr, orgHash8)

	report := &SOC2AuditReport{
		ReportID:     reportID,
		Organization: rb.config.Organization,
		Auditor:      rb.config.Auditor,
		PeriodStart:  rb.config.PeriodStart,
		PeriodEnd:    rb.config.PeriodEnd,
		GeneratedAt:  time.Now().UTC(),
		Type:         rb.config.Type,
		Controls:     evidence,
		Summary:      summary,
		Policies:     policies,
		Workpapers:   workpapers,
	}

	return report, nil
}

// SignReport signs a SOC 2 audit report using the attestation envelope system.
// It creates a signed envelope with Type "audit.soc2.v1", subject
// "aegisgate://audit/{reportID}", and a 365-day TTL.
func SignReport(report *SOC2AuditReport, kr *ioc.KeyRing) (*attestation.Envelope, error) {
	if report == nil {
		return nil, fmt.Errorf("soc2: SignReport: nil report")
	}
	if kr == nil {
		return nil, fmt.Errorf("soc2: SignReport: nil keyring")
	}

	// Marshal the report without the attestation field.
	reportCopy := *report
	reportCopy.Attestation = nil
	payload, err := json.Marshal(reportCopy)
	if err != nil {
		return nil, fmt.Errorf("soc2: SignReport: marshal report: %w", err)
	}

	subject := fmt.Sprintf("aegisgate://audit/%s", report.ReportID)
	attType := attestation.Type("audit.soc2.v1")

	// Register the type if not already registered (idempotent).
	_ = attestation.RegisterType(attType, attestation.TypeSpec{
		Domain:      "audit",
		Name:        "soc2",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/audit.soc2.v1.json",
		Owner:       "pkg/audit/soc2",
		Description: "SOC 2 audit report attestation",
	})

	// Register the "audit" subject kind if not already registered (idempotent).
	_ = attestation.RegisterKind("audit")

	// Get the key ID for the issuer string.
	keyID, _, err := kr.CurrentKey()
	if err != nil {
		return nil, fmt.Errorf("soc2: SignReport: get current key: %w", err)
	}
	issuer := fmt.Sprintf("audit-builder:%s", keyID)

	env, err := attestation.Sign(payload, subject, attType, issuer, kr, 365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("soc2: SignReport: sign: %w", err)
	}

	return env, nil
}

// ReportToText generates a human-readable text representation of a SOC 2 audit
// report, suitable for terminal output or plain-text archival.
func ReportToText(report *SOC2AuditReport) string {
	if report == nil {
		return ""
	}

	typeLabel := "I"
	if report.Type == AuditType2 {
		typeLabel = "II"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "SOC 2 Type %s Audit Report\n", typeLabel)
	fmt.Fprintf(&b, "Organization: %s\n", report.Organization)
	fmt.Fprintf(&b, "Auditor: %s\n", report.Auditor)
	fmt.Fprintf(&b, "Period: %s to %s\n",
		report.PeriodStart.Format("2006-01-02"),
		report.PeriodEnd.Format("2006-01-02"))
	fmt.Fprintf(&b, "Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339))

	s := report.Summary
	total := s.TotalControls
	pct := func(n int) float64 {
		if total == 0 {
			return 0
		}
		return float64(n) / float64(total) * 100
	}

	fmt.Fprintf(&b, "Summary:\n")
	fmt.Fprintf(&b, "  Total Controls: %d\n", total)
	fmt.Fprintf(&b, "  Met: %d (%.0f%%)\n", s.ControlsMet, pct(s.ControlsMet))
	fmt.Fprintf(&b, "  Not Met: %d (%.0f%%)\n", s.ControlsNotMet, pct(s.ControlsNotMet))
	fmt.Fprintf(&b, "  Partially Met: %d (%.0f%%)\n", s.ControlsPartial, pct(s.ControlsPartial))
	fmt.Fprintf(&b, "  Not Applicable: %d\n\n", s.ControlsNA)

	fmt.Fprintf(&b, "Controls:\n")
	for _, ctrl := range report.Controls {
		fmt.Fprintf(&b, "  %s  %s  %s  %s\n", ctrl.ControlID, ctrl.ControlName, ctrl.Category, ctrl.Status)
	}

	fmt.Fprintf(&b, "\nWorkpapers: %d\n", len(report.Workpapers))
	fmt.Fprintf(&b, "Policies: %d\n", len(report.Policies))

	return b.String()
}

// ReportToJSON marshals a SOC 2 audit report to indented JSON.
func ReportToJSON(report *SOC2AuditReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("soc2: ReportToJSON: nil report")
	}
	return json.MarshalIndent(report, "", "  ")
}

// computeSummary computes aggregate audit statistics from control evidence.
func computeSummary(evidence []ControlEvidence) AuditSummary {
	var summary AuditSummary
	summary.TotalControls = len(evidence)

	for _, ce := range evidence {
		switch ce.Status {
		case StatusMet:
			summary.ControlsMet++
		case StatusNotMet:
			summary.ControlsNotMet++
		case StatusPartiallyMet:
			summary.ControlsPartial++
		case StatusNotApplicable:
			summary.ControlsNA++
		}
	}

	if summary.TotalControls > 0 {
		applicable := summary.TotalControls - summary.ControlsNA
		if applicable > 0 {
			summary.ScorePct = float64(summary.ControlsMet) / float64(applicable) * 100
		}
	}

	return summary
}