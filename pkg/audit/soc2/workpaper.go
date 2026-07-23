// SPDX-FileCopyrightText: 2025 AegisGate Security
// SPDX-License-Identifier: MIT

// Package soc2 provides types and utilities for SOC 2 audit automation,
// covering trust service categories, evidence collection, compliance status
// tracking, and report generation aligned with AICPA TSC criteria.
//
// This file implements SOC 2 audit workpaper generation. Workpapers are the
// core artifact auditors produce - they document procedures, evidence, and
// conclusions for each Trust Service Category. Each workpaper is hash-linked
// and can be signed via the attestation envelope system for tamper-evidence.
package soc2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// categoryProcedures maps each Trust Service Category to its standard audit
// procedures. These are the steps an auditor performs to evaluate controls
// within that category, aligned with AICPA TSC criteria.
var categoryProcedures = map[TrustServiceCategory][]AuditProcedure{
	TSCSecurity: {
		{Step: 1, Description: "Inspect access control policies and procedures", Method: "inspect"},
		{Step: 2, Description: "Test logical access controls and authentication mechanisms", Method: "test"},
		{Step: 3, Description: "Verify encryption implementation for data at rest and in transit", Method: "verify"},
		{Step: 4, Description: "Review audit logging configuration and retention", Method: "review"},
		{Step: 5, Description: "Evaluate segregation of duties implementation", Method: "evaluate"},
	},
	TSCAvailability: {
		{Step: 1, Description: "Review capacity monitoring and alerting configuration", Method: "review"},
		{Step: 2, Description: "Inspect disaster recovery and business continuity plans", Method: "inspect"},
		{Step: 3, Description: "Test system availability metrics and SLA compliance", Method: "test"},
	},
	TSCProcessingIntegrity: {
		{Step: 1, Description: "Evaluate data validation controls and processing accuracy", Method: "evaluate"},
		{Step: 2, Description: "Review error handling and exception processing procedures", Method: "review"},
		{Step: 3, Description: "Test ML model validation and benchmarking", Method: "test"},
	},
	TSCConfidentiality: {
		{Step: 1, Description: "Inspect data classification procedures", Method: "inspect"},
		{Step: 2, Description: "Verify encryption and access restrictions for confidential data", Method: "verify"},
		{Step: 3, Description: "Review third-party risk management processes", Method: "review"},
	},
	TSCPrivacy: {
		{Step: 1, Description: "Review privacy notices and consent mechanisms", Method: "review"},
		{Step: 2, Description: "Inspect data minimization and retention procedures", Method: "inspect"},
		{Step: 3, Description: "Verify subject rights request handling", Method: "verify"},
	},
}

// categoryObjective maps each Trust Service Category to its workpaper objective.
var categoryObjective = map[TrustServiceCategory]string{
	TSCSecurity:            "Evaluate the effectiveness of controls designed to protect information and systems from unauthorized access, disclosure, and disruption.",
	TSCAvailability:        "Evaluate the effectiveness of controls designed to ensure system availability and operational continuity per SLA commitments.",
	TSCProcessingIntegrity: "Evaluate the effectiveness of controls designed to ensure data processing is complete, accurate, valid, and timely.",
	TSCConfidentiality:     "Evaluate the effectiveness of controls designed to protect confidential information from unauthorized access and disclosure.",
	TSCPrivacy:             "Evaluate the effectiveness of controls designed to protect personal information collection, use, retention, and disposal per privacy commitments.",
}

// categoryTitle maps each Trust Service Category to a human-readable name
// used in workpaper titles.
var categoryTitle = map[TrustServiceCategory]string{
	TSCSecurity:            "Security",
	TSCAvailability:        "Availability",
	TSCProcessingIntegrity: "Processing Integrity",
	TSCConfidentiality:     "Confidentiality",
	TSCPrivacy:             "Privacy",
}

// GenerateWorkpapers generates one workpaper per TSC category that has
// controls in the evidence slice. Each workpaper documents the audit
// procedures, evidence, and conclusions for that category.
func GenerateWorkpapers(evidence []ControlEvidence, periodStart, periodEnd time.Time, organization, auditor string) ([]Workpaper, error) {
	// Group evidence by category.
	byCategory := make(map[TrustServiceCategory][]ControlEvidence)
	for _, e := range evidence {
		byCategory[e.Category] = append(byCategory[e.Category], e)
	}

	var workpapers []Workpaper
	for _, cat := range AllTrustServiceCategories() {
		catEvidence, ok := byCategory[cat]
		if !ok {
			continue
		}
		wp, err := GenerateWorkpaper(cat, catEvidence, periodStart, periodEnd, organization, auditor)
		if err != nil {
			return nil, fmt.Errorf("generate workpaper for %s: %w", cat, err)
		}
		workpapers = append(workpapers, *wp)
	}
	return workpapers, nil
}

// GenerateWorkpaper generates a single workpaper for a specific TSC category.
// It filters the evidence by category, derives control results, selects the
// appropriate audit procedures, and computes an aggregate conclusion.
func GenerateWorkpaper(category TrustServiceCategory, evidence []ControlEvidence, periodStart, periodEnd time.Time, organization, auditor string) (*Workpaper, error) {
	// Filter evidence to only this category (defensive: caller should
	// already have filtered, but we ensure correctness).
	var filtered []ControlEvidence
	for _, e := range evidence {
		if e.Category == category {
			filtered = append(filtered, e)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no evidence for category %s", category)
	}

	// Build control results from evidence.
	var results []ControlResult
	for _, e := range filtered {
		details := strings.Join(e.Findings, "; ")
		if details == "" {
			details = fmt.Sprintf("Control %s assessed as %s", e.ControlID, e.Status)
		}
		results = append(results, ControlResult{
			ControlID:   e.ControlID,
			ControlName:  e.ControlName,
			Status:      e.Status,
			Details:     details,
		})
	}

	// Select procedures for this category.
	procedures := categoryProcedures[category]
	if procedures == nil {
		procedures = []AuditProcedure{}
	}

	// Build scope description.
	controlIDs := make([]string, len(filtered))
	for i, e := range filtered {
		controlIDs[i] = e.ControlID
	}
	scope := fmt.Sprintf("Controls %s for %s covering the period %s through %s",
		strings.Join(controlIDs, ", "),
		organization,
		periodStart.Format(time.DateOnly),
		periodEnd.Format(time.DateOnly),
	)

	// Build the title.
	titleName, ok := categoryTitle[category]
	if !ok {
		titleName = string(category)
	}
	title := fmt.Sprintf("SOC 2 %s Workpaper", titleName)

	// Build the objective.
	objective, ok := categoryObjective[category]
	if !ok {
		objective = fmt.Sprintf("Evaluate the effectiveness of controls for the %s trust service category.", titleName)
	}

	// Compute workpaper ID from content hash.
	content := workpaperContent(category, filtered, periodStart, periodEnd, organization, auditor)
	hash := sha256.Sum256([]byte(content))
	shortHash := hex.EncodeToString(hash[:])[:8]
	workpaperID := fmt.Sprintf("WP-%s-%s", strings.ToUpper(string(category)), shortHash)

	// Compute aggregate conclusion.
	conclusion := computeConclusion(results)

	wp := &Workpaper{
		WorkpaperID: workpaperID,
		Category:    category,
		Title:       title,
		Objective:   objective,
		Scope:       scope,
		Procedures:  procedures,
		Results:     results,
		Conclusion:  conclusion,
		PreparedBy:  auditor,
		Date:        time.Now(),
	}
	return wp, nil
}

// SignWorkpaper signs the workpaper using the attestation envelope system.
// It marshals the workpaper to JSON and creates a signed envelope with
// Type "audit.soc2.v1" and subject "aegisgate://audit/{workpaperID}".
func SignWorkpaper(wp *Workpaper, kr *ioc.KeyRing) (*attestation.Envelope, error) {
	if wp == nil {
		return nil, fmt.Errorf("soc2: SignWorkpaper: nil workpaper")
	}

	payload, err := json.Marshal(wp)
	if err != nil {
		return nil, fmt.Errorf("soc2: SignWorkpaper: marshal workpaper: %w", err)
	}

	subject := fmt.Sprintf("aegisgate://audit/%s", wp.WorkpaperID)
	attType := attestation.Type("audit.soc2.v1")

	// Register the type if not already registered (idempotent).
	_ = attestation.RegisterType(attType, attestation.TypeSpec{
		Domain:      "audit",
		Name:        "soc2",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/audit.soc2.v1.json",
		Owner:       "pkg/audit/soc2",
		Description: "SOC 2 audit workpaper attestation",
	})

	// Register the "audit" subject kind if not already registered (idempotent).
	_ = attestation.RegisterKind("audit")

	env, err := attestation.Sign(payload, subject, attType, "aegisgate:audit-key", kr, 0)
	if err != nil {
		return nil, fmt.Errorf("soc2: SignWorkpaper: sign: %w", err)
	}
	return env, nil
}

// WorkpaperToText generates a human-readable text representation of the
// workpaper for console/CLI output.
func WorkpaperToText(wp *Workpaper) string {
	if wp == nil {
		return "<nil workpaper>"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "=== %s ===\n", wp.Title)
	fmt.Fprintf(&b, "Workpaper ID : %s\n", wp.WorkpaperID)
	fmt.Fprintf(&b, "Category     : %s\n", wp.Category)
	fmt.Fprintf(&b, "Objective    : %s\n", wp.Objective)
	fmt.Fprintf(&b, "Scope        : %s\n", wp.Scope)
	fmt.Fprintf(&b, "Prepared By  : %s\n", wp.PreparedBy)
	fmt.Fprintf(&b, "Date         : %s\n", wp.Date.Format(time.DateOnly))
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "--- Procedures ---")
	for _, p := range wp.Procedures {
		fmt.Fprintf(&b, "  %d. [%s] %s\n", p.Step, strings.ToUpper(p.Method), p.Description)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "--- Results ---")
	for _, r := range wp.Results {
		fmt.Fprintf(&b, "  %s (%s): %s - %s\n", r.ControlID, r.ControlName, r.Status, r.Details)
	}
	fmt.Fprintln(&b)

	fmt.Fprintf(&b, "Conclusion   : %s\n", wp.Conclusion)
	return b.String()
}

// WorkpaperToJSON generates a JSON representation of the workpaper.
func WorkpaperToJSON(wp *Workpaper) ([]byte, error) {
	if wp == nil {
		return nil, fmt.Errorf("soc2: WorkpaperToJSON: nil workpaper")
	}
	data, err := json.MarshalIndent(wp, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("soc2: WorkpaperToJSON: marshal: %w", err)
	}
	return data, nil
}

// workpaperContent produces a deterministic string representation of the
// workpaper content for hashing. This ensures the same workpaper always
// produces the same hash, enabling stable WorkpaperID generation.
func workpaperContent(category TrustServiceCategory, evidence []ControlEvidence, periodStart, periodEnd time.Time, organization, auditor string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "category=%s\n", category)
	fmt.Fprintf(&b, "organization=%s\n", organization)
	fmt.Fprintf(&b, "auditor=%s\n", auditor)
	fmt.Fprintf(&b, "periodStart=%s\n", periodStart.Format(time.RFC3339))
	fmt.Fprintf(&b, "periodEnd=%s\n", periodEnd.Format(time.RFC3339))
	for _, e := range evidence {
		fmt.Fprintf(&b, "control=%s,status=%s\n", e.ControlID, e.Status)
	}
	return b.String()
}

// computeConclusion derives an aggregate conclusion from the control results.
// The conclusion reflects the overall compliance status for the workpaper's
// TSC category based on individual control outcomes.
func computeConclusion(results []ControlResult) string {
	if len(results) == 0 {
		return "No controls evaluated."
	}

	var met, notMet, partial, na int
	for _, r := range results {
		switch r.Status {
		case StatusMet:
			met++
		case StatusNotMet:
			notMet++
		case StatusPartiallyMet:
			partial++
		case StatusNotApplicable:
			na++
		}
	}

	applicable := len(results) - na

	switch {
	case applicable == 0:
		return "All controls are not applicable."
	case notMet > 0:
		return fmt.Sprintf("Exceptions identified: %d of %d applicable controls not met, %d partially met. Remediation required.",
			notMet, applicable, partial)
	case partial > 0:
		return fmt.Sprintf("All applicable controls met or partially met. %d of %d applicable controls partially met - monitor for improvement.",
			partial, applicable)
	default:
		return fmt.Sprintf("All %d applicable controls met. No exceptions identified.", applicable)
	}
}