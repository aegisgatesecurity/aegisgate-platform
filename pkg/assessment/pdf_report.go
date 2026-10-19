// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 3: PDF Report Generation using pkg/pdf (pure Go, zero external deps)
//
// pdf_report.go renders an AssessmentResult to a professional PDF document
// with cover page, executive summary, OWASP coverage, compliance posture,
// gap analysis, and per-scenario results.
//
// The PDF is generated entirely in memory using pkg/pdf.RenderReport.
// Zero external dependencies — uses only the Go standard library and
// the platform's own PDF renderer.

package assessment

import (
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/pdf"
)

// PDFReportConfig configures the PDF report generation.
type PDFReportConfig struct {
	// IncludeOWASPCoverage includes the OWASP LLM Top 10 coverage table.
	// Default: true.
	IncludeOWASPCoverage bool

	// IncludeCompliancePosture includes the compliance posture table for
	// all 31 frameworks. Default: true.
	IncludeCompliancePosture bool

	// IncludeGapAnalysis includes the gap analysis section (missed scenarios).
	// Default: true.
	IncludeGapAnalysis bool

	// IncludeScenarioDetails includes the per-scenario results table.
	// Default: true.
	IncludeScenarioDetails bool

	// IncludeGapReport includes the IOC feedback loop gap analysis report
	// (if available). Default: false (requires feedback loop output).
	IncludeGapReport bool

	// CompliancePostureV2 uses the 31-framework posture (V2) instead of
	// the 5-framework posture (V1). Default: true.
	CompliancePostureV2 bool

	// Author is the PDF metadata author. Default: "AegisGate Platform".
	Author string

	// Organization is the organization name for the cover page.
	// Default: "" (omitted if empty).
	Organization string
}

// DefaultPDFReportConfig returns the default PDF report configuration.
func DefaultPDFReportConfig() PDFReportConfig {
	return PDFReportConfig{
		IncludeOWASPCoverage:     true,
		IncludeCompliancePosture: true,
		IncludeGapAnalysis:       true,
		IncludeScenarioDetails:   true,
		IncludeGapReport:         false,
		CompliancePostureV2:      true,
		Author:                   "AegisGate Platform",
	}
}

// ToPDF renders the assessment result to a PDF document.
// Uses the default configuration.
func (r *AssessmentResult) ToPDF() ([]byte, error) {
	return r.ToPDFWithConfig(DefaultPDFReportConfig())
}

// ToPDFWithConfig renders the assessment result to a PDF document with
// the given configuration.
func (r *AssessmentResult) ToPDFWithConfig(cfg PDFReportConfig) ([]byte, error) {
	if cfg.Author == "" {
		cfg.Author = "AegisGate Platform"
	}

	sections := r.buildPDFSections(cfg)

	subject := fmt.Sprintf("Posture Assessment — %s", r.Timestamp.Format("Jan 2, 2006"))

	req := &pdf.RenderRequest{
		Title:           "AegisGate Posture Assessment Report",
		Author:          cfg.Author,
		Subject:         subject,
		Keywords:        "OWASP LLM Top 10, Posture Assessment, Security, Compliance, AI Security",
		PageSize:        pdf.PageLetter,
		Sections:        sections,
		Footer:          "AegisGate Security, LLC — Confidential",
		Header:          "AegisGate",
		HeaderSubtitle:  r.Timestamp.Format("Jan 2, 2006 15:04 MST"),
		FooterURL:       "https://aegisgatesecurity.io",
		FooterIncludeID: r.ID,
		GeneratedAt:     r.Timestamp,
	}

	return pdf.RenderReport(req)
}

// buildPDFSections constructs the PDF sections from the assessment result.
func (r *AssessmentResult) buildPDFSections(cfg PDFReportConfig) []pdf.Section {
	var sections []pdf.Section

	// --- Cover / Title ---
	orgLine := ""
	if cfg.Organization != "" {
		orgLine = fmt.Sprintf("Organization: %s", cfg.Organization)
	}

	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf(
			"Assessment ID: %s\nTimestamp: %s\nDuration: %v\n%s",
			r.ID, r.Timestamp.Format(time.RFC3339), r.Duration, orgLine,
		),
	})

	// --- Executive Summary ---
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: "Executive Summary",
	})

	scorePercent := r.Score * 100
	status := "PASS"
	if r.Score < 0.80 {
		status = "NEEDS IMPROVEMENT"
	}
	if r.Score < 0.60 {
		status = "FAIL"
	}

	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf(
			"This report presents the results of an AegisGate Posture Assessment, "+
				"which evaluates the security posture of an AI/LLM deployment against "+
				"the OWASP LLM Top 10 (2025) and 31 compliance frameworks.\n\n"+
				"Overall Score: %.1f%% (%d/%d attacks blocked)\n"+
				"Status: %s\n"+
				"Gaps Identified: %d\n"+
				"OWASP Categories Covered: %d/10",
			scorePercent, r.Blocked, r.Total, status, r.Missed, len(r.OWASPCoverage),
		),
	})

	// --- OWASP Coverage ---
	if cfg.IncludeOWASPCoverage {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: "OWASP LLM Top 10 Coverage",
		})

		owaspRows := [][]string{
			{"Category", "Total", "Blocked", "Missed", "Coverage"},
		}

		// Sort OWASP categories.
		owaspKeys := make([]string, 0, len(r.OWASPCoverage))
		for k := range r.OWASPCoverage {
			owaspKeys = append(owaspKeys, k)
		}
		sortStrings(owaspKeys)

		for _, k := range owaspKeys {
			cat := r.OWASPCoverage[k]
			owaspRows = append(owaspRows, []string{
				k,
				fmt.Sprintf("%d", cat.Total),
				fmt.Sprintf("%d", cat.Blocked),
				fmt.Sprintf("%d", cat.Missed),
				fmt.Sprintf("%.0f%%", cat.Coverage*100),
			})
		}

		sections = append(sections, pdf.Section{
			Kind:    pdf.SectionTable,
			Table:   pdf.Table{Rows: owaspRows},
			Columns: []float64{120, 60, 70, 60, 80},
		})
	}

	// --- Compliance Posture ---
	if cfg.IncludeCompliancePosture {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionPageBreak,
		})

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: "Compliance Posture",
		})

		var posture map[string]FrameworkPosture
		if cfg.CompliancePostureV2 {
			posture = ComputeCompliancePostureV2(r.ScenarioResults)
			sections = append(sections, pdf.Section{
				Kind: pdf.SectionParagraph,
				Text: fmt.Sprintf("Assessment across %d compliance frameworks.", FrameworkCount()),
			})
		} else {
			posture = r.CompliancePosture
			sections = append(sections, pdf.Section{
				Kind: pdf.SectionParagraph,
				Text: fmt.Sprintf("Assessment across %d compliance frameworks.", len(SupportedFrameworks())),
			})
		}

		compRows := [][]string{
			{"Framework", "Controls", "Verified", "At Risk", "Coverage"},
		}

		// Sort frameworks by coverage (ascending — worst first).
		fwKeys := make([]string, 0, len(posture))
		for k := range posture {
			fwKeys = append(fwKeys, k)
		}
		sortStrings(fwKeys)

		for _, k := range fwKeys {
			fp := posture[k]
			if fp.TotalControls == 0 {
				continue // Skip frameworks with no applicable controls.
			}
			info := FrameworkInfoByID(ComplianceFramework(k))
			name := k
			if info != nil {
				name = info.Name
			}
			compRows = append(compRows, []string{
				truncate(name, 35),
				fmt.Sprintf("%d", fp.TotalControls),
				fmt.Sprintf("%d", fp.Verified),
				fmt.Sprintf("%d", fp.AtRisk),
				fmt.Sprintf("%.0f%%", fp.Coverage*100),
			})
		}

		sections = append(sections, pdf.Section{
			Kind:    pdf.SectionTable,
			Table:   pdf.Table{Rows: compRows},
			Columns: []float64{180, 60, 60, 50, 60},
		})
	}

	// --- Gap Analysis ---
	if cfg.IncludeGapAnalysis && r.Missed > 0 {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionPageBreak,
		})

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: "Gap Analysis",
		})

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: fmt.Sprintf(
				"%d scenario(s) were not blocked by any detection layer. "+
					"These represent security gaps that should be addressed.",
				r.Missed,
			),
		})

		gapRows := [][]string{
			{"Scenario ID", "OWASP", "Name", "Detection Layer"},
		}

		for _, sr := range r.ScenarioResults {
			if !sr.Blocked {
				gapRows = append(gapRows, []string{
					sr.ScenarioID,
					sr.OWASP,
					truncate(sr.Name, 40),
					sr.DetectionLayer,
				})
			}
		}

		sections = append(sections, pdf.Section{
			Kind:    pdf.SectionTable,
			Table:   pdf.Table{Rows: gapRows},
			Columns: []float64{70, 50, 220, 70},
		})
	}

	// --- Scenario Details ---
	if cfg.IncludeScenarioDetails {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionPageBreak,
		})

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: "Scenario Results",
		})

		detailRows := [][]string{
			{"ID", "OWASP", "Name", "Blocked", "Layer", "ML Score"},
		}

		for _, sr := range r.ScenarioResults {
			blocked := "No"
			if sr.Blocked {
				blocked = "Yes"
			}
			mlScore := "-"
			if sr.MLScore > 0 {
				mlScore = fmt.Sprintf("%.4f", sr.MLScore)
			}
			detailRows = append(detailRows, []string{
				sr.ScenarioID,
				sr.OWASP,
				truncate(sr.Name, 35),
				blocked,
				sr.DetectionLayer,
				mlScore,
			})
		}

		sections = append(sections, pdf.Section{
			Kind:    pdf.SectionTable,
			Table:   pdf.Table{Rows: detailRows},
			Columns: []float64{60, 45, 170, 50, 50, 55},
		})
	}

	return sections
}

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// sortStrings sorts a slice of strings in place.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Ensure strings import is used (for truncate fallback).
var _ = strings.TrimSpace
