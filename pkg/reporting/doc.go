// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Platform-side Reporting wrapper (TODO-501)
//
// Package reporting wraps the upstream `pkg/reporting`
// package and adds platform-specific functionality:
//   - PDF rendering (via the local `pkg/pdf` package)
//   - Tier gating (PDF generation is free; no gate)
//   - Envelope signing of report artifacts
//     (TODO-601 in Tier 4; v0.1 of this package
//     does NOT sign — just generates the bytes)
//
// The wrapper is intentionally thin: the upstream
// `Reporter` does the heavy lifting (scheduling,
// persistence, status tracking, etc.). The wrapper
// only adds the PDF output format and any
// platform-specific glue.
//
// Why a wrapper and not a modification of the
// vendored upstream? The upstream `pkg/reporting` is
// vendored under `/upstream/` and is read-only. To
// add PDF support without modifying the vendored
// code, the platform's `pkg/reporting.Reporter`
// embeds the upstream `Reporter` and overrides the
// `Export()` method to add PDF support.

package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/pdf"
	upstream "github.com/aegisgatesecurity/aegisgate/pkg/reporting"
)

// =====================================================================
// Reporter
// =====================================================================

// Reporter is the platform-side reporting wrapper.
// It embeds the upstream `Reporter` to inherit
// scheduling, persistence, and status tracking, and
// overrides Export to add PDF support.
type Reporter struct {
	*upstream.Reporter
}

// NewReporter creates a new platform-side reporter.
// Wraps the upstream `New` constructor.
func NewReporter(cfg upstream.Config) (*Reporter, error) {
	r, err := upstream.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("reporting: New: %w", err)
	}
	return &Reporter{Reporter: r}, nil
}

// =====================================================================
// PDF export
// =====================================================================

// ExportPDF generates a PDF report for the given
// report ID. The PDF bytes are returned to the
// caller; the upstream `Reporter` is responsible
// for the underlying data (no data is duplicated).
//
// This is the platform's PDF addition to the upstream
// API. The flow:
//  1. Get the report (data + metadata) from the
//     upstream.
//  2. Build a PDF RenderRequest from the report's
//     metadata.
//  3. Build PDF sections from the report's Data
//     (using `pdf.BuildReportFromData`).
//  4. Render the PDF to bytes.
//
// Errors:
//   - reportID is empty
//   - the upstream report is not found
//   - the report's status is not "completed"
//   - the PDF renderer fails
func (r *Reporter) ExportPDF(ctx context.Context, reportID string) ([]byte, error) {
	if reportID == "" {
		return nil, fmt.Errorf("reporting: reportID is required")
	}
	// Get the report from the upstream.
	report, err := r.GetReport(reportID)
	if err != nil {
		return nil, fmt.Errorf("reporting: get report: %w", err)
	}
	// Only completed reports can be exported.
	if report.Status != upstream.ReportStatusCompleted {
		return nil, fmt.Errorf("reporting: report %s is not completed (status: %s)", reportID, report.Status)
	}
	// Build the PDF request.
	req := &pdf.RenderRequest{
		Title:       fmt.Sprintf("AegisGate Report %s", report.ID),
		Author:      "AegisGate Platform",
		Subject:     string(report.Type),
		Keywords:    "aegisgate, security, report",
		Footer:      fmt.Sprintf("Generated %s", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
		GeneratedAt: report.Completed,
		Sections:    pdf.BuildReportFromData("", string(report.Type), report.Data),
	}
	return pdf.RenderReport(req)
}

// ExportPDFAdHoc generates a PDF report directly
// from a title and data, bypassing the upstream
// reporter's scheduling and persistence. Useful
// for one-off PDF exports (e.g., from the CLI
// "aegisgate report pdf" verb).
func ExportPDFAdHoc(title string, data interface{}) ([]byte, error) {
	req := &pdf.RenderRequest{
		Title:    title,
		Author:   "AegisGate Platform",
		Footer:   fmt.Sprintf("Generated %s", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
		Sections: pdf.BuildReportFromData("", "", data),
	}
	return pdf.RenderReport(req)
}
