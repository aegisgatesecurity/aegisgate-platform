// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Platform-side Reporting wrapper tests (TODO-501)
//
// doc_test.go covers the platform-side Reporter
// wrapper and the ad-hoc PDF export. The tests
// are minimal (the heavy lifting is in pkg/pdf);
// the wrapper just delegates.

package reporting

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/pdf"
	upstream "github.com/aegisgatesecurity/aegisgate/pkg/reporting"
)

func TestExportPDFAdHoc_HappyPath(t *testing.T) {
	data := [][]string{
		{"Header A", "Header B"},
		{"value 1", "value 2"},
	}
	pdfBytes, err := ExportPDFAdHoc("Ad-hoc Test", data)
	if err != nil {
		t.Fatalf("ExportPDFAdHoc: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) {
		t.Errorf("Output is not a valid PDF")
	}
}

func TestExportPDFAdHoc_MapData(t *testing.T) {
	data := map[string]interface{}{
		"name":  "Test",
		"count": 42,
	}
	pdfBytes, err := ExportPDFAdHoc("Map Data Test", data)
	if err != nil {
		t.Fatalf("ExportPDFAdHoc: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) {
		t.Errorf("Output is not a valid PDF")
	}
}

func TestExportPDFAdHoc_EmptyTitle(t *testing.T) {
	// An empty title is a validation error in the PDF
	// renderer. The wrapper propagates the error.
	_, err := ExportPDFAdHoc("", []string{"data"})
	if err == nil {
		t.Errorf("ExportPDFAdHoc with empty title should fail")
	}
	if !strings.Contains(err.Error(), "Title") {
		t.Errorf("Error should mention 'Title', got: %v", err)
	}
}

func TestNewReporter_DefaultConfig(t *testing.T) {
	// Just ensure NewReporter can be called with a
	// minimal config. We don't actually start the
	// scheduler (that would require a separate
	// goroutine management in tests).
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	if r == nil {
		t.Errorf("Reporter is nil")
	}
	if r.Reporter == nil {
		t.Errorf("Embedded upstream Reporter is nil")
	}
}

func TestExportPDF_EmptyReportID(t *testing.T) {
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	_, err = r.ExportPDF(context.Background(), "")
	if err == nil {
		t.Errorf("ExportPDF with empty reportID should fail")
	}
	if !strings.Contains(err.Error(), "reportID") {
		t.Errorf("Error should mention 'reportID', got: %v", err)
	}
}

func TestExportPDF_ReportNotFound(t *testing.T) {
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	_, err = r.ExportPDF(context.Background(), "nonexistent-id")
	if err == nil {
		t.Errorf("ExportPDF with non-existent ID should fail")
	}
}

// defaultTestConfig returns a minimal upstream Config
// suitable for tests. The StoragePath is empty (no
// persistence), and the cleanup interval is long
// (tests don't run long enough for cleanup to fire).
func defaultTestConfig() upstream.Config {
	return upstream.Config{
		MaxReportAge:    24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
		StoragePath:     "", // no persistence
	}
}

// ============================================================================
// Integration: full roundtrip via BuildReportFromData
// ============================================================================

func TestIntegration_PDFRendererFromReportingWrapper(t *testing.T) {
	// Simulate a report's data shape (a summary report
	// is a map[string]interface{} in the upstream).
	reportData := map[string]interface{}{
		"total_events":  1234,
		"threats_found": 5,
		"iocs_blocked":  42,
		"uptime_pct":    99.97,
	}
	pdfBytes, err := ExportPDFAdHoc("Daily Summary", reportData)
	if err != nil {
		t.Fatalf("ExportPDFAdHoc: %v", err)
	}
	// Verify the PDF is valid.
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) {
		t.Errorf("Output is not a valid PDF")
	}
	// The wrapper sets a "Generated <timestamp>" footer.
	// The PDF should be valid; we don't assert on the
	// specific footer text (it includes the current
	// time, which would require clock injection to
	// assert deterministically).
}

// ============================================================================
// End-to-end: render the same data through pdf.RenderReport
// to confirm parity with the wrapper.
// ============================================================================

func TestParity_WrapperVsDirect(t *testing.T) {
	data := [][]string{
		{"A", "B"},
		{"1", "2"},
	}
	// Via wrapper.
	wrapperBytes, err := ExportPDFAdHoc("Parity Test", data)
	if err != nil {
		t.Fatalf("ExportPDFAdHoc: %v", err)
	}
	// Via direct call.
	directReq := &pdf.RenderRequest{
		Title:    "Parity Test",
		Sections: pdf.BuildReportFromData("", "", data),
		Footer:   "Generated " + pdfFormatTimeForParity(),
	}
	directBytes, err := pdf.RenderReport(directReq)
	if err != nil {
		t.Fatalf("pdf.RenderReport: %v", err)
	}
	// Both should have the same magic header.
	if !bytes.HasPrefix(wrapperBytes, []byte("%PDF-1.4")) {
		t.Errorf("Wrapper output is not a valid PDF")
	}
	if !bytes.HasPrefix(directBytes, []byte("%PDF-1.4")) {
		t.Errorf("Direct output is not a valid PDF")
	}
	// Both should have the same number of pages.
	wrapperPages := bytes.Count(wrapperBytes, []byte("/Type /Page "))
	directPages := bytes.Count(directBytes, []byte("/Type /Page "))
	if wrapperPages != directPages {
		t.Errorf("Page count mismatch: wrapper=%d, direct=%d", wrapperPages, directPages)
	}
}

// pdfFormatTimeForParity returns a fixed timestamp
// for parity tests (the wrapper and direct call
// should both embed "AegisGate Platform" in the
// footer regardless of the exact time).
func pdfFormatTimeForParity() string {
	return "TEST"
}
