// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"context"
	"strings"
	"testing"
	"time"

	upstream "github.com/aegisgatesecurity/aegisgate/pkg/reporting"
)

// ---- NewReporter: error path (invalid StoragePath) ----

func TestPhase5_NewReporter_InvalidStoragePath(t *testing.T) {
	cfg := upstream.Config{
		MaxReportAge:    24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
		StoragePath:     "/nonexistent/path/that/does/not/exist/cannot/create",
	}
	_, err := NewReporter(cfg)
	if err == nil {
		t.Fatal("expected error for invalid storage path")
	}
	if !strings.Contains(err.Error(), "reporting:") {
		t.Errorf("error should be wrapped with 'reporting:', got: %v", err)
	}
}

// ---- ExportPDF: report not completed (queued status) ----

func TestPhase5_ExportPDF_ReportNotCompleted(t *testing.T) {
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	// Generate a report — it starts as "queued" then runs in a goroutine
	report, err := r.Reporter.Generate(upstream.ReportRequest{
		Type:      upstream.ReportTypeSummary,
		Format:    upstream.ReportFormatJSON,
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Immediately check — the report may still be "queued" or "running"
	// If it's already completed, we'll skip this test
	current, err := r.Reporter.GetReport(report.ID)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}

	if current.Status == upstream.ReportStatusCompleted {
		t.Skip("report completed too fast to test not-completed path")
	}

	_, err = r.ExportPDF(context.Background(), report.ID)
	if err == nil {
		t.Fatal("expected error for non-completed report")
	}
	if !strings.Contains(err.Error(), "not completed") {
		t.Errorf("error should mention 'not completed', got: %v", err)
	}
}

// ---- ExportPDF: happy path with completed report ----

func TestPhase5_ExportPDF_HappyPath(t *testing.T) {
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	// Generate a summary report
	report, err := r.Reporter.Generate(upstream.ReportRequest{
		Type:      upstream.ReportTypeSummary,
		Format:    upstream.ReportFormatJSON,
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Poll until completed (timeout after 5 seconds)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := r.Reporter.GetReport(report.ID)
		if err != nil {
			t.Fatalf("GetReport: %v", err)
		}
		if current.Status == upstream.ReportStatusCompleted {
			break
		}
		if current.Status == upstream.ReportStatusFailed {
			t.Fatalf("report generation failed: %s", current.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now export as PDF
	pdfBytes, err := r.ExportPDF(context.Background(), report.ID)
	if err != nil {
		t.Fatalf("ExportPDF: %v", err)
	}
	if len(pdfBytes) == 0 {
		t.Error("expected non-empty PDF bytes")
	}
	// Verify it starts with PDF magic
	if string(pdfBytes[:5]) != "%PDF-" {
		t.Errorf("expected PDF magic header, got: %q", string(pdfBytes[:5]))
	}
}

// ---- ExportPDF: report not found (existing test covers this but let's
// also test with a different ID format) ----

func TestPhase5_ExportPDF_NotFound(t *testing.T) {
	r, err := NewReporter(defaultTestConfig())
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	_, err = r.ExportPDF(context.Background(), "phase5-nonexistent-id")
	if err == nil {
		t.Fatal("expected error for non-existent report")
	}
}
