// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Report CLI subcommand tests (D22)
//
// report_subcommand_test.go is a thin smoke test for the
// `aegisgate report pdf-from-report` CLI verb. D22 turned
// the previously-stubbed subcommand into a real reporter
// instantiation + ExportPDF call; this test verifies the
// CLI plumbing (flag parsing, exit codes, error messages).
//
// The real PDF generation is tested in pkg/reporting/doc_test.go;
// this file is concerned only with the CLI shell.

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestRunReportPDFFromReport_MissingID verifies that the
// subcommand exits 2 (usage error) when --id is not provided.
func TestRunReportPDFFromReport_MissingID(t *testing.T) {
	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	// Capture stdout too (the subcommand may print there).
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() { os.Stdout = oldStdout }()

	exit := runReportPDFFromReport([]string{})
	w.Close()
	wOut.Close()
	errBytes, _ := io.ReadAll(r)
	outBytes, _ := io.ReadAll(rOut)
	errStr := string(errBytes)
	_ = outBytes

	if exit != 2 {
		t.Errorf("expected exit code 2 for missing --id, got %d", exit)
	}
	if !strings.Contains(errStr, "--id is required") {
		t.Errorf("stderr should mention --id, got: %q", errStr)
	}
}

// TestRunReportPDFFromReport_NonexistentID verifies that the
// subcommand exits 1 (runtime error) when the report doesn't
// exist in the in-memory reporter.
func TestRunReportPDFFromReport_NonexistentID(t *testing.T) {
	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() { os.Stdout = oldStdout }()

	// Ephemeral in-memory reporter; the ID "nonexistent-id" is
	// not present, so ExportPDF returns "report not found".
	exit := runReportPDFFromReport([]string{"-id", "nonexistent-id-12345"})
	w.Close()
	wOut.Close()
	errBytes, _ := io.ReadAll(r)
	_ = rOut
	errStr := string(errBytes)

	if exit != 1 {
		t.Errorf("expected exit code 1 for non-existent report, got %d", exit)
	}
	if !strings.Contains(errStr, "export") {
		t.Errorf("stderr should mention export error, got: %q", errStr)
	}
}

// TestRunReportPDFFromReport_VerifyNotStubbed is a regression
// test for D22: the subcommand must NOT print the v0.1 stub
// message "not yet wired in v0.1". If this test fails, the
// stub has been re-introduced.
func TestRunReportPDFFromReport_VerifyNotStubbed(t *testing.T) {
	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() { os.Stdout = oldStdout }()

	// Trigger the non-existent-report path. The stub message
	// would appear here if the stub were re-introduced.
	_ = runReportPDFFromReport([]string{"-id", "stub-regression-test"})

	w.Close()
	wOut.Close()
	errBytes, _ := io.ReadAll(r)
	_ = rOut
	errStr := string(errBytes)

	if strings.Contains(errStr, "not yet wired in v0.1") {
		t.Errorf("stub message 'not yet wired in v0.1' detected - D22 fix has been reverted!")
	}
	if strings.Contains(errStr, "use 'report pdf --data-file' instead") {
		t.Errorf("stub redirect to 'report pdf --data-file' detected - D22 fix has been reverted!")
	}
}

// TestRunReportPDF_HappyPath is a smoke test for the working
// `report pdf` subcommand (the D22 work didn't touch this, but
// it's good to have as a baseline).
func TestRunReportPDF_HappyPath(t *testing.T) {
	// Capture stdout to verify the PDF bytes are written.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Empty data is valid (renders an empty PDF).
	exit := runReportPDF([]string{"-title", "Smoke Test"})

	w.Close()
	pdfBytes, _ := io.ReadAll(r)

	if exit != 0 {
		t.Errorf("expected exit 0, got %d", exit)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) {
		t.Errorf("output is not a valid PDF: %q", string(pdfBytes[:20]))
	}
}
