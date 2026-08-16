// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Reporting CLI subcommand (TODO-501)
//
// report_subcommand.go wires pkg/reporting into the
// CLI binary as:
//   - aegisgate report pdf --title=... --data-file=...
//   - aegisgate report pdf-from-report --id=...
//
// Tier gating: PDF generation is FREE (no gate). It
// is a utility, not a tier-gated feature.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/reporting"
	upstream "github.com/aegisgatesecurity/aegisgate/pkg/reporting"
)

// runReportSubcommand implements the "aegisgate
// report" CLI subcommand.
func runReportSubcommand(args []string) {
	if len(args) == 0 {
		reportUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "pdf":
		exitCode = runReportPDF(rest)
	case "pdf-from-report":
		exitCode = runReportPDFFromReport(rest)
	case "-help", "--help", "help":
		reportUsage()
	default:
		fmt.Fprintf(os.Stderr, "report: unknown verb %q\n", verb)
		reportUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// reportUsage prints the help text.
func reportUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate report — Reporting (TODO-501)

Usage:
  aegisgate report pdf --title=TITLE [--data-file=FILE]
  aegisgate report pdf-from-report --id=REPORT_ID [--out=FILE]

Flags (pdf):
  --title          the PDF title (REQUIRED)
  --data-file      JSON file containing the data to render
                   (the data shape determines the PDF layout)
  --out            write the PDF to this file (default: stdout)

Flags (pdf-from-report):
  --id             the upstream report ID (REQUIRED)
  --out            write the PDF to this file (default: stdout)

Examples:
  # Render an ad-hoc PDF from a JSON data file
  aegisgate report pdf --title="Daily Summary" --data-file=summary.json

  # Render a PDF from a previously generated upstream report
  aegisgate report pdf-from-report --id=abc-123
`)
}

// runReportPDF is the implementation of
// "aegisgate report pdf". Reads a JSON data file and
// renders it to a PDF.
func runReportPDF(args []string) int {
	fs := flag.NewFlagSet("report pdf", flag.ExitOnError)
	title := fs.String("title", "", "the PDF title (REQUIRED)")
	dataFile := fs.String("data-file", "", "JSON file containing the data to render")
	outFile := fs.String("out", "", "write the PDF to this file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *title == "" {
		fmt.Fprintf(os.Stderr, "report pdf: --title is required\n")
		return 2
	}
	var data interface{}
	if *dataFile != "" {
		raw, err := os.ReadFile(*dataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report pdf: read data file: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			fmt.Fprintf(os.Stderr, "report pdf: parse data file: %v\n", err)
			return 1
		}
	}
	pdfBytes, err := reporting.ExportPDFAdHoc(*title, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report pdf: %v\n", err)
		return 1
	}
	return writePDF(*outFile, pdfBytes)
}

// runReportPDFFromReport is the implementation of
// "aegisgate report pdf-from-report". Fetches a
// previously generated upstream report and renders
// it to a PDF.
//
// D22: implements the previously-unwired subcommand.
// Instantiates an ephemeral reporter (no persistence)
// and calls ExportPDF on the requested reportID.
// Requires the report to be in "completed" status
// (the Reporter.ExportPDF method enforces this).
func runReportPDFFromReport(args []string) int {
	fs := flag.NewFlagSet("report pdf-from-report", flag.ExitOnError)
	reportID := fs.String("id", "", "the upstream report ID (REQUIRED)")
	outFile := fs.String("out", "", "write the PDF to this file (default: stdout)")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout for report fetch + PDF render")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *reportID == "" {
		fmt.Fprintf(os.Stderr, "report pdf-from-report: --id is required\n")
		return 2
	}
	// Ephemeral reporter: no persistence (StoragePath=""), no
	// scheduler, in-memory only. This is sufficient for the
	// one-shot "render a previously-generated report" use case.
	reporter, err := reporting.NewReporter(upstream.Config{
		StoragePath:     "", // in-memory
		MaxConcurrent:   1,
		EnableScheduler: false,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "report pdf-from-report: new reporter: %v\n", err)
		return 1
	}
	// Render with a bounded context.
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	pdfBytes, err := reporter.ExportPDF(ctx, *reportID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report pdf-from-report: export: %v\n", err)
		return 1
	}
	return writePDF(*outFile, pdfBytes)
}

// writePDF writes the PDF bytes to a file or stdout.
func writePDF(outFile string, pdfBytes []byte) int {
	if outFile == "" {
		if _, err := os.Stdout.Write(pdfBytes); err != nil {
			fmt.Fprintf(os.Stderr, "report: write stdout: %v\n", err)
			return 1
		}
		return 0
	}
	if err := os.WriteFile(outFile, pdfBytes, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "report: write file: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Wrote %d bytes to %s\n", len(pdfBytes), outFile)
	return 0
}

// isReportSubcommand returns true if args look like the
// "aegisgate report" subcommand.
func isReportSubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "report"
}

// stripReportSubcommand removes the "report" prefix
// from args.
func stripReportSubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the report subcommand detection hook.
func init() {
	if isReportSubcommand(os.Args[1:]) {
		args := stripReportSubcommand(os.Args[1:])
		runReportSubcommand(args)
		// Unreachable: runReportSubcommand calls os.Exit.
	}
}
