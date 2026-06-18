// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Test Report Emitter
// =========================================================================
//
// report.go writes the test report to a JSON file and prints
// a human-readable summary to stdout.
//
// Output format (JSON):
//
//   {
//     "provider": "chatgpt",
//     "total": 14,
//     "passed": 12,
//     "failed": 2,
//     "results": [
//       {
//         "input": "Email me at john.doe@example.com",
//         "expected_match": "john.doe@example.com",
//         "expected_category": "pii_email",
//         "expected_severity": "high",
//         "passed": true,
//         "actual_detections": [
//           {
//             "category": "pii_email",
//             "severity": "high",
//             "match": "john.doe@example.com",
//             "start": 13,
//             "end": 33,
//             "pattern": "email_v1"
//           }
//         ]
//       },
//       ...
//     ]
//   }
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// emitReport writes the test report to the configured output
// path and prints a human-readable summary to stderr.
func emitReport(cfg *Config, report *TestReport) error {
	// JSON output.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(cfg.Output, data, 0o644); err != nil { // #nosec G304 G306 -- output path is a developer CLI arg, build artifact
		return fmt.Errorf("write report: %w", err)
	}
	// Human-readable summary to stderr.
	fmt.Fprintf(os.Stderr, "\n=== AegisGate Lens test report ===\n")
	fmt.Fprintf(os.Stderr, "Provider: %s\n", report.Provider)
	fmt.Fprintf(os.Stderr, "Total:    %d\n", report.Total)
	fmt.Fprintf(os.Stderr, "Passed:   %d\n", report.Passed)
	fmt.Fprintf(os.Stderr, "Failed:   %d\n", report.Failed)
	fmt.Fprintf(os.Stderr, "Report:   %s\n", cfg.Output)
	if report.Failed > 0 {
		fmt.Fprintf(os.Stderr, "\nFailures:\n")
		for _, r := range report.Results {
			if !r.Passed {
				fmt.Fprintf(os.Stderr, "  - %s\n", r.Summary())
			}
		}
	}
	return nil
}
