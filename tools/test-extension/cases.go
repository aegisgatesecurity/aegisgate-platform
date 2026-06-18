// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Test Case Loader
// =========================================================================
//
// cases.go loads the test cases from the Lens repo's
// test/ directory. Each test case is a JSON file of the form:
//
//   [
//     {
//       "input": "Email me at john.doe@example.com",
//       "expected_match": "john.doe@example.com",
//       "expected_category": "pii_email",
//       "expected_severity": "high",
//       "notes": "Standard email format"
//     },
//     ...
//   ]
//
// The harness iterates over the test cases, sets the prompt
// input to the test case's `input`, waits for the Lens to
// detect (or not detect), and asserts the expected outputs.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TestCase is a single test case from the Lens repo's
// test/ directory.
type TestCase struct {
	// Input is the synthetic prompt text. The harness
	// types this into the mock AI provider's prompt
	// textarea.
	Input string `json:"input"`

	// ExpectedMatch is the substring that the detector
	// should match (or null for false-positive cases).
	ExpectedMatch *string `json:"expected_match"`

	// ExpectedCategory is the Category enum value the
	// detector should produce (or null for false-positive
	// cases).
	ExpectedCategory *string `json:"expected_category"`

	// ExpectedSeverity is the Severity enum value the
	// detector should produce (or null for false-positive
	// cases).
	ExpectedSeverity *string `json:"expected_severity"`

	// Notes is a human-readable note about the test case.
	// Not used by the harness; included for documentation.
	Notes string `json:"notes"`
}

// loadCases loads all test cases from the Lens repo's
// test/ directory. We scan the directory for *.json files
// (rather than maintaining a hardcoded list of category
// names) so the harness is robust to new test categories
// being added in future versions of the Lens repo.
//
// The `provider` argument is currently unused but reserved
// for future provider-specific filtering.
func loadCases(testsDir, provider string) ([]TestCase, error) {
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, fmt.Errorf("read tests dir: %w", err)
	}
	var all []TestCase
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(testsDir, name) // #nosec G703 -- testsDir is a developer CLI arg
		data, err := os.ReadFile(path)        // #nosec G304 G703 -- testsDir is a developer CLI arg
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var cases []TestCase
		if err := json.Unmarshal(data, &cases); err != nil {
			// Skip files that aren't valid TestCase JSON
			// (e.g., README.json, package.json). The
			// failure is non-fatal because the harness is
			// robust to extra files in the test/ dir.
			_ = name // suppress unused warning
			continue
		}
		all = append(all, cases...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no test cases found in %s", testsDir)
	}
	return all, nil
}
