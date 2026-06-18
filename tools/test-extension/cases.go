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

// loadCases loads the test cases for the given provider
// from the Lens repo's test/ directory. The file path is
//
//	<tests>/<category>.json
//
// The lens schema is that each test file contains an array
// of TestCase objects, one per scenario.
func loadCases(testsDir, provider string) ([]TestCase, error) {
	var all []TestCase
	// The test files in the Lens repo are named by
	// category: pii_email.json, pii_credit_card.json, etc.
	// We load all of them.
	categories := []string{
		"pii_email",
		"pii_phone",
		"pii_ssn",
		"pii_credit_card",
		"secret_api_key",
		"source_code",
		"false_positives",
	}
	for _, cat := range categories {
		path := filepath.Join(testsDir, cat+".json")
		data, err := os.ReadFile(path) // #nosec G304 -- testsDir is a developer CLI arg
		if err != nil {
			if os.IsNotExist(err) {
				// Missing test file is not fatal; skip.
				continue
			}
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var cases []TestCase
		if err := json.Unmarshal(data, &cases); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		all = append(all, cases...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no test cases found in %s", testsDir)
	}
	return all, nil
}
