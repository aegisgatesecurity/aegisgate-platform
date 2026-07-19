// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Test Runner
// =========================================================================
//
// runner.go orchestrates the test run. For each test case:
//   1. Set the prompt textarea's value to the case's input.
//   2. Wait for the Lens's content script to evaluate the
//      detection logic (a short sleep, since the script is
//      synchronous).
//   3. Read the detection results from the page (the Lens
//      exposes its detection state via a global window var).
//   4. Assert the expected outputs.
//
// The Lens's content script writes a window.__lens_detections
// global array with the current detections. The harness
// reads this via Runtime.evaluate.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// lensDetection matches the Detection interface in
// src/detectors/index.ts.
type lensDetection struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Pattern  string `json:"pattern"`
}

// runTests runs all the test cases against the live Lens
// extension and returns a TestReport.
func runTests(cdp *devtoolsClient, cfg *Config, cases []TestCase) (*TestReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*time.Duration(len(cases)))
	defer cancel()
	report := &TestReport{
		Provider: cfg.Provider,
		Total:    len(cases),
		Results:  make([]TestResult, 0, len(cases)),
	}
	for i, c := range cases {
		result := runOneTest(ctx, cdp, cfg, c)
		report.Results = append(report.Results, result)
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[%d/%d] %s\n", i+1, len(cases), result.Summary())
		}
	}
	return report, nil
}

// runOneTest runs a single test case and returns the result.
func runOneTest(ctx context.Context, cdp *devtoolsClient, cfg *Config, c TestCase) TestResult {
	// Step 1: Set the prompt input's value to the case's input.
	// Use querySelector (not getElementById) so that the
	// same expression works for both id selectors
	// ("prompt-textarea") and attribute selectors
	// ("div[contenteditable='true']" for claude/gemini).
	setExpr := fmt.Sprintf(`
		(() => {
			const el = document.querySelector(%q);
			if (!el) return false;
			// Handle both <textarea>/<input> (use .value) and
			// contenteditable <div> (use .innerText). The original
			// test ext hardcoded .value which silently no-op'd on
			// contenteditable elements (claude, gemini, duck.ai,
			// grok.com) — causing 13/18 false failures on those
			// providers. See REAL-VERIFICATION-2026-07-03.md.
			var isContentEditable = (el.contentEditable === 'true' ||
			                          el.isContentEditable === true);
			if (isContentEditable) {
				// Set innerText (preserves newlines) and dispatch
				// input + change events so the Lens's listener fires.
				el.innerText = %q;
				el.dispatchEvent(new Event('input', { bubbles: true }));
				el.dispatchEvent(new Event('change', { bubbles: true }));
			} else {
				el.value = %q;
				el.dispatchEvent(new Event('input', { bubbles: true }));
				el.dispatchEvent(new Event('change', { bubbles: true }));
			}
			return true;
		})()
	`, promptSelector(cfg.Provider), c.Input, c.Input)
	setResult, err := cdp.evaluate(ctx, setExpr)
	if err != nil {
		return TestResult{
			Input:          c.Input,
			ExpectedMatch:  c.ExpectedMatch,
			ExpectedCat:    c.ExpectedCategory,
			ExpectedSev:    c.ExpectedSeverity,
			Passed:         false,
			FailureMessage: fmt.Sprintf("set input: %v", err),
		}
	}
	// json.RawMessage is a []byte. If the result is `false`
	// (a JS boolean), the byte slice is the JSON "false" (5 bytes).
	if string(setResult) == "false" {
		return TestResult{
			Input:          c.Input,
			ExpectedMatch:  c.ExpectedMatch,
			ExpectedCat:    c.ExpectedCategory,
			ExpectedSev:    c.ExpectedSeverity,
			Passed:         false,
			FailureMessage: "prompt textarea not found",
		}
	}

	// Step 2: Wait for the detection to run. The Lens's
	// content script runs synchronously on the 'input'
	// event, so a 50ms sleep is more than enough.
	time.Sleep(50 * time.Millisecond)

	// Step 3: Read the detection results.
	getExpr := `window.__lens_detections || []`
	getResult, err := cdp.evaluate(ctx, getExpr)
	detections, err := parseDetections(getResult)
	if err != nil {
		return TestResult{
			Input:          c.Input,
			ExpectedMatch:  c.ExpectedMatch,
			ExpectedCat:    c.ExpectedCategory,
			ExpectedSev:    c.ExpectedSeverity,
			Passed:         false,
			FailureMessage: fmt.Sprintf("parse detections: %v", err),
		}
	}

	// Step 4: Assert the expected outputs.
	return assertDetections(c, detections)
}

// parseDetections converts the CDP result (a Runtime.evaluate
// RemoteObject JSON wrapper) into []lensDetection.
//
// CDP's Runtime.evaluate returns a RemoteObject with this shape:
//
//	{
//	  "type": "object",
//	  "subtype": "array",
//	  "className": "Array",
//	  "value": [ ... actual array ... ],
//	  "description": "Array(N)"
//	}
//
// When returnByValue is true, the .value field contains the
// JSON-serialized return value. The original implementation
// (Bug C) tried to unmarshal the whole RemoteObject as the
// array, which fails for objects and arrays alike.
//
// This implementation extracts .value first, then unmarshals
// the inner array. Falls back to treating the raw input as a
// bare array (for direct callers that pass the array directly,
// which is what the unit tests do).
func parseDetections(raw json.RawMessage) ([]lensDetection, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// CDP's Runtime.evaluate response is double-wrapped:
	//   {
	//     "result": {           <-- outer cdpResponse.Result
	//       "type": "object",
	//       "value": [ ... ]    <-- the actual array (RemoteObject.value)
	//     }
	//   }
	// We need to extract result.value to get the array.
	var outer struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer.Result) == 0 {
		// Fallback: input might be a bare array or unwrapped RemoteObject.
		return parseDetectionsFallback(raw)
	}
	// Now parse the RemoteObject: { type, value, ... }
	var remoteObj struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(outer.Result, &remoteObj); err != nil || len(remoteObj.Value) == 0 {
		// RemoteObject didn't have a .value field. Try parsing result directly.
		return parseDetectionsFallback(outer.Result)
	}
	var dets []lensDetection
	if err := json.Unmarshal(remoteObj.Value, &dets); err != nil {
		return nil, err
	}
	return dets, nil
}

// parseDetectionsFallback tries to parse the raw input as either a
// bare JSON array (legacy call shape) or an unwrapped RemoteObject
// (in case the cdpResponse layer is absent in some test paths).
func parseDetectionsFallback(raw json.RawMessage) ([]lensDetection, error) {
	// Try as a bare array first.
	var dets []lensDetection
	if err := json.Unmarshal(raw, &dets); err == nil {
		return dets, nil
	}
	// Try as a RemoteObject (no cdpResponse wrapper).
	var remoteObj struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &remoteObj); err == nil && len(remoteObj.Value) > 0 {
		return dets, json.Unmarshal(remoteObj.Value, &dets)
	}
	return nil, fmt.Errorf("parseDetections: cannot extract detections array from %q", string(raw))
}

// assertDetections checks the actual detections against the
// expected outputs. Returns a TestResult.
func assertDetections(c TestCase, actual []lensDetection) TestResult {
	result := TestResult{
		Input:         c.Input,
		ActualDets:    actual,
		ExpectedMatch: c.ExpectedMatch,
		ExpectedCat:   c.ExpectedCategory,
		ExpectedSev:   c.ExpectedSeverity,
		Passed:        true,
	}
	// False-positive case: no detection expected.
	if c.ExpectedMatch == nil || *c.ExpectedMatch == "" {
		if len(actual) > 0 {
			result.Passed = false
			result.FailureMessage = fmt.Sprintf("expected no detection, got %d", len(actual))
		}
		return result
	}
	// Positive case: at least one detection must match
	// the expected match, category, and severity.
	for _, d := range actual {
		if d.Match == *c.ExpectedMatch &&
			(c.ExpectedCategory == nil || d.Category == *c.ExpectedCategory) &&
			(c.ExpectedSeverity == nil || d.Severity == *c.ExpectedSeverity) {
			return result
		}
	}
	// No matching detection found.
	result.Passed = false
	result.FailureMessage = fmt.Sprintf(
		"no detection matched (expected match=%q category=%v severity=%v, got %d detection(s))",
		*c.ExpectedMatch, strPtr(c.ExpectedCategory), strPtr(c.ExpectedSeverity), len(actual),
	)
	return result
}

// strPtr is a tiny helper to format a *string for printing.
func strPtr(s *string) string {
	if s == nil {
		return "<any>"
	}
	return *s
}

// promptSelector returns the CSS selector for the prompt
// input for the given AI provider. The selectors match the
// ones in src/content.ts. The returned selector is suitable
// for use with document.querySelector (so id selectors are
// prefixed with #, and attribute selectors are unchanged).
func promptSelector(provider string) string {
	switch provider {
	case "chatgpt", "chat-openai":
		return "#prompt-textarea" // id selector
	case "claude", "gemini", "duck", "grok":
		return "div[contenteditable='true']"
	case "copilot":
		return "#userInput" // id selector
	case "perplexity", "duckduckgo":
		return "textarea[id*=\"user-input\"]" // attribute selector
	case "x":
		return "#prompt-textarea" // x.com uses ChatGPT-style prompt
	}
	return "#prompt-textarea" // default
}

// TestReport is the top-level result of a test run.
type TestReport struct {
	Provider string       `json:"provider"`
	Total    int          `json:"total"`
	Passed   int          `json:"passed"`
	Failed   int          `json:"failed"`
	Results  []TestResult `json:"results"`
}

// TestResult is the result of running a single test case.
type TestResult struct {
	Input          string          `json:"input"`
	ActualDets     []lensDetection `json:"actual_detections,omitempty"`
	ExpectedMatch  *string         `json:"expected_match,omitempty"`
	ExpectedCat    *string         `json:"expected_category,omitempty"`
	ExpectedSev    *string         `json:"expected_severity,omitempty"`
	Passed         bool            `json:"passed"`
	FailureMessage string          `json:"failure_message,omitempty"`
}

// Summary returns a one-line summary of the result.
func (r TestResult) Summary() string {
	if r.Passed {
		return fmt.Sprintf("PASS: %s", truncate(r.Input, 60))
	}
	return fmt.Sprintf("FAIL: %s -- %s", truncate(r.Input, 40), r.FailureMessage)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
