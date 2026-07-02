// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Unit Tests
// =========================================================================
//
// Unit tests for the test harness itself. These tests do NOT
// require a running Chromium instance; they test the
// non-network parts of the harness.
//
// Tests:
//   - TestParseArgs: CLI flag parsing
//   - TestValidateInputs: input validation
//   - TestAssertDetections: the detection-matching logic
//   - TestLoadCases: the test case loader
//   - TestEmitReport: the report emitter
//   - TestParseDetections: JSON parsing of detection arrays
//   - TestPromptSelector: provider-specific CSS selector
//   - TestFindPortFromArgs: --remote-debugging-port extraction
//   - TestTruncate: string truncation helper
//   - TestStrPtr: nil-safe string pointer
//
// Network-dependent code (chromium, CDP, WebSocket) is NOT
// unit-tested here; it's covered by the integration tests
// that require a real Chromium instance.
//
// Run: go test -race ./tools/test-extension/...
// =========================================================================

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgs_Required(t *testing.T) {
	_, err := parseArgs([]string{})
	if err == nil {
		t.Error("expected error for missing required flags")
	}
}

func TestParseArgs_Valid(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--dist", "/tmp/lens-dist",
		"--tests", "/tmp/lens-tests",
		"--provider", "claude",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.Dist != "/tmp/lens-dist" {
		t.Errorf("Dist = %q", cfg.Dist)
	}
	if cfg.Tests != "/tmp/lens-tests" {
		t.Errorf("Tests = %q", cfg.Tests)
	}
	if cfg.Provider != "claude" {
		t.Errorf("Provider = %q", cfg.Provider)
	}
}

func TestParseArgs_Defaults(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--dist", "/tmp/lens-dist",
		"--tests", "/tmp/lens-tests",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.Provider != "chatgpt" {
		t.Errorf("default Provider = %q, want chatgpt", cfg.Provider)
	}
	if cfg.Port != 9222 {
		t.Errorf("default Port = %d, want 9222", cfg.Port)
	}
	if cfg.Output != "./test-report.json" {
		t.Errorf("default Output = %q", cfg.Output)
	}
}

func TestValidateInputs_DistMissing(t *testing.T) {
	cfg := &Config{
		Dist:     "/nonexistent/path/that/does/not/exist",
		Tests:    ".",
		Provider: "chatgpt",
	}
	if err := validateInputs(cfg); err == nil {
		t.Error("expected error for missing dist directory")
	}
}

func TestValidateInputs_TestsMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		Dist:     dir,
		Tests:    "/nonexistent/tests",
		Provider: "chatgpt",
	}
	if err := validateInputs(cfg); err == nil {
		t.Error("expected error for missing tests directory")
	}
}

func TestValidateInputs_MissingFile(t *testing.T) {
	// Both dirs exist but missing required dist files.
	dist := t.TempDir()
	tests := t.TempDir()
	cfg := &Config{
		Dist:     dist,
		Tests:    tests,
		Provider: "chatgpt",
	}
	if err := validateInputs(cfg); err == nil {
		t.Error("expected error for missing required dist file")
	}
}

func TestAssertDetections_PositiveMatch(t *testing.T) {
	match := "john.doe@example.com"
	cat := "pii_email"
	sev := "high"
	c := TestCase{
		Input:            "Email me at john.doe@example.com",
		ExpectedMatch:    &match,
		ExpectedCategory: &cat,
		ExpectedSeverity: &sev,
	}
	actual := []lensDetection{
		{Category: "pii_email", Severity: "high", Match: "john.doe@example.com", Start: 13, End: 33, Pattern: "email_v1"},
	}
	result := assertDetections(c, actual)
	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.FailureMessage)
	}
}

func TestAssertDetections_PositiveNoMatch(t *testing.T) {
	match := "john.doe@example.com"
	cat := "pii_email"
	c := TestCase{
		Input:            "Email me at john.doe@example.com",
		ExpectedMatch:    &match,
		ExpectedCategory: &cat,
	}
	actual := []lensDetection{
		{Category: "pii_phone", Severity: "high", Match: "555-1234", Start: 0, End: 8, Pattern: "phone_v1"},
	}
	result := assertDetections(c, actual)
	if result.Passed {
		t.Error("expected fail (no matching detection)")
	}
}

func TestAssertDetections_FalsePositive(t *testing.T) {
	// expected_match is null -> no detection expected.
	c := TestCase{
		Input:         "The weather is nice today",
		ExpectedMatch: nil,
	}
	actual := []lensDetection{}
	result := assertDetections(c, actual)
	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.FailureMessage)
	}
}

func TestAssertDetections_FalsePositiveGotDetection(t *testing.T) {
	c := TestCase{
		Input:         "The weather is nice today",
		ExpectedMatch: nil,
	}
	actual := []lensDetection{
		{Category: "pii_email", Severity: "high", Match: "x@y.com", Start: 0, End: 7, Pattern: "email_v1"},
	}
	result := assertDetections(c, actual)
	if result.Passed {
		t.Error("expected fail (got detection on a false-positive case)")
	}
}

func TestLoadCases_Valid(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal test file.
	piiEmail := `[{"input":"test","expected_match":"x","expected_category":"pii_email","expected_severity":"high"}]`
	if err := os.WriteFile(filepath.Join(dir, "pii_email.json"), []byte(piiEmail), 0o644); err != nil {
		t.Fatal(err)
	}
	cases, err := loadCases(dir, "chatgpt")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 {
		t.Errorf("len(cases) = %d, want 1", len(cases))
	}
}

func TestLoadCases_NoFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := loadCases(dir, "chatgpt")
	if err == nil {
		t.Error("expected error when no test files exist")
	}
}

func TestLoadCases_Malformed(t *testing.T) {
	// Malformed JSON files are now silently skipped (the
	// harness is robust to extra files in the test/ dir).
	// This test verifies that a malformed file does NOT
	// cause the loader to fail.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pii_email.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Add a valid file so the loader has at least one case.
	if err := os.WriteFile(filepath.Join(dir, "pii_phone.json"),
		[]byte(`[{"input":"x","expected_match":"y","expected_category":"pii_phone","expected_severity":"high"}]`),
		0o644); err != nil {
		t.Fatal(err)
	}
	cases, err := loadCases(dir, "chatgpt")
	if err != nil {
		t.Errorf("loadCases should not fail on malformed files, got: %v", err)
	}
	if len(cases) != 1 {
		t.Errorf("len(cases) = %d, want 1 (only the valid file should load)", len(cases))
	}
}

func TestParseDetections_Empty(t *testing.T) {
	dets, err := parseDetections(nil)
	if err != nil {
		t.Errorf("parseDetections(nil): %v", err)
	}
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0", len(dets))
	}
}

func TestParseDetections_Valid(t *testing.T) {
	raw := json.RawMessage(`[{"category":"pii_email","severity":"high","match":"x@y.z","start":0,"end":5,"pattern":"email_v1"}]`)
	dets, err := parseDetections(raw)
	if err != nil {
		t.Fatalf("parseDetections: %v", err)
	}
	if len(dets) != 1 {
		t.Fatalf("len(dets) = %d, want 1", len(dets))
	}
	if dets[0].Match != "x@y.z" {
		t.Errorf("Match = %q", dets[0].Match)
	}
}

func TestPromptSelector_AllProviders(t *testing.T) {
	cases := map[string]string{
		"chatgpt": "#prompt-textarea",
		"claude":  "div[contenteditable='true']",
		"gemini":  "div[contenteditable='true']",
		"copilot": "#userInput",
		"unknown": "#prompt-textarea", // default
	}
	for provider, expected := range cases {
		got := promptSelector(provider)
		if got != expected {
			t.Errorf("promptSelector(%q) = %q, want %q", provider, got, expected)
		}
	}
}

func TestFindPortFromArgs(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{[]string{"--remote-debugging-port=9222"}, 9222},
		{[]string{"--remote-debugging-port", "9333"}, 9333},
		{[]string{}, 9222},             // default
		{[]string{"--headless"}, 9222}, // port not specified
	}
	for _, tc := range tests {
		got := findPortFromArgs(tc.args)
		if got != tc.want {
			t.Errorf("findPortFromArgs(%v) = %d, want %d", tc.args, got, tc.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"abc", 5, "abc"},
		{"", 5, ""},
	}
	for _, tc := range cases {
		got := truncate(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestStrPtr(t *testing.T) {
	if strPtr(nil) != "<any>" {
		t.Error("strPtr(nil) should be <any>")
	}
	s := "hello"
	if strPtr(&s) != "hello" {
		t.Error("strPtr(&hello) should be hello")
	}
}

func TestFileURL(t *testing.T) {
	url, err := fileURL("testdata/chatgpt.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "file://") {
		t.Errorf("fileURL did not produce a file:// URL: %q", url)
	}
}

func TestEmitReport_Valid(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		Output:  filepath.Join(dir, "report.json"),
		Verbose: false,
	}
	report := &TestReport{
		Provider: "chatgpt",
		Total:    1,
		Passed:   1,
		Failed:   0,
		Results: []TestResult{
			{Input: "test", Passed: true},
		},
	}
	if err := emitReport(cfg, report); err != nil {
		t.Fatal(err)
	}
	// Verify the file was written.
	data, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "chatgpt") {
		t.Error("report does not contain provider name")
	}
}

func TestEmitReport_Failures(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		Output: filepath.Join(dir, "report.json"),
	}
	report := &TestReport{
		Provider: "chatgpt",
		Total:    2,
		Passed:   1,
		Failed:   1,
		Results: []TestResult{
			{Input: "pass", Passed: true},
			{Input: "fail", Passed: false, FailureMessage: "no match"},
		},
	}
	if err := emitReport(cfg, report); err != nil {
		t.Fatal(err)
	}
}

func TestWrapScriptForTest(t *testing.T) {
	script := "console.log('hello');"
	wrapped := wrapScriptForTest(script)
	// The wrapped script may have a leading newline.
	trimmed := strings.TrimSpace(wrapped)
	if !strings.HasPrefix(trimmed, "(function()") {
		t.Errorf("wrapped script should start with IIFE, got %q", trimmed[:50])
	}
	if !strings.Contains(wrapped, "window.__lens_detections") {
		t.Error("wrapped script should set window.__lens_detections")
	}
	if !strings.Contains(wrapped, script) {
		t.Error("wrapped script should contain the original script")
	}
}

func TestParseDetections_RemoteObjectEmpty(t *testing.T) {
	// CDP RemoteObject wrapping an empty array (false positive case).
	raw := json.RawMessage(`{"type":"object","subtype":"array","className":"Array","value":[],"description":"Array(0)"}`)
	dets, err := parseDetections(raw)
	if err != nil {
		t.Fatalf("parseDetections failed: %v", err)
	}
	if len(dets) != 0 {
		t.Errorf("expected 0 detections, got %d", len(dets))
	}
}

func TestParseDetections_RemoteObjectWithDetections(t *testing.T) {
	// CDP RemoteObject wrapping an array of two detections.
	raw := json.RawMessage(`{"type":"object","subtype":"array","className":"Array","value":[{"category":"pii_email","severity":"high","match":"john.doe@example.com","start":13,"end":33,"pattern":"email_v1"},{"category":"pii_phone","severity":"high","match":"555-1234","start":0,"end":8,"pattern":"phone_v1"}],"description":"Array(2)"}`)
	dets, err := parseDetections(raw)
	if err != nil {
		t.Fatalf("parseDetections failed: %v", err)
	}
	if len(dets) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(dets))
	}
	if dets[0].Category != "pii_email" || dets[0].Match != "john.doe@example.com" {
		t.Errorf("dets[0] = %+v, want pii_email / john.doe@example.com", dets[0])
	}
	if dets[1].Category != "pii_phone" || dets[1].Match != "555-1234" {
		t.Errorf("dets[1] = %+v, want pii_phone / 555-1234", dets[1])
	}
}

func TestParseDetections_BareArrayFallback(t *testing.T) {
	// Direct unit-test calls pass a bare array (not wrapped in RemoteObject).
	// The original code expected this shape; the new code should still handle it.
	raw := json.RawMessage(`[{"category":"pii_ssn","severity":"critical","match":"123-45-6789","start":10,"end":21,"pattern":"ssn_v1"}]`)
	dets, err := parseDetections(raw)
	if err != nil {
		t.Fatalf("parseDetections failed: %v", err)
	}
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if dets[0].Category != "pii_ssn" {
		t.Errorf("dets[0].Category = %q, want pii_ssn", dets[0].Category)
	}
}

func TestParseDetections_EmptyInput(t *testing.T) {
	// nil or empty input should return (nil, nil) — false positive case.
	dets, err := parseDetections(nil)
	if err != nil {
		t.Fatalf("parseDetections(nil) failed: %v", err)
	}
	if dets != nil {
		t.Errorf("expected nil detections, got %v", dets)
	}
	dets, err = parseDetections(json.RawMessage(""))
	if err != nil {
		t.Fatalf("parseDetections(empty) failed: %v", err)
	}
	if dets != nil {
		t.Errorf("expected nil detections, got %v", dets)
	}
}
