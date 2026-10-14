// SPDX-License-Identifier: Apache-2.0
package mcpserver

import "testing"

func TestParseSuppressions_PythonStyle(t *testing.T) {
	content := `import os
# aegisgate-ignore: dangerous_py_eval
eval(user_input)
`
	suppressions := ParseSuppressions(content)
	if len(suppressions) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(suppressions))
	}
	if suppressions[0].RuleID != "dangerous_py_eval" {
		t.Errorf("rule ID: got %q, want %q", suppressions[0].RuleID, "dangerous_py_eval")
	}
	if suppressions[0].Line != 2 {
		t.Errorf("line: got %d, want 2", suppressions[0].Line)
	}
}

func TestParseSuppressions_GoStyle(t *testing.T) {
	content := `package main
// aegisgate-ignore: dangerous_js_eval
result := eval(input)
`
	suppressions := ParseSuppressions(content)
	if len(suppressions) != 1 {
		t.Fatalf("expected 1, got %d", len(suppressions))
	}
	if suppressions[0].RuleID != "dangerous_js_eval" {
		t.Errorf("rule ID: got %q", suppressions[0].RuleID)
	}
}

func TestParseSuppressions_HTMLStyle(t *testing.T) {
	content := `<div>
<!-- aegisgate-ignore: xss_script_tag -->
<script>alert(1)</script>
`
	suppressions := ParseSuppressions(content)
	if len(suppressions) != 1 {
		t.Fatalf("expected 1, got %d", len(suppressions))
	}
	if suppressions[0].RuleID != "xss_script_tag" {
		t.Errorf("rule ID: got %q", suppressions[0].RuleID)
	}
}

func TestParseSuppressions_AllKeyword(t *testing.T) {
	content := `# aegisgate-ignore: all
eval(input)
exec(input)
`
	suppressions := ParseSuppressions(content)
	if len(suppressions) != 1 {
		t.Fatalf("expected 1, got %d", len(suppressions))
	}
	if suppressions[0].RuleID != "all" {
		t.Errorf("rule ID: got %q, want %q", suppressions[0].RuleID, "all")
	}
}

func TestParseSuppressions_MultipleOnSameLine(t *testing.T) {
	content := `# aegisgate-ignore: dangerous_py_eval # aegisgate-ignore: dangerous_py_exec
eval(input)
`
	suppressions := ParseSuppressions(content)
	if len(suppressions) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(suppressions))
	}
}

func TestApplySuppressions_BasicFiltering(t *testing.T) {
	findings := []SuppressedFinding{
		{RuleID: "dangerous_py_eval", Line: 3},
		{RuleID: "dangerous_py_exec", Line: 4},
	}
	suppressions := []Suppression{
		{RuleID: "dangerous_py_eval", Line: 2}, // suppresses line 2 and 3
	}

	filtered := ApplySuppressions(findings, suppressions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(filtered))
	}
	if filtered[0].RuleID != "dangerous_py_exec" {
		t.Errorf("remaining finding: got %q, want %q", filtered[0].RuleID, "dangerous_py_exec")
	}
}

func TestApplySuppressions_AllKeyword(t *testing.T) {
	findings := []SuppressedFinding{
		{RuleID: "dangerous_py_eval", Line: 3},
		{RuleID: "dangerous_py_exec", Line: 4},
	}
	suppressions := []Suppression{
		{RuleID: "all", Line: 2}, // suppresses everything on line 2 and 3
	}

	filtered := ApplySuppressions(findings, suppressions)
	// Line 3 should be suppressed (all), line 4 should remain
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after all-suppression, got %d", len(filtered))
	}
	if filtered[0].Line != 4 {
		t.Errorf("remaining line: got %d, want 4", filtered[0].Line)
	}
}

func TestApplySuppressions_NoSuppressions(t *testing.T) {
	findings := []SuppressedFinding{
		{RuleID: "dangerous_py_eval", Line: 3},
	}
	filtered := ApplySuppressions(findings, nil)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding (no suppressions), got %d", len(filtered))
	}
}

func TestApplySuppressions_NextLinePattern(t *testing.T) {
	// Suppression on line N applies to line N and N+1
	findings := []SuppressedFinding{
		{RuleID: "dangerous_py_eval", Line: 5},  // same line as suppression
		{RuleID: "dangerous_py_eval", Line: 6},  // next line (should be suppressed)
		{RuleID: "dangerous_py_eval", Line: 7},  // too far (should remain)
	}
	suppressions := []Suppression{
		{RuleID: "dangerous_py_eval", Line: 5},
	}

	filtered := ApplySuppressions(findings, suppressions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(filtered))
	}
	if filtered[0].Line != 7 {
		t.Errorf("remaining line: got %d, want 7", filtered[0].Line)
	}
}