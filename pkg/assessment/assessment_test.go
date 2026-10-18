// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 1: Tests

package assessment

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScenarioCount(t *testing.T) {
	count := ScenarioCount()
	if count < 40 {
		t.Errorf("expected at least 40 scenarios, got %d", count)
	}
	t.Logf("scenario count: %d", count)
}

func TestOWASPCoverage(t *testing.T) {
	scenarios := DefaultScenarios()
	owaspSeen := make(map[string]bool)
	for _, s := range scenarios {
		owaspSeen[s.OWASP] = true
	}
	// All 10 OWASP LLM Top 10 categories should be covered
	expected := []string{"LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"}
	for _, cat := range expected {
		if !owaspSeen[cat] {
			t.Errorf("missing OWASP category: %s", cat)
		}
	}
	t.Logf("OWASP categories covered: %d", len(owaspSeen))
}

func TestRunnerWithoutML(t *testing.T) {
	// Create runner with default config (no ML, response guard enabled)
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment run failed: %v", err)
	}

	if result.Total != ScenarioCount() {
		t.Errorf("expected %d total, got %d", ScenarioCount(), result.Total)
	}
	t.Logf("result: %d/%d blocked (%.1f%%)", result.Blocked, result.Total, result.Score*100)
	t.Logf("duration: %v", result.Duration)

	// Verify OWASP coverage was computed
	if len(result.OWASPCoverage) == 0 {
		t.Error("expected OWASP coverage to be computed")
	}

	// Verify compliance posture was computed
	if len(result.CompliancePosture) == 0 {
		t.Error("expected compliance posture to be computed")
	}

	// Verify we have at least some blocks (regex should catch prompt injection, PII, etc.)
	if result.Blocked == 0 {
		t.Error("expected at least some scenarios to be blocked by regex scanner")
	}
	t.Logf("blocked: %d, missed: %d", result.Blocked, result.Missed)
}

func TestReportJSON(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment run failed: %v", err)
	}

	jsonBytes, err := result.ToJSON()
	if err != nil {
		t.Fatalf("JSON serialization failed: %v", err)
	}

	// Verify JSON is valid and has expected fields
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("JSON is invalid: %v", err)
	}

	requiredFields := []string{"id", "timestamp", "total", "blocked", "missed", "score", "scenarios", "owasp_coverage"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("JSON missing required field: %s", field)
		}
	}
	t.Logf("JSON report: %d bytes", len(jsonBytes))
}

func TestReportCSV(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment run failed: %v", err)
	}

	csvBytes, err := result.ToCSV()
	if err != nil {
		t.Fatalf("CSV serialization failed: %v", err)
	}

	csvStr := string(csvBytes)
	if !strings.Contains(csvStr, "scenario_id") {
		t.Error("CSV missing header row")
	}
	// Count lines (header + data rows)
	lines := strings.Count(csvStr, "\n")
	if lines != result.Total+1 { // +1 for header
		t.Errorf("expected %d CSV lines, got %d", result.Total+1, lines)
	}
	t.Logf("CSV report: %d bytes, %d lines", len(csvBytes), lines)
}

func TestExecutiveSummary(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment run failed: %v", err)
	}

	summary := result.ExecutiveSummary()
	if !strings.Contains(summary, "Posture Assessment") {
		t.Error("executive summary missing title")
	}
	if !strings.Contains(summary, "%") {
		t.Error("executive summary missing percentage")
	}
	t.Logf("summary: %s", summary)
}

func TestGapReport(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment run failed: %v", err)
	}

	gaps := result.GapReport()
	if result.Missed > 0 && !strings.Contains(gaps, "Gaps found") {
		t.Error("gap report should mention gaps when missed > 0")
	}
	if result.Missed == 0 && !strings.Contains(gaps, "No gaps detected") {
		t.Error("gap report should say no gaps when missed == 0")
	}
	t.Logf("gap report:\n%s", gaps)
}

func TestAssessmentStore(t *testing.T) {
	store := NewAssessmentStore()

	if store.Latest() != nil {
		t.Error("new store should have nil latest")
	}

	// Save a result
	r := AssessmentResult{
		ID:      "test-1",
		Total:   10,
		Blocked: 8,
		Missed:  2,
		Score:   0.8,
	}
	store.Save(r)

	latest := store.Latest()
	if latest == nil || latest.ID != "test-1" {
		t.Error("latest should return the saved result")
	}

	got := store.Get("test-1")
	if got == nil || got.ID != "test-1" {
		t.Error("Get should return the saved result by ID")
	}

	gotNone := store.Get("nonexistent")
	if gotNone != nil {
		t.Error("Get should return nil for nonexistent ID")
	}

	history := store.History(0, 10)
	if len(history) != 1 {
		t.Errorf("expected 1 history result, got %d", len(history))
	}
}

func TestComplianceMapping(t *testing.T) {
	// Test that each OWASP category maps to at least some controls
	for _, fw := range SupportedFrameworks() {
		controls := ControlsForOWASP("LLM01", fw)
		if len(controls) == 0 {
			t.Logf("warning: no controls mapped for LLM01 in %s", fw)
		}
	}

	// Test full compliance posture computation
	results := []ScenarioResult{
		{ScenarioID: "LLM01-001", OWASP: "LLM01", Blocked: true},
		{ScenarioID: "LLM01-002", OWASP: "LLM01", Blocked: false},
		{ScenarioID: "LLM02-001", OWASP: "LLM02", Blocked: true},
	}

	posture := ComputeCompliancePosture(results)
	if len(posture) != 5 {
		t.Errorf("expected 5 frameworks in posture, got %d", len(posture))
	}

	// NIST 800-171 should have some verified controls from LLM01 and LLM02
	nist := posture["NIST800-171"]
	if nist.Verified == 0 {
		t.Error("expected NIST to have some verified controls")
	}
	t.Logf("NIST posture: %d verified, %d at-risk, %.1f%% coverage",
		nist.Verified, nist.AtRisk, nist.Coverage*100)
}
