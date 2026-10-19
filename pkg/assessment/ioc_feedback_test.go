// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 2: IOC Feedback Loop Tests
//
// These tests verify the feedback loop's gap analysis, IOC recording,
// federation, pre/post validation, and recommendation engine.
// They do NOT require CGO or the ONNX model — they use regex-only
// assessment (which has known gaps) to exercise the feedback loop.

package assessment

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =========================================================================
// Test helpers
// =========================================================================

// newTestIOCStore creates an in-memory IOC store for testing.
func newTestIOCStore(t *testing.T) *ioc.Store {
	t.Helper()
	store, err := ioc.NewStore(ioc.StoreConfig{
		Capacity: 1000,
		MaxAge:   24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create IOC store: %v", err)
	}
	return store
}

// runRegexOnlyAssessment runs the assessment with regex-only (no ML)
// and returns the result. This will have known gaps.
func runRegexOnlyAssessment(t *testing.T) *AssessmentResult {
	t.Helper()
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}
	return result
}

// =========================================================================
// Tests: Gap Analysis
// =========================================================================

// TestIOCFeedbackLoop_ProcessResults verifies that ProcessResults correctly
// identifies gaps, generates recommendations, and produces a valid report.
func TestIOCFeedbackLoop_ProcessResults(t *testing.T) {
	result := runRegexOnlyAssessment(t)

	// Create feedback loop WITHOUT IOC store (gap analysis only).
	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)

	report := fb.ProcessResults(result)

	if report == nil {
		t.Fatal("ProcessResults returned nil report")
	}

	t.Logf("=== Gap Analysis Report ===")
	t.Logf("Assessment ID: %s", report.AssessmentID)
	t.Logf("Total gaps: %d", report.TotalGaps)
	t.Logf("IOCs recorded: %d", report.IOCsRecorded)
	t.Logf("Federated gaps: %d", report.FederatedGaps)
	t.Logf("Recommendations: %d", len(report.Recommendations))

	// Should have gaps (regex-only has known misses).
	if report.TotalGaps == 0 {
		t.Log("WARNING: No gaps found in regex-only assessment — all scenarios blocked by regex alone")
	}

	// Without a store, IOCs should not be recorded.
	if report.IOCsRecorded != 0 {
		t.Errorf("expected 0 IOCs recorded without store, got %d", report.IOCsRecorded)
	}

	// Per-OWASP should sum to TotalGaps.
	totalFromOWASP := 0
	for _, count := range report.PerOWASP {
		totalFromOWASP += count
	}
	if totalFromOWASP != report.TotalGaps {
		t.Errorf("PerOWASP sum %d != TotalGaps %d", totalFromOWASP, report.TotalGaps)
	}

	// Each gap record should have a valid recommendation.
	for _, gap := range report.GapRecords {
		if gap.Recommendation.Suggestion == "" {
			t.Errorf("gap %s has empty recommendation suggestion", gap.ScenarioID)
		}
		if gap.Recommendation.Priority == "" {
			t.Errorf("gap %s has empty priority", gap.ScenarioID)
		}
		if gap.Recommendation.TargetLayer == "" {
			t.Errorf("gap %s has empty target layer", gap.ScenarioID)
		}
		if len(gap.Recommendation.AffectedScenarios) == 0 {
			t.Errorf("gap %s has no affected scenarios", gap.ScenarioID)
		}
		t.Logf("  GAP [%s] %s — type=%s, priority=%s, fix=%s",
			gap.OWASP, gap.ScenarioID, gap.GapType, gap.Recommendation.Priority, gap.Recommendation.FixType)
	}

	// Print recommendations.
	t.Logf("=== Prioritized Recommendations ===")
	for i, rec := range report.Recommendations {
		t.Logf("  %d. [%s] %s", i+1, rec.Priority, rec.Suggestion)
		t.Logf("     Fix: %s, Target: %s, Scenarios: %s",
			rec.FixType, rec.TargetLayer, strings.Join(rec.AffectedScenarios, ", "))
		if rec.CandidateRegex != "" {
			t.Logf("     Candidate regex: %s", rec.CandidateRegex)
		}
	}

	// Recommendations should be sorted by priority (critical first).
	for i := 1; i < len(report.Recommendations); i++ {
		prev := report.Recommendations[i-1].Priority
		curr := report.Recommendations[i].Priority
		if priorityRank(prev) > priorityRank(curr) {
			t.Errorf("recommendation %d (%s) should come before %d (%s) — not sorted by priority",
				i, curr, i-1, prev)
		}
	}
}

// TestIOCFeedbackLoop_WithIOCStore verifies that gaps are recorded as IOCs
// when an IOC store is provided.
func TestIOCFeedbackLoop_WithIOCStore(t *testing.T) {
	result := runRegexOnlyAssessment(t)

	store := newTestIOCStore(t)

	storeAdapter := ioc.NewStoreAdapter(store)
	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), storeAdapter)

	report := fb.ProcessResults(result)

	if report.TotalGaps == 0 {
		t.Skip("no gaps found — cannot test IOC recording")
	}

	// IOCs should have been recorded.
	if report.IOCsRecorded == 0 {
		t.Error("expected IOCs to be recorded, got 0")
	}
	t.Logf("Recorded %d gap IOCs out of %d gaps", report.IOCsRecorded, report.TotalGaps)

	// Verify IOCs are in the store.
	ctx := context.Background()
	size, err := storeAdapter.Size(ctx)
	if err != nil {
		t.Fatalf("failed to get store size: %v", err)
	}
	if size == 0 {
		t.Error("IOC store is empty after ProcessResults")
	}
	t.Logf("IOC store size: %d", size)

	// Verify the IOCs have the correct type and source.
	snapshot, err := storeAdapter.Snapshot(ctx)
	if err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	for _, iocRecord := range snapshot {
		if iocRecord.Type != ioc.IOCTypeComplianceViolation {
			t.Errorf("IOC %s has type %s, expected %s",
				iocRecord.Fingerprint[:16], iocRecord.Type, ioc.IOCTypeComplianceViolation)
		}
		if iocRecord.Source != "assessment" {
			t.Errorf("IOC %s has source %s, expected 'assessment'",
				iocRecord.Fingerprint[:16], iocRecord.Source)
		}
		if !iocRecord.AffectsGateway {
			t.Errorf("IOC %s should have AffectsGateway=true for federation",
				iocRecord.Fingerprint[:16])
		}
		t.Logf("  IOC: fp=%s..., sev=%s, source=%s, affectsGateway=%v",
			iocRecord.Fingerprint[:16], iocRecord.Severity, iocRecord.Source, iocRecord.AffectsGateway)
	}

	// Federation should be ready.
	if !report.FederationReady {
		t.Error("expected FederationReady=true")
	}
}

// TestIOCFeedbackLoop_Deduplication verifies that multiple gaps with the same
// recommendation are merged into a single recommendation.
func TestIOCFeedbackLoop_Deduplication(t *testing.T) {
	result := runRegexOnlyAssessment(t)

	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	report := fb.ProcessResults(result)

	if report.TotalGaps == 0 {
		t.Skip("no gaps found — cannot test deduplication")
	}

	// Count total affected scenarios across all recommendations.
	totalAffected := 0
	for _, rec := range report.Recommendations {
		totalAffected += len(rec.AffectedScenarios)
	}

	// Total affected should equal total gaps (each gap appears in exactly one recommendation).
	if totalAffected != report.TotalGaps {
		t.Errorf("total affected scenarios %d != total gaps %d — deduplication may be losing or duplicating gaps",
			totalAffected, report.TotalGaps)
	}

	// Number of recommendations should be <= number of gaps (dedup means fewer or equal).
	if len(report.Recommendations) > report.TotalGaps {
		t.Errorf("more recommendations (%d) than gaps (%d) — deduplication not working",
			len(report.Recommendations), report.TotalGaps)
	}

	t.Logf("Gaps: %d, Recommendations: %d (dedup ratio: %.1f gaps per recommendation)",
		report.TotalGaps, len(report.Recommendations),
		float64(report.TotalGaps)/float64(max(1, len(report.Recommendations))))
}

// =========================================================================
// Tests: Pre/Post Validation
// =========================================================================

// TestIOCFeedbackLoop_ValidateUpdate verifies the pre/post comparison logic.
func TestIOCFeedbackLoop_ValidateUpdate(t *testing.T) {
	// Create a pre-assessment result with some gaps.
	preResult := &AssessmentResult{
		ID:      "pre-test-001",
		Total:   5,
		Blocked: 3,
		Missed:  2,
		Score:   0.6,
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S2", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S3", Blocked: true, DetectionLayer: "ml"},
			{ScenarioID: "S4", Blocked: false, DetectionLayer: "none"},
			{ScenarioID: "S5", Blocked: false, DetectionLayer: "none"},
		},
	}

	// Create a post-assessment result where S4 is now blocked (gap closed),
	// but S5 is still missed (still missed), and no regressions.
	postResult := &AssessmentResult{
		ID:      "post-test-001",
		Total:   5,
		Blocked: 4,
		Missed:  1,
		Score:   0.8,
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S2", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S3", Blocked: true, DetectionLayer: "ml"},
			{ScenarioID: "S4", Blocked: true, DetectionLayer: "regex"}, // Gap closed!
			{ScenarioID: "S5", Blocked: false, DetectionLayer: "none"}, // Still missed
		},
	}

	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	vr := fb.ValidateUpdate(preResult, postResult)

	t.Logf("=== Validation Report ===")
	t.Logf("Pre score: %.1f%%, Post score: %.1f%%, Delta: +%.1f%%",
		vr.PreScore*100, vr.PostScore*100, vr.ScoreDelta*100)
	t.Logf("Gaps closed: %d (%v)", len(vr.GapsClosed), vr.GapsClosed)
	t.Logf("Regressions: %d (%v)", len(vr.Regressions), vr.Regressions)
	t.Logf("Still missed: %d (%v)", len(vr.StillMissed), vr.StillMissed)
	t.Logf("Passed: %v", vr.Passed)
	t.Logf("Summary: %s", vr.Summary)

	// Should have 1 gap closed (S4).
	if len(vr.GapsClosed) != 1 || vr.GapsClosed[0] != "S4" {
		t.Errorf("expected gaps closed = [S4], got %v", vr.GapsClosed)
	}

	// Should have 0 regressions.
	if len(vr.Regressions) != 0 {
		t.Errorf("expected 0 regressions, got %d: %v", len(vr.Regressions), vr.Regressions)
	}

	// Should have 1 still missed (S5).
	if len(vr.StillMissed) != 1 || vr.StillMissed[0] != "S5" {
		t.Errorf("expected still missed = [S5], got %v", vr.StillMissed)
	}

	// Should have passed.
	if !vr.Passed {
		t.Error("expected Passed=true (1 gap closed, 0 regressions)")
	}

	// Score delta should be +0.2.
	if vr.ScoreDelta < 0.19 || vr.ScoreDelta > 0.21 {
		t.Errorf("expected score delta ~0.2, got %.4f", vr.ScoreDelta)
	}
}

// TestIOCFeedbackLoop_ValidateUpdate_WithRegression verifies that regressions
// are detected and the validation fails.
func TestIOCFeedbackLoop_ValidateUpdate_WithRegression(t *testing.T) {
	preResult := &AssessmentResult{
		ID:      "pre-reg-001",
		Total:   3,
		Blocked: 2,
		Missed:  1,
		Score:   0.667,
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S2", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S3", Blocked: false, DetectionLayer: "none"},
		},
	}

	// Post: S3 is now blocked (gap closed), but S1 is now missed (regression!).
	postResult := &AssessmentResult{
		ID:      "post-reg-001",
		Total:   3,
		Blocked: 2,
		Missed:  1,
		Score:   0.667,
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: false, DetectionLayer: "none"}, // REGRESSION!
			{ScenarioID: "S2", Blocked: true, DetectionLayer: "regex"},
			{ScenarioID: "S3", Blocked: true, DetectionLayer: "regex"}, // Gap closed
		},
	}

	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	vr := fb.ValidateUpdate(preResult, postResult)

	t.Logf("=== Validation Report (Regression Test) ===")
	t.Logf("Gaps closed: %v", vr.GapsClosed)
	t.Logf("Regressions: %v", vr.Regressions)
	t.Logf("Passed: %v", vr.Passed)

	// Should have 1 gap closed (S3).
	if len(vr.GapsClosed) != 1 || vr.GapsClosed[0] != "S3" {
		t.Errorf("expected gaps closed = [S3], got %v", vr.GapsClosed)
	}

	// Should have 1 regression (S1).
	if len(vr.Regressions) != 1 || vr.Regressions[0] != "S1" {
		t.Errorf("expected 1 regression [S1], got %v", vr.Regressions)
	}

	// Should NOT have passed (regression detected).
	if vr.Passed {
		t.Error("expected Passed=false (regression detected)")
	}

	// Summary should mention regressions.
	if !strings.Contains(vr.Summary, "REGRESSION") {
		t.Errorf("summary should mention regression: %s", vr.Summary)
	}
}

// =========================================================================
// Tests: Gap Classification
// =========================================================================

// TestClassifyGap verifies the gap type classification logic.
func TestClassifyGap(t *testing.T) {
	tests := []struct {
		name    string
		sr      ScenarioResult
		wantGap GapType
	}{
		{
			name:    "all miss (no ML)",
			sr:      ScenarioResult{DetectionLayer: "none", MLScore: 0},
			wantGap: GapTypeAllMiss,
		},
		{
			name:    "ML miss (ML tried, below threshold)",
			sr:      ScenarioResult{DetectionLayer: "none", MLScore: 0.3},
			wantGap: GapTypeMLMiss,
		},
		{
			name:    "ML miss (layer=ml but not blocked — shouldn't happen but handle)",
			sr:      ScenarioResult{DetectionLayer: "ml", MLScore: 0.3},
			wantGap: GapTypeMLMiss,
		},
		{
			name:    "response miss",
			sr:      ScenarioResult{DetectionLayer: "response", MLScore: 0},
			wantGap: GapTypeResponseMiss,
		},
		{
			name:    "regex miss",
			sr:      ScenarioResult{DetectionLayer: "regex", MLScore: 0},
			wantGap: GapTypeRegexMiss,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyGap(tt.sr)
			if got != tt.wantGap {
				t.Errorf("classifyGap() = %s, want %s", got, tt.wantGap)
			}
		})
	}
}

// =========================================================================
// Tests: Recommendation Engine
// =========================================================================

// TestRecommendForGap verifies that recommendations are generated for each
// OWASP category and gap type.
func TestRecommendForGap(t *testing.T) {
	owaspCategories := []string{
		"LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
		"LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
	}

	for _, owasp := range owaspCategories {
		sr := ScenarioResult{
			ScenarioID:     owasp + "-TEST",
			Name:           "Test scenario for " + owasp,
			OWASP:          owasp,
			DetectionLayer: "none",
			MLScore:        0,
		}

		for _, gapType := range []GapType{GapTypeAllMiss, GapTypeMLMiss, GapTypeResponseMiss} {
			rec := recommendForGap(sr, gapType)

			if rec.Suggestion == "" {
				t.Errorf("%s/%s: empty suggestion", owasp, gapType)
			}
			if rec.FixType == "" {
				t.Errorf("%s/%s: empty fix type", owasp, gapType)
			}
			if rec.TargetLayer == "" {
				t.Errorf("%s/%s: empty target layer", owasp, gapType)
			}
			if rec.Priority == "" {
				t.Errorf("%s/%s: empty priority", owasp, gapType)
			}
		}
	}
}

// TestOWASPSeverity verifies the OWASP → severity mapping.
func TestOWASPSeverity(t *testing.T) {
	tests := []struct {
		owasp     string
		wantSev   ioc.Severity
		wantPrior RecommendationPriority
	}{
		{"LLM01", ioc.SeverityCritical, PriorityCritical},
		{"LLM03", ioc.SeverityCritical, PriorityCritical},
		{"LLM06", ioc.SeverityCritical, PriorityCritical},
		{"LLM02", ioc.SeverityHigh, PriorityHigh},
		{"LLM04", ioc.SeverityHigh, PriorityHigh},
		{"LLM05", ioc.SeverityHigh, PriorityHigh},
		{"LLM07", ioc.SeverityHigh, PriorityHigh},
		{"LLM08", ioc.SeverityHigh, PriorityHigh},
		{"LLM09", ioc.SeverityMedium, PriorityMedium},
		{"LLM10", ioc.SeverityMedium, PriorityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.owasp, func(t *testing.T) {
			gotSev := owaspSeverity(tt.owasp)
			if ioc.Severity(gotSev) != tt.wantSev {
				t.Errorf("owaspSeverity(%s) = %s, want %s", tt.owasp, gotSev, tt.wantSev)
			}
			gotPrior := owaspPriority(tt.owasp)
			if gotPrior != tt.wantPrior {
				t.Errorf("owaspPriority(%s) = %s, want %s", tt.owasp, gotPrior, tt.wantPrior)
			}
		})
	}
}

// =========================================================================
// Tests: IOC Fingerprint Stability
// =========================================================================

// TestGapIOCFingerprintStability verifies that the same scenario produces
// the same IOC fingerprint across calls — this is essential for federation.
func TestGapIOCFingerprintStability(t *testing.T) {
	sr := ScenarioResult{
		ScenarioID:     "LLM01-007",
		Name:           "Language switch — non-English injection",
		OWASP:          "LLM01",
		DetectionLayer: "none",
	}

	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	now := time.Now().UTC()

	// Build the same IOC twice — fingerprints must match.
	ioc1 := fb.buildGapIOC(sr, owaspSeverity(sr.OWASP), now)
	ioc2 := fb.buildGapIOC(sr, owaspSeverity(sr.OWASP), now.Add(time.Hour))

	if ioc1 == nil || ioc2 == nil {
		t.Fatal("buildGapIOC returned nil")
	}

	if ioc1.Fingerprint != ioc2.Fingerprint {
		t.Errorf("fingerprint mismatch: %s != %s — same scenario must produce same fingerprint",
			ioc1.Fingerprint, ioc2.Fingerprint)
	}

	// Different scenarios must produce different fingerprints.
	sr2 := ScenarioResult{
		ScenarioID:     "LLM03-002",
		Name:           "Dangerous function in code — eval()",
		OWASP:          "LLM03",
		DetectionLayer: "none",
	}
	ioc3 := fb.buildGapIOC(sr2, owaspSeverity(sr2.OWASP), now)
	if ioc3 == nil {
		t.Fatal("buildGapIOC returned nil for sr2")
	}
	if ioc1.Fingerprint == ioc3.Fingerprint {
		t.Error("different scenarios produced the same fingerprint — fingerprint collision")
	}

	t.Logf("LLM01-007 fingerprint: %s", ioc1.Fingerprint)
	t.Logf("LLM03-002 fingerprint: %s", ioc3.Fingerprint)
}

// =========================================================================
// Tests: Full Integration (regex-only → feedback → validation)
// =========================================================================

// TestIOCFeedbackLoop_FullIntegration runs the complete feedback loop
// workflow: run assessment → process results → simulate fix → re-run →
// validate update. This is the "self-improving" cycle in action.
//
// Since we can't dynamically add patterns at test time, we simulate the
// "fix" by running the assessment twice and comparing. The test verifies
// that the feedback loop infrastructure works end-to-end.
func TestIOCFeedbackLoop_FullIntegration(t *testing.T) {
	// Step 1: Run assessment.
	result1 := runRegexOnlyAssessment(t)
	t.Logf("Step 1: Assessment — %d/%d blocked (%.1f%%), %d gaps",
		result1.Blocked, result1.Total, result1.Score*100, result1.Missed)

	// Step 2: Process results with feedback loop (with IOC store).
	store := newTestIOCStore(t)
	storeAdapter := ioc.NewStoreAdapter(store)

	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), storeAdapter)
	report := fb.ProcessResults(result1)
	t.Logf("Step 2: Feedback — %d gaps, %d IOCs recorded, %d recommendations",
		report.TotalGaps, report.IOCsRecorded, len(report.Recommendations))

	// Step 3: Print the gap analysis summary.
	t.Logf("Step 3: Gap Analysis Summary:\n%s", report.Summary())

	// Step 4: Run assessment again (simulating "after fix" — but we haven't
	// actually fixed anything, so results should be the same).
	result2 := runRegexOnlyAssessment(t)
	t.Logf("Step 4: Re-run assessment — %d/%d blocked (%.1f%%)",
		result2.Blocked, result2.Total, result2.Score*100)

	// Step 5: Validate update (pre=result1, post=result2).
	// Since we didn't change anything, this should show 0 gaps closed and
	// 0 regressions (and thus NOT passed, since no gaps were closed).
	vr := fb.ValidateUpdate(result1, result2)
	t.Logf("Step 5: Validation — %s", vr.Summary)

	if len(vr.GapsClosed) != 0 {
		t.Errorf("expected 0 gaps closed (no changes made), got %d", len(vr.GapsClosed))
	}
	if len(vr.Regressions) != 0 {
		t.Errorf("expected 0 regressions (no changes made), got %d", len(vr.Regressions))
	}
	if len(vr.StillMissed) != result1.Missed {
		t.Errorf("expected %d still missed, got %d", result1.Missed, len(vr.StillMissed))
	}

	// Step 6: Verify IOC store has the gap IOCs from both runs.
	ctx := context.Background()
	size, _ := storeAdapter.Size(ctx)
	t.Logf("Step 6: IOC store size after two runs: %d", size)

	// Running the assessment twice with the same gaps should increment the
	// Count on existing IOCs (not create new ones). The store size should
	// equal the number of unique gaps (not 2x).
	if report.TotalGaps > 0 && size != report.IOCsRecorded {
		// Each gap should produce one IOC, and re-running should increment
		// Count, not create new entries.
		// However, some gaps might be below MinGapSeverity and not recorded.
		t.Logf("IOC store size %d vs IOCs recorded %d — may differ if some gaps below severity threshold",
			size, report.IOCsRecorded)
	}

	// Verify that re-running ProcessResults on the second result increments
	// counts (not creates new IOCs).
	report2 := fb.ProcessResults(result2)
	t.Logf("Step 6b: Second feedback — %d IOCs recorded (should be same as first: %d)",
		report2.IOCsRecorded, report.IOCsRecorded)

	if report2.IOCsRecorded != report.IOCsRecorded {
		t.Errorf("second run recorded %d IOCs, expected same as first run (%d) — Observe should increment, not duplicate",
			report2.IOCsRecorded, report.IOCsRecorded)
	}

	// Store size should not have doubled.
	size2, _ := storeAdapter.Size(ctx)
	t.Logf("IOC store size after second feedback: %d (should equal first: %d)", size2, size)
	if size2 != size {
		t.Errorf("store size changed from %d to %d — Observe should increment Count, not create new IOCs",
			size, size2)
	}

	// Verify counts were incremented.
	snapshot, _ := storeAdapter.Snapshot(ctx)
	for _, iocRec := range snapshot {
		if iocRec.Count < 2 {
			t.Errorf("IOC %s has Count=%d, expected >= 2 (observed twice)", iocRec.Fingerprint[:16], iocRec.Count)
		}
		t.Logf("  IOC: fp=%s..., count=%d, sev=%s", iocRec.Fingerprint[:16], iocRec.Count, iocRec.Severity)
	}
}

// =========================================================================
// Test: No-Op Feedback Loop (disabled config)
// =========================================================================

// TestIOCFeedbackLoop_Disabled verifies that a disabled feedback loop
// produces an empty report without errors.
func TestIOCFeedbackLoop_Disabled(t *testing.T) {
	result := runRegexOnlyAssessment(t)

	cfg := IOCFeedbackConfig{
		EnableIOCRecording:  false,
		EnableFederation:    false,
		EnableGapAnalysis:   false,
		EnableCorroboration: false,
	}

	store := newTestIOCStore(t)
	storeAdapter := ioc.NewStoreAdapter(store)

	fb := NewIOCFeedbackLoop(cfg, storeAdapter)
	report := fb.ProcessResults(result)

	if report.TotalGaps != 0 {
		t.Errorf("disabled feedback loop should produce 0 gaps, got %d", report.TotalGaps)
	}
	if report.IOCsRecorded != 0 {
		t.Errorf("disabled feedback loop should record 0 IOCs, got %d", report.IOCsRecorded)
	}

	// Store should be empty.
	ctx := context.Background()
	size, _ := storeAdapter.Size(ctx)
	if size != 0 {
		t.Errorf("store should be empty with disabled feedback loop, got size %d", size)
	}
}

// =========================================================================
// Test: Gap Analysis Report Summary
// =========================================================================

// TestGapAnalysisReport_Summary verifies the human-readable summary.
func TestGapAnalysisReport_Summary(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	report := fb.ProcessResults(result)

	summary := report.Summary()
	if summary == "" {
		t.Fatal("Summary() returned empty string")
	}
	if !strings.Contains(summary, "Gap Analysis Report") {
		t.Error("summary should contain 'Gap Analysis Report'")
	}
	if !strings.Contains(summary, "Total gaps:") {
		t.Error("summary should contain 'Total gaps:'")
	}

	t.Logf("Summary output:\n%s", summary)
}

// =========================================================================
// Helper: priority rank for test assertions
// =========================================================================

// priorityRank returns a numeric rank for priority comparison in tests.
func priorityRank(p RecommendationPriority) int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 3
	default:
		return 4
	}
}
