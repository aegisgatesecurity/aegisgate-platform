// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Adversarial Benchmark Suite tests
//
// benchmark_test.go tests the SXC corpus infrastructure, the
// ResponseGuardScanner adapter, and the BenchmarkRunner.

package evaluator

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// SXC Corpus tests
// =====================================================================

func TestSXCCorpus_HasExpectedShape(t *testing.T) {
	records := SXCCorpus()
	if len(records) != 158 {
		t.Errorf("SXC corpus: got %d records, want 158", len(records))
	}
	// Every record has a non-empty ID, text, and facet.
	for i, r := range records {
		if r.ID == "" {
			t.Errorf("record %d: empty ID", i)
		}
		if r.Text == "" {
			t.Errorf("record %d (%s): empty text", i, r.ID)
		}
		if r.Facet == "" {
			t.Errorf("record %d (%s): empty facet", i, r.ID)
		}
		if r.Category == "" {
			t.Errorf("record %d (%s): empty category", i, r.ID)
		}
		if r.ExpectedLabel != 0 && r.ExpectedLabel != 1 {
			t.Errorf("record %d (%s): expected_label=%d, want 0 or 1", i, r.ID, r.ExpectedLabel)
		}
	}
	// Every record has a unique ID.
	seen := make(map[string]struct{}, len(records))
	for _, r := range records {
		if _, dup := seen[r.ID]; dup {
			t.Errorf("duplicate record ID: %s", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
}

func TestSXCCorpus_FacetCounts(t *testing.T) {
	records := SXCCorpus()
	facetCounts := make(map[SXCFacet]int)
	for _, r := range records {
		facetCounts[r.Facet]++
	}
	// Expected: secrets=74, xss=24, compliance=60.
	expected := map[SXCFacet]int{
		SXCFacetSecrets:   74,
		SXCFacetXSS:       24,
		SXCFacetCompliance: 60,
	}
	for facet, want := range expected {
		got := facetCounts[facet]
		if got != want {
			t.Errorf("facet %s: got %d records, want %d", facet, got, want)
		}
	}
}

func TestSXCCorpus_PosNegBalance(t *testing.T) {
	records := SXCCorpus()
	posCount := 0
	negCount := 0
	for _, r := range records {
		if r.ExpectedLabel == 1 {
			posCount++
		} else {
			negCount++
		}
	}
	// Each category has exactly 1 positive and 1 negative record.
	// 79 categories * 2 = 158 records.
	if posCount != negCount {
		t.Errorf("pos/neg balance: pos=%d, neg=%d, want equal", posCount, negCount)
	}
}

func TestSXCByFacet(t *testing.T) {
	secrets := SXCByFacet(SXCFacetSecrets)
	if len(secrets) != 74 {
		t.Errorf("SXCByFacet(secrets): got %d records, want 74", len(secrets))
	}
	xss := SXCByFacet(SXCFacetXSS)
	if len(xss) != 24 {
		t.Errorf("SXCByFacet(xss): got %d records, want 24", len(xss))
	}
	compliance := SXCByFacet(SXCFacetCompliance)
	if len(compliance) != 60 {
		t.Errorf("SXCByFacet(compliance): got %d records, want 60", len(compliance))
	}
}

func TestSXCByCategory(t *testing.T) {
	records := SXCByCategory(SXCCatSecretAWSKey)
	if len(records) != 2 {
		t.Errorf("SXCByCategory(secret_aws_key): got %d records, want 2", len(records))
	}
	// One positive, one negative.
	pos := 0
	neg := 0
	for _, r := range records {
		if r.ExpectedLabel == 1 {
			pos++
		} else {
			neg++
		}
	}
	if pos != 1 || neg != 1 {
		t.Errorf("SXCByCategory(secret_aws_key): pos=%d neg=%d, want 1 1", pos, neg)
	}
}

func TestSXCPositive(t *testing.T) {
	pos := SXCPositive()
	if len(pos) != 79 {
		t.Errorf("SXCPositive: got %d records, want 79", len(pos))
	}
	for _, r := range pos {
		if r.ExpectedLabel != 1 {
			t.Errorf("SXCPositive: record %s has expected_label=%d, want 1", r.ID, r.ExpectedLabel)
		}
	}
}

func TestSXCNegative(t *testing.T) {
	neg := SXCNegative()
	if len(neg) != 79 {
		t.Errorf("SXCNegative: got %d records, want 79", len(neg))
	}
	for _, r := range neg {
		if r.ExpectedLabel != 0 {
			t.Errorf("SXCNegative: record %s has expected_label=%d, want 0", r.ID, r.ExpectedLabel)
		}
	}
}

func TestSXCCategoryCount(t *testing.T) {
	count := SXCCategoryCount()
	// 37 secrets + 12 xss + 30 compliance = 79 categories
	// Wait, let me count: 37 + 12 + 20 = 69? No...
	// Secrets: 37+1(db_url)=38? Let me check what we actually have.
	// The SXC corpus has 79 distinct categories (158 records / 2 = 79 pos/neg pairs).
	if count != 79 {
		t.Errorf("SXCCategoryCount: got %d, want 79", count)
	}
}

// =====================================================================
// Benchmark runner tests
// =====================================================================

// mockScanner is a test scanner that detects based on a simple rule:
// positive records (expected_label=1) are always detected, negative
// records (expected_label=0) are never flagged.
type mockScanner struct {
	name string
}

func (m *mockScanner) Scan(ctx context.Context, record SXCRecord) (*BenchmarkDetection, error) {
	if record.ExpectedLabel == 1 {
		return &BenchmarkDetection{
			Detected: true,
			Threats: []BenchmarkThreat{
				{Type: "mock", Severity: 3, Message: "mock detection", Category: string(record.Category)},
			},
			LatencyMillis: 1,
		}, nil
	}
	return &BenchmarkDetection{
		Detected:      false,
		Threats:       []BenchmarkThreat{},
		LatencyMillis: 1,
	}, nil
}

func (m *mockScanner) Name() string { return m.name }

func TestBenchmarkRunner_MockPerfectDetection(t *testing.T) {
	scanner := &mockScanner{name: "MockPerfect"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	// With a perfect scanner, we expect:
	// - All positive records detected (TP)
	// - All negative records not flagged (TN)
	// - 0 FP, 0 FN
	if result.TruePositives != 79 {
		t.Errorf("TP: got %d, want 79", result.TruePositives)
	}
	if result.TrueNegatives != 79 {
		t.Errorf("TN: got %d, want 79", result.TrueNegatives)
	}
	if result.FalsePositives != 0 {
		t.Errorf("FP: got %d, want 0", result.FalsePositives)
	}
	if result.FalseNegatives != 0 {
		t.Errorf("FN: got %d, want 0", result.FalseNegatives)
	}
	if result.Precision != 1.0 {
		t.Errorf("Precision: got %.4f, want 1.0", result.Precision)
	}
	if result.Recall != 1.0 {
		t.Errorf("Recall: got %.4f, want 1.0", result.Recall)
	}
	if result.F1Score != 1.0 {
		t.Errorf("F1: got %.4f, want 1.0", result.F1Score)
	}
	if result.Accuracy != 1.0 {
		t.Errorf("Accuracy: got %.4f, want 1.0", result.Accuracy)
	}
	if result.TotalRecords != 158 {
		t.Errorf("TotalRecords: got %d, want 158", result.TotalRecords)
	}
	if result.ScannerName != "MockPerfect" {
		t.Errorf("ScannerName: got %s, want MockPerfect", result.ScannerName)
	}
}

func TestBenchmarkRunner_FilterByFacet(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background(), WithFacet(SXCFacetSecrets))
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}
	if result.TotalRecords != 74 {
		t.Errorf("TotalRecords for secrets facet: got %d, want 74", result.TotalRecords)
	}
}

func TestBenchmarkRunner_FilterByCategory(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background(), WithCategory(SXCCatSecretAWSKey))
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}
	if result.TotalRecords != 2 {
		t.Errorf("TotalRecords for secret_aws_key category: got %d, want 2", result.TotalRecords)
	}
}

func TestBenchmarkRunner_FilterByRecordIDs(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background(), WithRecordIDs([]string{
		"SCRT-secret_aws_key-pos-001",
		"XSS-xss_script_tag-pos-075",
		"CMP-owasp_llm01_prompt_injection-pos-099",
	}))
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}
	if result.TotalRecords != 3 {
		t.Errorf("TotalRecords for 3 specific records: got %d, want 3", result.TotalRecords)
	}
	if result.TruePositives != 3 {
		t.Errorf("TP: got %d, want 3", result.TruePositives)
	}
}

func TestBenchmarkRunner_EmptyFilter(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	_, err = runner.RunBenchmark(context.Background(), WithCategory("nonexistent_category"))
	if err == nil {
		t.Error("expected error for empty filter, got nil")
	}
}

func TestClassifyOutcome(t *testing.T) {
	tests := []struct {
		expected int
		detected bool
		want     string
	}{
		{1, true, "TP"},
		{0, false, "TN"},
		{0, true, "FP"},
		{1, false, "FN"},
	}
	for _, tt := range tests {
		got := classifyOutcome(tt.expected, tt.detected)
		if got != tt.want {
			t.Errorf("classifyOutcome(%d, %v): got %s, want %s", tt.expected, tt.detected, got, tt.want)
		}
	}
}

func TestBenchmarkRunner_FacetBreakdown(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	// Check all three facets are present.
	if len(result.FacetBreakdown) != 3 {
		t.Errorf("FacetBreakdown: got %d facets, want 3", len(result.FacetBreakdown))
	}
	for _, facet := range []SXCFacet{SXCFacetSecrets, SXCFacetXSS, SXCFacetCompliance} {
		fb, ok := result.FacetBreakdown[facet]
		if !ok {
			t.Errorf("FacetBreakdown: missing facet %s", facet)
			continue
		}
		if fb.Precision != 1.0 || fb.Recall != 1.0 || fb.F1Score != 1.0 {
			t.Errorf("Facet %s: P=%.4f R=%.4f F1=%.4f (want 1.0 for perfect scanner)",
				facet, fb.Precision, fb.Recall, fb.F1Score)
		}
	}
}

func TestBenchmarkRunner_CategoryBreakdown(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	// All 79 categories should be present.
	if len(result.CategoryBreakdown) != 79 {
		t.Errorf("CategoryBreakdown: got %d categories, want 79", len(result.CategoryBreakdown))
	}
}

func TestBenchmarkReportText(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	report := BenchmarkReportText(result)
	if report == "" {
		t.Error("BenchmarkReportText: empty report")
	}
	// Check key sections are present.
	if !strings.Contains(report, "AegisGate SXC Benchmark Report") {
		t.Error("report missing header")
	}
	if !strings.Contains(report, "Precision:") {
		t.Error("report missing precision")
	}
	if !strings.Contains(report, "Recall:") {
		t.Error("report missing recall")
	}
	if !strings.Contains(report, "F1 Score:") {
		t.Error("report missing F1")
	}
	if !strings.Contains(report, "Facet Breakdown") {
		t.Error("report missing facet breakdown")
	}
	if !strings.Contains(report, "Category Breakdown") {
		t.Error("report missing category breakdown")
	}
}

func TestBenchmarkReportJSON(t *testing.T) {
	scanner := &mockScanner{name: "TestScanner"}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	data, err := BenchmarkReportJSON(result)
	if err != nil {
		t.Fatalf("BenchmarkReportJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("BenchmarkReportJSON: empty output")
	}
	// Verify it's valid JSON.
	if data[0] != '{' {
		t.Errorf("JSON output should start with '{', got %c", data[0])
	}
}

// mockAllDetectedScanner flags everything as detected (even negative records).
type mockAllDetectedScanner struct{}

func (m *mockAllDetectedScanner) Scan(ctx context.Context, record SXCRecord) (*BenchmarkDetection, error) {
	return &BenchmarkDetection{
		Detected: true,
		Threats: []BenchmarkThreat{
			{Type: "mock", Severity: 3, Message: "detected", Category: "all"},
		},
		LatencyMillis: 1,
	}, nil
}

func (m *mockAllDetectedScanner) Name() string { return "AllDetected" }

func TestBenchmarkRunner_AllDetected(t *testing.T) {
	scanner := &mockAllDetectedScanner{}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	// An over-sensitive scanner: TP=79, FP=79, TN=0, FN=0.
	if result.TruePositives != 79 {
		t.Errorf("TP: got %d, want 79", result.TruePositives)
	}
	if result.FalsePositives != 79 {
		t.Errorf("FP: got %d, want 79", result.FalsePositives)
	}
	if result.TrueNegatives != 0 {
		t.Errorf("TN: got %d, want 0", result.TrueNegatives)
	}
	if result.FalseNegatives != 0 {
		t.Errorf("FN: got %d, want 0", result.FalseNegatives)
	}
	// Precision should be 0.5 (79 TP / 158 total flagged).
	if result.Precision != 0.5 {
		t.Errorf("Precision: got %.4f, want 0.5", result.Precision)
	}
	// Recall should be 1.0 (79 TP / 79 actual positives).
	if result.Recall != 1.0 {
		t.Errorf("Recall: got %.4f, want 1.0", result.Recall)
	}
}

// mockNoneDetectedScanner flags nothing as detected (even positive records).
type mockNoneDetectedScanner struct{}

func (m *mockNoneDetectedScanner) Scan(ctx context.Context, record SXCRecord) (*BenchmarkDetection, error) {
	return &BenchmarkDetection{
		Detected:      false,
		Threats:       []BenchmarkThreat{},
		LatencyMillis: 1,
	}, nil
}

func (m *mockNoneDetectedScanner) Name() string { return "NoneDetected" }

func TestBenchmarkRunner_NoneDetected(t *testing.T) {
	scanner := &mockNoneDetectedScanner{}
	kr := mustKeyRing(t)
	runner, err := NewBenchmarkRunner(scanner, kr)
	if err != nil {
		t.Fatalf("NewBenchmarkRunner: %v", err)
	}

	result, err := runner.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}

	// An under-sensitive scanner: TP=0, FP=0, TN=79, FN=79.
	if result.TruePositives != 0 {
		t.Errorf("TP: got %d, want 0", result.TruePositives)
	}
	if result.FalseNegatives != 79 {
		t.Errorf("FN: got %d, want 79", result.FalseNegatives)
	}
	if result.TrueNegatives != 79 {
		t.Errorf("TN: got %d, want 79", result.TrueNegatives)
	}
	// Precision should be 0 (0 TP / 0 flagged).
	if result.Precision != 0 {
		t.Errorf("Precision: got %.4f, want 0", result.Precision)
	}
	// Recall should be 0 (0 TP / 79 actual positives).
	if result.Recall != 0 {
		t.Errorf("Recall: got %.4f, want 0", result.Recall)
	}
}

// =====================================================================
// Nil scanner / nil keyring tests
// =====================================================================

func TestNewBenchmarkRunner_NilScanner(t *testing.T) {
	kr := mustKeyRing(t)
	_, err := NewBenchmarkRunner(nil, kr)
	if err == nil {
		t.Error("expected error for nil scanner, got nil")
	}
}

func TestNewBenchmarkRunner_NilKeyRing(t *testing.T) {
	scanner := &mockScanner{name: "Test"}
	_, err := NewBenchmarkRunner(scanner, nil)
	if err == nil {
		t.Error("expected error for nil keyRing, got nil")
	}
}

// =====================================================================
// Helpers
// =====================================================================

func mustKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	return kr
}