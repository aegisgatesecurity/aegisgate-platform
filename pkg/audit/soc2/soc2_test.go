// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Audit Automation Tests
// =========================================================================

package soc2

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// mustKeyRing creates a valid keyring for signing tests.
func mustKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	return kr
}

// mockComplianceScanner is a test double for ComplianceScanner.
type mockComplianceScanner struct {
	enforced    bool
	score       float64
	total       int
	enforcedCnt int
}

func (m *mockComplianceScanner) ScanFramework(ctx context.Context, framework string, lic interface{}) (*compliance.FrameworkScanResult, error) {
	reason := "module_not_owned"
	if m.enforced {
		reason = "module_owned"
	}
	return &compliance.FrameworkScanResult{
		Framework:        "soc2",
		DisplayName:      "SOC 2 Type II",
		Enforced:         m.enforced,
		Score:            m.score,
		ControlsTotal:    m.total,
		ControlsEnforced: m.enforcedCnt,
		CompliancePct:    m.score,
		ReasonEnforced:   reason,
		LastScan:         time.Now().UTC(),
	}, nil
}

// ============================================================================
// TrustServiceCategory tests
// ============================================================================

func TestAllTrustServiceCategories(t *testing.T) {
	cats := AllTrustServiceCategories()
	if len(cats) != 5 {
		t.Errorf("expected 5 categories, got %d", len(cats))
	}
	expected := map[TrustServiceCategory]bool{
		TSCSecurity: true, TSCAvailability: true,
		TSCProcessingIntegrity: true, TSCConfidentiality: true,
		TSCPrivacy: true,
	}
	for _, c := range cats {
		if !expected[c] {
			t.Errorf("unexpected category: %s", c)
		}
	}
}

func TestTrustServiceCategoryString(t *testing.T) {
	tests := []struct {
		cat  TrustServiceCategory
		want string
	}{
		{TSCSecurity, "security"},
		{TSCAvailability, "availability"},
		{TSCProcessingIntegrity, "processing_integrity"},
		{TSCConfidentiality, "confidentiality"},
		{TSCPrivacy, "privacy"},
	}
	for _, tt := range tests {
		if got := tt.cat.String(); got != tt.want {
			t.Errorf("TrustServiceCategory(%q).String() = %q, want %q", tt.cat, got, tt.want)
		}
	}
}

// ============================================================================
// EvidenceCollector tests
// ============================================================================

func TestEvidenceCollector_NilScanner(t *testing.T) {
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, nil)
	ctx := context.Background()
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect with nil scanner: %v", err)
	}
	// Should still get all 15 controls with policy references
	if len(evidence) != 15 {
		t.Errorf("expected 15 controls with nil scanner, got %d", len(evidence))
	}
	// All controls should have StatusNotMet since no scanner
	for _, ce := range evidence {
		if ce.Status != StatusNotMet {
			t.Errorf("expected StatusNotMet for %s, got %s", ce.ControlID, ce.Status)
		}
	}
}

func TestEvidenceCollector_WithContextCancellation(t *testing.T) {
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()
	_, err := collector.Collect(ctx, start, end)
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

func TestEvidenceCollector_InvalidPeriod(t *testing.T) {
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, nil)
	start := time.Now()
	end := time.Now().Add(-24 * time.Hour) // end before start

	_, err := collector.Collect(context.Background(), start, end)
	if err == nil {
		t.Error("expected error for invalid period")
	}
}

func TestEvidenceCollector_CollectAll(t *testing.T) {
	scanner := &mockComplianceScanner{
		enforced:    true,
		score:       80.0,
		total:       15,
		enforcedCnt: 12,
	}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	ctx := context.Background()
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(evidence) != 15 {
		t.Errorf("expected 15 controls, got %d", len(evidence))
	}
	// All controls should be StatusMet since scanner says enforced
	for _, ce := range evidence {
		if ce.Status != StatusMet {
			t.Errorf("expected StatusMet for %s, got %s", ce.ControlID, ce.Status)
		}
	}
}

func TestEvidenceCollector_FilterByCategory(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		Categories:   []TrustServiceCategory{TSCSecurity},
	}
	collector := NewEvidenceCollector(config, scanner)
	ctx := context.Background()
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Security has 10 controls (CC1.1, CC1.4, CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.2, CC7.3, CC7.4 + AI-001)
	// That's 10 Security controls + 1 AI-001 = 10 (AI-001 maps to Security too)
	for _, ce := range evidence {
		if ce.Category != TSCSecurity {
			t.Errorf("expected only Security controls, got %s", ce.Category)
		}
	}
}

func TestEvidenceCollector_EvidenceSources(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	ctx := context.Background()
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, ce := range evidence {
		hasCompliance := false
		hasPolicy := false
		for _, src := range ce.Sources {
			if src.Source == EvidenceSourceCompliance {
				hasCompliance = true
			}
			if src.Source == EvidenceSourcePolicy {
				hasPolicy = true
			}
		}
		if !hasCompliance {
			t.Errorf("%s: missing compliance source", ce.ControlID)
		}
		if !hasPolicy {
			t.Errorf("%s: missing policy source", ce.ControlID)
		}
	}
}

// ============================================================================
// soc2Controls tests
// ============================================================================

func TestSoc2Controls(t *testing.T) {
	controls := soc2Controls()
	if len(controls) != 15 {
		t.Errorf("expected 15 SOC 2 controls, got %d", len(controls))
	}
	expectedIDs := map[string]bool{
		"SOC2-CC1.1": true, "SOC2-CC1.4": true,
		"SOC2-CC6.1": true, "SOC2-CC6.2": true, "SOC2-CC6.3": true,
		"SOC2-CC6.6": true, "SOC2-CC6.7": true,
		"SOC2-CC7.2": true, "SOC2-CC7.3": true, "SOC2-CC7.4": true,
		"SOC2-PI1.2": true,
		"SOC2-A1.1": true,
		"SOC2-C1.1": true, "SOC2-C2.1": true,
		"SOC2-AI-001": true,
	}
	for _, ctrl := range controls {
		if !expectedIDs[ctrl.ID] {
			t.Errorf("unexpected control ID: %s", ctrl.ID)
		}
	}
}

// ============================================================================
// Policy tests
// ============================================================================

func TestPolicyTemplates(t *testing.T) {
	policies := PolicyTemplates()
	if len(policies) != 5 {
		t.Errorf("expected 5 policy templates, got %d", len(policies))
	}
	for _, p := range policies {
		if p.ID == "" {
			t.Error("policy has empty ID")
		}
		if p.Title == "" {
			t.Error("policy has empty title")
		}
		if p.Content == "" {
			t.Error("policy has empty content")
		}
		if len(p.Controls) == 0 {
			t.Errorf("policy %s has no controls", p.ID)
		}
	}
}

func TestPolicyForCategory(t *testing.T) {
	policies, err := PolicyForCategory(TSCSecurity)
	if err != nil {
		t.Fatalf("PolicyForCategory: %v", err)
	}
	if len(policies) == 0 {
		t.Error("expected at least one security policy")
	}
	for _, p := range policies {
		if p.Category != TSCSecurity {
			t.Errorf("expected Security category, got %s", p.Category)
		}
	}
}

func TestPolicyForControl(t *testing.T) {
	policies, err := PolicyForControl("SOC2-CC6.1")
	if err != nil {
		t.Fatalf("PolicyForControl: %v", err)
	}
	if len(policies) == 0 {
		t.Error("expected at least one policy for CC6.1")
	}
}

// ============================================================================
// Workpaper tests
// ============================================================================

func TestGenerateWorkpapers(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	ctx := context.Background()
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	workpapers, err := GenerateWorkpapers(evidence, start, end, "TestOrg", "TestAuditor")
	if err != nil {
		t.Fatalf("GenerateWorkpapers: %v", err)
	}
	if len(workpapers) == 0 {
		t.Error("expected at least one workpaper")
	}
	for _, wp := range workpapers {
		if wp.WorkpaperID == "" {
			t.Error("workpaper has empty ID")
		}
		if wp.Category == "" {
			t.Error("workpaper has empty category")
		}
		if len(wp.Procedures) == 0 {
			t.Errorf("workpaper %s has no procedures", wp.WorkpaperID)
		}
		if len(wp.Results) == 0 {
			t.Errorf("workpaper %s has no results", wp.WorkpaperID)
		}
	}
}

func TestGenerateWorkpaper_SingleCategory(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		Categories:   []TrustServiceCategory{TSCAvailability},
	}
	collector := NewEvidenceCollector(config, scanner)
	ctx := context.Background()
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	evidence, err := collector.Collect(ctx, start, end)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	wp, err := GenerateWorkpaper(TSCAvailability, evidence, start, end, "TestOrg", "TestAuditor")
	if err != nil {
		t.Fatalf("GenerateWorkpaper: %v", err)
	}
	if wp.Category != TSCAvailability {
		t.Errorf("expected Availability category, got %s", wp.Category)
	}
}

func TestGenerateWorkpaper_NoEvidence(t *testing.T) {
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()

	// Privacy category has no controls in our current set
	_, err := GenerateWorkpaper(TSCPrivacy, []ControlEvidence{}, start, end, "TestOrg", "TestAuditor")
	if err == nil {
		t.Error("expected error for category with no evidence")
	}
}

func TestWorkpaperToText(t *testing.T) {
	wp := &Workpaper{
		WorkpaperID: "WP-SEC-A1B2C3D4",
		Category:    TSCSecurity,
		Title:       "SOC 2 Security Workpaper",
		Objective:   "Evaluate security controls",
		Scope:       "All SOC 2 security controls",
		Procedures: []AuditProcedure{
			{Step: 1, Description: "Inspect access controls", Method: "inspection"},
			{Step: 2, Description: "Test authentication", Method: "testing"},
		},
		Results: []ControlResult{
			{ControlID: "SOC2-CC6.1", ControlName: "Access Controls", Status: StatusMet, Details: "All requirements met"},
		},
		Conclusion: "Security controls are operating effectively.",
		PreparedBy: "TestAuditor",
		Date:       time.Now(),
	}

	text := WorkpaperToText(wp)
	if !strings.Contains(text, "WP-SEC-A1B2C3D4") {
		t.Error("text output missing workpaper ID")
	}
	if !strings.Contains(text, "Security") {
		t.Error("text output missing category")
	}
	if !strings.Contains(text, "Access Controls") {
		t.Error("text output missing control name")
	}
}

func TestWorkpaperToJSON(t *testing.T) {
	wp := &Workpaper{
		WorkpaperID: "WP-SEC-TEST1234",
		Category:    TSCSecurity,
		Title:       "SOC 2 Security Workpaper",
		Objective:   "Test",
		Scope:       "Test",
		Procedures:  []AuditProcedure{},
		Results:     []ControlResult{},
		Conclusion:  "Test conclusion",
		PreparedBy:  "TestAuditor",
		Date:        time.Now(),
	}

	data, err := WorkpaperToJSON(wp)
	if err != nil {
		t.Fatalf("WorkpaperToJSON: %v", err)
	}
	if !json.Valid(data) {
		t.Error("WorkpaperToJSON produced invalid JSON")
	}
	var parsed Workpaper
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal workpaper JSON: %v", err)
	}
	if parsed.WorkpaperID != "WP-SEC-TEST1234" {
		t.Errorf("expected workpaper ID WP-SEC-TEST1234, got %s", parsed.WorkpaperID)
	}
}

// ============================================================================
// Report tests
// ============================================================================

func TestReportBuilder_Build(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		PeriodStart:  time.Now().Add(-90 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType2,
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if report.Organization != "TestOrg" {
		t.Errorf("expected Organization TestOrg, got %s", report.Organization)
	}
	if report.Auditor != "TestAuditor" {
		t.Errorf("expected Auditor TestAuditor, got %s", report.Auditor)
	}
	if report.Type != AuditType2 {
		t.Errorf("expected Type2, got %s", report.Type)
	}
	if len(report.Controls) == 0 {
		t.Error("report has no controls")
	}
	if len(report.Policies) == 0 {
		t.Error("report has no policies")
	}
	if len(report.Workpapers) == 0 {
		t.Error("report has no workpapers")
	}
}

func TestReportBuilder_SignReport(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		PeriodStart:  time.Now().Add(-90 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType2,
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	kr := mustKeyRing(t)
	env, err := SignReport(report, kr)
	if err != nil {
		t.Fatalf("SignReport: %v", err)
	}
	if env == nil {
		t.Fatal("SignReport returned nil envelope")
	}
	if env.Type != "audit.soc2.v1" {
		t.Errorf("expected type audit.soc2.v1, got %s", env.Type)
	}
}

func TestComputeSummary(t *testing.T) {
	evidence := []ControlEvidence{
		{ControlID: "CC6.1", Status: StatusMet},
		{ControlID: "CC6.2", Status: StatusMet},
		{ControlID: "CC6.3", Status: StatusNotMet},
		{ControlID: "CC6.6", Status: StatusPartiallyMet},
		{ControlID: "CC6.7", Status: StatusNotApplicable},
	}
	summary := computeSummary(evidence)
	if summary.TotalControls != 5 {
		t.Errorf("expected 5 total, got %d", summary.TotalControls)
	}
	if summary.ControlsMet != 2 {
		t.Errorf("expected 2 met, got %d", summary.ControlsMet)
	}
	if summary.ControlsNotMet != 1 {
		t.Errorf("expected 1 not met, got %d", summary.ControlsNotMet)
	}
	if summary.ControlsPartial != 1 {
		t.Errorf("expected 1 partial, got %d", summary.ControlsPartial)
	}
	if summary.ControlsNA != 1 {
		t.Errorf("expected 1 N/A, got %d", summary.ControlsNA)
	}
}

func TestReportToText(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		PeriodStart:  time.Now().Add(-90 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType2,
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	text := ReportToText(report)
	if !strings.Contains(text, "SOC 2") {
		t.Error("text report missing SOC 2 header")
	}
	if !strings.Contains(text, "TestOrg") {
		t.Error("text report missing organization")
	}
	if !strings.Contains(text, "Summary") {
		t.Error("text report missing summary section")
	}
}

func TestReportToJSON(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 80.0, total: 15, enforcedCnt: 12}
	config := EvidenceCollectorConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "TestOrg",
		Auditor:      "TestAuditor",
		PeriodStart:  time.Now().Add(-90 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType2,
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	data, err := ReportToJSON(report)
	if err != nil {
		t.Fatalf("ReportToJSON: %v", err)
	}
	if !json.Valid(data) {
		t.Error("ReportToJSON produced invalid JSON")
	}
}