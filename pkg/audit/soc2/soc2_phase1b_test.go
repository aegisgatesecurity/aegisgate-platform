// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Audit Automation Phase 1b Tests
// =========================================================================
//
// soc2_phase1b_test.go targets functions with low coverage identified in
// the Phase 1b coverage push (84.1% → 90%+). Tests focus on edge cases,
// error paths, and previously untested functions such as SignWorkpaper
// and computeConclusion.
package soc2

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
)

// ============================================================================
// enrichFromScan tests (evidence.go:196 — was 71.4%)
// ============================================================================

func TestPhase1bEnrichFromScan_Enforced(t *testing.T) {
	ce := ControlEvidence{
		ControlID:   "SOC2-CC6.1",
		ControlName: "Access Controls",
		Category:    TSCSecurity,
		Status:      StatusNotMet,
		Sources:     []EvidenceRef{},
		Findings:    []string{},
	}
	sr := &compliance.FrameworkScanResult{
		Framework:        "soc2",
		DisplayName:      "SOC 2 Type II",
		Enforced:         true,
		CompliancePct:    85.0,
		ControlsTotal:    15,
		ControlsEnforced: 12,
		LastScan:         time.Now().UTC(),
	}
	result := enrichFromScan(ce, sr)
	if result.Status != StatusMet {
		t.Errorf("expected StatusMet, got %s", result.Status)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings to be populated")
	}
	if !strings.Contains(result.Findings[0], "enforced") {
		t.Errorf("expected finding to mention enforced, got %s", result.Findings[0])
	}
	// Should have a compliance source appended
	found := false
	for _, src := range result.Sources {
		if src.Source == EvidenceSourceCompliance {
			found = true
			if src.ReferenceID != "soc2" {
				t.Errorf("expected reference ID soc2, got %s", src.ReferenceID)
			}
		}
	}
	if !found {
		t.Error("expected compliance source to be appended")
	}
}

func TestPhase1bEnrichFromScan_NotEnforced(t *testing.T) {
	ce := ControlEvidence{
		ControlID:   "SOC2-CC6.1",
		ControlName: "Access Controls",
		Category:    TSCSecurity,
		Status:      StatusMet,
		Sources:     []EvidenceRef{},
		Findings:    []string{},
	}
	sr := &compliance.FrameworkScanResult{
		Framework:         "soc2",
		DisplayName:       "SOC 2 Type II",
		Enforced:          false,
		CompliancePct:     40.0,
		ControlsTotal:     15,
		ControlsEnforced:  6,
		ReasonNotEnforced: "module_not_owned",
		LastScan:          time.Now().UTC(),
	}
	result := enrichFromScan(ce, sr)
	if result.Status != StatusPartiallyMet {
		t.Errorf("expected StatusPartiallyMet, got %s", result.Status)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings to be populated")
	}
	if !strings.Contains(result.Findings[0], "not enforced") {
		t.Errorf("expected finding to mention not enforced, got %s", result.Findings[0])
	}
}

// ============================================================================
// PolicyForCategory tests (policy.go:204 — was 85.7%)
// ============================================================================

func TestPhase1bPolicyForCategory_UnknownCategory(t *testing.T) {
	// Use a category that has no policies
	unknownCat := TrustServiceCategory("nonexistent")
	policies, err := PolicyForCategory(unknownCat)
	if err == nil {
		t.Error("expected error for unknown category")
	}
	if policies != nil {
		t.Errorf("expected nil policies, got %d", len(policies))
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention the category name, got %s", err.Error())
	}
}

func TestPhase1bPolicyForCategory_AllKnownCategories(t *testing.T) {
	for _, cat := range AllTrustServiceCategories() {
		policies, err := PolicyForCategory(cat)
		if err != nil {
			t.Errorf("PolicyForCategory(%s): %v", cat, err)
		}
		if len(policies) == 0 {
			t.Errorf("expected at least one policy for %s", cat)
		}
	}
}

// ============================================================================
// PolicyForControl tests (policy.go:220 — was 88.9%)
// ============================================================================

func TestPhase1bPolicyForControl_UnknownControl(t *testing.T) {
	policies, err := PolicyForControl("SOC2-UNKNOWN-999")
	if err == nil {
		t.Error("expected error for unknown control")
	}
	if policies != nil {
		t.Errorf("expected nil policies, got %d", len(policies))
	}
	if !strings.Contains(err.Error(), "SOC2-UNKNOWN-999") {
		t.Errorf("error should mention the control ID, got %s", err.Error())
	}
}

func TestPhase1bPolicyForControl_ExistingControls(t *testing.T) {
	// Test a few known controls to exercise the match loop
	controls := []string{"SOC2-CC1.1", "SOC2-A1.1", "SOC2-C2.1", "SOC2-PI1.2"}
	for _, ctrlID := range controls {
		policies, err := PolicyForControl(ctrlID)
		if err != nil {
			t.Errorf("PolicyForControl(%s): %v", ctrlID, err)
		}
		if len(policies) == 0 {
			t.Errorf("expected at least one policy for %s", ctrlID)
		}
	}
}

// ============================================================================
// Build tests (report.go:64 — was 86.4%)
// ============================================================================

func TestPhase1bBuild_EmptyCategoriesUsesAll(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: true, score: 90.0, total: 15, enforcedCnt: 15}
	config := EvidenceCollectorConfig{
		Organization: "Phase1bOrg",
		Auditor:      "Phase1bAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "Phase1bOrg",
		Auditor:      "Phase1bAuditor",
		PeriodStart:  time.Now().Add(-30 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType1,
		// Categories left empty → should default to all
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if report.Type != AuditType1 {
		t.Errorf("expected Type1, got %s", report.Type)
	}
	if len(report.Policies) != 5 {
		t.Errorf("expected 5 policies (all categories), got %d", len(report.Policies))
	}
}

func TestPhase1bBuild_SpecificCategories(t *testing.T) {
	scanner := &mockComplianceScanner{enforced: false, score: 0, total: 15, enforcedCnt: 0}
	config := EvidenceCollectorConfig{
		Organization: "Phase1bOrg",
		Auditor:      "Phase1bAuditor",
	}
	collector := NewEvidenceCollector(config, scanner)
	builder := NewReportBuilder(ReportConfig{
		Organization: "Phase1bOrg",
		Auditor:      "Phase1bAuditor",
		PeriodStart:  time.Now().Add(-30 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		Type:         AuditType2,
		Categories:   []TrustServiceCategory{TSCSecurity},
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Only security policies should be included (1 policy for security)
	if len(report.Policies) != 1 {
		t.Errorf("expected 1 policy (security only), got %d", len(report.Policies))
	}
	for _, p := range report.Policies {
		if p.Category != TSCSecurity {
			t.Errorf("expected only Security policies, got %s", p.Category)
		}
	}
}

// ============================================================================
// SignReport tests (report.go:122 — was 76.2%)
// ============================================================================

func TestPhase1bSignReport_NilReport(t *testing.T) {
	kr := mustKeyRing(t)
	_, err := SignReport(nil, kr)
	if err == nil {
		t.Error("expected error for nil report")
	}
	if !strings.Contains(err.Error(), "nil report") {
		t.Errorf("expected nil report error, got %s", err.Error())
	}
}

func TestPhase1bSignReport_NilKeyRing(t *testing.T) {
	report := &SOC2AuditReport{
		ReportID:     "SOC2-20260101-deadbeef",
		Organization: "TestOrg",
		Auditor:      "TestAud",
		PeriodStart:  time.Now().Add(-30 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		GeneratedAt:  time.Now().UTC(),
		Type:         AuditType2,
		Controls:     []ControlEvidence{},
		Summary:      AuditSummary{},
	}
	_, err := SignReport(report, nil)
	if err == nil {
		t.Error("expected error for nil keyring")
	}
	if !strings.Contains(err.Error(), "nil keyring") {
		t.Errorf("expected nil keyring error, got %s", err.Error())
	}
}

func TestPhase1bSignReport_ValidReport(t *testing.T) {
	report := &SOC2AuditReport{
		ReportID:     "SOC2-20260101-test1234",
		Organization: "TestOrg",
		Auditor:      "TestAud",
		PeriodStart:  time.Now().Add(-30 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		GeneratedAt:  time.Now().UTC(),
		Type:         AuditType1,
		Controls: []ControlEvidence{
			{
				ControlID:    "SOC2-CC6.1",
				ControlName:  "Access Controls",
				Category:     TSCSecurity,
				Status:       StatusMet,
				Sources:      []EvidenceRef{},
				LastAssessed: time.Now().UTC(),
			},
		},
		Summary: AuditSummary{
			TotalControls: 1,
			ControlsMet:   1,
			ScorePct:      100.0,
		},
	}
	kr := mustKeyRing(t)
	env, err := SignReport(report, kr)
	if err != nil {
		t.Fatalf("SignReport: %v", err)
	}
	if env == nil {
		t.Fatal("returned nil envelope")
	}
	if env.Type != "audit.soc2.v1" {
		t.Errorf("expected type audit.soc2.v1, got %s", env.Type)
	}
	if !strings.Contains(env.Subject, "SOC2-20260101-test1234") {
		t.Errorf("expected subject to contain report ID, got %s", env.Subject)
	}
}

// ============================================================================
// ReportToJSON tests (report.go:219 — was 66.7%)
// ============================================================================

func TestPhase1bReportToJSON_NilReport(t *testing.T) {
	_, err := ReportToJSON(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
	if !strings.Contains(err.Error(), "nil report") {
		t.Errorf("expected nil report error, got %s", err.Error())
	}
}

func TestPhase1bReportToJSON_ValidReport(t *testing.T) {
	report := &SOC2AuditReport{
		ReportID:     "SOC2-TEST-JSON-01",
		Organization: "JSONTestOrg",
		Auditor:      "JSONTestAud",
		PeriodStart:  time.Now().Add(-30 * 24 * time.Hour),
		PeriodEnd:    time.Now(),
		GeneratedAt:  time.Now().UTC(),
		Type:         AuditType2,
		Controls: []ControlEvidence{
			{
				ControlID:    "SOC2-CC6.1",
				ControlName:  "Access Controls",
				Category:     TSCSecurity,
				Status:       StatusMet,
				Sources:      []EvidenceRef{},
				LastAssessed: time.Now().UTC(),
			},
		},
		Summary: AuditSummary{
			TotalControls: 1,
			ControlsMet:   1,
			ScorePct:      100.0,
		},
	}
	data, err := ReportToJSON(report)
	if err != nil {
		t.Fatalf("ReportToJSON: %v", err)
	}
	if !json.Valid(data) {
		t.Error("ReportToJSON produced invalid JSON")
	}
	var parsed SOC2AuditReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.ReportID != "SOC2-TEST-JSON-01" {
		t.Errorf("expected report ID SOC2-TEST-JSON-01, got %s", parsed.ReportID)
	}
	if parsed.Organization != "JSONTestOrg" {
		t.Errorf("expected org JSONTestOrg, got %s", parsed.Organization)
	}
}

// ============================================================================
// GenerateWorkpaper tests (workpaper.go:106 — was 87.9%)
// ============================================================================

func TestPhase1bGenerateWorkpaper_AllMet(t *testing.T) {
	evidence := []ControlEvidence{
		{
			ControlID:    "SOC2-CC6.1",
			ControlName:  "Access Controls",
			Category:     TSCSecurity,
			Status:       StatusMet,
			Sources:      []EvidenceRef{},
			Findings:     []string{"Control fully implemented"},
			LastAssessed: time.Now().UTC(),
		},
	}
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()
	wp, err := GenerateWorkpaper(TSCSecurity, evidence, start, end, "TestOrg", "TestAud")
	if err != nil {
		t.Fatalf("GenerateWorkpaper: %v", err)
	}
	if wp.Category != TSCSecurity {
		t.Errorf("expected Security, got %s", wp.Category)
	}
	if !strings.Contains(wp.Title, "Security") {
		t.Errorf("expected title to contain Security, got %s", wp.Title)
	}
	if len(wp.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(wp.Results))
	}
	if wp.Results[0].Details != "Control fully implemented" {
		t.Errorf("expected findings as details, got %s", wp.Results[0].Details)
	}
}

func TestPhase1bGenerateWorkpaper_EmptyFindingsDefaultDetails(t *testing.T) {
	evidence := []ControlEvidence{
		{
			ControlID:    "SOC2-CC6.1",
			ControlName:  "Access Controls",
			Category:     TSCSecurity,
			Status:       StatusNotMet,
			Sources:      []EvidenceRef{},
			Findings:     []string{}, // empty findings
			LastAssessed: time.Now().UTC(),
		},
	}
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()
	wp, err := GenerateWorkpaper(TSCSecurity, evidence, start, end, "TestOrg", "TestAud")
	if err != nil {
		t.Fatalf("GenerateWorkpaper: %v", err)
	}
	// When findings are empty, details should be the default format
	if !strings.Contains(wp.Results[0].Details, "SOC2-CC6.1") {
		t.Errorf("expected default details with control ID, got %s", wp.Results[0].Details)
	}
	if !strings.Contains(wp.Results[0].Details, "not_met") {
		t.Errorf("expected default details with status, got %s", wp.Results[0].Details)
	}
}

func TestPhase1bGenerateWorkpaper_FiltersByCategory(t *testing.T) {
	// Pass evidence from multiple categories; only matching ones should be in results
	evidence := []ControlEvidence{
		{
			ControlID:    "SOC2-CC6.1",
			ControlName:  "Access Controls",
			Category:     TSCSecurity,
			Status:       StatusMet,
			Sources:      []EvidenceRef{},
			LastAssessed: time.Now().UTC(),
		},
		{
			ControlID:    "SOC2-A1.1",
			ControlName:  "Capacity Planning",
			Category:     TSCAvailability,
			Status:       StatusMet,
			Sources:      []EvidenceRef{},
			LastAssessed: time.Now().UTC(),
		},
	}
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()
	wp, err := GenerateWorkpaper(TSCSecurity, evidence, start, end, "TestOrg", "TestAud")
	if err != nil {
		t.Fatalf("GenerateWorkpaper: %v", err)
	}
	if len(wp.Results) != 1 {
		t.Errorf("expected 1 result (security only), got %d", len(wp.Results))
	}
	if wp.Results[0].ControlID != "SOC2-CC6.1" {
		t.Errorf("expected SOC2-CC6.1, got %s", wp.Results[0].ControlID)
	}
}

// ============================================================================
// SignWorkpaper tests (workpaper.go:193 — was 0.0%) ** BIGGEST GAIN **
// ============================================================================

func TestPhase1bSignWorkpaper_NilWorkpaper(t *testing.T) {
	kr := mustKeyRing(t)
	_, err := SignWorkpaper(nil, kr)
	if err == nil {
		t.Error("expected error for nil workpaper")
	}
	if !strings.Contains(err.Error(), "nil workpaper") {
		t.Errorf("expected nil workpaper error, got %s", err.Error())
	}
}

func TestPhase1bSignWorkpaper_NilKeyRing(t *testing.T) {
	wp := &Workpaper{
		WorkpaperID: "WP-SEC-TEST0001",
		Category:    TSCSecurity,
		Title:       "Test Workpaper",
		Objective:   "Test",
		Scope:       "Test",
		Procedures:  []AuditProcedure{},
		Results:     []ControlResult{},
		Conclusion:  "Test",
		PreparedBy:  "TestAud",
		Date:        time.Now(),
	}
	_, err := SignWorkpaper(wp, nil)
	if err == nil {
		t.Error("expected error for nil keyring")
	}
}

func TestPhase1bSignWorkpaper_ValidWorkpaper(t *testing.T) {
	wp := &Workpaper{
		WorkpaperID: "WP-SEC-VALID001",
		Category:    TSCSecurity,
		Title:       "SOC 2 Security Workpaper",
		Objective:   "Evaluate security controls",
		Scope:       "All SOC 2 security controls",
		Procedures: []AuditProcedure{
			{Step: 1, Description: "Inspect access controls", Method: "inspect"},
		},
		Results: []ControlResult{
			{ControlID: "SOC2-CC6.1", ControlName: "Access Controls", Status: StatusMet, Details: "Met"},
		},
		Conclusion: "All controls met.",
		PreparedBy: "TestAud",
		Date:       time.Now(),
	}
	kr := mustKeyRing(t)
	env, err := SignWorkpaper(wp, kr)
	if err != nil {
		t.Fatalf("SignWorkpaper: %v", err)
	}
	if env == nil {
		t.Fatal("returned nil envelope")
	}
	if env.Type != "audit.soc2.v1" {
		t.Errorf("expected type audit.soc2.v1, got %s", env.Type)
	}
	if !strings.Contains(env.Subject, "WP-SEC-VALID001") {
		t.Errorf("expected subject to contain workpaper ID, got %s", env.Subject)
	}
	// Payload should be valid JSON (the marshaled workpaper)
	if !json.Valid(env.RawPayload) {
		t.Error("envelope payload is not valid JSON")
	}
}

func TestPhase1bSignWorkpaper_GeneratedWorkpaper(t *testing.T) {
	// Sign a workpaper generated by GenerateWorkpaper to exercise the full path
	evidence := []ControlEvidence{
		{
			ControlID:    "SOC2-CC6.1",
			ControlName:  "Access Controls",
			Category:     TSCSecurity,
			Status:       StatusMet,
			Sources:      []EvidenceRef{},
			Findings:     []string{"All checks passed"},
			LastAssessed: time.Now().UTC(),
		},
	}
	start := time.Now().Add(-90 * 24 * time.Hour)
	end := time.Now()
	wp, err := GenerateWorkpaper(TSCSecurity, evidence, start, end, "TestOrg", "TestAud")
	if err != nil {
		t.Fatalf("GenerateWorkpaper: %v", err)
	}
	kr := mustKeyRing(t)
	env, err := SignWorkpaper(wp, kr)
	if err != nil {
		t.Fatalf("SignWorkpaper with generated workpaper: %v", err)
	}
	if env == nil {
		t.Fatal("returned nil envelope")
	}
	if !strings.HasPrefix(env.Subject, "aegisgate://audit/WP-") {
		t.Errorf("expected subject prefix aegisgate://audit/WP-, got %s", env.Subject)
	}
}

// ============================================================================
// WorkpaperToJSON tests (workpaper.go:261 — was 66.7%)
// ============================================================================

func TestPhase1bWorkpaperToJSON_NilWorkpaper(t *testing.T) {
	_, err := WorkpaperToJSON(nil)
	if err == nil {
		t.Error("expected error for nil workpaper")
	}
	if !strings.Contains(err.Error(), "nil workpaper") {
		t.Errorf("expected nil workpaper error, got %s", err.Error())
	}
}

func TestPhase1bWorkpaperToJSON_ValidWorkpaper(t *testing.T) {
	wp := &Workpaper{
		WorkpaperID: "WP-CONF-JSON0001",
		Category:    TSCConfidentiality,
		Title:       "SOC 2 Confidentiality Workpaper",
		Objective:   "Evaluate confidentiality controls",
		Scope:       "Confidentiality controls scope",
		Procedures: []AuditProcedure{
			{Step: 1, Description: "Inspect data classification", Method: "inspect"},
			{Step: 2, Description: "Verify encryption", Method: "verify"},
		},
		Results: []ControlResult{
			{ControlID: "SOC2-C1.1", ControlName: "Confidential Info", Status: StatusMet, Details: "All met"},
			{ControlID: "SOC2-C2.1", ControlName: "Third-Party Risk", Status: StatusPartiallyMet, Details: "Partial"},
		},
		Conclusion: "Mostly met.",
		PreparedBy: "TestAud",
		ReviewedBy: "Reviewer",
		Date:       time.Now(),
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
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.WorkpaperID != "WP-CONF-JSON0001" {
		t.Errorf("expected WP-CONF-JSON0001, got %s", parsed.WorkpaperID)
	}
	if parsed.ReviewedBy != "Reviewer" {
		t.Errorf("expected ReviewedBy Reviewer, got %s", parsed.ReviewedBy)
	}
	if len(parsed.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(parsed.Results))
	}
}

// ============================================================================
// computeConclusion tests (workpaper.go:291 — was 53.3%)
// ============================================================================

func TestPhase1bComputeConclusion_EmptyResults(t *testing.T) {
	result := computeConclusion([]ControlResult{})
	if result != "No controls evaluated." {
		t.Errorf("expected 'No controls evaluated.', got %s", result)
	}
}

func TestPhase1bComputeConclusion_AllMet(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusMet},
		{ControlID: "C2", Status: StatusMet},
		{ControlID: "C3", Status: StatusMet},
	}
	result := computeConclusion(results)
	if !strings.Contains(result, "All 3 applicable controls met") {
		t.Errorf("expected all met message, got %s", result)
	}
	if strings.Contains(result, "Exceptions") {
		t.Errorf("should not mention exceptions when all met, got %s", result)
	}
}

func TestPhase1bComputeConclusion_NotMetPresent(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusMet},
		{ControlID: "C2", Status: StatusNotMet},
		{ControlID: "C3", Status: StatusPartiallyMet},
	}
	result := computeConclusion(results)
	if !strings.Contains(result, "Exceptions identified") {
		t.Errorf("expected exceptions message, got %s", result)
	}
	if !strings.Contains(result, "1 of 3") {
		t.Errorf("expected 1 of 3 applicable, got %s", result)
	}
}

func TestPhase1bComputeConclusion_PartialOnly(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusMet},
		{ControlID: "C2", Status: StatusPartiallyMet},
	}
	result := computeConclusion(results)
	if !strings.Contains(result, "partially met") {
		t.Errorf("expected partially met message, got %s", result)
	}
	if strings.Contains(result, "Exceptions") {
		t.Errorf("should not mention exceptions when no not_met, got %s", result)
	}
	if !strings.Contains(result, "1 of 2") {
		t.Errorf("expected 1 of 2 partial, got %s", result)
	}
}

func TestPhase1bComputeConclusion_AllNotApplicable(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusNotApplicable},
		{ControlID: "C2", Status: StatusNotApplicable},
	}
	result := computeConclusion(results)
	if !strings.Contains(result, "not applicable") {
		t.Errorf("expected not applicable message, got %s", result)
	}
}

func TestPhase1bComputeConclusion_MixedWithNA(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusMet},
		{ControlID: "C2", Status: StatusNotApplicable},
		{ControlID: "C3", Status: StatusNotApplicable},
	}
	result := computeConclusion(results)
	// applicable = 3 - 2 = 1, all applicable met → "All 1 applicable controls met"
	if !strings.Contains(result, "All 1 applicable controls met") {
		t.Errorf("expected 'All 1 applicable controls met', got %s", result)
	}
}

func TestPhase1bComputeConclusion_NotMetWithNA(t *testing.T) {
	results := []ControlResult{
		{ControlID: "C1", Status: StatusMet},
		{ControlID: "C2", Status: StatusNotMet},
		{ControlID: "C3", Status: StatusNotApplicable},
	}
	result := computeConclusion(results)
	// applicable = 3 - 1 = 2, notMet=1 → exceptions
	if !strings.Contains(result, "Exceptions identified") {
		t.Errorf("expected exceptions message, got %s", result)
	}
	if !strings.Contains(result, "1 of 2") {
		t.Errorf("expected 1 of 2 applicable, got %s", result)
	}
}
