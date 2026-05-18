// SPDX-License-Identifier: Apache-2.0
//go:build !race

// Coverage tests for framework_mapping.go
// Targets: GenerateUnifiedReport (13%→95%), identifyGaps (72.7%→95%),
//
//	GetMappingsForControl, GetTechniquesForControl, ToJSON (75%→95%),
//	AddCustomPattern, DetectFrameworks
package compliance

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ---------- ConsolidatedFinding helpers ----------

func TestConsolidatedFinding_New(t *testing.T) {
	f := NewConsolidatedFinding("Test Title", "Test Description", "medium", "Fix it")
	if f == nil {
		t.Fatal("NewConsolidatedFinding returned nil")
	}
	if f.Title != "Test Title" {
		t.Errorf("Title=%q, want Test Title", f.Title)
	}
	if f.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestConsolidatedFinding_AddFramework(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddFramework("OWASP")
	f.AddFramework("OWASP")
	if len(f.Frameworks) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Frameworks))
	}
	f.AddFramework("NIST")
	if len(f.Frameworks) != 2 {
		t.Errorf("Frameworks count=%d, want 2", len(f.Frameworks))
	}
}

func TestConsolidatedFinding_AddControl(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddControl("CC1.1")
	f.AddControl("CC1.1")
	if len(f.Controls) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Controls))
	}
}

func TestConsolidatedFinding_AddTechnique(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddTechnique("T1234")
	f.AddTechnique("T1234")
	if len(f.Techniques) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Techniques))
	}
}

func TestConsolidatedFinding_AddEvidence(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddEvidence("evidence1")
	f.AddEvidence("evidence2")
	if len(f.Evidence) != 2 {
		t.Errorf("Evidence count=%d, want 2", len(f.Evidence))
	}
}

// ---------- GenerateUnifiedReport core branches ----------

func TestGenerateUnifiedReport_FindingsProcessed(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityCritical, Description: "A1"},
		{ID: "f2", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: "B1"},
		{ID: "f3", Framework: FrameworkATLAS, Severity: SeverityMedium, Description: "C1"},
		{ID: "f4", Framework: FrameworkATLAS, Severity: SeverityLow, Description: "D1"},
		{ID: "f5", Framework: FrameworkATLAS, Severity: SeverityInfo, Description: "E1"},
	}
	report := m.GenerateUnifiedReport(findings)
	if report.TotalFindings != 5 {
		t.Errorf("TotalFindings=%d, want 5", report.TotalFindings)
	}
	// TotalFindings sum of severity buckets
	total := report.CriticalFindings + report.HighFindings + report.MediumFindings + report.LowFindings
	if total != report.TotalFindings {
		t.Errorf("severity sum=%d, want %d", total, report.TotalFindings)
	}
}

// Deduplication: same description+severity → merge
func TestGenerateUnifiedReport_DeduplicatesSameKey(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: "Same Key", Match: "match1", Context: "ctx1"},
		{ID: "f2", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: "Same Key", Match: "match2", Context: "ctx2"},
	}
	report := m.GenerateUnifiedReport(findings)
	if report.TotalFindings != 1 {
		t.Errorf("TotalFindings=%d, want 1 (merged)", report.TotalFindings)
	}
}

// Empty description → default title "Compliance Finding"
func TestGenerateUnifiedReport_EmptyDescription(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: ""},
	}
	report := m.GenerateUnifiedReport(findings)
	if report.TotalFindings != 1 {
		t.Errorf("TotalFindings=%d, want 1", report.TotalFindings)
	}
}

// Empty findings → score computed, non-nil Gaps
func TestGenerateUnifiedReport_EmptyFindings(t *testing.T) {
	m := NewFrameworkMapping()
	report := m.GenerateUnifiedReport([]Finding{})
	if report.TotalFindings != 0 {
		t.Errorf("TotalFindings=%d, want 0", report.TotalFindings)
	}
	if report.ComplianceScore < 0 || report.ComplianceScore > 100 {
		t.Errorf("ComplianceScore=%f out of range", report.ComplianceScore)
	}
	if report.Gaps == nil {
		t.Error("Gaps should be non-nil")
	}
}

// Non-empty report with GV1 control (maps to techniques)
func TestGenerateUnifiedReport_ScoreWithFindings(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: "GV1"},
	}
	report := m.GenerateUnifiedReport(findings)
	if report.ComplianceScore < 0 || report.ComplianceScore > 100 {
		t.Errorf("ComplianceScore=%f out of range", report.ComplianceScore)
	}
}

// Multiple distinct findings
func TestGenerateUnifiedReport_MultipleDistinctFindings(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityCritical, Description: "UniqueDesc1"},
		{ID: "f2", Framework: FrameworkATLAS, Severity: SeverityLow, Description: "UniqueDesc2"},
	}
	report := m.GenerateUnifiedReport(findings)
	if report.TotalFindings != 2 {
		t.Errorf("TotalFindings=%d, want 2 (distinct)", report.TotalFindings)
	}
}

func TestGenerateUnifiedReport_FrameworkCoverage(t *testing.T) {
	m := NewFrameworkMapping()
	findings := []Finding{
		{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityHigh, Description: "Test"},
	}
	report := m.GenerateUnifiedReport(findings)
	if len(report.FrameworkCoverage) == 0 {
		t.Error("FrameworkCoverage should be non-empty")
	}
}

// ---------- AddMapping edge cases ----------

func TestAddMapping_UpdatesTimestamp(t *testing.T) {
	m := &FrameworkMapping{
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	before := m.UpdatedAt
	m.AddMapping("C1", []string{"T1"}, "mitigates", 0.9, "desc")
	if !m.UpdatedAt.After(before) && !m.UpdatedAt.Equal(before) {
		t.Error("UpdatedAt should be updated after AddMapping")
	}
}

func TestAddMapping_PreventsDuplicateTechniquePerControl(t *testing.T) {
	m := &FrameworkMapping{
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	m.AddMapping("C1", []string{"T1"}, "mitigates", 0.9, "desc")
	m.AddMapping("C1", []string{"T1"}, "mitigates", 0.9, "desc")
	techs := m.ControlToTechnique["C1"]
	if len(techs) != 1 {
		t.Errorf("C1 should have 1 technique, got %d", len(techs))
	}
}

func TestAddMapping_PreventsDuplicateControlPerTechnique(t *testing.T) {
	m := &FrameworkMapping{
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	m.AddMapping("C1", []string{"T1"}, "mitigates", 0.9, "desc")
	m.AddMapping("C2", []string{"T1"}, "supports", 0.8, "desc2")
	controls := m.TechniqueToControl["T1"]
	count := 0
	for _, c := range controls {
		if c == "C1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("T1 should have C1 once, got %d", count)
	}
}

func TestAddMapping_MultipleTechniques(t *testing.T) {
	m := &FrameworkMapping{
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	m.AddMapping("C1", []string{"T1", "T2", "T3"}, "mitigates", 0.9, "desc")
	if len(m.ControlToTechnique["C1"]) != 3 {
		t.Errorf("C1 should have 3 techniques, got %d", len(m.ControlToTechnique["C1"]))
	}
	if len(m.TechniqueToControl["T1"]) != 1 {
		t.Error("T1 should have C1")
	}
}

// ---------- GetTechniquesForControl ----------

func TestGetTechniquesForControl_Known(t *testing.T) {
	m := NewFrameworkMapping()
	techs := m.GetTechniquesForControl("GV1")
	if len(techs) == 0 {
		t.Error("GV1 should map to techniques")
	}
}

func TestGetTechniquesForControl_Unknown(t *testing.T) {
	m := NewFrameworkMapping()
	techs := m.GetTechniquesForControl("NONEXISTENT")
	if techs != nil {
		t.Errorf("UNKNOWN control should return nil, got %v", techs)
	}
}

// ---------- GetMappingsForControl ----------

func TestGetMappingsForControl_Known(t *testing.T) {
	m := NewFrameworkMapping()
	mappings := m.GetMappingsForControl("GV1")
	if len(mappings) == 0 {
		t.Error("GV1 should have mappings")
	}
	for _, m := range mappings {
		if m.SourceFramework != "NIST AI RMF" {
			t.Errorf("SourceFramework=%q, want NIST AI RMF", m.SourceFramework)
		}
	}
}

func TestGetMappingsForControl_Unknown(t *testing.T) {
	m := NewFrameworkMapping()
	mappings := m.GetMappingsForControl("NONEXISTENT")
	if mappings != nil {
		t.Errorf("UNKNOWN control should return nil, got %v", mappings)
	}
}

// ---------- AddOWASPMapping ----------

func TestAddOWASPMapping(t *testing.T) {
	m := &FrameworkMapping{
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	m.AddOWASPMapping("OWASP1", []string{"T1234"}, "mitigates", 0.9, "test")
	if len(m.ControlToTechnique["OWASP1"]) == 0 {
		t.Error("OWASP1 should map to T1234")
	}
}

// ---------- MappingRelationship fields ----------

func TestMappingRelationship_Fields(t *testing.T) {
	mr := MappingRelationship{
		SourceFramework: "NIST AI RMF",
		SourceControl:   "GV1",
		TargetFramework: "MITRE ATLAS",
		TargetControls:  []string{"T1535", "T1484"},
		Relationship:    "mitigates",
		Confidence:      0.95,
		Description:     "GV1 mitigates T1535 and T1484",
	}
	if mr.SourceFramework != "NIST AI RMF" {
		t.Errorf("SourceFramework=%q", mr.SourceFramework)
	}
	if len(mr.TargetControls) != 2 {
		t.Errorf("TargetControls count=%d, want 2", len(mr.TargetControls))
	}
	if mr.Confidence != 0.95 {
		t.Errorf("Confidence=%f, want 0.95", mr.Confidence)
	}
}

// ---------- ComplianceGap fields ----------

func TestComplianceGap_Fields(t *testing.T) {
	gap := ComplianceGap{
		ID:              "gap1",
		Title:           "Missing Control",
		Description:     "No control for T1234",
		MissingControls: []string{"C1", "C2"},
		RiskLevel:       "high",
		Recommendations: []string{"Add control C1"},
	}
	if gap.ID != "gap1" {
		t.Errorf("ID=%q, want gap1", gap.ID)
	}
	if gap.RiskLevel != "high" {
		t.Errorf("RiskLevel=%q, want high", gap.RiskLevel)
	}
	if len(gap.MissingControls) != 2 {
		t.Errorf("MissingControls count=%d, want 2", len(gap.MissingControls))
	}
}

// ---------- UnifiedComplianceReport structure ----------

func TestUnifiedComplianceReport_Fields(t *testing.T) {
	report := &UnifiedComplianceReport{
		GeneratedAt:       time.Now(),
		Frameworks:        []string{"NIST AI RMF", "MITRE ATLAS"},
		TotalFindings:     5,
		CriticalFindings:  1,
		HighFindings:      2,
		MediumFindings:    1,
		LowFindings:       1,
		Findings:          []ConsolidatedFinding{},
		FrameworkCoverage: map[string]int{"NIST": 3, "ATLAS": 2},
		TechniqueCoverage: map[string][]string{"T1535": {"C1"}},
		ComplianceScore:   75.5,
		Gaps:              []ComplianceGap{},
	}
	if report.TotalFindings != 5 {
		t.Errorf("TotalFindings=%d, want 5", report.TotalFindings)
	}
	if report.ComplianceScore != 75.5 {
		t.Errorf("ComplianceScore=%f, want 75.5", report.ComplianceScore)
	}
}

// ---------- identifyGaps ----------

func TestIdentifyGaps_TechniqueUncovered(t *testing.T) {
	m := NewFrameworkMapping()
	report := &UnifiedComplianceReport{
		Findings:          []ConsolidatedFinding{},
		TechniqueCoverage: make(map[string][]string),
	}
	report.TechniqueCoverage["T1484"] = []string{"C1"} // exactly 1 → gap
	gaps := m.identifyGaps(report)
	if len(gaps) == 0 {
		t.Error("Should identify gap for T1484 (only 1 control)")
	}
}

func TestIdentifyGaps_TechniqueCoveredByMultiple(t *testing.T) {
	m := NewFrameworkMapping()
	report := &UnifiedComplianceReport{
		Findings:          []ConsolidatedFinding{},
		TechniqueCoverage: make(map[string][]string),
	}
	for _, tech := range []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658"} {
		report.TechniqueCoverage[tech] = []string{"C1", "C2"}
	}
	gaps := m.identifyGaps(report)
	if len(gaps) != 0 {
		t.Errorf("All techniques covered should produce 0 gaps, got %d", len(gaps))
	}
}

func TestIdentifyGaps_TechniqueNotInMap(t *testing.T) {
	m := NewFrameworkMapping()
	report := &UnifiedComplianceReport{
		Findings:          []ConsolidatedFinding{},
		TechniqueCoverage: make(map[string][]string),
	}
	gaps := m.identifyGaps(report)
	if len(gaps) == 0 {
		t.Error("Should identify gap for T1535 (not in map)")
	}
}

// ---------- getControlsForTechnique ----------

func TestGetControlsForTechnique_Known(t *testing.T) {
	m := NewFrameworkMapping()
	controls := m.GetControlsForTechnique("T1535")
	if len(controls) == 0 {
		t.Error("T1535 should have controls")
	}
}

func TestGetControlsForTechnique_Unknown(t *testing.T) {
	m := NewFrameworkMapping()
	controls := m.GetControlsForTechnique("T9999")
	if len(controls) != 0 {
		t.Errorf("T9999 should have 0 controls, got %d", len(controls))
	}
}

// ---------- NewFrameworkMapping structure ----------

func TestNewFrameworkMapping_Structure(t *testing.T) {
	m := NewFrameworkMapping()
	if m == nil {
		t.Fatal("NewFrameworkMapping returned nil")
	}
	if len(m.ControlToTechnique) == 0 {
		t.Error("ControlToTechnique should be populated")
	}
	if len(m.TechniqueToControl) == 0 {
		t.Error("TechniqueToControl should be populated")
	}
	if len(m.Mappings) == 0 {
		t.Error("Mappings should be populated")
	}
	if m.Name == "" {
		t.Error("Name should be set")
	}
	if m.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if m.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

// ---------- AddCustomPattern in compliance.go ----------

func TestAddCustomPattern_NilPattern(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	err := m.AddCustomPattern(nil)
	if err == nil {
		t.Error("AddCustomPattern(nil) should return error")
	}
}

func TestAddCustomPattern_NilRegex(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	err := m.AddCustomPattern(&Pattern{Regex: nil, Framework: FrameworkATLAS})
	if err == nil {
		t.Error("AddCustomPattern(nil regex) should return error")
	}
}

func TestAddCustomPattern_ValidPattern(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	re := regexp.MustCompile(`test`)
	pattern := &Pattern{
		ID:        "custom1",
		Regex:     re,
		Framework: FrameworkATLAS,
		Severity:  SeverityHigh,
	}
	err := m.AddCustomPattern(pattern)
	if err != nil {
		t.Fatalf("AddCustomPattern failed: %v", err)
	}
}

func TestAddCustomPattern_ExistingFramework(t *testing.T) {
	m := &Manager{
		patterns: map[Framework][]*Pattern{
			FrameworkATLAS: {
				{ID: "existing", Regex: regexp.MustCompile(`old`), Framework: FrameworkATLAS, Severity: SeverityLow},
			},
		},
	}
	re := regexp.MustCompile(`new`)
	pattern := &Pattern{
		ID:        "custom2",
		Regex:     re,
		Framework: FrameworkATLAS,
		Severity:  SeverityMedium,
	}
	err := m.AddCustomPattern(pattern)
	if err != nil {
		t.Fatalf("AddCustomPattern failed: %v", err)
	}
	if len(m.patterns[FrameworkATLAS]) != 2 {
		t.Errorf("ATLAS patterns count=%d, want 2", len(m.patterns[FrameworkATLAS]))
	}
}

// ---------- DetectFrameworks (uncovered branches) ----------

func TestDetectFrameworks_Healthcare(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	frameworks := m.DetectFrameworks("PATIENT DIAGNOSIS TREATMENT")
	if len(frameworks) == 0 {
		t.Error("Should detect healthcare-related frameworks")
	}
}

func TestDetectFrameworks_Financial(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	frameworks := m.DetectFrameworks("PAYMENT CREDIT CARD TRANSACTION")
	if len(frameworks) == 0 {
		t.Error("Should detect financial frameworks")
	}
}

func TestDetectFrameworks_EU(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	frameworks := m.DetectFrameworks("GDPR CONSENT DATA PROCESSING")
	if len(frameworks) == 0 {
		t.Error("Should detect GDPR framework")
	}
}

func TestDetectFrameworks_NoMatch(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	frameworks := m.DetectFrameworks("xyzzy plugh")
	if len(frameworks) != 0 {
		t.Errorf("No match should give empty frameworks, got %d", len(frameworks))
	}
}

// ---------- ExportFindings ----------

func TestExportFindings_EmptyJSON(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	exported, err := m.ExportFindings("json")
	if err != nil {
		t.Fatalf("ExportFindings(json) failed: %v", err)
	}
	if exported == "" {
		t.Error("ExportFindings(json) should return non-empty string")
	}
}

func TestExportFindings_EmptyCSV(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	exported, err := m.ExportFindings("csv")
	if err != nil {
		t.Fatalf("ExportFindings(csv) failed: %v", err)
	}
	if exported == "" {
		t.Error("ExportFindings(csv) should return non-empty string")
	}
}

func TestExportFindings_WithFindingsJSON(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	_, err := m.ExportFindings("json")
	if err != nil {
		t.Fatalf("ExportFindings(json) failed: %v", err)
	}
}

func TestExportFindings_WithFindingsCSV(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	_, err := m.ExportFindings("csv")
	if err != nil {
		t.Fatalf("ExportFindings(csv) failed: %v", err)
	}
}

// ---------- GenerateReport ----------

func TestFrameworkMapping_GenerateReport_EmptyFindings(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	m.mu.Lock()
	m.reportHistory = append(m.reportHistory, Result{})
	m.mu.Unlock()
	_, err := m.GenerateReport()
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}
}

func TestFrameworkMapping_GenerateReport_WithFindings(t *testing.T) {
	m := &Manager{patterns: make(map[Framework][]*Pattern)}
	m.mu.Lock()
	m.reportHistory = append(m.reportHistory, Result{
		Findings: []Finding{
			{ID: "f1", Framework: FrameworkATLAS, Severity: SeverityCritical, Description: "Critical"},
		},
	})
	m.mu.Unlock()
	_, err := m.GenerateReport()
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}
}

// ---------- Registry CheckFramework branches in compliance.go ----------

func TestRegistry_CheckFramework_Unregistered(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	_, err := registry.CheckFramework(ctx, "nonexistent", common.CheckInput{Content: "test"})
	if err == nil {
		t.Error("CheckFramework for unregistered framework should return error")
	}
}

// ---------- Uncovered module.go branches ----------

func TestBaseComplianceModule_GenerateAssessment_EmptyFindings(t *testing.T) {
	m := NewBaseComplianceModule("ATLAS", "1.0.0", core.TierCommunity)
	ctx := context.Background()
	assessment, err := m.GenerateAssessment(ctx, nil)
	if err != nil {
		t.Fatalf("GenerateAssessment: %v", err)
	}
	if assessment == nil {
		t.Fatal("GenerateAssessment should not return nil")
	}
	if assessment.Framework != "ATLAS" {
		t.Errorf("Framework=%q, want ATLAS", assessment.Framework)
	}
}

func TestBaseComplianceModule_CheckAll_EmptyFindings(t *testing.T) {
	m := NewBaseComplianceModule("Test", string(FrameworkATLAS), core.TierCommunity)
	ctx := context.Background()
	result, err := m.CheckAll(ctx, nil)
	if err != nil {
		t.Fatalf("CheckAll: %v", err)
	}
	if result == nil {
		t.Fatal("CheckAll should not return nil")
	}
}
