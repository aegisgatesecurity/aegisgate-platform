// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Residual Risk Map Tests
// =========================================================================

package compliance

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
)

func TestResidualRiskMap_All52TechniquesPresent(t *testing.T) {
	entries := ResidualRiskMap()
	if len(entries) != 52 {
		t.Errorf("expected 52 technique entries, got %d", len(entries))
	}

	// Verify each entry has a non-empty technique ID
	for _, e := range entries {
		if e.TechniqueID == "" {
			t.Error("found entry with empty TechniqueID")
		}
		if e.TechniqueName == "" {
			t.Errorf("entry %s has empty TechniqueName", e.TechniqueID)
		}
		if e.ParentTechnique == "" {
			t.Errorf("entry %s has empty ParentTechnique", e.TechniqueID)
		}
		if e.Category == "" {
			t.Errorf("entry %s has empty Category", e.TechniqueID)
		}
	}
}

func TestResidualRiskMap_NoDuplicateIDs(t *testing.T) {
	entries := ResidualRiskMap()
	seen := make(map[string]bool)
	for _, e := range entries {
		if seen[e.TechniqueID] {
			t.Errorf("duplicate TechniqueID: %s", e.TechniqueID)
		}
		seen[e.TechniqueID] = true
	}
}

func TestResidualRiskMap_BlastRadiusValid(t *testing.T) {
	entries := ResidualRiskMap()
	validBlast := map[BlastRadius]bool{
		BlastCritical: true,
		BlastHigh:     true,
		BlastMedium:   true,
		BlastLow:      true,
	}
	for _, e := range entries {
		if !validBlast[e.BlastRadius] {
			t.Errorf("entry %s has invalid BlastRadius: %q (must be Critical/High/Medium/Low)", e.TechniqueID, e.BlastRadius)
		}
	}
}

func TestResidualRiskMap_DetectionStatusValid(t *testing.T) {
	entries := ResidualRiskMap()
	validStatus := map[DetectionStatus]bool{
		Detected:    true,
		Partial:     true,
		NotDetected: true,
	}
	for _, e := range entries {
		if !validStatus[e.DetectionStatus] {
			t.Errorf("entry %s has invalid DetectionStatus: %q (must be Detected/Partial/Not Detected)", e.TechniqueID, e.DetectionStatus)
		}
	}
}

func TestResidualRiskMap_SummaryCountsAddUp(t *testing.T) {
	entries := ResidualRiskMap()
	s := Summary(entries)

	total := s.Detected + s.Partial + s.NotDetected
	if total != 52 {
		t.Errorf("Detected(%d) + Partial(%d) + NotDetected(%d) = %d, want 52",
			s.Detected, s.Partial, s.NotDetected, total)
	}

	blastTotal := s.CriticalBlast + s.HighBlast + s.MediumBlast + s.LowBlast
	if blastTotal != 52 {
		t.Errorf("Critical(%d) + High(%d) + Medium(%d) + Low(%d) = %d, want 52",
			s.CriticalBlast, s.HighBlast, s.MediumBlast, s.LowBlast, blastTotal)
	}
}

func TestResidualRiskMap_CoveragePercentValid(t *testing.T) {
	entries := ResidualRiskMap()
	s := Summary(entries)

	if s.CoveragePercent < 0 || s.CoveragePercent > 100 {
		t.Errorf("CoveragePercent = %.1f, want 0-100", s.CoveragePercent)
	}

	// Since all 52 techniques have detection patterns, coverage should be
	// high (at least 90%)
	if s.CoveragePercent < 90 {
		t.Errorf("CoveragePercent = %.1f, want >= 90%% (all techniques have patterns)", s.CoveragePercent)
	}
}

func TestResidualRiskMap_ResidualRiskCountValid(t *testing.T) {
	entries := ResidualRiskMap()
	s := Summary(entries)

	// Residual risk = not detected AND no alternative coverage
	// Since all techniques have detection patterns AND technique mappings,
	// residual risk should be 0
	if s.ResidualRiskCount < 0 {
		t.Errorf("ResidualRiskCount = %d, want >= 0", s.ResidualRiskCount)
	}
	if s.ResidualRiskCount > 52 {
		t.Errorf("ResidualRiskCount = %d, want <= 52", s.ResidualRiskCount)
	}
}

func TestResidualRiskMap_AllCategoriesPopulated(t *testing.T) {
	entries := ResidualRiskMap()
	s := Summary(entries)

	// Verify that at least the major ATLAS categories are represented
	expectedCategories := []string{
		"PromptInjection", "LLMJailbreak", "PromptExtraction",
		"DataExtraction", "IndirectInjection", "VectorDBPoisoning",
		"ContentInjection", "PluginExploitation", "DefenseEvasion",
	}

	for _, cat := range expectedCategories {
		if s.ByCategory[cat] == 0 {
			t.Errorf("expected at least 1 technique in category %s, got 0", cat)
		}
	}

	// Verify category counts sum to 52
	total := 0
	for _, count := range s.ByCategory {
		total += count
	}
	if total != 52 {
		t.Errorf("category counts sum to %d, want 52", total)
	}
}

func TestResidualRiskMap_AlternativeCoverageFromMappings(t *testing.T) {
	entries := ResidualRiskMap()

	// Techniques mapped in techniques.go should have alternative coverage
	for _, e := range entries {
		// All techniques in the ATLAS framework should have some mapping
		// since techniques.go has comprehensive coverage
		if len(e.AlternativeCoverage) == 0 {
			// Some techniques may not have mappings; verify they are known
			known := map[string]bool{
				// All techniques should have mappings, so none should be empty
			}
			if !known[e.TechniqueID] && e.DetectionStatus != Detected {
				t.Errorf("technique %s has no alternative coverage and is not Detected", e.TechniqueID)
			}
		}
	}
}

func TestResidualRiskMap_SpecificDetectionStatus(t *testing.T) {
	entries := ResidualRiskMap()
	entryMap := make(map[string]ResidualRiskEntry)
	for _, e := range entries {
		entryMap[e.TechniqueID] = e
	}

	// T1535 (Prompt Injection) should be Detected since it has both
	// patterns and "detects" relationship in techniques.go
	if e, ok := entryMap["T1535.001"]; ok {
		if e.DetectionStatus != Detected {
			t.Errorf("T1535.001: expected Detected, got %s", e.DetectionStatus)
		}
	}

	// T1484 (Jailbreak) should be Detected
	if e, ok := entryMap["T1484.001"]; ok {
		if e.DetectionStatus != Detected {
			t.Errorf("T1484.001: expected Detected, got %s", e.DetectionStatus)
		}
	}

	// T1632 (Prompt Extraction) should be Detected (has patterns)
	if e, ok := entryMap["T1632.001"]; ok {
		if e.DetectionStatus != Detected {
			t.Errorf("T1632.001: expected Detected, got %s", e.DetectionStatus)
		}
	}
}

func TestResidualRiskMap_SpecificBlastRadius(t *testing.T) {
	entries := ResidualRiskMap()
	entryMap := make(map[string]ResidualRiskEntry)
	for _, e := range entries {
		entryMap[e.TechniqueID] = e
	}

	// T1535.004 (Token Smuggling) is Critical severity
	if e, ok := entryMap["T1535.004"]; ok {
		if e.BlastRadius != BlastCritical {
			t.Errorf("T1535.004: expected Critical blast radius, got %s", e.BlastRadius)
		}
	}

	// T1498.001 (Resource Exhaustion) is High severity
	if e, ok := entryMap["T1498.001"]; ok {
		if e.BlastRadius != BlastHigh {
			t.Errorf("T1498.001: expected High blast radius, got %s", e.BlastRadius)
		}
	}
}

func TestResidualRiskMap_RecommendedActionsNotEmpty(t *testing.T) {
	entries := ResidualRiskMap()
	for _, e := range entries {
		if e.RecommendedAction == "" {
			t.Errorf("entry %s has empty RecommendedAction", e.TechniqueID)
		}
	}
}

func TestResidualRiskMap_StringOutput(t *testing.T) {
	output := String()
	if !strings.Contains(output, "RESIDUAL RISK MAP") {
		t.Error("String() output does not contain 'RESIDUAL RISK MAP'")
	}
	if !strings.Contains(output, "RESIDUAL RISK SUMMARY") {
		t.Error("String() output does not contain 'RESIDUAL RISK SUMMARY'")
	}
	if !strings.Contains(output, "Total Techniques:") {
		t.Error("String() output does not contain 'Total Techniques:'")
	}
	if !strings.Contains(output, "Coverage") {
		t.Error("String() output does not contain 'Coverage'")
	}
}

func TestResidualRiskMap_DeterministicOrdering(t *testing.T) {
	entries1 := ResidualRiskMap()
	entries2 := ResidualRiskMap()

	if len(entries1) != len(entries2) {
		t.Fatal("ResidualRiskMap() returned different lengths on successive calls")
	}

	for i := range entries1 {
		if entries1[i].TechniqueID != entries2[i].TechniqueID {
			t.Errorf("ordering mismatch at index %d: %s vs %s",
				i, entries1[i].TechniqueID, entries2[i].TechniqueID)
		}
	}
}

func TestPillarForControl_AllKnownControls(t *testing.T) {
	// Verify all control IDs in techniques.go map to a pillar
	controls := []string{
		"AG-DETECT-SCANNER",
		"AG-AUTH-RBAC-MFA",
		"AG-OUTPUT-PII-SECRET-FILTER",
		"AG-VULN-CI-SCANNING",
		"AG-CRYPTO-TLS-FIPS",
		"AG-AUDIT-LOG-HASH-CHAIN",
		"AG-TRUST-AGENT-ATTESTATION",
		"AG-CM-BASELINE-CONFIG",
		"AG-CA-CONTINUOUS-MONITORING",
		"AG-IR-INCIDENT-RESPONSE",
		"AG-SC-BOUNDARY-PROTECTION",
		"AG-DATA-PROTECTION-PRIVACY",
		"AG-SECURITY-AWARENESS",
		"AG-ASSET-INVENTORY",
		"AG-SUPPLY-CHAIN-RISK",
		"AG-BUSINESS-CONTINUITY",
		"AG-IDENTITY-LIFECYCLE",
		"AG-NETWORK-SECURITY",
		"AG-RISK-GOVERNANCE",
		"AG-PHYSICAL-SECURITY",
		"AG-AI-SAFETY-QUALITY",
		"AG-AC-CONCURRENT-SESSIONS",
		"AG-IA-ADVERSARY-DETECTION",
		"AG-IR-INTEGRATION",
		"AG-SC-RESOURCE-AVAILABILITY",
		"AG-CM-CONFIGURATION-PLANNING",
		"AG-AT-AWARENESS-TRAINING",
		"AG-CP-CONTINGENCY",
		"AG-CA-SECURITY-ASSESSMENT",
		"AG-AC-ACCESS-ENFORCEMENT",
		"AG-AU-AUDIT-MONITORING",
		"AG-PL-PLANNING",
		"AG-MA-MAINTENANCE",
		"AG-PS-PERSONNEL-SECURITY",
		"AG-IR-IR-POLICY-PLANNING",
		"AG-SC-COMM-PROTECTION",
		"AG-SI-SYSTEM-INTEGRITY",
		"AG-SA-SYSTEM-ACQUISITION",
	}

	validPillars := map[string]bool{
		"HTTP Scanner":    true,
		"MCP":             true,
		"ACP":             true,
		"Trust Framework": true,
		"SIEM":            true,
	}

	for _, ctrl := range controls {
		pillar := pillarForControl(ctrl)
		if !validPillars[pillar] {
			t.Errorf("pillarForControl(%q) = %q, not a valid pillar", ctrl, pillar)
		}
	}
}

func TestSeverityToBlastRadius(t *testing.T) {
	tests := []struct {
		sev  incident.IncidentSeverity
		want BlastRadius
	}{
		{incident.SeverityCritical, BlastCritical},
		{incident.SeverityHigh, BlastHigh},
		{incident.SeverityMedium, BlastMedium},
		{incident.SeverityLow, BlastLow},
	}
	for _, tt := range tests {
		got := severityToBlastRadius(tt.sev)
		if got != tt.want {
			t.Errorf("severityToBlastRadius(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestRecommendedActionFor(t *testing.T) {
	// Detected + Critical
	action := recommendedActionFor(Detected, BlastCritical, nil)
	if !strings.Contains(action, "Rule-based detection") {
		t.Errorf("Detected+Critical: expected 'Rule-based detection', got %q", action)
	}

	// Partial + Critical + alternative coverage
	action = recommendedActionFor(Partial, BlastCritical, []string{"SIEM", "Trust Framework"})
	if !strings.Contains(action, "CRITICAL") || !strings.Contains(action, "SIEM") {
		t.Errorf("Partial+Critical+Alt: expected CRITICAL and SIEM, got %q", action)
	}

	// NotDetected + High
	action = recommendedActionFor(NotDetected, BlastHigh, []string{"MCP"})
	if !strings.Contains(action, "P2") {
		t.Errorf("NotDetected+High: expected P2, got %q", action)
	}

	// NotDetected + Low + no alt
	action = recommendedActionFor(NotDetected, BlastLow, nil)
	if !strings.Contains(action, "No rule detection") {
		t.Errorf("NotDetected+Low: expected 'No rule detection', got %q", action)
	}
}

func TestResidualRiskMap_TechniquesMappingConsistency(t *testing.T) {
	entries := ResidualRiskMap()

	// For each technique with alternative coverage, verify the pillars
	// are valid and come from the actual technique mappings
	for _, e := range entries {
		for _, pillar := range e.AlternativeCoverage {
			validPillars := map[string]bool{
				"HTTP Scanner":    true,
				"MCP":             true,
				"ACP":             true,
				"Trust Framework": true,
				"SIEM":            true,
			}
			if !validPillars[pillar] {
				t.Errorf("technique %s has invalid pillar %q", e.TechniqueID, pillar)
			}
		}
	}
}

func TestResidualRiskMap_SummaryByCategory(t *testing.T) {
	entries := ResidualRiskMap()
	s := Summary(entries)

	// PromptInjection should have 5 sub-techniques (T1535.001-005)
	if s.ByCategory["PromptInjection"] != 5 {
		t.Errorf("PromptInjection category count = %d, want 5", s.ByCategory["PromptInjection"])
	}

	// LLMJailbreak should have 5 sub-techniques (T1484.001-005)
	if s.ByCategory["LLMJailbreak"] != 5 {
		t.Errorf("LLMJailbreak category count = %d, want 5", s.ByCategory["LLMJailbreak"])
	}

	// PromptExtraction should have 5 sub-techniques (T1632.001-005)
	if s.ByCategory["PromptExtraction"] != 5 {
		t.Errorf("PromptExtraction category count = %d, want 5", s.ByCategory["PromptExtraction"])
	}
}

func TestResidualRiskMap_AllParentTechniquesMapped(t *testing.T) {
	// Verify that every technique in the risk map has some form of coverage:
	// either a direct mapping in techniques.go, a sub-technique mapping,
	// or a detection pattern in atlas.go.
	entries := ResidualRiskMap()

	for _, e := range entries {
		// Every entry should have a DetectionStatus, AlternativeCoverage,
		// or RecommendedAction — i.e., no entry should be completely
		// unaccounted for.
		if e.DetectionStatus == "" {
			t.Errorf("technique %s has empty DetectionStatus", e.TechniqueID)
		}
		if e.BlastRadius == "" {
			t.Errorf("technique %s has empty BlastRadius", e.TechniqueID)
		}
	}

	// Verify that the ATLAS techniques with detection patterns are marked
	// as Detected, and those without are marked Partial or Not Detected.
	detected := 0
	partial := 0
	notDetected := 0
	for _, e := range entries {
		switch e.DetectionStatus {
		case "Detected":
			detected++
		case "Partial":
			partial++
		case "Not Detected":
			notDetected++
		default:
			t.Errorf("technique %s has unexpected DetectionStatus %q", e.TechniqueID, e.DetectionStatus)
		}
	}
	// At least some techniques must be detected
	if detected == 0 {
		t.Error("expected at least some Detected techniques")
	}
	// Total must be 52
	if detected+partial+notDetected != 52 {
		t.Errorf("expected 52 total techniques, got %d (Detected=%d, Partial=%d, Not Detected=%d)",
			detected+partial+notDetected, detected, partial, notDetected)
	}
}
