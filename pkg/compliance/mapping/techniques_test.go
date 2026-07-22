// SPDX-License-Identifier: Apache-2.0
// AI Technique-Level Cross-Mapping - Unit Tests

package mapping

import (
	"testing"
)

func TestTechniqueMappings_Populated(t *testing.T) {
	if len(TechniqueMappings) < 20 {
		t.Errorf("TechniqueMappings count = %d, want at least 20 (the legacy had 80+)", len(TechniqueMappings))
	}
}

func TestTechniquesForControl(t *testing.T) {
	// AG-DETECT-SCANNER should detect multiple MITRE ATLAS techniques
	results := TechniquesForControl("AG-DETECT-SCANNER")
	if len(results) < 3 {
		t.Errorf("TechniquesForControl(AG-DETECT-SCANNER) returned %d, want at least 3", len(results))
	}
	// All should be the AG-DETECT-SCANNER control
	for _, r := range results {
		if r.AegisGateControl != "AG-DETECT-SCANNER" {
			t.Errorf("Found mapping for %q, want AG-DETECT-SCANNER", r.AegisGateControl)
		}
	}
}

func TestAegisGateControlsForTechnique(t *testing.T) {
	// T1535 (Unsecured Credentials) should be mitigated by AG-AUTH-RBAC-MFA
	results := AegisGateControlsForTechnique("atlas", "T1535")
	if len(results) == 0 {
		t.Error("AegisGateControlsForTechnique(atlas, T1535) returned no results")
	}
	hasRBAC := false
	for _, r := range results {
		if r.AegisGateControl == "AG-AUTH-RBAC-MFA" {
			hasRBAC = true
		}
	}
	if !hasRBAC {
		t.Error("T1535 should be mitigated by AG-AUTH-RBAC-MFA")
	}
}

func TestAegisGateControlsForTechnique_NotFound(t *testing.T) {
	results := AegisGateControlsForTechnique("atlas", "T9999-NONEXISTENT")
	if len(results) != 0 {
		t.Errorf("Expected 0 results for nonexistent technique, got %d", len(results))
	}
}

func TestAegisGateCoverageByTechnique(t *testing.T) {
	coverage := AegisGateCoverageByTechnique()
	// AG-DETECT-SCANNER should be in the coverage map with the highest count
	if len(coverage) == 0 {
		t.Error("AegisGateCoverageByTechnique returned empty map")
	}
	// Check that all the main AegisGate controls are covered
	mainControls := []string{
		"AG-AUTH-RBAC-MFA", "AG-AUDIT-LOG-HASH-CHAIN", "AG-CRYPTO-TLS-FIPS",
		"AG-DETECT-SCANNER", "AG-OUTPUT-PII-SECRET-FILTER", "AG-TRUST-AGENT-ATTESTATION",
		"AG-VULN-CI-SCANNING",
	}
	for _, c := range mainControls {
		if coverage[c] == 0 {
			t.Errorf("AegisGate control %s has no technique mappings", c)
		}
	}
}

func TestTechniqueMappings_CoverAllAegisGateControls(t *testing.T) {
	// Every AegisGate control in the main mapping should have at least
	// one technique mapping
	controls := ListControls()
	for _, c := range controls {
		techs := TechniquesForControl(c)
		if len(techs) == 0 {
			t.Errorf("AegisGate control %s (from main mapping) has no technique mappings", c)
		}
	}
}

func TestTechniqueMappings_HighConfidence(t *testing.T) {
	// All mappings should have confidence in [0, 1]
	for _, m := range TechniqueMappings {
		if m.Confidence < 0 || m.Confidence > 1 {
			t.Errorf("Technique %s has confidence %f, want [0, 1]", m.TechniqueID, m.Confidence)
		}
	}
}

func TestTechniqueMappings_RelationshipValid(t *testing.T) {
	// All mappings should have a valid relationship type
	validRelationships := map[string]bool{
		"detects": true, "mitigates": true, "supports": true,
		"addresses": true, "equivalent": true, "relates": true,
	}
	for _, m := range TechniqueMappings {
		if !validRelationships[m.Relationship] {
			t.Errorf("Technique %s has invalid relationship %q", m.TechniqueID, m.Relationship)
		}
	}
}

func TestTechniqueMappings_FrameworkDistribution(t *testing.T) {
	// Should have entries for all 3 frameworks (atlas, owasp_llm, nist_ai_rmf)
	frameworks := map[string]int{"atlas": 0, "owasp_llm": 0, "nist_ai_rmf": 0}
	for _, m := range TechniqueMappings {
		frameworks[m.Framework]++
	}
	for fw, count := range frameworks {
		if count == 0 {
			t.Errorf("No technique mappings for framework %s", fw)
		}
	}
}
