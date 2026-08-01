// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ATLAS Enrichment Tests
// =========================================================================

package incident

import (
	"strings"
	"testing"
)

func TestEnrichATLASFinding_KnownTechnique(t *testing.T) {
	info, ok := EnrichATLASFinding("T1535.001")
	if !ok {
		t.Fatal("expected T1535.001 to be found in enrichment DB")
	}
	if info.ID != "T1535.001" {
		t.Errorf("ID = %q; want %q", info.ID, "T1535.001")
	}
	if info.Technique != "T1535" {
		t.Errorf("Technique = %q; want %q", info.Technique, "T1535")
	}
	if info.Category != "PromptInjection" {
		t.Errorf("Category = %q; want %q", info.Category, "PromptInjection")
	}
	if info.Severity != SeverityHigh {
		t.Errorf("Severity = %q; want %q", info.Severity, SeverityHigh)
	}
	if len(info.RecommendedResponse) == 0 {
		t.Error("RecommendedResponse should not be empty")
	}
	if len(info.ComplianceMappings) == 0 {
		t.Error("ComplianceMappings should not be empty")
	}
	if info.InvestigationPriority < 1 || info.InvestigationPriority > 5 {
		t.Errorf("InvestigationPriority = %d; want 1-5", info.InvestigationPriority)
	}
}

func TestEnrichATLASFinding_CriticalTechnique(t *testing.T) {
	info, ok := EnrichATLASFinding("T1484.001")
	if !ok {
		t.Fatal("expected T1484.001 to be found")
	}
	if info.Severity != SeverityCritical {
		t.Errorf("Severity = %q; want %q", info.Severity, SeverityCritical)
	}
	if info.InvestigationPriority != 1 {
		t.Errorf("InvestigationPriority = %d; want 1 for critical", info.InvestigationPriority)
	}
}

func TestEnrichATLASFinding_UnknownTechnique(t *testing.T) {
	_, ok := EnrichATLASFinding("T9999.999")
	if ok {
		t.Error("expected unknown technique to return false")
	}
}

func TestEnrichATLASFindings_Dedup(t *testing.T) {
	infos := EnrichATLASFindings([]string{"T1535.001", "T1535.002", "T1535.001"})
	if len(infos) != 2 {
		t.Errorf("expected 2 deduplicated results, got %d", len(infos))
	}
}

func TestEnrichATLASFindings_UnknownSkipped(t *testing.T) {
	infos := EnrichATLASFindings([]string{"T1535.001", "T9999.999"})
	if len(infos) != 1 {
		t.Errorf("expected 1 result (unknown skipped), got %d", len(infos))
	}
}

func TestGetRecommendedPlaybook(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"T1535.001", "pb_atlas_prompt_injection"},
		{"T1484.001", "pb_atlas_prompt_injection"},
		{"T1632.001", "pb_atlas_data_extraction"},
		{"T1589.002", "pb_atlas_data_extraction"},
		{"T1584.001", "pb_atlas_indirect_injection"},
		{"T1613.001", "pb_atlas_indirect_injection"},
		{"T1563.001", "pb_atlas_plugin_exploitation"},
		{"T1622.001", "pb_atlas_defense_evasion"},
		{"T1498.001", "pb_atlas_resource_exhaustion"},
		{"T1606.001", "pb_atlas_credential_forgery"},
		{"T9999.999", "pb_fedramp_ir4"},
	}
	for _, tt := range tests {
		got := GetRecommendedPlaybook(tt.id)
		if got != tt.want {
			t.Errorf("GetRecommendedPlaybook(%q) = %q; want %q", tt.id, got, tt.want)
		}
	}
}

func TestGetATLASTechniqueIDs(t *testing.T) {
	ids := GetATLASTechniqueIDs("PromptInjection")
	if len(ids) == 0 {
		t.Error("expected at least 1 PromptInjection technique")
	}
	for _, id := range ids {
		info, ok := atlasTechniqueDB[id]
		if !ok {
			t.Errorf("technique %s not found in DB", id)
		}
		if info.Category != "PromptInjection" {
			t.Errorf("technique %s has category %q; want PromptInjection", id, info.Category)
		}
	}
}

func TestAllATLASTechniqueIDs(t *testing.T) {
	ids := AllATLASTechniqueIDs()
	if len(ids) != len(atlasTechniqueDB) {
		t.Errorf("AllATLASTechniqueIDs returned %d IDs; want %d", len(ids), len(atlasTechniqueDB))
	}
}

func TestFormatEnrichmentSummary(t *testing.T) {
	summary := FormatEnrichmentSummary("T1535.001")
	if !strings.Contains(summary, "T1535.001") {
		t.Errorf("summary should contain technique ID: %q", summary)
	}
	if !strings.Contains(summary, "PromptInjection") {
		t.Errorf("summary should contain category: %q", summary)
	}
	if !strings.Contains(summary, "high") {
		t.Errorf("summary should contain severity: %q", summary)
	}

	unknown := FormatEnrichmentSummary("T9999.999")
	if !strings.Contains(unknown, "unknown") {
		t.Errorf("unknown technique summary should contain 'unknown': %q", unknown)
	}
}

func TestATLASTechniqueDB_Coverage(t *testing.T) {
	// Verify that all 52 ATLAS sub-technique IDs from the compliance
	// engine are represented in the enrichment database.
	knownIDs := map[string]bool{
		// Prompt Injection (5)
		"T1535.001": true, "T1535.002": true, "T1535.003": true,
		"T1535.004": true, "T1535.005": true,
		// LLM Jailbreak (5)
		"T1484.001": true, "T1484.002": true, "T1484.003": true,
		"T1484.004": true, "T1484.005": true,
		// Prompt Extraction (5)
		"T1632.001": true, "T1632.002": true, "T1632.003": true,
		"T1632.004": true, "T1632.005": true,
		// Data Extraction (5)
		"T1589.001": true, "T1589.002": true, "T1589.003": true,
		"T1589.004": true, "T1589.005": true,
		// Indirect Injection (5)
		"T1584.001": true, "T1584.002": true, "T1584.003": true,
		"T1584.004": true, "T1584.005": true,
		// Vector DB Poisoning (3)
		"T1600.001": true, "T1600.002": true, "T1600.003": true,
		// Content Injection (3)
		"T1613.001": true, "T1613.002": true, "T1613.003": true,
		// Plugin Exploitation (3)
		"T1563.001": true, "T1563.002": true, "T1563.003": true,
		// Defense Evasion (3)
		"T1622.001": true, "T1622.002": true, "T1622.003": true,
		// Credential Forgery (2)
		"T1606.001": true, "T1606.002": true,
		// MFA Bypass (2)
		"T1621.001": true, "T1621.002": true,
		// Elevation of Privilege (2)
		"T1548.001": true, "T1548.002": true,
		// Inhibit Recovery (2)
		"T1490.001": true, "T1490.002": true,
		// Denial of Service (2)
		"T1498.001": true, "T1498.002": true,
		// Endpoint Denial (2)
		"T1499.001": true, "T1499.002": true,
		// Config Exfiltration (2)
		"T1602.001": true, "T1602.002": true,
		// Resource Exhaustion (1)
		"T1648.001": true,
	}

	missing := 0
	for id := range knownIDs {
		if _, ok := atlasTechniqueDB[id]; !ok {
			t.Errorf("missing enrichment for ATLAS technique %s", id)
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d ATLAS techniques missing from enrichment DB", missing)
	}

	// Verify no extra entries that aren't in knownIDs
	for id := range atlasTechniqueDB {
		if !knownIDs[id] {
			t.Errorf("enrichment DB has unexpected technique %s", id)
		}
	}
}

func TestATLASTechniqueDB_AllHaveRequiredFields(t *testing.T) {
	for id, info := range atlasTechniqueDB {
		t.Run(id, func(t *testing.T) {
			if info.ID != id {
				t.Errorf("ID mismatch: map key %q != info.ID %q", id, info.ID)
			}
			if info.Technique == "" {
				t.Error("Technique should not be empty")
			}
			if info.Name == "" {
				t.Error("Name should not be empty")
			}
			if info.Category == "" {
				t.Error("Category should not be empty")
			}
			if info.Severity == "" {
				t.Error("Severity should not be empty")
			}
			if info.Description == "" {
				t.Error("Description should not be empty")
			}
			if len(info.RecommendedResponse) == 0 {
				t.Error("RecommendedResponse should not be empty")
			}
			if info.InvestigationPriority < 1 || info.InvestigationPriority > 5 {
				t.Errorf("InvestigationPriority = %d; want 1-5", info.InvestigationPriority)
			}
		})
	}
}