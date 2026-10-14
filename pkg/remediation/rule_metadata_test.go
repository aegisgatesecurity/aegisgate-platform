// SPDX-License-Identifier: Apache-2.0

package remediation

import (
	"strings"
	"testing"
)

func TestGetRuleMetadata(t *testing.T) {
	known := []string{
		"owasp_llm01_prompt_injection",
		"owasp_llm02_insecure_output",
		"owasp_llm04_model_dos",
		"owasp_llm10_model_theft",
		"atlas_jailbreak",
	}
	for _, id := range known {
		m := GetRuleMetadata(id)
		if m.RuleID != id {
			t.Errorf("GetRuleMetadata(%q): RuleID = %q, want %q", id, m.RuleID, id)
		}
		if m.Description == "" {
			t.Errorf("GetRuleMetadata(%q): Description is empty", id)
		}
		if m.Remediation == "" {
			t.Errorf("GetRuleMetadata(%q): Remediation is empty", id)
		}
		if len(m.CWE) == 0 {
			t.Errorf("GetRuleMetadata(%q): CWE is empty", id)
		}
		if m.OWASPLLMTop == "" {
			t.Errorf("GetRuleMetadata(%q): OWASPLLMTop is empty", id)
		}
		// Entries with an OWASP LLM Top reference should be enriched
		// with NIST/EU framework mappings.
		if m.OWASPLLMTop != "" && len(m.NISTAIRMF) == 0 {
			t.Errorf("GetRuleMetadata(%q): NISTAIRMF not enriched for OWASP %s", id, m.OWASPLLMTop)
		}
	}
}

func TestGetRuleMetadataUnknown(t *testing.T) {
	m := GetRuleMetadata("totally_unknown_rule_xyz")
	if m.RuleID != "totally_unknown_rule_xyz" {
		t.Errorf("GetRuleMetadata(unknown): RuleID = %q, want %q", m.RuleID, "totally_unknown_rule_xyz")
	}
	if m.Remediation != remediationDefault {
		t.Errorf("GetRuleMetadata(unknown): Remediation = %q, want remediationDefault", m.Remediation)
	}
}

func TestGetAllRuleMetadata(t *testing.T) {
	all := GetAllRuleMetadata()
	if len(all) == 0 {
		t.Fatal("GetAllRuleMetadata() returned empty map")
	}
	// Verify a few known entries exist.
	for _, id := range []string{
		"owasp_llm01_prompt_injection",
		"owasp_llm10_model_theft",
		"atlas_jailbreak",
	} {
		if _, ok := all[id]; !ok {
			t.Errorf("GetAllRuleMetadata(): missing key %q", id)
		}
	}
	// Verify that modifying the returned map does not affect the
	// internal map.
	delete(all, "owasp_llm01_prompt_injection")
	again := GetAllRuleMetadata()
	if _, ok := again["owasp_llm01_prompt_injection"]; !ok {
		t.Error("GetAllRuleMetadata(): returned map is not a copy (mutation leaked)")
	}
}

func TestGetRemediation(t *testing.T) {
	// Known rule returns its specific remediation text.
	got := GetRemediation("owasp_llm01_prompt_injection")
	if got != remediationPromptInjection {
		t.Errorf("GetRemediation(owasp_llm01_prompt_injection): got %q, want remediationPromptInjection", got)
	}
	// Another known rule.
	got = GetRemediation("owasp_llm04_model_dos")
	if got != remediationModelDoS {
		t.Errorf("GetRemediation(owasp_llm04_model_dos): got %q, want remediationModelDoS", got)
	}
}

func TestGetRemediationUnknown(t *testing.T) {
	got := GetRemediation("nonexistent_rule_abc")
	if got != remediationDefault {
		t.Errorf("GetRemediation(unknown): got %q, want remediationDefault", got)
	}
	if got == "" {
		t.Error("GetRemediation(unknown): returned empty string")
	}
}

func TestGetOWASPMapping(t *testing.T) {
	cwe, name, nistAiRmf, nistCsf, euAiArticles, ok := GetOWASPMapping("LLM01")
	if !ok {
		t.Fatal("GetOWASPMapping(LLM01): ok = false, want true")
	}
	if cwe != 77 {
		t.Errorf("GetOWASPMapping(LLM01): CWE = %d, want 77", cwe)
	}
	if name != "Prompt Injection" {
		t.Errorf("GetOWASPMapping(LLM01): Name = %q, want %q", name, "Prompt Injection")
	}
	if len(nistAiRmf) == 0 {
		t.Error("GetOWASPMapping(LLM01): NISTAIRMF is empty")
	}
	if len(nistCsf) == 0 {
		t.Error("GetOWASPMapping(LLM01): NISTCSF is empty")
	}
	if len(euAiArticles) == 0 {
		t.Error("GetOWASPMapping(LLM01): EUAIArticles is empty")
	}
}

func TestGetOWASPMappingUnknown(t *testing.T) {
	_, _, _, _, _, ok := GetOWASPMapping("LLM99")
	if ok {
		t.Error("GetOWASPMapping(LLM99): ok = true, want false")
	}
}

func TestOWASPMapComplete(t *testing.T) {
	for i := 1; i <= 10; i++ {
		llmID := "LLM" + func() string {
			if i < 10 {
				return "0" + string(rune('0'+i))
			}
			return "10"
		}()
		entry, ok := owaspLLMMap[llmID]
		if !ok {
			t.Errorf("owaspLLMMap missing %s", llmID)
			continue
		}
		if entry.CWE == 0 {
			t.Errorf("owaspLLMMap[%s]: CWE is 0", llmID)
		}
		if entry.Name == "" {
			t.Errorf("owaspLLMMap[%s]: Name is empty", llmID)
		}
		if len(entry.NISTAIRMF) == 0 {
			t.Errorf("owaspLLMMap[%s]: NISTAIRMF is empty", llmID)
		}
	}
}

func TestRemediationConstants(t *testing.T) {
	consts := []struct {
		name string
		val  string
	}{
		{"remediationPromptInjection", remediationPromptInjection},
		{"remediationSecrets", remediationSecrets},
		{"remediationPII", remediationPII},
		{"remediationXSS", remediationXSS},
		{"remediationOT", remediationOT},
		{"remediationCompliance", remediationCompliance},
		{"remediationHarmful", remediationHarmful},
		{"remediationATLAS", remediationATLAS},
		{"remediationDefault", remediationDefault},
		{"remediationDangerousCode", remediationDangerousCode},
		{"remediationInsecureOutput", remediationInsecureOutput},
		{"remediationModelDoS", remediationModelDoS},
		{"remediationSupplyChain", remediationSupplyChain},
		{"remediationSensitiveInfo", remediationSensitiveInfo},
		{"remediationExcessiveAgency", remediationExcessiveAgency},
		{"remediationOverreliance", remediationOverreliance},
		{"remediationModelTheft", remediationModelTheft},
		{"remediationTrainingPoisoning", remediationTrainingPoisoning},
	}
	// The task says 16 remediation constants, but the source defines 18
	// (including remediationDefault and remediationModelTheft). We verify
	// all of them are non-empty.
	for _, c := range consts {
		if strings.TrimSpace(c.val) == "" {
			t.Errorf("%s is empty", c.name)
		}
	}
}
func TestGetRuleMetadataWithDefault(t *testing.T) {
	// Known rule should return the same as GetRuleMetadata.
	m1 := GetRuleMetadataWithDefault("owasp_llm01_prompt_injection")
	m2 := GetRuleMetadata("owasp_llm01_prompt_injection")
	if m1.RuleID != m2.RuleID {
		t.Errorf("GetRuleMetadataWithDefault != GetRuleMetadata for known rule: %q vs %q", m1.RuleID, m2.RuleID)
	}

	// Unknown rule should return a metadata with the rule ID and default remediation.
	m := GetRuleMetadataWithDefault("unknown_rule_xyz")
	if m.RuleID != "unknown_rule_xyz" {
		t.Errorf("GetRuleMetadataWithDefault(unknown): RuleID = %q, want %q", m.RuleID, "unknown_rule_xyz")
	}
	if m.Remediation != remediationDefault {
		t.Errorf("GetRuleMetadataWithDefault(unknown): Remediation = %q, want remediationDefault", m.Remediation)
	}
}

func TestGetRemediationForCategory(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{"prompt_injection_xss", remediationPromptInjection},
		{"prompt_injection_custom", remediationPromptInjection},     // prefix match
		{"prompt_injection", remediationPromptInjection},             // containment fallback
		{"pii_ssn", remediationPII},
		{"secret_api_key", remediationSecrets},
		{"xss_script", remediationXSS},
		{"ot_modbus", remediationOT},
		{"dangerous_eval", remediationDangerousCode},
		{"harmful_content", remediationHarmful},
		{"mitre_atlas_jailbreak", remediationATLAS},
		{"unknown_category", remediationDefault},
		{"", remediationDefault},
	}
	for _, tc := range tests {
		got := getRemediationForCategory(tc.category)
		if got != tc.want {
			t.Errorf("getRemediationForCategory(%q) = %q, want %q", tc.category, got, tc.want)
		}
	}
}

func TestGetRuleMetadataPrefixMatch(t *testing.T) {
	// Test prefix matching path — a rule ID that matches a prefix matcher
	// but isn't an explicit entry should still return metadata with
	// category-based remediation.
	m := GetRuleMetadata("prompt_injection_custom_variant")
	if m.RuleID != "prompt_injection_custom_variant" {
		t.Errorf("GetRuleMetadata(prefix-match): RuleID = %q", m.RuleID)
	}
	// Should have gotten remediation from the prefix matcher.
	if m.Remediation == remediationDefault {
		t.Error("GetRuleMetadata(prefix-match): got default remediation, expected category-specific")
	}
	if m.Remediation != remediationPromptInjection {
		t.Errorf("GetRuleMetadata(prefix-match): Remediation = %q, want remediationPromptInjection", m.Remediation)
	}
}

func TestGetAllRuleMetadataCount(t *testing.T) {
	all := GetAllRuleMetadata()
	if len(all) < 20 {
		t.Errorf("GetAllRuleMetadata(): expected at least 20 entries, got %d", len(all))
	}
}
