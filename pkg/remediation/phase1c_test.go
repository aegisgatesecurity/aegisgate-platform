// SPDX-License-Identifier: Apache-2.0

package remediation

import (
	"testing"
)

// TestPhase1c_PromptInjectionContainment covers the containment-check
// branch in GetRuleMetadata for IDs that contain "prompt_injection" but
// do not start with the "prompt_injection_" prefix (e.g., IDs like
// "ml_prompt_injection" that are not explicit map entries).
func TestPhase1c_PromptInjectionContainment(t *testing.T) {
	m := GetRuleMetadata("ml_prompt_injection")
	if m.RuleID != "ml_prompt_injection" {
		t.Errorf("RuleID = %q, want %q", m.RuleID, "ml_prompt_injection")
	}
	if m.Remediation == remediationDefault {
		t.Error("got default remediation, expected prompt-injection-specific")
	}
	if m.Remediation != remediationPromptInjection {
		t.Errorf("Remediation = %q, want remediationPromptInjection", m.Remediation)
	}
	if m.OWASPLLMTop == "" {
		t.Error("OWASPLLMTop is empty — containment path should set it from template")
	}
	if len(m.NISTAIRMF) == 0 {
		t.Error("NISTAIRMF not enriched in containment path")
	}
}

// TestPhase1c_TokenSlackContainment covers the containment-check branch
// for rule IDs containing "token" or "slack" that don't match any
// explicit entry or prefix matcher.
func TestPhase1c_TokenSlackContainment(t *testing.T) {
	tests := []string{
		"hardcoded_token",
		"slack_webhook_url",
		"SlackToken",
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			m := GetRuleMetadata(id)
			if m.RuleID != id {
				t.Errorf("RuleID = %q, want %q", m.RuleID, id)
			}
			if len(m.CWE) == 0 || m.CWE[0] != 798 {
				t.Errorf("CWE = %v, want [798]", m.CWE)
			}
			if m.Remediation != remediationSecrets {
				t.Errorf("Remediation = %q, want remediationSecrets", m.Remediation)
			}
			if m.Description == "" {
				t.Error("Description is empty")
			}
		})
	}
}

// TestPhase1c_GetRemediationForCategoryContainment exercises the
// containment fallback in getRemediationForCategory for a non-prefix
// but still prompt-injection-containing category.
func TestPhase1c_GetRemediationForCategoryContainment(t *testing.T) {
	got := getRemediationForCategory("ml_prompt_injection")
	if got != remediationPromptInjection {
		t.Errorf("getRemediationForCategory(ml_prompt_injection) = %q, want remediationPromptInjection", got)
	}
}
