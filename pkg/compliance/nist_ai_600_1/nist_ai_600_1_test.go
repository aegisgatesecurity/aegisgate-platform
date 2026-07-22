// SPDX-License-Identifier: Apache-2.0
// NIST AI 600-1 (GenAI Profile) Compliance Module - Unit Tests
// v3.x Tier 1: 12/12 in-scope controls tested.

package nist_ai_600_1

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewNISTAIGenAIProfileModule(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	if m == nil {
		t.Fatal("NewNISTAIGenAIProfileModule returned nil")
	}
	if m.Framework() != "nist_ai_600_1" {
		t.Errorf("Framework() = %q, want nist_ai_600_1", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0 (v3.x Tier 1 new module)", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 12 {
		t.Errorf("len(Controls()) = %d, want 12 (v3.x Tier 1: 12 of 12 GenAI Profile categories)", len(controls))
	}
	for _, c := range controls {
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", c.ID)
		}
	}
}

func TestNISTAIGenAIControlIDsPresent(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	haveIDs := make(map[string]bool)
	for _, c := range m.Controls() {
		haveIDs[c.ID] = true
	}
	// All 12 GenAI Profile categories
	expected := []string{
		"NIST-AI-6001-1",  // Confabulation
		"NIST-AI-6001-2",  // Data Privacy
		"NIST-AI-6001-3",  // Information Integrity
		"NIST-AI-6001-4",  // Harmful Bias
		"NIST-AI-6001-5",  // Privacy Concerns of Multimodal
		"NIST-AI-6001-6",  // System Prompt Security
		"NIST-AI-6001-7",  // CBRN Information
		"NIST-AI-6001-8",  // Hazardous Information
		"NIST-AI-6001-9",  // Vulnerable Populations
		"NIST-AI-6001-10", // Abusive Content
		"NIST-AI-6001-11", // Sensitive Content and IP
		"NIST-AI-6001-12", // Information on Using AI
	}
	for _, id := range expected {
		if !haveIDs[id] {
			t.Errorf("Expected control %s not registered", id)
		}
	}
}

func TestNISTAIGenAI_Confabulation(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	ctx := context.Background()
	t.Run("compliant", func(t *testing.T) {
		input := []byte("hallucination_detector grounding citation factuality_check confidence_calibration")
		r, err := m.checkConfabulation(ctx, input)
		if err != nil {
			t.Fatalf("checkConfabulation: %v", err)
		}
		if string(r.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant (msg: %q)", r.Status, r.Message)
		}
	})
	t.Run("partial", func(t *testing.T) {
		input := []byte("hallucination_detector grounding")
		r, err := m.checkConfabulation(ctx, input)
		if err != nil {
			t.Fatalf("checkConfabulation: %v", err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("Status = %s, want partial", r.Status)
		}
	})
	t.Run("non_compliant", func(t *testing.T) {
		input := []byte("nothing_here")
		r, err := m.checkConfabulation(ctx, input)
		if err != nil {
			t.Fatalf("checkConfabulation: %v", err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", r.Status)
		}
	})
}

func TestNISTAIGenAI_PromptInjection(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	ctx := context.Background()
	t.Run("compliant (all 4 markers)", func(t *testing.T) {
		input := []byte("prompt_injection_detector system_prompt_protection prompt_audit_log prompt_allowlist")
		r, err := m.checkSystemPromptSecurity(ctx, input)
		if err != nil {
			t.Fatalf("checkSystemPromptSecurity: %v", err)
		}
		if string(r.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant (msg: %q)", r.Status, r.Message)
		}
	})
	t.Run("non_compliant", func(t *testing.T) {
		input := []byte("nothing_here")
		r, err := m.checkSystemPromptSecurity(ctx, input)
		if err != nil {
			t.Fatalf("checkSystemPromptSecurity: %v", err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", r.Status)
		}
	})
}

func TestNISTAIGenAI_Module_Dependencies(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	deps := m.Dependencies()
	if len(deps) != 2 {
		t.Errorf("Dependencies() returned %d items, want 2", len(deps))
	}
}

func TestNISTAIGenAI_AllAutomated(t *testing.T) {
	m := NewNISTAIGenAIProfileModule()
	checks := map[string]func(context.Context, []byte) (*compliance.ControlCheckResult, error){
		"NIST-AI-6001-1":  m.checkConfabulation,
		"NIST-AI-6001-2":  m.checkDataPrivacy,
		"NIST-AI-6001-3":  m.checkInformationIntegrity,
		"NIST-AI-6001-4":  m.checkHarmfulBias,
		"NIST-AI-6001-5":  m.checkMultimodalPrivacy,
		"NIST-AI-6001-6":  m.checkSystemPromptSecurity,
		"NIST-AI-6001-7":  m.checkCBRNInformation,
		"NIST-AI-6001-8":  m.checkHazardousInformation,
		"NIST-AI-6001-9":  m.checkVulnerablePopulations,
		"NIST-AI-6001-10": m.checkAbusiveContent,
		"NIST-AI-6001-11": m.checkSensitiveContent,
		"NIST-AI-6001-12": m.checkAIDisclosure,
	}
	compliantConfig := []byte(`{
		"hallucination_detector": true, "grounding": true, "citation": true, "factuality_check": true, "confidence_calibration": true,
		"pii_scanner": true, "output_filtering": true, "tenant_isolation": true, "data_classification": true,
		"content_verification": true, "provenance": true, "watermarking": true, "factuality_check": true,
		"bias_testing": true, "fairness_metrics": true, "dataset_diversity": true, "bias_monitoring": true,
		"multimodal_pii_detection": true, "biometric_redaction": true, "image_pii_detection": true, "audio_pii_detection": true,
		"prompt_injection_detector": true, "system_prompt_protection": true, "prompt_audit_log": true, "prompt_allowlist": true,
		"cbrn_content_filter": true, "harmful_substance_detection": true, "output_moderation": true, "content_classification": true,
		"harmful_content_filter": true, "violence_detection": true, "self_harm_detection": true, "illegal_activity_detection": true,
		"age_verification": true, "content_filtering": true, "child_safety_filter": true, "accessibility_compliance": true,
		"abusive_content_filter": true, "content_moderation": true, "user_reporting": true, "toxicity_detection": true,
		"copyright_detection": true, "ip_protection": true, "watermarking": true, "provenance_tracking": true,
		"ai_disclosure": true, "transparency_notice": true, "user_documentation": true, "feedback_mechanism": true
	}`)
	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			r, err := checkFn(context.Background(), compliantConfig)
			if err != nil {
				t.Fatalf("check%s: %v", controlID, err)
			}
			if string(r.Status) != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, r.Status, r.Message)
			}
		})
	}
}
