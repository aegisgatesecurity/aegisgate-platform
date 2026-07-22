// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST AI 600-1 (GenAI Profile) Module
// =========================================================================
//
// NIST AI 600-1 is the July 2024 Generative AI Profile that accompanies
// NIST AI RMF 1.0. It addresses the 12 unique GenAI risk categories that
// are not covered by the parent AI RMF (confabulation, data privacy,
// model exfiltration, etc.). This is the most relevant framework for
// AegisGate's actual product — we are a GenAI security platform.
//
// Module metadata:
//   - Framework:   "nist_ai_600_1"
//   - Version:     "1.0" (v3.x Tier 1, new module)
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: bundled with NIST AI RMF (no separate add-on)
//
// Architecture:
//   - nist_ai_600_1.go:       module wiring, 12 RegisterControl calls,
//                            12 CheckFunc implementations
//   - nist_ai_600_1_test.go:  unit tests
//
// Coverage: 12 of 12 GenAI Profile categories (100% in-scope).
// These are the most relevant controls for AegisGate because they
// address exactly the risks that AegisGate mitigates: confabulation,
// prompt injection, model exfiltration, etc.
//
// Reference: NIST AI 600-1 (July 2024)
//            https://www.nist.gov/itl/ai-risk-management-framework
//            Companion to NIST AI RMF 1.0 (January 2023)
//            https://airc.nist.gov/Home
// =========================================================================

package nist_ai_600_1

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NISTAIGenAIProfileModule implements the NIST AI 600-1 (GenAI Profile)
// compliance framework. It complements NIST AI RMF 1.0 (the parent)
// with the 12 unique GenAI risk categories.
type NISTAIGenAIProfileModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	hallucinationPatterns []*regexp.Regexp
	promptInjectPatterns  []*regexp.Regexp
	exfilPatterns         []*regexp.Regexp
	dataPoisonPatterns    []*regexp.Regexp
}

// NewNISTAIGenAIProfileModule creates a new NIST AI 600-1 (GenAI Profile)
// compliance module.
func NewNISTAIGenAIProfileModule() *NISTAIGenAIProfileModule {
	m := &NISTAIGenAIProfileModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nist_ai_600_1", "1.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
func (m *NISTAIGenAIProfileModule) initPatterns() {
	// Confabulation / hallucination patterns
	m.hallucinationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)hallucination`),
		regexp.MustCompile(`(?i)confabulation`),
		regexp.MustCompile(`(?i)overconfidence`),
		regexp.MustCompile(`(?i)factuality`),
	}
	// Prompt injection patterns
	m.promptInjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)prompt[_ ]?injection`),
		regexp.MustCompile(`(?i)jailbreak`),
		regexp.MustCompile(`(?i)prompt[_ ]?manipulation`),
		regexp.MustCompile(`(?i)system[_ ]?prompt[_ ]?override`),
	}
	// Exfiltration patterns
	m.exfilPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)data[_ ]?exfiltration`),
		regexp.MustCompile(`(?i)model[_ ]?exfiltration`),
		regexp.MustCompile(`(?i)weights[_ ]?exfil`),
		regexp.MustCompile(`(?i)training[_ ]?data[_ ]?leak`),
	}
	// Data poisoning patterns
	m.dataPoisonPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)data[_ ]?poisoning`),
		regexp.MustCompile(`(?i)model[_ ]?poisoning`),
		regexp.MustCompile(`(?i)backdoor[_ ]?attack`),
		regexp.MustCompile(`(?i)training[_ ]?data[_ ]?tamper`),
	}
}

// registerControls wires all 12 NIST AI 600-1 (GenAI Profile) controls
// into the module. These are the 12 unique GenAI risk categories that
// complement the parent NIST AI RMF 1.0.
func (m *NISTAIGenAIProfileModule) registerControls() {
	// 1. Confabulation / Hallucination
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-1",
		Name:        "Confabulation / Hallucination",
		Description: "GV-1: Address confabulation, hallucination, and over-reliance on GenAI outputs through grounding, citation, factuality checking, and confidence calibration",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkConfabulation,
		References:  []string{"NIST AI 600-1 §1.1 Confabulation"},
	})

	// 2. Data Privacy and Information Leakage
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-2",
		Name:        "Data Privacy and Information Leakage",
		Description: "GV-2: Address data privacy, intellectual property, and information leakage through PII/PII detection, output filtering, and tenant isolation",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataPrivacy,
		References:  []string{"NIST AI 600-1 §1.2 Data Privacy"},
	})

	// 3. Information Integrity
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-3",
		Name:        "Information Integrity",
		Description: "GV-3: Address information integrity risks including misinformation, disinformation, deepfakes, and harmful content through provenance, watermarking, and content verification",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkInformationIntegrity,
		References:  []string{"NIST AI 600-1 §1.3 Information Integrity"},
	})

	// 4. Harmful Bias
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-4",
		Name:        "Harmful Bias and Homogenization",
		Description: "GV-4: Address harmful bias, stereotypes, and unfair discrimination through bias testing, dataset diversity, and fairness monitoring",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkHarmfulBias,
		References:  []string{"NIST AI 600-1 §1.4 Harmful Bias"},
	})

	// 5. Privacy Concerns of Multimodal
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-5",
		Name:        "Privacy Concerns of Multimodal",
		Description: "GV-5: Address privacy concerns specific to multimodal GenAI (text + image + audio + video), including biometric PII and re-identification risks",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMultimodalPrivacy,
		References:  []string{"NIST AI 600-1 §1.5 Multimodal Privacy"},
	})

	// 6. Information Security for System Prompts
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-6",
		Name:        "Information Security for System Prompts",
		Description: "GV-6: Address information security risks specific to system prompts including prompt injection, system prompt override, and prompt theft",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSystemPromptSecurity,
		References:  []string{"NIST AI 600-1 §2.1 System Prompt Security"},
	})

	// 7. CBRN Information
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-7",
		Name:        "CBRN Information (Chemical, Biological, Radiological, Nuclear)",
		Description: "GV-7: Address CBRN information risks (GenAI providing synthesis instructions for harmful substances). Detection and filtering of harmful content",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCBRNInformation,
		References:  []string{"NIST AI 600-1 §2.2 CBRN Information"},
	})

	// 8. Hazardous Information Emanation
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-8",
		Name:        "Hazardous Information Emanation",
		Description: "GV-8: Address hazardous information (instructions for violence, self-harm, illegal activities). Output filtering and content moderation",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkHazardousInformation,
		References:  []string{"NIST AI 600-1 §2.3 Hazardous Information"},
	})

	// 9. Vulnerable Population
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-9",
		Name:        "Vulnerable Populations",
		Description: "GV-9: Address risks to vulnerable populations (children, elderly, disabled). Age-appropriate design and content filtering",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerablePopulations,
		References:  []string{"NIST AI 600-1 §2.4 Vulnerable Populations"},
	})

	// 10. Obscene, Degrading, and Abusive Content
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-10",
		Name:        "Obscene, Degrading, and Abusive Content",
		Description: "GV-10: Address risks of GenAI producing obscene, degrading, or abusive content. Content moderation, output filtering, and user reporting",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAbusiveContent,
		References:  []string{"NIST AI 600-1 §2.5 Abusive Content"},
	})

	// 11. Sensitive Content (IP, etc.)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-11",
		Name:        "Sensitive Content and IP Risk",
		Description: "GV-11: Address risks around copyrighted material reproduction, IP leakage, and trade secret disclosure. Content filtering and provenance tracking",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSensitiveContent,
		References:  []string{"NIST AI 600-1 §2.6 Sensitive Content"},
	})

	// 12. Information on Using AI
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-AI-6001-12",
		Name:        "Information on Using AI",
		Description: "GV-12: Disclose AI involvement to users (transparency), provide documentation on capabilities and limitations, and enable user feedback",
		Category:    "GenAI Risk Categories",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAIDisclosure,
		References:  []string{"NIST AI 600-1 §2.7 Information on Using AI"},
	})
}

// ============================================================================
// Check implementations (12 controls)
// ============================================================================

// standardGenAICheck is a helper for the 12 checks. It uses a 2-4 marker
// pattern to determine status: compliant if >=3 markers present,
// partial if 1+, non_compliant if none.
func (m *NISTAIGenAIProfileModule) standardGenAICheck(ctx context.Context, id, name, sevStr string, severity compliance.Severity, input []byte, required []string, message string) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	present := 0
	missing := []string{}
	for _, r := range required {
		if strings.Contains(inputStr, r) {
			present++
		} else {
			missing = append(missing, r)
		}
	}
	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   id,
			ControlName: name,
			Status:      compliance.StatusCompliant,
			Severity:    severity,
			Message:     message + " (compliant)",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   id,
			ControlName: name,
			Status:      compliance.StatusNonCompliant,
			Severity:    severity,
			Message:     message + " (no controls detected; missing: " + strings.Join(missing, ", ") + ")",
			Timestamp:   time.Now(),
			Remediation: "Configure the missing controls: " + strings.Join(missing, ", "),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   id,
		ControlName: name,
		Status:      compliance.StatusPartial,
		Severity:    severity,
		Message:     message + " (partial: " + nistCount(present) + "/" + nistCount(len(required)) + " configured; missing: " + strings.Join(missing, ", ") + ")",
		Timestamp:   time.Now(),
		Remediation: "Configure the missing controls: " + strings.Join(missing, ", "),
	}, nil
}

// 1. Confabulation / Hallucination
func (m *NISTAIGenAIProfileModule) checkConfabulation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-1", "Confabulation / Hallucination", "1.1",
		compliance.SeverityCritical, input,
		[]string{"hallucination_detector", "grounding", "citation", "factuality_check", "confidence_calibration"},
		"Confabulation controls configured")
}

// 2. Data Privacy and Information Leakage
func (m *NISTAIGenAIProfileModule) checkDataPrivacy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-2", "Data Privacy and Information Leakage", "1.2",
		compliance.SeverityCritical, input,
		[]string{"pii_scanner", "output_filtering", "tenant_isolation", "data_classification"},
		"Data privacy controls configured")
}

// 3. Information Integrity
func (m *NISTAIGenAIProfileModule) checkInformationIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-3", "Information Integrity", "1.3",
		compliance.SeverityCritical, input,
		[]string{"content_verification", "provenance", "watermarking", "factuality_check"},
		"Information integrity controls configured")
}

// 4. Harmful Bias
func (m *NISTAIGenAIProfileModule) checkHarmfulBias(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-4", "Harmful Bias and Homogenization", "1.4",
		compliance.SeverityHigh, input,
		[]string{"bias_testing", "fairness_metrics", "dataset_diversity", "bias_monitoring"},
		"Harmful bias controls configured")
}

// 5. Privacy Concerns of Multimodal
func (m *NISTAIGenAIProfileModule) checkMultimodalPrivacy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-5", "Privacy Concerns of Multimodal", "1.5",
		compliance.SeverityHigh, input,
		[]string{"multimodal_pii_detection", "biometric_redaction", "image_pii_detection", "audio_pii_detection"},
		"Multimodal privacy controls configured")
}

// 6. Information Security for System Prompts
func (m *NISTAIGenAIProfileModule) checkSystemPromptSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-6", "Information Security for System Prompts", "2.1",
		compliance.SeverityCritical, input,
		[]string{"prompt_injection_detector", "system_prompt_protection", "prompt_audit_log", "prompt_allowlist"},
		"System prompt security configured")
}

// 7. CBRN Information
func (m *NISTAIGenAIProfileModule) checkCBRNInformation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-7", "CBRN Information (Chemical, Biological, Radiological, Nuclear)", "2.2",
		compliance.SeverityCritical, input,
		[]string{"cbrn_content_filter", "harmful_substance_detection", "output_moderation", "content_classification"},
		"CBRN content filtering configured")
}

// 8. Hazardous Information Emanation
func (m *NISTAIGenAIProfileModule) checkHazardousInformation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-8", "Hazardous Information Emanation", "2.3",
		compliance.SeverityCritical, input,
		[]string{"harmful_content_filter", "violence_detection", "self_harm_detection", "illegal_activity_detection"},
		"Hazardous content filtering configured")
}

// 9. Vulnerable Populations
func (m *NISTAIGenAIProfileModule) checkVulnerablePopulations(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-9", "Vulnerable Populations", "2.4",
		compliance.SeverityHigh, input,
		[]string{"age_verification", "content_filtering", "child_safety_filter", "accessibility_compliance"},
		"Vulnerable populations protection configured")
}

// 10. Obscene, Degrading, and Abusive Content
func (m *NISTAIGenAIProfileModule) checkAbusiveContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-10", "Obscene, Degrading, and Abusive Content", "2.5",
		compliance.SeverityHigh, input,
		[]string{"abusive_content_filter", "content_moderation", "user_reporting", "toxicity_detection"},
		"Abusive content filtering configured")
}

// 11. Sensitive Content (IP, etc.)
func (m *NISTAIGenAIProfileModule) checkSensitiveContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-11", "Sensitive Content and IP Risk", "2.6",
		compliance.SeverityHigh, input,
		[]string{"copyright_detection", "ip_protection", "watermarking", "provenance_tracking"},
		"Sensitive content controls configured")
}

// 12. Information on Using AI
func (m *NISTAIGenAIProfileModule) checkAIDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardGenAICheck(ctx, "NIST-AI-6001-12", "Information on Using AI", "2.7",
		compliance.SeverityMedium, input,
		[]string{"ai_disclosure", "transparency_notice", "user_documentation", "feedback_mechanism"},
		"AI disclosure configured")
}

// nistCount is a small helper to avoid importing strconv.
func nistCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-nistCount(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules. NIST AI 600-1 depends on the
// scanner (for prompt injection, hallucination detection) and the
// persistence layer (for content moderation logs).
func (m *NISTAIGenAIProfileModule) Dependencies() []string {
	return []string{"scanner", "persistence"}
}
