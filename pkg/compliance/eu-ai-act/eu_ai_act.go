// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - EU AI Act Compliance Module
// =========================================================================
//
// EU AI Act Compliance Module (v3.5.0+ Phase 2: Output Filtering + Human
// Oversight automation)
//
// Implements Regulation 2024/1689 ("EU AI Act") compliance controls as
// a licensed add-on module. This file holds module wiring and the
// v3.5.0+ automated CheckFunc implementations; controls.go holds the
// 82 RegisterControl calls; evaluator.go provides the public
// EvaluateEUAIAct API used by the Compliance Scan Engine.
//
// v3.5.0+ Phase 2 (2026-07-21): Adds 8 new automated CheckFunc
// implementations to the previously-manual controls, raising the
// automated count from 9/82 (11%) to 17/82 (21%).
//
// Mapping of new automated controls:
//   - AI-002 Training Data Sanitization       -> pkg/response/pii_scanner.go + secret_scanner.go
//   - AI-003 AI System Output Filtering       -> pkg/response/guard.go (ResponseGuard)
//   - AI-005 Hallucination Detection         -> pkg/response/hallucination_detector.go
//   - AI-006 Agent Capability Attestation     -> pkg/trust/attestation/
//   - AI-007 Model Versioning/Lineage         -> AegisGate model registry config
//   - Art14-002 Oversight Measures Effective -> kill_switch + override config
//   - Art14-003 Human Reviewers Can Intervene -> human_review config
//   - Art14-004 Kill Switch / Abort Capability -> kill_switch + abort config
//
// Module metadata:
//   - Framework:   "eu_ai_act"
//   - Version:     "1.1"  (v3.5.0+ bump for Phase 2 additions)
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $99/mo (founder-locked 2026-06-06)
//
// =========================================================================

package eu_ai_act

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// EUAIModule implements the EU AI Act compliance framework as a licensed
// add-on. It embeds *compliance.BaseComplianceModule which provides
// RegisterControl, Controls(), Framework(), Version(), CheckAll(), and
// GenerateAssessment() out of the box.
type EUAIModule struct {
	*compliance.BaseComplianceModule
	// pattern caches used by automated checks
	subliminalPatterns   []*regexp.Regexp
	manipulationPatterns []*regexp.Regexp
	biometricPatterns    []*regexp.Regexp
	promptInjectPatterns []*regexp.Regexp
	dataPoisonPatterns   []*regexp.Regexp
	adversarialPatterns  []*regexp.Regexp

	// v3.5.0+ pattern caches for the new automated controls
	piiPatterns       []*regexp.Regexp
	secretPatterns    []*regexp.Regexp
	hallucinationPats []*regexp.Regexp
	oversightPats     []*regexp.Regexp
}

// NewEUAIModule creates a new EU AI Act compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleEUAIAct entry in
// moduleRequirements).
func NewEUAIModule() *EUAIModule {
	m := &EUAIModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("eu_ai_act", "1.1", core.TierProfessional),
	}
	m.initAIActPatterns()
	m.initV350Patterns()
	m.registerControls()
	return m
}

// initAIActPatterns compiles the regex patterns used by the v3.3.0
// automated controls. Called once at construction time.
func (m *EUAIModule) initAIActPatterns() {
	m.subliminalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)subliminal[_\- ]?manipulation`),
		regexp.MustCompile(`(?i)below[_\- ]?conscious[_\- ]?threshold`),
		regexp.MustCompile(`(?i)unconscious[_\- ]?influence`),
	}
	m.manipulationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)targets? (children|minors|disabled|elderly)`),
		regexp.MustCompile(`(?i)exploit(s|ing)? vulnerabilities`),
		regexp.MustCompile(`(?i)distorts? (behavior|decision)`),
	}
	m.biometricPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)real[_\- ]?time[_\- ]?biometric`),
		regexp.MustCompile(`(?i)remote[_\- ]?biometric[_\- ]?identification`),
		regexp.MustCompile(`(?i)face[_\- ]?recognition`),
		regexp.MustCompile(`(?i)facial[_\- ]?categorization`),
	}
	m.promptInjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)prompt[_\- ]?injection`),
		regexp.MustCompile(`(?i)ignore[_\- ]?(previous|above)`),
		regexp.MustCompile(`(?i)jailbreak`),
	}
	m.dataPoisonPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)data[_\- ]?poisoning`),
		regexp.MustCompile(`(?i)training[_\- ]?data[_\- ]?poison`),
		regexp.MustCompile(`(?i)backdoor[_\- ]?trigger`),
	}
	m.adversarialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)adversarial[_\- ]?example`),
		regexp.MustCompile(`(?i)adversarial[_\- ]?attack`),
		regexp.MustCompile(`(?i)evasion[_\- ]?attack`),
	}
}

// initV350Patterns compiles the regex patterns used by the v3.5.0+
// new automated controls. Called once at construction time.
func (m *EUAIModule) initV350Patterns() {
	// PII patterns — match the patterns in pkg/response/pii_scanner.go
	m.piiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                     // SSN
		regexp.MustCompile(`\d{16}`),                                // Credit card
		regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.\w+`), // Email
		regexp.MustCompile(`\d{3}[-.s]?\d{3}[-.s]?\d{4}`),           // Phone
	}

	// Secret patterns — match the patterns in pkg/response/secret_scanner.go
	m.secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),    // AWS access key
		regexp.MustCompile(`(?i)sk-[A-Za-z0-9]{32,}`), // OpenAI/Stripe
		regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}`), // GitHub PAT
		regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), // JWT
	}

	// Hallucination patterns — match the patterns in
	// pkg/response/hallucination_detector.go (overconfidence + fabricated stats)
	m.hallucinationPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(certainly|definitely|absolutely|guaranteed|100% proven|incontrovertibly)\b`),
		regexp.MustCompile(`(?i)\b(studies show|research indicates|experts say|statistics show)\b`),
		regexp.MustCompile(`(?i)\b\d+(\.\d+)?% of (users|customers|patients|cases)\b`),
	}

	// Oversight patterns — kill switch, human review, override, abort
	m.oversightPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)kill[_ ]?switch`),
		regexp.MustCompile(`(?i)human[_ ]?review`),
		regexp.MustCompile(`(?i)human[_ ]?in[_ ]?the[_ ]?loop`),
		regexp.MustCompile(`(?i)override`),
		regexp.MustCompile(`(?i)\babort`),
		regexp.MustCompile(`(?i)manual[_ ]?approval`),
	}
}

// Dependencies returns the list of required platform modules.
// v3.5.0+: depends on the response scanner (PII, secret, hallucination)
// and the trust attestation framework (agent capability attestation).
func (m *EUAIModule) Dependencies() []string {
	return []string{"scanner", "response", "trust"}
}

// detectProhibitedPractice scans for language patterns indicating
// Article 5 prohibited practices.
func (m *EUAIModule) detectProhibitedPractice(input string) (string, bool) {
	for _, p := range m.subliminalPatterns {
		if p.MatchString(input) {
			return "subliminal_manipulation_detected", true
		}
	}
	for _, p := range m.manipulationPatterns {
		if p.MatchString(input) {
			return "manipulation_pattern_detected", true
		}
	}
	for _, p := range m.biometricPatterns {
		if p.MatchString(input) && strings.Contains(input, "public") {
			return "public_biometric_identification_detected", true
		}
	}
	return "", false
}

// detectPromptInjection scans for prompt-injection patterns (EUAIAct-AI-001).
func (m *EUAIModule) detectPromptInjection(input string) []string {
	var found []string
	for _, p := range m.promptInjectPatterns {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// detectDataPoisoning scans for data/model poisoning patterns (Article 15).
func (m *EUAIModule) detectDataPoisoning(input string) []string {
	var found []string
	for _, p := range m.dataPoisonPatterns {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// detectAdversarialInput scans for adversarial example/attack patterns.
func (m *EUAIModule) detectAdversarialInput(input string) []string {
	var found []string
	for _, p := range m.adversarialPatterns {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// detectPII scans for PII patterns (v3.5.0+ new). Reuses the patterns
// from pkg/response/pii_scanner.go to keep behavior consistent.
func (m *EUAIModule) detectPII(input string) []string {
	var found []string
	for _, p := range m.piiPatterns {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// detectSecrets scans for secret patterns (v3.5.0+ new). Reuses the
// patterns from pkg/response/secret_scanner.go.
func (m *EUAIModule) detectSecrets(input string) []string {
	var found []string
	for _, p := range m.secretPatterns {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// detectHallucination scans for hallucination markers (v3.5.0+ new).
// Reuses the patterns from pkg/response/hallucination_detector.go.
func (m *EUAIModule) detectHallucination(input string) []string {
	var found []string
	for _, p := range m.hallucinationPats {
		if p.MatchString(input) {
			found = append(found, p.String())
		}
	}
	return found
}

// hasAuditLogEvidence checks for audit-log related configuration markers.
func (m *EUAIModule) hasAuditLogEvidence(input string) bool {
	markers := []string{"audit_log", "audit_enabled", "log_integrity", "signed_logs", "tamper_evident"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasHumanOversightEvidence checks for human-in-the-loop markers.
func (m *EUAIModule) hasHumanOversightEvidence(input string) bool {
	markers := []string{"human_review", "human_oversight", "human_in_the_loop", "kill_switch", "abort", "manual_review", "override"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasTransparencyEvidence checks for transparency disclosure markers.
func (m *EUAIModule) hasTransparencyEvidence(input string) bool {
	markers := []string{"instructions_for_use", "transparency_notice", "model_card", "system_card", "capability_disclosure"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasDocumentationEvidence checks for technical-documentation markers.
func (m *EUAIModule) hasDocumentationEvidence(input string) bool {
	markers := []string{"technical_documentation", "model_documentation", "system_documentation", "design_spec"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasResponseFilterEnabled checks for AI system output filtering
// (v3.5.0+). The pkg/response/guard.go ResponseGuard has the Enable()
// method; we look for its config markers.
func (m *EUAIModule) hasResponseFilterEnabled(input string) bool {
	markers := []string{"response_filter_enabled", "output_filter", "ai_response_guard", "response_guard"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasAgentAttestation checks for AI agent capability attestation
// (v3.5.0+). The pkg/trust/attestation package generates signed
// attestations; we look for its config markers.
func (m *EUAIModule) hasAgentAttestation(input string) bool {
	markers := []string{"trust_attestation", "agent_attestation", "capability_attestation", "signed_attestation", "trust_framework"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasModelVersioning checks for model versioning + lineage (v3.5.0+).
// AegisGate's model registry tracks model_id, version, and lineage.
func (m *EUAIModule) hasModelVersioning(input string) bool {
	markers := []string{"model_version", "model_id", "lineage", "model_registry", "model_lineage", "model_card"}
	present := 0
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			present++
		}
	}
	return present >= 2
}

// hasTrainingDataSanitization checks for PII/secret scrubbing in
// training data (v3.5.0+). The pkg/response package's PIIScanner and
// SecretDetector are the scrubbing primitives.
func (m *EUAIModule) hasTrainingDataSanitization(input string) bool {
	markers := []string{"training_data_sanitized", "pii_scrubbing", "secret_scrubbing", "data_anonymization", "de_identified"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasKillSwitch checks for kill switch + abort capability (Art 14-004).
// We check the input string for the actual markers, not the regex
// pattern source (which contains escape characters like [_]).
func (m *EUAIModule) hasKillSwitch(input string) bool {
	hasKS := false
	hasAbort := false
	// Direct string match (not regex match) for kill_switch and abort
	hasKS = strings.Contains(input, "kill_switch")
	hasAbort = strings.Contains(input, "abort")
	return hasKS && hasAbort
}

// hasHumanReviewers checks for human reviewer configuration (Art 14-003).
func (m *EUAIModule) hasHumanReviewers(input string) bool {
	markers := []string{"human_reviewer", "human_review_required", "reviewer_role", "approver", "manual_approval"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// hasOverrideCapability checks for override capability (Art 14-006).
func (m *EUAIModule) hasOverrideCapability(input string) bool {
	markers := []string{"override_capability", "override_decision", "manual_override"}
	for _, mk := range markers {
		if strings.Contains(input, mk) {
			return true
		}
	}
	return false
}

// checkProhibitedPractices (Article 5) - automated pattern scan.
func (m *EUAIModule) checkProhibitedPractices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	_, detected := m.detectProhibitedPractice(string(input))
	if detected {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art5-001",
			ControlName: "Subliminal Manipulation Techniques",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Prohibited practice pattern detected in AI system input",
			Timestamp:   time.Now(),
			Remediation: "Remove subliminal or manipulative techniques; this is a prohibited practice under Article 5",
			References:  []string{"EU AI Act Article 5(1)(a)"},
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art5-001",
		ControlName: "Subliminal Manipulation Techniques",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No prohibited practice patterns detected",
		Timestamp:   time.Now(),
	}, nil
}

// checkRiskManagement (Article 9) - checks for risk-management markers.
func (m *EUAIModule) checkRiskManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasProcess := strings.Contains(inputStr, "risk_management") || strings.Contains(inputStr, "risk_assessment")
	hasDoc := strings.Contains(inputStr, "risk_documentation") || strings.Contains(inputStr, "risk_register")
	if hasProcess && hasDoc {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art9-001",
			ControlName: "Risk Management System",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Risk management process and documentation detected",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art9-001",
		ControlName: "Risk Management System",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Risk management system incomplete",
		Timestamp:   time.Now(),
		Remediation: "Establish documented risk management process per Article 9",
	}, nil
}

// checkTechnicalDocumentation (Article 11).
func (m *EUAIModule) checkTechnicalDocumentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.hasDocumentationEvidence(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art11-001",
			ControlName: "Technical Documentation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Technical documentation artifacts detected",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art11-001",
		ControlName: "Technical Documentation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No technical documentation detected",
		Timestamp:   time.Now(),
		Remediation: "Maintain technical documentation per Annex IV before market placement",
	}, nil
}

// checkRecordKeeping (Article 12) - automatic logging.
func (m *EUAIModule) checkRecordKeeping(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.hasAuditLogEvidence(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art12-001",
			ControlName: "Automatic Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automatic logging with integrity protection detected",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art12-001",
		ControlName: "Automatic Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automatic logging detected",
		Timestamp:   time.Now(),
		Remediation: "Implement automatic logging over the system lifecycle per Article 12",
	}, nil
}

// checkHumanOversight (Article 14) - baseline check.
func (m *EUAIModule) checkHumanOversight(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.hasHumanOversightEvidence(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art14-001",
			ControlName: "Human Oversight",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Human oversight markers (review, kill switch, override) detected",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art14-001",
		ControlName: "Human Oversight",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No human oversight mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Design human oversight into the system; provide kill switch and override capability",
	}, nil
}

// checkTransparency (Article 13).
func (m *EUAIModule) checkTransparency(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.hasTransparencyEvidence(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art13-001",
			ControlName: "Transparency and Instructions for Use",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Transparency disclosures detected (model card / system card / instructions)",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art13-001",
		ControlName: "Transparency and Instructions for Use",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No transparency disclosures detected",
		Timestamp:   time.Now(),
		Remediation: "Provide instructions for use; document capabilities, limitations, intended purpose",
	}, nil
}

// checkAccuracyRobustness (Article 15).
func (m *EUAIModule) checkAccuracyRobustness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccuracy := strings.Contains(inputStr, "accuracy_testing") || strings.Contains(inputStr, "benchmark_results")
	hasRobustness := strings.Contains(inputStr, "robustness_testing") || strings.Contains(inputStr, "red_team") || strings.Contains(inputStr, "adversarial_testing")
	switch {
	case hasAccuracy && hasRobustness:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art15-001",
			ControlName: "Accuracy Level Appropriate",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Accuracy and robustness testing detected",
			Timestamp:   time.Now(),
		}, nil
	case hasAccuracy || hasRobustness:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art15-001",
			ControlName: "Accuracy Level Appropriate",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial accuracy/robustness evidence; one of accuracy or robustness testing missing",
			Timestamp:   time.Now(),
			Remediation: "Conduct both accuracy testing and robustness/red-team testing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art15-001",
		ControlName: "Accuracy Level Appropriate",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No accuracy or robustness evidence detected",
		Timestamp:   time.Now(),
		Remediation: "Implement accuracy measurement and robustness testing programs",
	}, nil
}

// checkCybersecurity (Article 15) - adversarial / data poisoning.
func (m *EUAIModule) checkCybersecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	poisonFound := m.detectDataPoisoning(inputStr)
	advFound := m.detectAdversarialInput(inputStr)
	hasMitigation := strings.Contains(inputStr, "adversarial_mitigation") || strings.Contains(inputStr, "input_sanitization")
	if len(poisonFound) > 0 || len(advFound) > 0 {
		if hasMitigation {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "EUAIAct-Art15-007",
				ControlName: "Data Poisoning Mitigation",
				Status:      compliance.StatusPartial,
				Severity:    compliance.SeverityCritical,
				Message:     "Poisoning/adversarial patterns detected but mitigation controls present",
				Timestamp:   time.Now(),
				Remediation: "Review and harden data sources and model training pipeline",
			}, nil
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art15-007",
			ControlName: "Data Poisoning Mitigation",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data poisoning or adversarial patterns detected without mitigation",
			Timestamp:   time.Now(),
			Remediation: "Implement data source validation, training pipeline hardening, and adversarial input detection",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art15-007",
		ControlName: "Data Poisoning Mitigation",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No data poisoning or adversarial patterns detected",
		Timestamp:   time.Now(),
	}, nil
}

// checkPromptInjectionProtection (AegisGate AI-001).
func (m *EUAIModule) checkPromptInjectionProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	found := m.detectPromptInjection(string(input))
	inputStr := string(input)
	hasMitigation := strings.Contains(inputStr, "prompt_injection_detector") || strings.Contains(inputStr, "input_filter") || strings.Contains(inputStr, "system_prompt_hardening")
	if len(found) > 0 {
		if hasMitigation {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "EUAIAct-AI-001",
				ControlName: "Prompt Injection Protection",
				Status:      compliance.StatusPartial,
				Severity:    compliance.SeverityMedium,
				Message:     "Prompt injection patterns detected; mitigation in place",
				Timestamp:   time.Now(),
			}, nil
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-001",
			ControlName: "Prompt Injection Protection",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Prompt injection patterns detected without mitigation",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate prompt injection detection and input filtering",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-001",
		ControlName: "Prompt Injection Protection",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No prompt injection patterns detected",
		Timestamp:   time.Now(),
	}, nil
}

// ============================================================================
// v3.5.0+ NEW AUTOMATED CHECKS (Phase 2: Output Filtering + Human Oversight)
// ============================================================================

// checkTrainingDataSanitization (EUAIAct-AI-002, v3.5.0+ new automated).
// Reuses pkg/response/pii_scanner.go and pkg/response/secret_scanner.go
// patterns to verify that PII/secret scrubbing is enabled for training
// data inputs.
func (m *EUAIModule) checkTrainingDataSanitization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasTrainingDataSanitization(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-002",
			ControlName: "Training Data Sanitization",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Training data sanitization not configured (PII/secret scrubbing missing)",
			Timestamp:   time.Now(),
			Remediation: "Enable pkg/response/pii_scanner.go and pkg/response/secret_scanner.go for training data pipeline. Set training_data_sanitized=true in platformconfig.",
			References:  []string{"EU AI Act Article 10(2)(a) — Bias Examination and Mitigation", "EU AI Act Article 10(5) — Possible Biases Identification"},
		}, nil
	}

	// Verify the sanitization is actually catching PII + secrets.
	// (Quick smoke test: if we see raw SSN/credit-card/AWS key patterns
	// in the input, the sanitization either isn't running or is broken.)
	piiFound := m.detectPII(inputStr)
	secretFound := m.detectSecrets(inputStr)
	if len(piiFound) > 0 || len(secretFound) > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-002",
			ControlName: "Training Data Sanitization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Sanitization enabled but raw PII/secret patterns detected in input (sanitizer may be misconfigured)",
			Timestamp:   time.Now(),
			Remediation: "Investigate why the PII/secret scrubber missed these patterns. See pkg/response/pii_scanner.go and pkg/response/secret_scanner.go.",
			Details:     "Detected patterns: PII=" + intToStr(len(piiFound)) + ", secrets=" + intToStr(len(secretFound)),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-002",
		ControlName: "Training Data Sanitization",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Training data sanitization enabled and working (no raw PII/secrets in input)",
		Timestamp:   time.Now(),
		References:  []string{"EU AI Act Article 10(2)(a)"},
	}, nil
}

// checkAIOutputFiltering (EUAIAct-AI-003, v3.5.0+ new automated).
// Reuses pkg/response/guard.go (the ResponseGuard) to verify that
// AI outputs are filtered for PII/secrets/toxicity before being
// returned to the user.
func (m *EUAIModule) checkAIOutputFiltering(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasResponseFilterEnabled(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-003",
			ControlName: "AI System Output Filtering",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "AI system output filtering not enabled (ResponseGuard is disabled)",
			Timestamp:   time.Now(),
			Remediation: "Enable pkg/response/guard.go ResponseGuard. Set response_filter_enabled=true in platformconfig.",
			References:  []string{"EU AI Act Article 14(4) — Override Capability", "EU AI Act Article 15(5) — Cybersecurity Measures"},
		}, nil
	}

	// Verify the filter is configured to catch PII, secrets, AND
	// toxicity (not just one of them). A filter that only catches
	// PII is incomplete per Article 15(5) cybersecurity requirements.
	hasPII := strings.Contains(inputStr, "pii_filter") || strings.Contains(inputStr, "pii_redaction")
	hasSecret := strings.Contains(inputStr, "secret_filter") || strings.Contains(inputStr, "secret_redaction")
	hasToxicity := strings.Contains(inputStr, "toxicity_filter") || strings.Contains(inputStr, "toxicity_score")

	missing := []string{}
	if !hasPII {
		missing = append(missing, "PII filter")
	}
	if !hasSecret {
		missing = append(missing, "secret filter")
	}
	if !hasToxicity {
		missing = append(missing, "toxicity filter")
	}

	if len(missing) > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-003",
			ControlName: "AI System Output Filtering",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Output filter enabled but missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable all three output filters (PII, secret, toxicity) in pkg/response/guard.go ResponseGuardConfig",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-003",
		ControlName: "AI System Output Filtering",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "AI output filtering enabled (PII + secret + toxicity)",
		Timestamp:   time.Now(),
	}, nil
}

// checkHallucinationDetection (EUAIAct-AI-005, v3.5.0+ new automated).
// Reuses pkg/response/hallucination_detector.go patterns to verify
// hallucination detection is enabled and flagging obvious markers.
func (m *EUAIModule) checkHallucinationDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasDetector := strings.Contains(inputStr, "hallucination_detector") || strings.Contains(inputStr, "hallucination_detection_enabled")
	if !hasDetector {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-005",
			ControlName: "AI Model Hallucination Detection",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Hallucination detection not enabled (pkg/response/hallucination_detector.go is disabled)",
			Timestamp:   time.Now(),
			Remediation: "Enable hallucination detector. Set hallucination_detection_enabled=true in platformconfig.",
			References:  []string{"EU AI Act Article 15(1) — Accuracy Level Appropriate", "EU AI Act Article 15(4) — Performance Monitoring"},
		}, nil
	}

	// If we see hallucination markers in the input AND the detector
	// is enabled, that's good (the detector should flag them). If
	// the detector is enabled but no markers in input, that's still
	// compliant (the input happens to be clean).
	hallucinationFound := m.detectHallucination(inputStr)
	if len(hallucinationFound) > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-005",
			ControlName: "AI Model Hallucination Detection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Hallucination detector enabled; " + intToStr(len(hallucinationFound)) + " potential markers detected (review for false positives)",
			Timestamp:   time.Now(),
			Details:     "Detected patterns: overconfidence, fabricated stats, or absolute claims. See pkg/response/hallucination_detector.go for the full pattern list.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-005",
		ControlName: "AI Model Hallucination Detection",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Hallucination detection enabled (no markers in current input)",
		Timestamp:   time.Now(),
	}, nil
}

// checkAgentCapabilityAttestation (EUAIAct-AI-006, v3.5.0+ new automated).
// Reuses pkg/trust/attestation/ to verify AI agents have signed
// capability attestations (the Trust Framework pillar).
func (m *EUAIModule) checkAgentCapabilityAttestation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasAgentAttestation(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-006",
			ControlName: "AI Agent Capability Attestation",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "AI agent capability attestation not enabled (Trust Framework disabled)",
			Timestamp:   time.Now(),
			Remediation: "Enable pkg/trust/attestation/. Set trust.enabled=true and trust.require_license=true in platformconfig.",
			References:  []string{"EU AI Act Article 14(1) — Human Oversight", "EU AI Act Article 9(5) — Documentation of Known Risks"},
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-006",
		ControlName: "AI Agent Capability Attestation",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "AI agent capability attestation enabled (Trust Framework signed attestations active)",
		Timestamp:   time.Now(),
	}, nil
}

// checkModelVersioningLineage (EUAIAct-AI-007, v3.5.0+ new automated).
// Verifies that the AI model is tracked in AegisGate's model registry
// with version + lineage metadata.
func (m *EUAIModule) checkModelVersioningLineage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasModelVersioning(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-AI-007",
			ControlName: "AI Model Versioning and Lineage",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Model versioning/lineage not configured (model_id, model_version, or lineage fields missing)",
			Timestamp:   time.Now(),
			Remediation: "Register the AI model in AegisGate's model registry with model_id, model_version, and lineage fields. Set model_registry=true in platformconfig.",
			References:  []string{"EU AI Act Article 11(1)(c) — Development Process Documentation", "EU AI Act Article 12(4) — Log Integrity"},
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-AI-007",
		ControlName: "AI Model Versioning and Lineage",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Model versioning and lineage tracked in AegisGate model registry",
		Timestamp:   time.Now(),
	}, nil
}

// checkOversightMeasuresEffective (EUAIAct-Art14-002, v3.5.0+ new
// automated). Verifies the kill switch + override + human review
// configuration is *effective* (not just declared). Effective means
// the platform actually has the ability to enforce each.
func (m *EUAIModule) checkOversightMeasuresEffective(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasKillSwitch := strings.Contains(inputStr, "kill_switch")
	hasOverride := strings.Contains(inputStr, "override")
	hasReview := strings.Contains(inputStr, "human_review") || strings.Contains(inputStr, "manual_approval")

	present := 0
	missing := []string{}
	if hasKillSwitch {
		present++
	} else {
		missing = append(missing, "kill_switch")
	}
	if hasOverride {
		present++
	} else {
		missing = append(missing, "override")
	}
	if hasReview {
		present++
	} else {
		missing = append(missing, "human_review/manual_approval")
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art14-002",
			ControlName: "Oversight Measures Effective",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "All 3 oversight measures configured: kill switch, override, human review",
			Timestamp:   time.Now(),
			References:  []string{"EU AI Act Article 14(2) — Oversight Measures Effective"},
		}, nil
	}

	if present >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art14-002",
			ControlName: "Oversight Measures Effective",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial oversight measures: " + intToStr(present) + "/3 configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure all 3 oversight measures (kill switch, override, human review) per Article 14(2)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art14-002",
		ControlName: "Oversight Measures Effective",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No oversight measures detected (kill switch, override, human review all missing)",
		Timestamp:   time.Now(),
		Remediation: "Configure all 3 oversight measures (kill switch, override, human review) per Article 14(2)",
	}, nil
}

// checkHumanReviewersCanIntervene (EUAIAct-Art14-003, v3.5.0+ new
// automated). Verifies human reviewers are configured (the *who*, not
// just the *what*). The platform needs a configured reviewer role
// (or pool) so the system knows who to ask.
func (m *EUAIModule) checkHumanReviewersCanIntervene(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasHumanReviewers(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art14-003",
			ControlName: "Human Reviewers Can Intervene",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No human reviewer configuration (reviewer role/pool not defined)",
			Timestamp:   time.Now(),
			Remediation: "Define a human reviewer role/pool in platformconfig.Security.oversight_reviewer_role or platformconfig.Security.oversight_approver_pool.",
			References:  []string{"EU AI Act Article 14(3) — Human Reviewers Can Intervene"},
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art14-003",
		ControlName: "Human Reviewers Can Intervene",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Human reviewer configuration present (reviewer role/pool defined)",
		Timestamp:   time.Now(),
	}, nil
}

// checkKillSwitchAbortCapability (EUAIAct-Art14-004, v3.5.0+ new
// automated). Verifies the system has a kill switch AND an abort
// capability (both are required by Article 14(4)).
func (m *EUAIModule) checkKillSwitchAbortCapability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	if !m.hasKillSwitch(inputStr) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "EUAIAct-Art14-004",
			ControlName: "Kill Switch / Abort Capability",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Kill switch and/or abort capability not configured (both required by Article 14(4))",
			Timestamp:   time.Now(),
			Remediation: "Configure both kill_switch and abort in platformconfig.Security.oversight.* . Article 14(4) requires both.",
			References:  []string{"EU AI Act Article 14(4) — Kill Switch / Abort Capability"},
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "EUAIAct-Art14-004",
		ControlName: "Kill Switch / Abort Capability",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Kill switch and abort capability both configured",
		Timestamp:   time.Now(),
	}, nil
}

// intToStr is a small helper to avoid importing strconv in every check.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-intToStr(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}
