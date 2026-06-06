// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform
// =========================================================================
//
// EU AI Act Compliance Module (v3.3.0 Phase 1)
//
// Implements Regulation 2024/1689 ("EU AI Act") compliance controls as
// a licensed add-on module. This is the 7th framework in the Compliance
// Scan Engine, joining HIPAA, PCI-DSS, SOC 2, ISO 42001, FedRAMP, and
// FIPS 140-2/140-3.
//
// Module metadata:
//   - Framework: "eu_ai_act"
//   - Version:   "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $99/mo (founder-locked 2026-06-06)
//
// Coverage: 82 controls across 8 categories spanning Articles 5, 9, 10,
// 11, 12, 13, 14, 15, 51, 52, 53, 55 of Regulation 2024/1689, plus 10
// AegisGate-specific AI controls. See registerControls() in controls.go
// for the full list. This file holds module wiring and representative
// automated CheckFunc implementations; controls.go holds the bulk of
// the RegisterControl calls; evaluator.go provides the public
// EvaluateEUAIAct API used by the Compliance Scan Engine.

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
}

// NewEUAIModule creates a new EU AI Act compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Professional+ tier via pkg/compliance/gating.go
// (license.ModuleEUAIAct entry in moduleRequirements). The TierProfessional
// passed to NewBaseComplianceModule is the platform module system tier
// metadata (used by ModuleRegistry); the actual customer gating uses
// the gating.go table.
func NewEUAIModule() *EUAIModule {
	m := &EUAIModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("eu_ai_act", "1.0", core.TierProfessional),
	}
	m.initAIActPatterns()
	m.registerControls()
	return m
}

// initAIActPatterns compiles the regex patterns used by automated
// controls. Called once at construction time.
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

// Dependencies returns the list of required platform modules.
// The compliance scan engine depends on the proxy scanner for input.
func (m *EUAIModule) Dependencies() []string {
	return []string{"scanner"}
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

// checkHumanOversight (Article 14).
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
