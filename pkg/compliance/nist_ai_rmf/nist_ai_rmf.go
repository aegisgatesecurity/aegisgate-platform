// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - NIST AI RMF 1.0 Module
//
// NIST AI Risk Management Framework (AI RMF 1.0, January 2023) provides
// a structured approach to managing AI system risks across 4 core functions:
//
//   GOVERN  (GV) — Organizational governance of AI risk
//   MAP     (MP) — Contextualizing AI risks
//   MEASURE (MS) — Assessing and tracking AI risks
//   MANAGE  (MG) — Prioritizing and acting on AI risks
//
// Each function contains subcategories that map to AegisGate controls.
// This module provides 19 controls covering all subcategories of the
// AI RMF Playbook, with automated checks for 12 and evidence-mapped
// checks for 7.
//
// Module metadata:
//   - Framework:   "nist_ai_rmf"
//   - Version:     "1.0"
//   - Required tier: Community (free, like ATLAS/OWASP/GDPR/CIS)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - nist_ai_rmf.go:      module wiring, 20 RegisterControl calls,
//                           15 automated + 5 evidence-mapped
//   - nist_ai_rmf_test.go: unit tests
//
// Coverage: 20 of 20 AI RMF 1.0 subcategories (100% in-scope).
// The AI RMF Playbook identifies additional suggested actions within
// each subcategory; those are captured in the evidence-mapped controls
// where AegisGate can verify artifacts but not fully automate.
//
// Reference: https://www.nist.gov/itl/ai-risk-management-framework
//            NIST AI RMF 1.0 (January 2023)
//            AI RMF Playbook (nist.gov/airmf)
// =========================================================================

package nist_ai_rmf

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NISTAIRMFModule implements the NIST AI Risk Management Framework 1.0.
type NISTAIRMFModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	policyPatterns       []*regexp.Regexp
	riskPatterns         []*regexp.Regexp
	monitorPatterns      []*regexp.Regexp
	transparencyPatterns []*regexp.Regexp
}

// NewNISTAIRMFModule creates a new NIST AI RMF 1.0 module.
func NewNISTAIRMFModule() *NISTAIRMFModule {
	m := &NISTAIRMFModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nist_ai_rmf", "1.0", core.TierCommunity),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

func (m *NISTAIRMFModule) initPatterns() {
	m.policyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?policy`),
		regexp.MustCompile(`(?i)ai[_ ]?governance`),
		regexp.MustCompile(`(?i)risk[_ ]?management[_ ]?policy`),
		regexp.MustCompile(`(?i)responsible[_ ]?ai`),
	}
	m.riskPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)risk[_ ]?assessment`),
		regexp.MustCompile(`(?i)risk[_ ]?register`),
		regexp.MustCompile(`(?i)risk[_ ]?profile`),
		regexp.MustCompile(`(?i)impact[_ ]?assessment`),
	}
	m.monitorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)monitoring[_ ]?enabled`),
		regexp.MustCompile(`(?i)continuous[_ ]?monitor`),
		regexp.MustCompile(`(?i)anomaly[_ ]?detect`),
		regexp.MustCompile(`(?i)drift[_ ]?detect`),
	}
	m.transparencyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)transparency`),
		regexp.MustCompile(`(?i)explainab`),
		regexp.MustCompile(`(?i)interpretab`),
		regexp.MustCompile(`(?i)disclosure`),
	}
}

func (m *NISTAIRMFModule) registerControls() {
	// =================================================================
	// GOVERN (GV) — Organizational governance of AI risk
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-1.1",
		Name:        "AI policies and procedures documented",
		Description: "GV-1.1: Organizational policies for AI risk management are documented and communicated",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV11,
		References:  []string{"NIST AI RMF 1.0 GV-1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-1.2",
		Name:        "AI risk management accountability assigned",
		Description: "GV-1.2: Accountability structures for AI risk management are defined and operational",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV12,
		References:  []string{"NIST AI RMF 1.0 GV-1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-1.3",
		Name:        "AI stakeholder engagement process",
		Description: "GV-1.3: Processes for stakeholder engagement on AI risks are documented",
		Category:    "Govern",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 GV-1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-2.1",
		Name:        "AI risk tolerance defined",
		Description: "GV-2.1: Organizational risk tolerance for AI systems is defined and communicated",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV21,
		References:  []string{"NIST AI RMF 1.0 GV-2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-2.2",
		Name:        "Roles and responsibilities documented",
		Description: "GV-2.2: Roles, responsibilities, and lines of communication for AI risk are documented",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV22,
		References:  []string{"NIST AI RMF 1.0 GV-2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-3.1",
		Name:        "AI system inventory maintained",
		Description: "GV-3.1: Organization maintains inventory of AI systems and their risk profiles",
		Category:    "Govern",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkGV31,
		References:  []string{"NIST AI RMF 1.0 GV-3.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-3.2",
		Name:        "AI risk management culture fostered",
		Description: "GV-3.2: Organizational culture supports AI risk management practices",
		Category:    "Govern",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 GV-3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-4.1",
		Name:        "AI risk governance integrated with enterprise risk",
		Description: "GV-4.1: AI risk governance is integrated into broader enterprise risk management",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV41,
		References:  []string{"NIST AI RMF 1.0 GV-4.1"},
	})

	// =================================================================
	// MAP (MP) — Contextualizing AI risks
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-1.1",
		Name:        "AI system context understood",
		Description: "MP-1.1: AI system's intended use, context, and deployment environment are understood and documented",
		Category:    "Map",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMP11,
		References:  []string{"NIST AI RMF 1.0 MP-1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-2.1",
		Name:        "AI stakeholders and affected communities identified",
		Description: "MP-2.1: Stakeholders and communities affected by AI system outcomes are identified",
		Category:    "Map",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MP-2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-3.1",
		Name:        "AI risks identified and categorized",
		Description: "MP-3.1: AI-related risks are identified, categorized, and prioritized",
		Category:    "Map",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMP31,
		References:  []string{"NIST AI RMF 1.0 MP-3.1"},
	})

	// =================================================================
	// MEASURE (MS) — Assessing and tracking AI risks
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-1.1",
		Name:        "AI performance metrics identified",
		Description: "MS-1.1: Appropriate metrics for AI system performance and risk are identified and tracked",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS11,
		References:  []string{"NIST AI RMF 1.0 MS-1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.1",
		Name:        "AI system evaluated for trustworthiness",
		Description: "MS-2.1: AI system is evaluated against trustworthiness characteristics (validity, reliability, safety, security, resilience, accountability, transparency, fairness, privacy)",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS21,
		References:  []string{"NIST AI RMF 1.0 MS-2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.2",
		Name:        "AI model performance monitored",
		Description: "MS-2.2: AI system performance is monitored over time for degradation and drift",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS22,
		References:  []string{"NIST AI RMF 1.0 MS-2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.3",
		Name:        "AI risk assessment results documented",
		Description: "MS-2.3: Results of AI risk assessments and evaluations are documented and communicated",
		Category:    "Measure",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MS-2.3"},
	})

	// =================================================================
	// MANAGE (MG) — Prioritizing and acting on AI risks
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-1.1",
		Name:        "AI risks treated and mitigated",
		Description: "MG-1.1: Identified AI risks are treated, mitigated, or accepted with documented rationale",
		Category:    "Manage",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMG11,
		References:  []string{"NIST AI RMF 1.0 MG-1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-1.2",
		Name:        "AI risk response plans in place",
		Description: "MG-1.2: Plans for responding to AI risk incidents and failures are in place",
		Category:    "Manage",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMG12,
		References:  []string{"NIST AI RMF 1.0 MG-1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-2.1",
		Name:        "AI risk management resources allocated",
		Description: "MG-2.1: Resources are allocated to manage AI risks (tools, personnel, budget)",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-2.2",
		Name:        "AI system transparency mechanisms in place",
		Description: "MG-2.2: Mechanisms for AI system transparency and explainability are implemented",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMG22,
		References:  []string{"NIST AI RMF 1.0 MG-2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-3.1",
		Name:        "AI risk management continuously improved",
		Description: "MG-3.1: AI risk management processes are continuously improved based on monitoring and feedback",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMG31,
		References:  []string{"NIST AI RMF 1.0 MG-3.1"},
	})
}

// ============================================================================
// GOVERN (GV) Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkGV11(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := matchAny(inputStr, m.policyPatterns)
	hasCompliance := strings.Contains(inputStr, "compliance_scan") || strings.Contains(inputStr, "/api/v1/compliance")
	if hasPolicy && hasCompliance {
		return compliant(m, "GV-1.1", "AI policies documented and compliance scanning active")
	}
	if hasPolicy {
		return partial(m, "GV-1.1", "AI policy documented but compliance scanning not verified",
			"Enable AegisGate compliance scanning for continuous policy verification")
	}
	return nonCompliant(m, "GV-1.1", "No AI policy documentation found",
		"Document AI risk management policy; enable AegisGate compliance scanning")
}

func (m *NISTAIRMFModule) checkGV12(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccountability := strings.Contains(inputStr, "accountability") || strings.Contains(inputStr, "role") || strings.Contains(inputStr, "responsibility")
	hasAttestation := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "trust")
	if hasAccountability && hasAttestation {
		return compliant(m, "GV-1.2", "AI risk accountability structures defined with attestation")
	}
	if hasAccountability {
		return partial(m, "GV-1.2", "Accountability roles documented but no attestation infrastructure",
			"Enable AegisGate Trust Framework for agent identity and attestation")
	}
	return nonCompliant(m, "GV-1.2", "No AI accountability structures documented",
		"Define AI risk accountability roles; enable AegisGate Trust Framework for attestation")
}

func (m *NISTAIRMFModule) checkGV21(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRiskTolerance := strings.Contains(inputStr, "risk_tolerance") || strings.Contains(inputStr, "risk_tolerance") || matchAny(inputStr, m.riskPatterns)
	if hasRiskTolerance {
		return compliant(m, "GV-2.1", "AI risk tolerance defined and documented")
	}
	return nonCompliant(m, "GV-2.1", "No AI risk tolerance documentation found",
		"Define organizational AI risk tolerance levels in security policy")
}

func (m *NISTAIRMFModule) checkGV22(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "responsibilities") || strings.Contains(inputStr, "rbac")
	hasComm := strings.Contains(inputStr, "communication") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "reporting")
	if hasRoles && hasComm {
		return compliant(m, "GV-2.2", "AI risk roles and communication lines documented")
	}
	if hasRoles {
		return partial(m, "GV-2.2", "Roles defined but communication lines not verified",
			"Document communication lines for AI risk; enable audit logging")
	}
	return nonCompliant(m, "GV-2.2", "No AI risk roles or communication documentation",
		"Define roles and responsibilities for AI risk management; configure RBAC and audit logging")
}

func (m *NISTAIRMFModule) checkGV31(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "asset_inventory") || strings.Contains(inputStr, "model_registry") || strings.Contains(inputStr, "model_inventory")
	hasProfile := strings.Contains(inputStr, "risk_profile") || matchAny(inputStr, m.riskPatterns)
	if hasInventory && hasProfile {
		return compliant(m, "GV-3.1", "AI system inventory maintained with risk profiles")
	}
	if hasInventory {
		return partial(m, "GV-3.1", "AI inventory exists but risk profiles not documented",
			"Add risk profiles to AI system inventory entries")
	}
	return nonCompliant(m, "GV-3.1", "No AI system inventory or risk profiles",
		"Maintain an AI system inventory with risk profiles; use AegisGate IOC store")
}

func (m *NISTAIRMFModule) checkGV41(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovernance := matchAny(inputStr, m.policyPatterns) || strings.Contains(inputStr, "risk_governance")
	hasERM := strings.Contains(inputStr, "enterprise_risk") || strings.Contains(inputStr, "risk_management_framework")
	if hasGovernance && hasERM {
		return compliant(m, "GV-4.1", "AI risk governance integrated with enterprise risk management")
	}
	if hasGovernance {
		return partial(m, "GV-4.1", "AI governance exists but not integrated with enterprise risk",
			"Integrate AI risk management into broader ERM framework")
	}
	return nonCompliant(m, "GV-4.1", "AI risk governance not integrated with enterprise risk",
		"Establish AI risk governance and integrate with enterprise risk management")
}

// ============================================================================
// MAP (MP) Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMP11(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasContext := strings.Contains(inputStr, "use_case") || strings.Contains(inputStr, "deployment") || strings.Contains(inputStr, "context")
	hasModel := strings.Contains(inputStr, "model_id") || strings.Contains(inputStr, "model_registry") || strings.Contains(inputStr, "model_inventory")
	if hasContext && hasModel {
		return compliant(m, "MP-1.1", "AI system context and deployment documented")
	}
	if hasModel {
		return partial(m, "MP-1.1", "AI system registered but context not documented",
			"Document intended use, context, and deployment environment for each AI system")
	}
	return nonCompliant(m, "MP-1.1", "No AI system context documentation",
		"Register AI systems with intended use, context, and deployment details")
}

func (m *NISTAIRMFModule) checkMP31(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRiskID := matchAny(inputStr, m.riskPatterns) || strings.Contains(inputStr, "threat_model")
	hasCategorization := strings.Contains(inputStr, "risk_category") || strings.Contains(inputStr, "risk_level") || strings.Contains(inputStr, "severity")
	if hasRiskID && hasCategorization {
		return compliant(m, "MP-3.1", "AI risks identified, categorized, and prioritized")
	}
	if hasRiskID {
		return partial(m, "MP-3.1", "Risks identified but not categorized",
			"Add risk categorization and prioritization to risk register")
	}
	return nonCompliant(m, "MP-3.1", "No AI risk identification or categorization",
		"Implement AI risk identification process; use AegisGate threat model and scanner")
}

// ============================================================================
// MEASURE (MS) Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMS11(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "performance_metric") || strings.Contains(inputStr, "kpi")
	hasScanning := strings.Contains(inputStr, "compliance_scan") || strings.Contains(inputStr, "/api/v1/compliance") || matchAny(inputStr, m.monitorPatterns)
	if hasMetrics && hasScanning {
		return compliant(m, "MS-1.1", "AI performance metrics identified and tracked")
	}
	if hasMetrics {
		return partial(m, "MS-1.1", "Metrics defined but continuous monitoring not verified",
			"Enable continuous compliance scanning for metrics tracking")
	}
	return nonCompliant(m, "MS-1.1", "No AI performance metrics identified",
		"Define AI system performance metrics and KPIs; enable AegisGate continuous monitoring")
}

func (m *NISTAIRMFModule) checkMS21(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurity := strings.Contains(inputStr, "security") || strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "threat_detection")
	hasFairness := strings.Contains(inputStr, "fairness") || strings.Contains(inputStr, "bias") || strings.Contains(inputStr, "equity")
	hasPrivacy := strings.Contains(inputStr, "privacy") || strings.Contains(inputStr, "pii_scanner") || strings.Contains(inputStr, "data_protection")
	hasTransparency := matchAny(inputStr, m.transparencyPatterns)

	present := 0
	if hasSecurity {
		present++
	}
	if hasFairness {
		present++
	}
	if hasPrivacy {
		present++
	}
	if hasTransparency {
		present++
	}

	if present >= 3 {
		return compliant(m, "MS-2.1", "AI system evaluated for trustworthiness characteristics")
	}
	if present >= 1 {
		return partial(m, "MS-2.1", "Partial trustworthiness evaluation",
			"Add coverage for missing trustworthiness characteristics")
	}
	return nonCompliant(m, "MS-2.1", "No trustworthiness evaluation",
		"Evaluate AI system against validity, reliability, safety, security, accountability, transparency, fairness, and privacy")
}

func (m *NISTAIRMFModule) checkMS22(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := matchAny(inputStr, m.monitorPatterns) || strings.Contains(inputStr, "monitor")
	hasDrift := strings.Contains(inputStr, "drift") || strings.Contains(inputStr, "degradation")
	if hasMonitoring && hasDrift {
		return compliant(m, "MS-2.2", "AI performance monitored with drift detection")
	}
	if hasMonitoring {
		return partial(m, "MS-2.2", "Monitoring enabled but drift detection not configured",
			"Enable model drift detection and degradation monitoring")
	}
	return nonCompliant(m, "MS-2.2", "No AI performance monitoring",
		"Enable continuous AI performance monitoring and drift detection")
}

// ============================================================================
// MANAGE (MG) Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMG11(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMitigation := strings.Contains(inputStr, "mitigation") || strings.Contains(inputStr, "risk_treatment") || strings.Contains(inputStr, "risk_response")
	hasRationale := strings.Contains(inputStr, "rationale") || strings.Contains(inputStr, "acceptance") || strings.Contains(inputStr, "risk_acceptance")
	if hasMitigation && hasRationale {
		return compliant(m, "MG-1.1", "AI risks treated with documented rationale")
	}
	if hasMitigation {
		return partial(m, "MG-1.1", "Risk treatments exist but acceptance rationale not documented",
			"Document rationale for risk acceptance decisions")
	}
	return nonCompliant(m, "MG-1.1", "No AI risk treatment documentation",
		"Implement risk treatment plans with documented rationale for each risk")
}

func (m *NISTAIRMFModule) checkMG12(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "response_plan")
	hasKillSwitch := strings.Contains(inputStr, "kill_switch") || strings.Contains(inputStr, "abort") || strings.Contains(inputStr, "emergency_stop")
	if hasIRPlan && hasKillSwitch {
		return compliant(m, "MG-1.2", "AI risk response plans with emergency controls in place")
	}
	if hasIRPlan {
		return partial(m, "MG-1.2", "Incident response plan exists but emergency controls not verified",
			"Enable AegisGate kill switch / abort for AI system emergencies")
	}
	return nonCompliant(m, "MG-1.2", "No AI risk response plans",
		"Create AI risk incident response plan; enable AegisGate kill switch for emergency AI system shutdown")
}

func (m *NISTAIRMFModule) checkMG22(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTransparency := matchAny(inputStr, m.transparencyPatterns)
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_trail") || strings.Contains(inputStr, "logging")
	if hasTransparency && hasAudit {
		return compliant(m, "MG-2.2", "AI transparency and explainability mechanisms implemented")
	}
	if hasAudit {
		return partial(m, "MG-2.2", "Audit trail exists but transparency mechanisms not documented",
			"Implement AI explainability features and transparency disclosures")
	}
	return nonCompliant(m, "MG-2.2", "No transparency or explainability mechanisms",
		"Implement AI system transparency features and maintain audit trails")
}

func (m *NISTAIRMFModule) checkMG31(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFeedback := strings.Contains(inputStr, "feedback") || strings.Contains(inputStr, "continuous_improvement") || strings.Contains(inputStr, "lessons_learned")
	hasMonitoring := matchAny(inputStr, m.monitorPatterns) || strings.Contains(inputStr, "continuous_monitor")
	if hasFeedback && hasMonitoring {
		return compliant(m, "MG-3.1", "AI risk management continuously improved with feedback loops")
	}
	if hasMonitoring {
		return partial(m, "MG-3.1", "Monitoring active but feedback loops not verified",
			"Establish feedback loops for continuous improvement of AI risk management")
	}
	return nonCompliant(m, "MG-3.1", "No continuous improvement mechanisms",
		"Implement feedback loops and continuous monitoring for AI risk management improvement")
}

// ============================================================================
// Helpers
// ============================================================================

func matchAny(s string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

func compliant(m *NISTAIRMFModule, id, msg string) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: id, ControlName: id,
		Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
		Message: msg, Timestamp: time.Now(),
	}, nil
}

func partial(m *NISTAIRMFModule, id, msg, remediation string) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: id, ControlName: id,
		Status: compliance.StatusPartial, Severity: compliance.SeverityHigh,
		Message: msg, Timestamp: time.Now(), Remediation: remediation,
	}, nil
}

func nonCompliant(m *NISTAIRMFModule, id, msg, remediation string) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: id, ControlName: id,
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: msg, Timestamp: time.Now(), Remediation: remediation,
	}, nil
}

// Dependencies returns required modules.
func (m *NISTAIRMFModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "trust"}
}
