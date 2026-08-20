// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO/IEC 42001 AI Management System Module
// =========================================================================
//
// Implements ISO/IEC 42001:2023 (AI Management System) compliance controls
// as a licensed add-on module.
//
// Module metadata:
//   - Framework:     "iso_42001"
//   - Version:       "2.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Controls:      38 (23 automated, 15 manual)
//   - Categories:    7 (Context, Leadership, Planning, Support, Operation,
//                      Performance Evaluation, AI Controls)
//
// Coverage spans Clauses 4-9 of ISO/IEC 42001:2023 plus an AI-specific
// extension covering model security, data provenance, documentation, and
// decommissioning.
//
// Reference: ISO/IEC 42001:2023 AI Management Systems
//            https://www.iso.org/standard/81230.html
//
// =========================================================================

package iso42001

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ISO42001Module implements the ISO/IEC 42001 AI Management System
// compliance framework as a licensed add-on. It embeds
// *compliance.BaseComplianceModule which provides RegisterControl,
// Controls(), Framework(), Version(), CheckAll(), and
// GenerateAssessment() out of the box.
type ISO42001Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	policyPatterns     []*regexp.Regexp
	riskPatterns       []*regexp.Regexp
	documentationPats  []*regexp.Regexp
	aimsProcessPats    []*regexp.Regexp
	governancePats     []*regexp.Regexp
	impactAssessPats   []*regexp.Regexp
	awarenessPats      []*regexp.Regexp
	requirementsPats   []*regexp.Regexp
	verificationPats   []*regexp.Regexp
	perfMetricsPats    []*regexp.Regexp
	modelSecurityPats  []*regexp.Regexp
	dataProvenancePats []*regexp.Regexp
}

// NewISO42001Module creates a new ISO 42001 compliance module. It is
// safe to call multiple times; the module is stateless after
// construction aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleISO42001 entry in
// moduleRequirements).
func NewISO42001Module() *ISO42001Module {
	m := &ISO42001Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("iso_42001", "2.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated
// controls. Called once at construction time.
func (m *ISO42001Module) initPatterns() {
	m.policyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?policy`),
		regexp.MustCompile(`(?i)acceptable[_ ]?use[_ ]?policy`),
		regexp.MustCompile(`(?i)ai[_ ]?governance`),
		regexp.MustCompile(`(?i)aims[_ ]?policy`),
	}
	m.riskPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)risk[_ ]?assessment`),
		regexp.MustCompile(`(?i)risk[_ ]?treatment`),
		regexp.MustCompile(`(?i)ai[_ ]?risk`),
		regexp.MustCompile(`(?i)threat[_ ]?model`),
		regexp.MustCompile(`(?i)adversarial[_ ]?risk`),
	}
	m.documentationPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)statement[_ ]?of[_ ]?applicability`),
		regexp.MustCompile(`(?i)risk[_ ]?register`),
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)compliance[_ ]?report`),
	}
	m.aimsProcessPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)aims`),
		regexp.MustCompile(`(?i)ai[_ ]?management[_ ]?system`),
		regexp.MustCompile(`(?i)process[_ ]?definition`),
	}
	m.governancePats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?governance`),
		regexp.MustCompile(`(?i)ai[_ ]?committee`),
		regexp.MustCompile(`(?i)ai[_ ]?board`),
	}
	m.impactAssessPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)impact[_ ]?assessment`),
		regexp.MustCompile(`(?i)ai[_ ]?impact`),
		regexp.MustCompile(`(?i)societal[_ ]?impact`),
	}
	m.awarenessPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?awareness`),
		regexp.MustCompile(`(?i)training`),
		regexp.MustCompile(`(?i)ai[_ ]?literacy`),
	}
	m.requirementsPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?requirements`),
		regexp.MustCompile(`(?i)system[_ ]?design`),
		regexp.MustCompile(`(?i)safety[_ ]?requirements`),
	}
	m.verificationPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?verification`),
		regexp.MustCompile(`(?i)model[_ ]?validation`),
		regexp.MustCompile(`(?i)ai[_ ]?testing`),
	}
	m.perfMetricsPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?metrics`),
		regexp.MustCompile(`(?i)performance[_ ]?metrics`),
		regexp.MustCompile(`(?i)model[_ ]?performance`),
	}
	m.modelSecurityPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)model[_ ]?security`),
		regexp.MustCompile(`(?i)adversarial`),
		regexp.MustCompile(`(?i)model[_ ]?protection`),
	}
	m.dataProvenancePats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)data[_ ]?provenance`),
		regexp.MustCompile(`(?i)data[_ ]?lineage`),
		regexp.MustCompile(`(?i)data[_ ]?tracking`),
	}
}

// registerControls wires all 38 ISO 42001 controls into the module.
// Called once from NewISO42001Module. The 18 automated controls
// reference check* methods defined below; the remaining 20 are manual
// review.
func (m *ISO42001Module) registerControls() {
	// ====================================================================
	// Clause 4: Context of the Organization (4 controls, 2 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-4.1",
		Name:        "Understanding the organization and its context",
		Description: "Understand the organization's context and the needs/expectations of interested parties",
		Category:    "Context of the Organization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIPolicy,
		References:  []string{"ISO/IEC 42001:2023 4.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-4.2",
		Name:        "Understanding the needs and expectations of interested parties",
		Description: "Determine interested parties relevant to the AI management system and their requirements",
		Category:    "Context of the Organization",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 4.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-4.3",
		Name:        "Determining the scope of the AI management system",
		Description: "Determine the boundary and applicability of the AI management system",
		Category:    "Context of the Organization",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 4.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-4.4",
		Name:        "AI management system and its processes",
		Description: "Establish, implement, maintain, and continually improve the AI management system",
		Category:    "Context of the Organization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIMSProcesses,
		References:  []string{"ISO/IEC 42001:2023 4.4"},
	})

	// ====================================================================
	// Clause 5: Leadership (5 controls, 2 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.1",
		Name:        "Leadership and commitment",
		Description: "Top management demonstrates leadership and commitment to the AI management system",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"ISO/IEC 42001:2023 5.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.2",
		Name:        "Policy",
		Description: "AI policy is established, communicated, and maintained",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDocumentedInfo,
		References:  []string{"ISO/IEC 42001:2023 5.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.3",
		Name:        "Organizational roles, responsibilities, and authorities",
		Description: "Assign and communicate roles, responsibilities, and authorities for the AI management system",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 5.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.P1",
		Name:        "AI governance framework",
		Description: "Establish an AI governance framework with clear accountability",
		Category:    "Leadership",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIGovernance,
		References:  []string{"ISO/IEC 42001:2023 5.1 (Governance Extension)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.P2",
		Name:        "AI ethics oversight",
		Description: "Establish AI ethics oversight mechanism for responsible AI development",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 5.1 (Ethics Extension)"},
	})

	// ====================================================================
	// Clause 6: Planning (5 controls, 2 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.1",
		Name:        "Actions to address risks and opportunities",
		Description: "AI risks are identified, assessed, and treated",
		Category:    "Planning",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskTreatment,
		References:  []string{"ISO/IEC 42001:2023 6.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.2",
		Name:        "AI objectives and planning to achieve them",
		Description: "Establish AI objectives and plan how to achieve them",
		Category:    "Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 6.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.3",
		Name:        "AI system impact assessment",
		Description: "Assess the impact of AI systems on individuals, society, and the environment",
		Category:    "Planning",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIImpactAssess,
		References:  []string{"ISO/IEC 42001:2023 6.1 (Impact Assessment)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.P1",
		Name:        "AI risk treatment plan",
		Description: "Develop and maintain an AI risk treatment plan",
		Category:    "Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 6.1 (Treatment Plan)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.P2",
		Name:        "Change management planning",
		Description: "Plan for changes that may affect the AI management system",
		Category:    "Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 6.3 (Change Planning)"},
	})

	// ====================================================================
	// Clause 7: Support (5 controls, 2 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.1",
		Name:        "Resources",
		Description: "Determine and provide resources needed for the AI management system",
		Category:    "Support",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 7.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.2",
		Name:        "Competence",
		Description: "Ensure persons performing AI-related work are competent",
		Category:    "Support",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 7.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.3",
		Name:        "Awareness",
		Description: "Ensure awareness of AI policy, risks, and responsibilities",
		Category:    "Support",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAwareness,
		References:  []string{"ISO/IEC 42001:2023 7.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.4",
		Name:        "Communication",
		Description: "Determine and implement internal/external communications about the AI management system",
		Category:    "Support",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 7.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.5",
		Name:        "Documented information",
		Description: "Documented information is created, updated, and controlled",
		Category:    "Support",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMonitoring,
		References:  []string{"ISO/IEC 42001:2023 7.5"},
	})

	// ====================================================================
	// Clause 8: Operation (8 controls, 4 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.1",
		Name:        "Operational planning and control",
		Description: "Plan, implement, and control the processes needed to meet AI management system requirements",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOperationalPlanning,
		References:  []string{"ISO/IEC 42001:2023 8.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.2",
		Name:        "AI system requirements and design",
		Description: "Define AI system requirements including safety, security, fairness, and transparency",
		Category:    "Operation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIRequirements,
		References:  []string{"ISO/IEC 42001:2023 8.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.3",
		Name:        "AI system development and deployment",
		Description: "Control AI system changes (model updates, prompt template changes, agent configuration changes) and review unintended consequences",
		Category:    "Operation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
		References:  []string{"ISO/IEC 42001:2023 8.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.4",
		Name:        "AI system verification and validation",
		Description: "Verify and validate AI systems before and after deployment",
		Category:    "Operation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIVerification,
		References:  []string{"ISO/IEC 42001:2023 8.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.5",
		Name:        "AI system operation and monitoring",
		Description: "Operate and monitor AI systems throughout their lifecycle",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIOperationMonitoring,
		References:  []string{"ISO/IEC 42001:2023 8.5"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.6",
		Name:        "AI system incident management",
		Description: "Establish procedures for managing AI-related incidents",
		Category:    "Operation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIIncidentManagement,
		References:  []string{"ISO/IEC 42001:2023 8.6"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.7",
		Name:        "Data management for AI systems",
		Description: "Manage data used for AI system training, testing, and operation",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIDataManagement,
		References:  []string{"ISO/IEC 42001:2023 8.7"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.P1",
		Name:        "Third-party AI system controls",
		Description: "Establish controls for third-party and vendor-provided AI systems",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 8.1 (Third-Party Extension)"},
	})

	// ====================================================================
	// Clause 9: Performance Evaluation (7 controls, 3 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.1",
		Name:        "Monitoring, measurement, analysis, and evaluation",
		Description: "AIMS performance is monitored, measured, analyzed, and evaluated",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMonitoring,
		References:  []string{"ISO/IEC 42001:2023 9.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.2",
		Name:        "Internal audit",
		Description: "Conduct internal audits at planned intervals to verify the AI management system conforms to requirements",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalAudit,
		References:  []string{"ISO/IEC 42001:2023 9.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.3",
		Name:        "Management review",
		Description: "Top management reviews the AI management system at planned intervals",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 9.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.P1",
		Name:        "AI system performance metrics",
		Description: "Define and track performance metrics for AI systems",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIPerformanceMetrics,
		References:  []string{"ISO/IEC 42001:2023 9.1 (Performance Metrics)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.P2",
		Name:        "Bias and fairness evaluation",
		Description: "Evaluate AI systems for bias and fairness on an ongoing basis",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBiasFairnessEvaluation,
		References:  []string{"ISO/IEC 42001:2023 9.1 (Bias & Fairness)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.P3",
		Name:        "Transparency and explainability reporting",
		Description: "Report on AI system transparency and explainability",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 9.1 (Transparency)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.P4",
		Name:        "Continual improvement",
		Description: "Implement continual improvement of the AI management system",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 10.1 (Continual Improvement)"},
	})

	// ====================================================================
	// AI Controls (4 controls, 3 automated)
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-AI-01",
		Name:        "AI model security",
		Description: "Implement security controls specific to AI/ML models including adversarial attack protection",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelSecurity,
		References:  []string{"ISO/IEC 42001:2023 AI Controls - Model Security"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-AI-02",
		Name:        "AI data provenance and lineage",
		Description: "Track and document data provenance and lineage for AI training and operation",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataProvenance,
		References:  []string{"ISO/IEC 42001:2023 AI Controls - Data Provenance"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-AI-03",
		Name:        "AI model documentation",
		Description: "Maintain documentation for AI models including model cards and datasheets",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelDocumentation,
		References:  []string{"ISO/IEC 42001:2023 AI Controls - Model Documentation"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-AI-04",
		Name:        "AI system retirement and decommissioning",
		Description: "Establish procedures for safely retiring and decommissioning AI systems",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO/IEC 42001:2023 AI Controls - Decommissioning"},
	})
}

// ============================================================================
// Check implementations — existing (preserved from v1.1)
// ============================================================================

// checkAIPolicy verifies that an AI policy is documented, communicated,
// and includes acceptable use provisions.
func (m *ISO42001Module) checkAIPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := false
	for _, p := range m.policyPatterns {
		if p.MatchString(inputStr) {
			hasPolicy = true
			break
		}
	}
	hasCommunication := strings.Contains(inputStr, "communicated") || strings.Contains(inputStr, "published") || strings.Contains(inputStr, "documented")

	if hasPolicy && hasCommunication {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-4.1",
			ControlName: "Understanding the organization and its context",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI policy established and documented",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-4.1",
			ControlName: "Understanding the organization and its context",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "AI policy detected but no documented communication",
			Timestamp:   time.Now(),
			Remediation: "Ensure AI policy is documented and published to all relevant parties",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-4.1",
		ControlName: "Understanding the organization and its context",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI policy detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and document an AI policy (e.g., 'AegisGate AI Acceptable Use Policy' in your internal docs)",
	}, nil
}

// checkRiskAssessment verifies that AI risk assessment is performed.
func (m *ISO42001Module) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matchedPatterns := []string{}
	for _, p := range m.riskPatterns {
		if p.MatchString(inputStr) {
			matchedPatterns = append(matchedPatterns, p.String())
		}
	}

	if len(matchedPatterns) >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.1",
			ControlName: "Leadership and commitment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI risk assessment detected with multiple risk patterns",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(matchedPatterns) == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.1",
			ControlName: "Leadership and commitment",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Single risk pattern detected; recommend documenting multiple risk dimensions",
			Timestamp:   time.Now(),
			Remediation: "Document risk across multiple dimensions: adversarial, privacy, model behavior, regulatory",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-5.1",
		ControlName: "Leadership and commitment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI risk assessment detected",
		Timestamp:   time.Now(),
		Remediation: "Perform an AI risk assessment covering adversarial, privacy, model behavior, and regulatory risks",
	}, nil
}

// checkDocumentedInfo verifies that required documented information
// (statement of applicability, risk register, audit logs) is in place.
func (m *ISO42001Module) checkDocumentedInfo(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.documentationPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.2",
			ControlName: "Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Documented information controls in place",
			Timestamp:   time.Now(),
		}, nil
	}

	if matched >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.2",
			ControlName: "Policy",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Some documented information detected; full set recommended",
			Timestamp:   time.Now(),
			Remediation: "Document: Statement of Applicability, Risk Register, Audit Logs, Compliance Reports",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-5.2",
		ControlName: "Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No documented information detected",
		Timestamp:   time.Now(),
		Remediation: "Create SoA, risk register, audit log, compliance report (the AegisGate Trust Framework generates the audit log automatically)",
	}, nil
}

// checkRiskTreatment verifies that risk treatment is implemented and
// has measurable effectiveness (e.g., blocking rate, false positive rate).
func (m *ISO42001Module) checkRiskTreatment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTreatment := strings.Contains(inputStr, "risk_treatment") || strings.Contains(inputStr, "treatment_plan")
	hasBlocking := strings.Contains(inputStr, "block") || strings.Contains(inputStr, "deny")
	hasAudit := false
	for _, p := range m.auditLogPatterns() {
		if p.MatchString(inputStr) {
			hasAudit = true
			break
		}
	}

	if hasTreatment && (hasBlocking || hasAudit) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.1",
			ControlName: "Actions to address risks and opportunities",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI risk treatment implemented with measurable controls",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTreatment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.1",
			ControlName: "Actions to address risks and opportunities",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Risk treatment plan documented but no measurable controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement measurable controls: blocking rate, false positive rate, audit log",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-6.1",
		ControlName: "Actions to address risks and opportunities",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No risk treatment plan detected",
		Timestamp:   time.Now(),
		Remediation: "Implement a risk treatment plan: define risks, mitigations, owners, and measurable effectiveness metrics",
	}, nil
}

// checkMonitoring verifies that AIMS performance monitoring is in place
// (metrics, dashboards, alerting).
func (m *ISO42001Module) checkMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "metric") || strings.Contains(inputStr, "prometheus")
	hasDashboard := strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "grafana")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty") || strings.Contains(inputStr, "slack_alert")

	present := 0
	if hasMetrics {
		present++
	}
	if hasDashboard {
		present++
	}
	if hasAlerting {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.5",
			ControlName: "Documented information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AIMS performance monitoring configured",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.5",
			ControlName: "Documented information",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial monitoring configured; recommend metrics + dashboard + alerting",
			Timestamp:   time.Now(),
			Remediation: "Configure metrics (Prometheus), dashboard (Grafana), and alerting (PagerDuty, Slack) for AIMS performance",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-7.5",
		ControlName: "Documented information",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AIMS performance monitoring detected",
		Timestamp:   time.Now(),
		Remediation: "Set up metrics collection, dashboards, and alerting for AI management system performance",
	}, nil
}

// checkOperationalPlanning verifies that AI operational processes
// are planned and controlled. Maps to ISO 42001 8.1.
func (m *ISO42001Module) checkOperationalPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := false
	for _, p := range m.policyPatterns {
		if p.MatchString(inputStr) {
			hasPolicy = true
			break
		}
	}
	hasDocumentation := false
	for _, p := range m.documentationPats {
		if p.MatchString(inputStr) {
			hasDocumentation = true
			break
		}
	}

	if hasPolicy && hasDocumentation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.1",
			ControlName: "Operational planning and control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Operational planning and control verified: AI policy + documented operational procedures",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasPolicy || hasDocumentation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.1",
			ControlName: "Operational planning and control",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial operational planning: 1 of 2 components (need both AI policy AND documented operational procedures)",
			Timestamp:   time.Now(),
			Remediation: "Document both the AI policy and the operational procedures for AI system deployment (AegisGate deployment guide + AI acceptable use policy)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.1",
		ControlName: "Operational planning and control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No operational planning detected",
		Timestamp:   time.Now(),
		Remediation: "Document the AI policy AND the operational procedures for AI system deployment",
	}, nil
}

// checkChangeManagement verifies that AI system changes are
// controlled and reviewed. Maps to ISO 42001 8.3.
func (m *ISO42001Module) checkChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVersionControl := strings.Contains(inputStr, "model_version") || strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "git")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log") || strings.Contains(inputStr, "envelope")
	hasReviewProcess := strings.Contains(inputStr, "code_review") || strings.Contains(inputStr, "pr_review") || strings.Contains(inputStr, "change_review")
	hasRollback := strings.Contains(inputStr, "rollback") || strings.Contains(inputStr, "revert") || strings.Contains(inputStr, "previous_version")

	present := 0
	missing := []string{}
	if hasVersionControl {
		present++
	} else {
		missing = append(missing, "version control")
	}
	if hasAttestations {
		present++
	} else {
		missing = append(missing, "signed attestations")
	}
	if hasReviewProcess {
		present++
	} else {
		missing = append(missing, "review process")
	}
	if hasRollback {
		present++
	} else {
		missing = append(missing, "rollback capability")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.3",
			ControlName: "AI system development and deployment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI change management verified: version control + signed attestations + review process + rollback",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.3",
			ControlName: "AI system development and deployment",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No AI change management controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enable version control + AegisGate signed attestations + code review + rollback capability",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.3",
		ControlName: "AI system development and deployment",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Partial AI change management: " + isoCount(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing change management components (version control, signed attestations, review process, rollback)",
	}, nil
}

// checkInternalAudit verifies that internal audits are conducted.
// Maps to ISO 42001 9.1.
func (m *ISO42001Module) checkInternalAudit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns() {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasAuditSchedule := strings.Contains(inputStr, "audit_schedule") || strings.Contains(inputStr, "audit_plan") || strings.Contains(inputStr, "scheduled_audit")
	hasAuditReport := strings.Contains(inputStr, "audit_report") || strings.Contains(inputStr, "audit_findings") || strings.Contains(inputStr, "audit_results")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit log")
	}
	if hasAuditSchedule {
		present++
	} else {
		missing = append(missing, "audit schedule")
	}
	if hasAuditReport {
		present++
	} else {
		missing = append(missing, "audit report")
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Monitoring, measurement, analysis, and evaluation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal audit verified: audit log + audit schedule + audit report",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Monitoring, measurement, analysis, and evaluation",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No internal audit controls detected",
			Timestamp:   time.Now(),
			Remediation: "Set up audit log + audit schedule + audit report per ISO 42001 9.1",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.2",
		ControlName: "Monitoring, measurement, analysis, and evaluation",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial internal audit: " + isoCount(present) + "/3 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing internal audit components (audit log, audit schedule, audit report)",
	}, nil
}

// checkManagementReview verifies that management reviews are
// conducted. Maps to ISO 42001 9.2.
func (m *ISO42001Module) checkManagementReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCisoDigest := strings.Contains(inputStr, "ciso_digest") || strings.Contains(inputStr, "ciso_posture") || strings.Contains(inputStr, "executive_digest")
	hasReviewSchedule := strings.Contains(inputStr, "review_schedule") || strings.Contains(inputStr, "management_review") || strings.Contains(inputStr, "scheduled_review")
	hasReviewMinutes := strings.Contains(inputStr, "review_minutes") || strings.Contains(inputStr, "meeting_minutes") || strings.Contains(inputStr, "review_notes")
	hasActionItems := strings.Contains(inputStr, "action_items") || strings.Contains(inputStr, "follow_up") || strings.Contains(inputStr, "decisions")

	present := 0
	missing := []string{}
	if hasCisoDigest {
		present++
	} else {
		missing = append(missing, "CISO digest (executive summary)")
	}
	if hasReviewSchedule {
		present++
	} else {
		missing = append(missing, "review schedule")
	}
	if hasReviewMinutes {
		present++
	} else {
		missing = append(missing, "review minutes")
	}
	if hasActionItems {
		present++
	} else {
		missing = append(missing, "action items")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Internal audit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Management review verified: CISO digest + review schedule + review minutes + action items",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Internal audit",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No management review detected",
			Timestamp:   time.Now(),
			Remediation: "Set up CISO Posture Digest (AegisGate pkg/reporting/) + management review schedule + meeting minutes + action items",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.2",
		ControlName: "Internal audit",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial management review: " + isoCount(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing management review components (CISO digest, schedule, minutes, action items)",
	}, nil
}

// ============================================================================
// Check implementations — new (v2.0)
// ============================================================================

// checkAIMSProcesses verifies that AI management system processes are
// defined and documented. Maps to ISO 42001 4.4.
func (m *ISO42001Module) checkAIMSProcesses(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.aimsProcessPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-4.4",
			ControlName: "AI management system and its processes",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI management system processes detected with multiple process indicators",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-4.4",
			ControlName: "AI management system and its processes",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AIMS process definition detected",
			Timestamp:   time.Now(),
			Remediation: "Document full AIMS process definition including all AI management system processes",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-4.4",
		ControlName: "AI management system and its processes",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI management system processes detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and document AI management system (AIMS) processes and their interactions",
	}, nil
}

// checkAIGovernance verifies that an AI governance framework with clear
// accountability is established. Maps to ISO 42001 5.P1.
func (m *ISO42001Module) checkAIGovernance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.governancePats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.P1",
			ControlName: "AI governance framework",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI governance framework detected with multiple governance structures",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.P1",
			ControlName: "AI governance framework",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI governance framework detected",
			Timestamp:   time.Now(),
			Remediation: "Establish a comprehensive AI governance framework with AI committee, board oversight, and clear accountability",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-5.P1",
		ControlName: "AI governance framework",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI governance framework detected",
		Timestamp:   time.Now(),
		Remediation: "Establish an AI governance framework with AI committee, board oversight, and clear accountability structure",
	}, nil
}

// checkAIImpactAssess verifies that AI system impact assessments are
// performed. Maps to ISO 42001 6.3.
func (m *ISO42001Module) checkAIImpactAssess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.impactAssessPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.3",
			ControlName: "AI system impact assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI system impact assessment detected with multiple impact dimensions",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.3",
			ControlName: "AI system impact assessment",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI impact assessment detected",
			Timestamp:   time.Now(),
			Remediation: "Document comprehensive AI impact assessment covering individuals, society, and environment",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-6.3",
		ControlName: "AI system impact assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI system impact assessment detected",
		Timestamp:   time.Now(),
		Remediation: "Perform AI system impact assessments covering individuals, society, and the environment",
	}, nil
}

// checkAIAwareness verifies that AI awareness training is in place.
// Maps to ISO 42001 7.3.
func (m *ISO42001Module) checkAIAwareness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.awarenessPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.3",
			ControlName: "Awareness",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI awareness and training program detected with multiple awareness indicators",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.3",
			ControlName: "Awareness",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI awareness program detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI awareness training covering AI policy, risks, and AI literacy",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-7.3",
		ControlName: "Awareness",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI awareness training detected",
		Timestamp:   time.Now(),
		Remediation: "Establish AI awareness training programs covering AI policy, risks, responsibilities, and AI literacy",
	}, nil
}

// checkAIRequirements verifies that AI system requirements including
// safety, security, fairness, and transparency are defined.
// Maps to ISO 42001 8.2.
func (m *ISO42001Module) checkAIRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.requirementsPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}
	hasSafety := strings.Contains(inputStr, "safety") || strings.Contains(inputStr, "fairness")
	hasTransparency := strings.Contains(inputStr, "transparency") || strings.Contains(inputStr, "explainab")

	if matched >= 2 || (matched >= 1 && (hasSafety || hasTransparency)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.2",
			ControlName: "AI system requirements and design",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI system requirements defined with safety, security, and design documentation",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 || hasSafety || hasTransparency {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.2",
			ControlName: "AI system requirements and design",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI system requirements detected",
			Timestamp:   time.Now(),
			Remediation: "Document comprehensive AI system requirements including safety, security, fairness, and transparency",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.2",
		ControlName: "AI system requirements and design",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI system requirements or design documentation detected",
		Timestamp:   time.Now(),
		Remediation: "Define AI system requirements including safety, security, fairness, and transparency requirements",
	}, nil
}

// checkAIVerification verifies that AI system verification and
// validation activities are performed. Maps to ISO 42001 8.4.
func (m *ISO42001Module) checkAIVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.verificationPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.4",
			ControlName: "AI system verification and validation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI system verification and validation detected with multiple testing indicators",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.4",
			ControlName: "AI system verification and validation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI verification and validation detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI verification and validation including model validation and AI testing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.4",
		ControlName: "AI system verification and validation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI system verification or validation detected",
		Timestamp:   time.Now(),
		Remediation: "Establish AI system verification and validation procedures including model validation and AI testing before and after deployment",
	}, nil
}

// checkAIPerformanceMetrics verifies that AI system performance
// metrics are defined and tracked. Maps to ISO 42001 9.P1.
func (m *ISO42001Module) checkAIPerformanceMetrics(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.perfMetricsPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.P1",
			ControlName: "AI system performance metrics",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI system performance metrics detected with multiple metric indicators",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.P1",
			ControlName: "AI system performance metrics",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI performance metrics detected",
			Timestamp:   time.Now(),
			Remediation: "Define and track comprehensive AI performance metrics including model performance and AI-specific metrics",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.P1",
		ControlName: "AI system performance metrics",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI system performance metrics detected",
		Timestamp:   time.Now(),
		Remediation: "Define and track AI system performance metrics including model performance, accuracy, and AI-specific KPIs",
	}, nil
}

// checkAIModelSecurity verifies that AI/ML model security controls
// including adversarial attack protection are implemented.
// Maps to ISO 42001 AI-01.
func (m *ISO42001Module) checkAIModelSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.modelSecurityPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-AI-01",
			ControlName: "AI model security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI model security controls detected with adversarial attack protection",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-AI-01",
			ControlName: "AI model security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI model security controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI model security including adversarial attack protection and model protection controls",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-AI-01",
		ControlName: "AI model security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI model security controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI/ML model security controls including adversarial attack protection, model protection, and model security monitoring",
	}, nil
}

// checkDataProvenance verifies that data provenance and lineage for AI
// training and operation are tracked and documented.
// Maps to ISO 42001 AI-02.
func (m *ISO42001Module) checkDataProvenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.dataProvenancePats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-AI-02",
			ControlName: "AI data provenance and lineage",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI data provenance and lineage tracking detected with multiple indicators",
			Timestamp:   time.Now(),
		}, nil
	}
	if matched == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-AI-02",
			ControlName: "AI data provenance and lineage",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial data provenance and lineage tracking detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive data provenance, lineage, and tracking for AI training and operation data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-AI-02",
		ControlName: "AI data provenance and lineage",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI data provenance or lineage tracking detected",
		Timestamp:   time.Now(),
		Remediation: "Establish data provenance, lineage, and tracking for all AI training, testing, and operational data",
	}, nil
}

// ============================================================================
// Helpers
// ============================================================================

// isoCount is a small helper to avoid importing strconv.
func isoCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-isoCount(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// auditLogPatterns is a helper for the risk treatment check. Returns
// the same patterns used by the SOC 2 module's audit logging check
// (duplicated here to keep modules decoupled).
func (m *ISO42001Module) auditLogPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
	}
}

// Dependencies returns required modules.
func (m *ISO42001Module) Dependencies() []string {
	return []string{"scanner", "trust", "metrics"}
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *ISO42001Module) checkAIOperationMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOperation := strings.Contains(inputStr, "ai_operation") || strings.Contains(inputStr, "system_operation") || strings.Contains(inputStr, "ai_monitoring")
	hasMetrics := strings.Contains(inputStr, "operational_metrics") || strings.Contains(inputStr, "ai_performance_monitoring") || strings.Contains(inputStr, "system_monitoring")
	if hasOperation && hasMetrics {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.5", ControlName: "AI system operation and monitoring", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI system operation and monitoring detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasOperation {
		violations = append(violations, "AI operation not configured")
	}
	if !hasMetrics {
		violations = append(violations, "operational monitoring not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.5", ControlName: "AI system operation and monitoring", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "AI operation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement AI system operation and monitoring"}, nil
}

func (m *ISO42001Module) checkAIIncidentManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIncident := strings.Contains(inputStr, "ai_incident") || strings.Contains(inputStr, "incident_management") || strings.Contains(inputStr, "ai_incident_response")
	hasProcedure := strings.Contains(inputStr, "incident_procedure") || strings.Contains(inputStr, "ai_incident_procedure") || strings.Contains(inputStr, "incident_plan")
	if hasIncident && hasProcedure {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.6", ControlName: "AI system incident management", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI incident management detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasIncident {
		violations = append(violations, "AI incident management not configured")
	}
	if !hasProcedure {
		violations = append(violations, "incident procedures not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.6", ControlName: "AI system incident management", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "AI incident gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement AI system incident management procedures"}, nil
}

func (m *ISO42001Module) checkAIDataManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDataMgmt := strings.Contains(inputStr, "data_management") || strings.Contains(inputStr, "ai_data_management") || strings.Contains(inputStr, "data_governance")
	hasQuality := strings.Contains(inputStr, "data_quality") || strings.Contains(inputStr, "data_lineage") || strings.Contains(inputStr, "data_provenance")
	if hasDataMgmt && hasQuality {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.7", ControlName: "Data management for AI systems", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI data management with quality controls detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasDataMgmt {
		violations = append(violations, "data management not configured")
	}
	if !hasQuality {
		violations = append(violations, "data quality not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-8.7", ControlName: "Data management for AI systems", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Data management gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement data management for AI systems"}, nil
}

func (m *ISO42001Module) checkBiasFairnessEvaluation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBias := strings.Contains(inputStr, "bias_detection") || strings.Contains(inputStr, "bias_evaluation") || strings.Contains(inputStr, "fairness_evaluation")
	hasMetrics := strings.Contains(inputStr, "bias_metrics") || strings.Contains(inputStr, "fairness_metrics") || strings.Contains(inputStr, "bias_monitoring")
	if hasBias && hasMetrics {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-9.P2", ControlName: "Bias and fairness evaluation", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Bias and fairness evaluation detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasBias {
		violations = append(violations, "bias evaluation not configured")
	}
	if !hasMetrics {
		violations = append(violations, "bias metrics not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-9.P2", ControlName: "Bias and fairness evaluation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Bias evaluation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement bias and fairness evaluation"}, nil
}

func (m *ISO42001Module) checkAIModelDocumentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDocs := strings.Contains(inputStr, "model_documentation") || strings.Contains(inputStr, "ai_documentation") || strings.Contains(inputStr, "model_docs")
	hasVersioned := strings.Contains(inputStr, "versioned_documentation") || strings.Contains(inputStr, "model_card") || strings.Contains(inputStr, "model_version")
	if hasDocs && hasVersioned {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-AI-03", ControlName: "AI model documentation", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI model documentation detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasDocs {
		violations = append(violations, "model documentation not configured")
	}
	if !hasVersioned {
		violations = append(violations, "versioned documentation not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO42001-AI-03", ControlName: "AI model documentation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Documentation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement AI model documentation with versioning"}, nil
}
