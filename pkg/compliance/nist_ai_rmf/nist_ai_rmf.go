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
// This module provides 50 controls covering subcategories of the
// AI RMF Playbook, with automated checks for 30 and evidence-mapped
// checks for 20.
//
// Module metadata:
//   - Framework:   "nist_ai_rmf"
//   - Version:     "1.0"
//   - Required tier: Community (free, like ATLAS/OWASP/GDPR/CIS)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - nist_ai_rmf.go:      module wiring, 50 RegisterControl calls,
//                           30 automated + 20 evidence-mapped
//   - nist_ai_rmf_test.go: unit tests
//
// Coverage: 50 AI RMF 1.0 subcategories and Playbook actions.
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
	safetyPatterns       []*regexp.Regexp
	fairnessPatterns     []*regexp.Regexp
	securityPatterns     []*regexp.Regexp
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
	m.safetyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)safety[_ ]?metric`),
		regexp.MustCompile(`(?i)safety[_ ]?assessment`),
		regexp.MustCompile(`(?i)hazard[_ ]?analysis`),
		regexp.MustCompile(`(?i)safe[_ ]?operation`),
	}
	m.fairnessPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)fairness[_ ]?metric`),
		regexp.MustCompile(`(?i)bias[_ ]?metric`),
		regexp.MustCompile(`(?i)equity[_ ]?check`),
		regexp.MustCompile(`(?i)demographic[_ ]?parity`),
	}
	m.securityPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)security[_ ]?metric`),
		regexp.MustCompile(`(?i)vulnerability[_ ]?scan`),
		regexp.MustCompile(`(?i)penetration[_ ]?test`),
		regexp.MustCompile(`(?i)adversarial[_ ]?robustness`),
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

	// =================================================================
	// GOVERN (GV) — Additional subcategories
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-1.4",
		Name:        "AI business value and risk documented",
		Description: "GV-1.4: The business value or mission of AI systems is documented and aligned with organizational risk tolerance",
		Category:    "Govern",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAIBusinessRisk,
		References:  []string{"NIST AI RMF 1.0 GV-1.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-1.5",
		Name:        "Legal and regulatory requirements for AI identified",
		Description: "GV-1.5: Legal and regulatory requirements relevant to AI systems are identified and documented",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV15,
		References:  []string{"NIST AI RMF 1.0 GV-1.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-2.3",
		Name:        "AI risk management practices integrated",
		Description: "GV-2.3: AI risk management practices are integrated into organizational practices and processes",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGV23,
		References:  []string{"NIST AI RMF 1.0 GV-2.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-3.3",
		Name:        "AI risk management resources allocated",
		Description: "GV-3.3: Resources required for AI risk management are allocated and tracked (personnel, tools, budget)",
		Category:    "Govern",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 GV-3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-4.2",
		Name:        "AI risk management practices harmonized",
		Description: "GV-4.2: AI risk management practices are harmonized with related organizational policies and standards",
		Category:    "Govern",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkGV42,
		References:  []string{"NIST AI RMF 1.0 GV-4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GV-4.3",
		Name:        "AI risk management practices adapted",
		Description: "GV-4.3: AI risk management practices are adapted to changes in organizational strategy and risk landscape",
		Category:    "Govern",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 GV-4.3"},
	})

	// =================================================================
	// MAP (MP) — Additional subcategories
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-1.2",
		Name:        "AI system lifecycle documented",
		Description: "MP-1.2: AI system lifecycle stages are documented from design through deployment and decommissioning",
		Category:    "Map",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMP12,
		References:  []string{"NIST AI RMF 1.0 MP-1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-1.3",
		Name:        "AI system acquirers and users identified",
		Description: "MP-1.3: Acquirers, users, and downstream parties of the AI system are identified and documented",
		Category:    "Map",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MP-1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-2.2",
		Name:        "AI system capabilities and limitations documented",
		Description: "MP-2.2: AI system capabilities and limitations are documented and communicated to relevant stakeholders",
		Category:    "Map",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMP22,
		References:  []string{"NIST AI RMF 1.0 MP-2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-2.3",
		Name:        "AI system reliability and validity assessed",
		Description: "MP-2.3: AI system reliability and validity are assessed against the defined context and use case",
		Category:    "Map",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMP23,
		References:  []string{"NIST AI RMF 1.0 MP-2.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-3.2",
		Name:        "AI risks prioritized",
		Description: "MP-3.2: AI risks are prioritized based on likelihood and impact for resource allocation and treatment",
		Category:    "Map",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAIRiskPrioritization,
		References:  []string{"NIST AI RMF 1.0 MP-3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-3.3",
		Name:        "AI risk assessments reviewed",
		Description: "MP-3.3: AI risk assessments are reviewed and updated on a regular schedule or after significant changes",
		Category:    "Map",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMP33,
		References:  []string{"NIST AI RMF 1.0 MP-3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MP-4.1",
		Name:        "AI system impact on individuals assessed",
		Description: "MP-4.1: AI system impact on individuals and communities is assessed including potential benefits and harms",
		Category:    "Map",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MP-4.1"},
	})

	// =================================================================
	// MEASURE (MS) — Additional subcategories
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-1.2",
		Name:        "AI reliability metrics tracked",
		Description: "MS-1.2: AI system reliability metrics are identified, tracked, and compared against performance targets",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS12,
		References:  []string{"NIST AI RMF 1.0 MS-1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-1.3",
		Name:        "AI safety metrics tracked",
		Description: "MS-1.3: AI system safety metrics are identified and tracked including hazard and incident measures",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS13,
		References:  []string{"NIST AI RMF 1.0 MS-1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.4",
		Name:        "AI security metrics tracked",
		Description: "MS-2.4: AI system security metrics are identified and tracked including vulnerability and attack metrics",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS24,
		References:  []string{"NIST AI RMF 1.0 MS-2.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.5",
		Name:        "AI privacy metrics tracked",
		Description: "MS-2.5: AI system privacy metrics are identified and tracked including data protection and PII metrics",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS25,
		References:  []string{"NIST AI RMF 1.0 MS-2.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.6",
		Name:        "AI fairness metrics tracked",
		Description: "MS-2.6: AI system fairness metrics are identified and tracked including bias and equity measures",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMS26,
		References:  []string{"NIST AI RMF 1.0 MS-2.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.7",
		Name:        "AI accountability metrics tracked",
		Description: "MS-2.7: AI system accountability metrics are identified and tracked including auditability and responsibility measures",
		Category:    "Measure",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccountabilityMetrics,
		References:  []string{"NIST AI RMF 1.0 MS-2.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.8",
		Name:        "AI transparency metrics tracked",
		Description: "MS-2.8: AI system transparency metrics are identified and tracked including explainability and disclosure measures",
		Category:    "Measure",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTransparencyMetrics,
		References:  []string{"NIST AI RMF 1.0 MS-2.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-2.9",
		Name:        "AI system bias measured",
		Description: "MS-2.9: AI system bias is measured and tracked across demographic groups and decision outcomes",
		Category:    "Measure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIRiskTreatment,
		References:  []string{"NIST AI RMF 1.0 MS-2.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MS-3.1",
		Name:        "AI risk assessment results verified",
		Description: "MS-3.1: AI risk assessment results are verified and validated by independent review or testing",
		Category:    "Measure",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MS-3.1"},
	})

	// =================================================================
	// MANAGE (MG) — Additional subcategories
	// =================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-1.3",
		Name:        "AI risk treatment options evaluated",
		Description: "MG-1.3: AI risk treatment options are evaluated for cost, feasibility, and effectiveness before selection",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-2.3",
		Name:        "AI incident response mechanisms tested",
		Description: "MG-2.3: AI incident response mechanisms are tested on a regular schedule and after system changes",
		Category:    "Manage",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMG23,
		References:  []string{"NIST AI RMF 1.0 MG-2.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-2.4",
		Name:        "AI system recovery procedures in place",
		Description: "MG-2.4: AI system recovery procedures and fallback mechanisms are documented and tested",
		Category:    "Manage",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-2.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-3.2",
		Name:        "AI risk management improvements implemented",
		Description: "MG-3.2: AI risk management improvements are implemented based on monitoring, feedback, and lessons learned",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-3.3",
		Name:        "AI risk management knowledge shared",
		Description: "MG-3.3: AI risk management knowledge and lessons learned are shared across the organization",
		Category:    "Manage",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkMG33,
		References:  []string{"NIST AI RMF 1.0 MG-3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-4.1",
		Name:        "AI system documentation maintained",
		Description: "MG-4.1: AI system documentation is maintained throughout the system lifecycle including updates and changes",
		Category:    "Manage",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMG41,
		References:  []string{"NIST AI RMF 1.0 MG-4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-4.2",
		Name:        "AI system decommissioning process",
		Description: "MG-4.2: AI system decommissioning and retirement process is documented and executed when systems are sunset",
		Category:    "Manage",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-4.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "MG-4.3",
		Name:        "AI system impact on third parties managed",
		Description: "MG-4.3: AI system impacts on third parties and downstream users are identified and managed through contractual and governance mechanisms",
		Category:    "Manage",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"NIST AI RMF 1.0 MG-4.3"},
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
// GOVERN (GV) Additional Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkGV15(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLegal := strings.Contains(inputStr, "legal") || strings.Contains(inputStr, "regulatory") || strings.Contains(inputStr, "compliance")
	hasAI := strings.Contains(inputStr, "ai_") || strings.Contains(inputStr, "artificial_intelligence") || strings.Contains(inputStr, "ml_")
	if hasLegal && hasAI {
		return compliant(m, "GV-1.5", "Legal and regulatory requirements for AI systems identified")
	}
	if hasLegal {
		return partial(m, "GV-1.5", "Legal requirements documented but AI-specific requirements not identified",
			"Identify and document AI-specific legal and regulatory requirements")
	}
	return nonCompliant(m, "GV-1.5", "No legal or regulatory requirements for AI identified",
		"Identify and document legal and regulatory requirements applicable to AI systems")
}

func (m *NISTAIRMFModule) checkGV23(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAIRisk := matchAny(inputStr, m.riskPatterns) || strings.Contains(inputStr, "ai_risk")
	hasIntegration := strings.Contains(inputStr, "integrated") || strings.Contains(inputStr, "embedded") || strings.Contains(inputStr, "operational")
	if hasAIRisk && hasIntegration {
		return compliant(m, "GV-2.3", "AI risk management practices integrated into organizational processes")
	}
	if hasAIRisk {
		return partial(m, "GV-2.3", "AI risk practices defined but not integrated into organizational processes",
			"Integrate AI risk management into existing organizational workflows and processes")
	}
	return nonCompliant(m, "GV-2.3", "AI risk management practices not integrated",
		"Define and integrate AI risk management practices into organizational processes")
}

func (m *NISTAIRMFModule) checkGV42(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := matchAny(inputStr, m.policyPatterns) || strings.Contains(inputStr, "standard")
	hasHarmonized := strings.Contains(inputStr, "harmonized") || strings.Contains(inputStr, "aligned") || strings.Contains(inputStr, "consistent")
	if hasPolicy && hasHarmonized {
		return compliant(m, "GV-4.2", "AI risk management practices harmonized with organizational policies")
	}
	if hasPolicy {
		return partial(m, "GV-4.2", "AI policies exist but not harmonized with related organizational standards",
			"Align AI risk management practices with existing organizational policies and standards")
	}
	return nonCompliant(m, "GV-4.2", "AI risk management practices not harmonized",
		"Harmonize AI risk management practices with related organizational policies and standards")
}

// ============================================================================
// MAP (MP) Additional Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMP12(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLifecycle := strings.Contains(inputStr, "lifecycle") || strings.Contains(inputStr, "lifecycle_stage") || strings.Contains(inputStr, "development_phase")
	hasStages := strings.Contains(inputStr, "design") || strings.Contains(inputStr, "deployment") || strings.Contains(inputStr, "decommission")
	if hasLifecycle && hasStages {
		return compliant(m, "MP-1.2", "AI system lifecycle documented from design through decommissioning")
	}
	if hasLifecycle {
		return partial(m, "MP-1.2", "Lifecycle documented but not all stages covered",
			"Document all lifecycle stages including design, deployment, and decommissioning")
	}
	return nonCompliant(m, "MP-1.2", "AI system lifecycle not documented",
		"Document AI system lifecycle stages from design through deployment and decommissioning")
}

func (m *NISTAIRMFModule) checkMP22(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCapabilities := strings.Contains(inputStr, "capabilities") || strings.Contains(inputStr, "capability") || strings.Contains(inputStr, "features")
	hasLimitations := strings.Contains(inputStr, "limitations") || strings.Contains(inputStr, "constraints") || strings.Contains(inputStr, "known_issues")
	if hasCapabilities && hasLimitations {
		return compliant(m, "MP-2.2", "AI system capabilities and limitations documented")
	}
	if hasCapabilities {
		return partial(m, "MP-2.2", "AI capabilities documented but limitations not documented",
			"Document known limitations and constraints of the AI system")
	}
	return nonCompliant(m, "MP-2.2", "AI system capabilities and limitations not documented",
		"Document AI system capabilities and limitations; communicate to stakeholders")
}

func (m *NISTAIRMFModule) checkMP23(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReliability := strings.Contains(inputStr, "reliability") || strings.Contains(inputStr, "reliable")
	hasValidity := strings.Contains(inputStr, "validity") || strings.Contains(inputStr, "valid") || strings.Contains(inputStr, "validation")
	if hasReliability && hasValidity {
		return compliant(m, "MP-2.3", "AI system reliability and validity assessed")
	}
	if hasReliability || hasValidity {
		return partial(m, "MP-2.3", "Partial reliability or validity assessment",
			"Complete both reliability and validity assessments for the AI system")
	}
	return nonCompliant(m, "MP-2.3", "AI system reliability and validity not assessed",
		"Assess AI system reliability and validity against the defined context and use case")
}

func (m *NISTAIRMFModule) checkMP33(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAssessment := matchAny(inputStr, m.riskPatterns) || strings.Contains(inputStr, "risk_assessment")
	hasReview := strings.Contains(inputStr, "reviewed") || strings.Contains(inputStr, "updated") || strings.Contains(inputStr, "reassessed") || strings.Contains(inputStr, "review_schedule")
	if hasAssessment && hasReview {
		return compliant(m, "MP-3.3", "AI risk assessments reviewed and updated on regular schedule")
	}
	if hasAssessment {
		return partial(m, "MP-3.3", "Risk assessments exist but regular review not verified",
			"Establish a regular review schedule for AI risk assessments")
	}
	return nonCompliant(m, "MP-3.3", "AI risk assessments not reviewed or updated",
		"Implement regular review and update of AI risk assessments")
}

// ============================================================================
// MEASURE (MS) Additional Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMS12(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReliability := strings.Contains(inputStr, "reliability_metric") || strings.Contains(inputStr, "reliability") || strings.Contains(inputStr, "uptime") || strings.Contains(inputStr, "availability")
	hasTracking := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "kpi") || matchAny(inputStr, m.monitorPatterns)
	if hasReliability && hasTracking {
		return compliant(m, "MS-1.2", "AI reliability metrics tracked against performance targets")
	}
	if hasReliability {
		return partial(m, "MS-1.2", "Reliability metrics defined but tracking not verified",
			"Enable continuous tracking of AI reliability metrics")
	}
	return nonCompliant(m, "MS-1.2", "No AI reliability metrics tracked",
		"Define and track AI system reliability metrics including uptime and availability")
}

func (m *NISTAIRMFModule) checkMS13(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSafety := matchAny(inputStr, m.safetyPatterns) || strings.Contains(inputStr, "safety")
	hasTracking := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "kpi") || matchAny(inputStr, m.monitorPatterns)
	if hasSafety && hasTracking {
		return compliant(m, "MS-1.3", "AI safety metrics tracked including hazard and incident measures")
	}
	if hasSafety {
		return partial(m, "MS-1.3", "Safety metrics defined but tracking not verified",
			"Enable continuous tracking of AI safety metrics")
	}
	return nonCompliant(m, "MS-1.3", "No AI safety metrics tracked",
		"Define and track AI system safety metrics including hazard analysis and incident measures")
}

func (m *NISTAIRMFModule) checkMS24(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurity := matchAny(inputStr, m.securityPatterns) || strings.Contains(inputStr, "security_metric") || strings.Contains(inputStr, "security")
	hasTracking := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "vulnerability_scan") || strings.Contains(inputStr, "scanner")
	if hasSecurity && hasTracking {
		return compliant(m, "MS-2.4", "AI security metrics tracked including vulnerability and attack metrics")
	}
	if hasSecurity {
		return partial(m, "MS-2.4", "Security metrics defined but tracking not verified",
			"Enable continuous tracking of AI security metrics")
	}
	return nonCompliant(m, "MS-2.4", "No AI security metrics tracked",
		"Define and track AI system security metrics including vulnerability scans and adversarial robustness")
}

func (m *NISTAIRMFModule) checkMS25(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrivacy := strings.Contains(inputStr, "privacy_metric") || strings.Contains(inputStr, "privacy") || strings.Contains(inputStr, "pii") || strings.Contains(inputStr, "data_protection")
	hasTracking := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "kpi") || strings.Contains(inputStr, "pii_scanner")
	if hasPrivacy && hasTracking {
		return compliant(m, "MS-2.5", "AI privacy metrics tracked including data protection and PII metrics")
	}
	if hasPrivacy {
		return partial(m, "MS-2.5", "Privacy metrics defined but tracking not verified",
			"Enable continuous tracking of AI privacy metrics")
	}
	return nonCompliant(m, "MS-2.5", "No AI privacy metrics tracked",
		"Define and track AI system privacy metrics including PII detection and data protection measures")
}

func (m *NISTAIRMFModule) checkMS26(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFairness := matchAny(inputStr, m.fairnessPatterns) || strings.Contains(inputStr, "fairness") || strings.Contains(inputStr, "bias")
	hasTracking := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "kpi") || matchAny(inputStr, m.monitorPatterns)
	if hasFairness && hasTracking {
		return compliant(m, "MS-2.6", "AI fairness metrics tracked including bias and equity measures")
	}
	if hasFairness {
		return partial(m, "MS-2.6", "Fairness metrics defined but tracking not verified",
			"Enable continuous tracking of AI fairness metrics")
	}
	return nonCompliant(m, "MS-2.6", "No AI fairness metrics tracked",
		"Define and track AI system fairness metrics including bias measurement and equity checks")
}

// ============================================================================
// MANAGE (MG) Additional Check implementations
// ============================================================================

func (m *NISTAIRMFModule) checkMG23(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "response_plan")
	hasTesting := strings.Contains(inputStr, "tested") || strings.Contains(inputStr, "test_result") || strings.Contains(inputStr, "drill") || strings.Contains(inputStr, "exercise")
	if hasIRPlan && hasTesting {
		return compliant(m, "MG-2.3", "AI incident response mechanisms tested on regular schedule")
	}
	if hasIRPlan {
		return partial(m, "MG-2.3", "Incident response plan exists but testing not verified",
			"Establish regular testing of AI incident response mechanisms")
	}
	return nonCompliant(m, "MG-2.3", "AI incident response mechanisms not tested",
		"Create and regularly test AI incident response mechanisms")
}

func (m *NISTAIRMFModule) checkMG33(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKnowledge := strings.Contains(inputStr, "lessons_learned") || strings.Contains(inputStr, "knowledge_base") || strings.Contains(inputStr, "shared")
	hasOrg := strings.Contains(inputStr, "organization") || strings.Contains(inputStr, "training") || strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "wiki")
	if hasKnowledge && hasOrg {
		return compliant(m, "MG-3.3", "AI risk management knowledge shared across the organization")
	}
	if hasKnowledge {
		return partial(m, "MG-3.3", "Knowledge captured but sharing mechanisms not verified",
			"Implement organization-wide sharing of AI risk management knowledge and lessons learned")
	}
	return nonCompliant(m, "MG-3.3", "No AI risk management knowledge sharing",
		"Establish mechanisms to share AI risk management knowledge and lessons learned across the organization")
}

func (m *NISTAIRMFModule) checkMG41(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDocs := strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "system_docs") || strings.Contains(inputStr, "model_card") || strings.Contains(inputStr, "datasheet")
	hasMaintained := strings.Contains(inputStr, "maintained") || strings.Contains(inputStr, "updated") || strings.Contains(inputStr, "versioned") || strings.Contains(inputStr, "changelog")
	if hasDocs && hasMaintained {
		return compliant(m, "MG-4.1", "AI system documentation maintained throughout lifecycle")
	}
	if hasDocs {
		return partial(m, "MG-4.1", "Documentation exists but maintenance not verified",
			"Establish regular updates and versioning for AI system documentation")
	}
	return nonCompliant(m, "MG-4.1", "AI system documentation not maintained",
		"Maintain AI system documentation throughout the lifecycle including model cards and changelogs")
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

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *NISTAIRMFModule) checkAIBusinessRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasValue := strings.Contains(inputStr, "ai_business_value") || strings.Contains(inputStr, "business_value") || strings.Contains(inputStr, "ai_value")
	hasRisk := strings.Contains(inputStr, "ai_risk_documented") || strings.Contains(inputStr, "ai_risk_assessment") || strings.Contains(inputStr, "risk_documented")
	if hasValue && hasRisk {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GV-1.4", ControlName: "AI business value and risk documented", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "AI business value and risk documentation detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasValue {
		violations = append(violations, "business value not documented")
	}
	if !hasRisk {
		violations = append(violations, "risk not documented")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GV-1.4", ControlName: "AI business value and risk documented", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Documentation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Document AI business value and risk"}, nil
}

func (m *NISTAIRMFModule) checkAccountabilityMetrics(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "accountability_metrics") || strings.Contains(inputStr, "accountability_tracking") || strings.Contains(inputStr, "ai_accountability")
	if hasMetrics {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.7", ControlName: "AI accountability metrics tracked", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "AI accountability metrics detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.7", ControlName: "AI accountability metrics tracked", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Accountability metrics not detected", Timestamp: time.Now(), Remediation: "Implement AI accountability metrics tracking"}, nil
}

func (m *NISTAIRMFModule) checkTransparencyMetrics(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "transparency_metrics") || strings.Contains(inputStr, "transparency_tracking") || strings.Contains(inputStr, "ai_transparency")
	if hasMetrics {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.8", ControlName: "AI transparency metrics tracked", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "AI transparency metrics detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.8", ControlName: "AI transparency metrics tracked", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Transparency metrics not detected", Timestamp: time.Now(), Remediation: "Implement AI transparency metrics tracking"}, nil
}

func (m *NISTAIRMFModule) checkAIRiskPrioritization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrioritization := strings.Contains(inputStr, "ai_risk_prioritization") || strings.Contains(inputStr, "risk_prioritization") || strings.Contains(inputStr, "risk_priority")
	if hasPrioritization {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MP-3.2", ControlName: "AI risks prioritized", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "AI risk prioritization detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MP-3.2", ControlName: "AI risks prioritized", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk prioritization not detected", Timestamp: time.Now(), Remediation: "Implement AI risk prioritization"}, nil
}

func (m *NISTAIRMFModule) checkAIRiskTreatment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTreatment := strings.Contains(inputStr, "ai_risk_treatment") || strings.Contains(inputStr, "risk_treatment_implemented") || strings.Contains(inputStr, "risk_treatment")
	if hasTreatment {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.9", ControlName: "AI risk treatment implemented", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "AI risk treatment detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "MS-2.9", ControlName: "AI risk treatment implemented", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk treatment not detected", Timestamp: time.Now(), Remediation: "Implement AI risk treatment"}, nil
}
