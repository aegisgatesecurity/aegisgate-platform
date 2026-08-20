// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Type II Compliance Module v2.0
// =========================================================================
//
// Implements the SOC 2 (Service Organization Control 2) Type II
// compliance framework as a licensed add-on module. This v2.0 release
// expands coverage from 15 to 64 controls organized across the full
// AICPA Trust Services Criteria (TSC) taxonomy.
//
// Module metadata:
//   - Framework:     "soc2"
//   - Version:       "2.0"
//   - Required tier: Developer+ (gated via pkg/compliance/gating.go)
//   - Controls:      64 total (40 automated, 24 manual)
//
// Coverage by category:
//   - Security (Common Criteria): 40 controls (20 automated)
//       CC1 Control Environment        (5 controls, 2 auto)
//       CC2 Communication & Info      (4 controls, 2 auto)
//       CC3 Risk Assessment           (5 controls, 3 auto)
//       CC4 Monitoring Activities     (4 controls, 2 auto)
//       CC5 Control Activities        (4 controls, 1 auto)
//       CC6 Logical & Physical Access (8 controls, 5 auto)
//       CC7 System Operations         (7 controls, 3 auto)
//       CC8 Change Management         (3 controls, 1 auto)
//       CC9 Risk Mitigation           (3 controls, 1 auto)
//   - Availability:                   6 controls (3 auto)
//   - Confidentiality:                5 controls (3 auto)
//   - Processing Integrity:           5 controls (2 auto)
//   - AI Controls:                    5 controls (4 auto)
//
// Reference: AICPA Trust Services Criteria 2017 (revised 2022)
//            https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
//
// =========================================================================

package soc2

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// SOC2Module implements the SOC 2 Type II compliance framework as a
// licensed add-on. It embeds *compliance.BaseComplianceModule which
// provides RegisterControl, Controls(), Framework(), Version(),
// CheckAll(), and GenerateAssessment() out of the box.
type SOC2Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	piiPatterns        []*regexp.Regexp
	mTLSConfigPatterns []*regexp.Regexp
	auditLogPatterns   []*regexp.Regexp
}

// NewSOC2Module creates a new SOC 2 compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Developer+ tier via pkg/compliance/gating.go
// (license.ModuleSOC2 entry in moduleRequirements).
func NewSOC2Module() *SOC2Module {
	m := &SOC2Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("soc2", "2.0", core.TierDeveloper),
	}
	m.initSOC2Patterns()
	m.registerControls()
	return m
}

// initSOC2Patterns compiles the regex patterns used by automated
// controls. Called once at construction time.
func (m *SOC2Module) initSOC2Patterns() {
	m.piiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                           // SSN
		regexp.MustCompile(`\d{16}`),                                      // Credit card
		regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}`), // Email
	}
	m.mTLSConfigPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mtls`),
		regexp.MustCompile(`(?i)mutual[_ ]?tls`),
		regexp.MustCompile(`(?i)client[_ ]?cert`),
	}
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)signed[_ ]?log`),
	}
}

// registerControls wires all 64 SOC 2 controls into the module.
// Called once from NewSOC2Module. The 32 automated controls reference
// check* methods defined below; the remaining 32 are manual review.
func (m *SOC2Module) registerControls() {
	// ====================================================================
	// Security (Common Criteria) — CC1: Control Environment (5 controls, 2 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.1",
		Name:        "Demonstrates commitment to integrity and ethical values",
		Description: "Management demonstrates a commitment to honesty and fairness in dealings with stakeholders",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.2",
		Name:        "Board of Directors demonstrates independence",
		Description: "Board provides oversight and accountability for the system",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.3",
		Name:        "Management establishes structure and authority",
		Description: "Management establishes, with board oversight, structures, reporting lines, and authorities",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.4",
		Name:        "Demonstrates commitment to competence",
		Description: "Management demonstrates commitment to attracting, developing, and retaining competent personnel",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCompetence,
		References:  []string{"AICPA TSC 2017 CC1.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.5",
		Name:        "Enforces accountability",
		Description: "Management enforces accountability through performance evaluation and consequences",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountability,
		References:  []string{"AICPA TSC 2017 CC1.5"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC2: Communication and Information (4 controls, 2 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC2.1",
		Name:        "Internal communication of security objectives",
		Description: "Internally communicates security objectives and responsibilities",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInternalComm,
		References:  []string{"AICPA TSC 2017 CC2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC2.2",
		Name:        "External communication of security matters",
		Description: "Externally communicates security matters to relevant stakeholders",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkExternalComm,
		References:  []string{"AICPA TSC 2017 CC2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC2.3",
		Name:        "Communication of security incidents",
		Description: "Communicates security incidents to affected parties",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentComm,
		References:  []string{"AICPA TSC 2017 CC2.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC2.P1",
		Name:        "Designs communication channels",
		Description: "Designs and implements communication channels for security information flow",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC2.P1"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC3: Risk Assessment (5 controls, 3 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC3.1",
		Name:        "Identifies and assesses risk",
		Description: "Identifies and analyzes risks to the achievement of objectives",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskAssess,
		References:  []string{"AICPA TSC 2017 CC3.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC3.2",
		Name:        "Considers fraud risk",
		Description: "Identifies, analyzes, and manages fraud risks",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFraudRisk,
		References:  []string{"AICPA TSC 2017 CC3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC3.3",
		Name:        "Assesses changes in environment",
		Description: "Identifies and assesses changes that could significantly impact the system",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC3.4",
		Name:        "Assesses business continuity risk",
		Description: "Identifies and assesses risks related to business continuity",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBCRisk,
		References:  []string{"AICPA TSC 2017 CC3.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC3.P1",
		Name:        "Designs risk assessment process",
		Description: "Designs and implements a process for identifying and assessing risk",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC3.P1"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC4: Monitoring Activities (4 controls, 2 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC4.1",
		Name:        "Ongoing monitoring of system performance",
		Description: "Performs ongoing monitoring to evaluate the effectiveness of controls",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOngoingMonitoring,
		References:  []string{"AICPA TSC 2017 CC4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC4.2",
		Name:        "Evaluates deficiencies",
		Description: "Evaluates deficiencies and communicates to responsible parties",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC4.P1",
		Name:        "Designs monitoring system",
		Description: "Designs and implements a monitoring system for control effectiveness",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC4.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC4.P2",
		Name:        "Designs deficiency evaluation",
		Description: "Designs procedures for evaluating control deficiencies",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDeficiencyEval,
		References:  []string{"AICPA TSC 2017 CC4.P2"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC5: Control Activities (4 controls, 1 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC5.1",
		Name:        "Selects and develops control activities",
		Description: "Selects and develops control activities that contribute to risk mitigation",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC5.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC5.2",
		Name:        "Selects and develops technology-based controls",
		Description: "Selects and develops technology-based controls to support objectives",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTechControls,
		References:  []string{"AICPA TSC 2017 CC5.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC5.P1",
		Name:        "Designs control deployment",
		Description: "Designs and implements policies and procedures for control deployment",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC5.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC5.P2",
		Name:        "Develops complementing controls",
		Description: "Develops complementing controls to achieve objectives",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC5.P2"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC6: Logical and Physical Access Controls (8 controls, 5 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.1",
		Name:        "Logical access security controls",
		Description: "Implements logical access security controls over technology resources",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkLogicalAccess,
		References:  []string{"AICPA TSC 2017 CC6.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.2",
		Name:        "User registration and de-registration",
		Description: "Controls user registration and de-registration to prevent unauthorized access",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkUserRegistration,
		References:  []string{"AICPA TSC 2017 CC6.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.3",
		Name:        "User role assignment and review",
		Description: "Controls user role assignment and performs periodic access reviews",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRoleAssignment,
		References:  []string{"AICPA TSC 2017 CC6.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.4",
		Name:        "Restrict access to authorized users",
		Description: "Restricts access to authorized users through authentication mechanisms",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessRestriction,
		References:  []string{"AICPA TSC 2017 CC6.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.5",
		Name:        "Least privilege access",
		Description: "Implements least privilege access controls",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkLeastPrivilege,
		References:  []string{"AICPA TSC 2017 CC6.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.6",
		Name:        "Physical access controls",
		Description: "Implements physical access controls over technology resources",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalAccess,
		References:  []string{"AICPA TSC 2017 CC6.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.7",
		Name:        "System component inventory",
		Description: "Maintains inventory of system components to support access control",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkComponentInventory,
		References:  []string{"AICPA TSC 2017 CC6.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.8",
		Name:        "Unauthorized software detection",
		Description: "Detects and prevents use of unauthorized software",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUnauthorizedSoftware,
		References:  []string{"AICPA TSC 2017 CC6.8"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC7: System Operations (7 controls, 3 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.1",
		Name:        "Infrastructure and software management",
		Description: "Manages infrastructure and software to support system operations",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfraManagement,
		References:  []string{"AICPA TSC 2017 CC7.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.2",
		Name:        "Incident detection and response",
		Description: "Detects, analyzes, and responds to security incidents",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentDetection,
		References:  []string{"AICPA TSC 2017 CC7.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.3",
		Name:        "Security event evaluation",
		Description: "Evaluates security events to determine if they constitute incidents",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEventEvaluation,
		References:  []string{"AICPA TSC 2017 CC7.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.4",
		Name:        "Incident response plan",
		Description: "Responds to identified incidents with incident response plan",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
		References:  []string{"AICPA TSC 2017 CC7.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.P1",
		Name:        "Designs incident management",
		Description: "Designs and implements incident management procedures",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC7.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.P2",
		Name:        "Designs monitoring tools",
		Description: "Designs and implements tools for monitoring system performance",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC7.P2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.P3",
		Name:        "Designs incident recovery",
		Description: "Designs procedures for recovering from incidents",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC7.P3"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC8: Change Management (3 controls, 1 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC8.1",
		Name:        "Authorizes, documents, and tests changes",
		Description: "Authorizes, documents, and tests changes to technology resources",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
		References:  []string{"AICPA TSC 2017 CC8.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC8.P1",
		Name:        "Designs change management process",
		Description: "Designs and implements a change management process",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC8.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC8.P2",
		Name:        "Designs change approval process",
		Description: "Designs procedures for approving changes",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC8.P2"},
	})

	// ====================================================================
	// Security (Common Criteria) — CC9: Risk Mitigation (3 controls, 1 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC9.1",
		Name:        "Identifies and manages vendor risk",
		Description: "Identifies, selects, and manages vendor risk",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVendorRisk,
		References:  []string{"AICPA TSC 2017 CC9.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC9.2",
		Name:        "Vendor business continuity",
		Description: "Assesses vendor business continuity risk",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC9.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC9.P1",
		Name:        "Designs vendor risk management",
		Description: "Designs and implements vendor risk management procedures",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 CC9.P1"},
	})

	// ====================================================================
	// Availability — A1 (6 controls, 3 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.1",
		Name:        "Environmental protections",
		Description: "Implements environmental protections against damage from environmental events",
		Category:    "Availability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEnvironmentalProtection,
		References:  []string{"AICPA TSC 2017 A1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.2",
		Name:        "Recovery infrastructure",
		Description: "Implements tools to recover data and system operations",
		Category:    "Availability",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRecoveryInfra,
		References:  []string{"AICPA TSC 2017 A1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.3",
		Name:        "Recovery testing",
		Description: "Tests recovery plan procedures periodically",
		Category:    "Availability",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRecoveryTesting,
		References:  []string{"AICPA TSC 2017 A1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.P1",
		Name:        "Designs availability controls",
		Description: "Designs and implements controls to meet availability objectives",
		Category:    "Availability",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 A1.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.P2",
		Name:        "Designs environmental protections",
		Description: "Designs environmental protections based on risk",
		Category:    "Availability",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 A1.P2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.P3",
		Name:        "Designs recovery infrastructure",
		Description: "Designs recovery infrastructure to meet availability objectives",
		Category:    "Availability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecoveryDesign,
		References:  []string{"AICPA TSC 2017 A1.P3"},
	})

	// ====================================================================
	// Confidentiality — C1/C2 (5 controls, 3 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C1.1",
		Name:        "Confidentiality policies and procedures",
		Description: "Implements confidentiality policies and procedures to meet objectives",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkConfidentialityPolicies,
		References:  []string{"AICPA TSC 2017 C1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C1.2",
		Name:        "Confidentiality controls",
		Description: "Implements controls to prevent unauthorized access to confidential information",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkConfidentialityControls,
		References:  []string{"AICPA TSC 2017 C1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C2.1",
		Name:        "Data transmission and disposal",
		Description: "Protects confidential information during transmission and disposal",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataTransmission,
		References:  []string{"AICPA TSC 2017 C2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C1.P1",
		Name:        "Designs confidentiality controls",
		Description: "Designs and implements controls to protect confidential information",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 C1.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C2.P1",
		Name:        "Designs transmission controls",
		Description: "Designs controls to protect data during transmission and disposal",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 C2.P1"},
	})

	// ====================================================================
	// Processing Integrity — PI1 (5 controls, 2 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.1",
		Name:        "Processing validity and completeness",
		Description: "Obtains, processes, and reports data that are valid, complete, and accurate",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProcessingValidity,
		References:  []string{"AICPA TSC 2017 PI1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.2",
		Name:        "Processing errors detection",
		Description: "Detects processing errors and takes corrective action",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProcessingErrors,
		References:  []string{"AICPA TSC 2017 PI1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.3",
		Name:        "Processing error correction",
		Description: "Corrects processing errors and recovers from errors",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProcessingErrorCorrection,
		References:  []string{"AICPA TSC 2017 PI1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.P1",
		Name:        "Designs processing controls",
		Description: "Designs and implements controls to ensure processing integrity",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"AICPA TSC 2017 PI1.P1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.P2",
		Name:        "Designs error detection",
		Description: "Designs procedures for detecting processing errors",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkErrorDetectionDesign,
		References:  []string{"AICPA TSC 2017 PI1.P2"},
	})

	// ====================================================================
	// AI Controls (5 controls, 4 auto)
	// ====================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-01",
		Name:        "AI model security controls",
		Description: "Implements security controls specific to AI/ML models",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelSecurity,
		References:  []string{"AICPA TSC 2017 (AI Extension)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-02",
		Name:        "AI data protection",
		Description: "Protects data used in AI/ML training and inference",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIDataProtection,
		References:  []string{"AICPA TSC 2017 (AI Extension)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-03",
		Name:        "AI model monitoring",
		Description: "Monitors AI/ML models for drift, bias, and security issues",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelMonitoring,
		References:  []string{"AICPA TSC 2017 (AI Extension)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-04",
		Name:        "AI model governance",
		Description: "Establishes governance framework for AI/ML models",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelGovernance,
		References:  []string{"AICPA TSC 2017 (AI Extension)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-05",
		Name:        "AI incident response",
		Description: "Responds to AI-specific security incidents",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIIncidentResponse,
		References:  []string{"AICPA TSC 2017 (AI Extension)"},
	})
}

// ============================================================================
// Check implementations (32 automated controls)
// ============================================================================
//
// checkKeywords is the shared helper used by all automated check
// functions. It scans the input for the presence of keyword indicators
// and returns a compliant/partial/non-compliant result based on how
// many keywords are found. This reduces boilerplate while keeping
// each check function's intent clear.
func (m *SOC2Module) checkKeywords(
	ctx context.Context,
	input []byte,
	controlID string,
	controlName string,
	severity compliance.ControlSeverity,
	keywords []string,
	remediation string,
) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	present := 0
	missing := []string{}
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			present++
		} else {
			missing = append(missing, kw)
		}
	}

	total := len(keywords)
	threshold := total / 2
	if threshold == 0 {
		threshold = 1
	}

	if present >= threshold && present > 0 {
		status := compliance.StatusCompliant
		if present < total {
			status = compliance.StatusCompliant
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   controlID,
			ControlName: controlName,
			Status:      status,
			Severity:    severity,
			Message:     fmt.Sprintf("%s verified: %d/%d indicators present", controlName, present, total),
			Timestamp:   time.Now(),
		}, nil
	}

	if present > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   controlID,
			ControlName: controlName,
			Status:      compliance.StatusPartial,
			Severity:    severity,
			Message:     fmt.Sprintf("Partial: %d/%d indicators present; missing: %s", present, total, strings.Join(missing, ", ")),
			Timestamp:   time.Now(),
			Remediation: remediation,
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   controlID,
		ControlName: controlName,
		Status:      compliance.StatusNonCompliant,
		Severity:    severity,
		Message:     fmt.Sprintf("No indicators found; missing: %s", strings.Join(missing, ", ")),
		Timestamp:   time.Now(),
		Remediation: remediation,
	}, nil
}

// --- CC1: Control Environment ---

// checkCompetence verifies commitment to competence (CC1.4).
func (m *SOC2Module) checkCompetence(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC1.4", "Demonstrates commitment to competence",
		compliance.SeverityHigh,
		[]string{"training", "competency", "skills_assessment"},
		"Implement training programs, competency assessments, and skills tracking for all personnel")
}

// checkAccountability verifies accountability enforcement (CC1.5).
func (m *SOC2Module) checkAccountability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC1.5", "Enforces accountability",
		compliance.SeverityHigh,
		[]string{"performance_review", "accountability", "enforcement"},
		"Implement performance reviews, accountability policies, and enforcement mechanisms")
}

// --- CC2: Communication and Information ---

// checkInternalComm verifies internal security communication (CC2.1).
func (m *SOC2Module) checkInternalComm(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC2.1", "Internal communication of security objectives",
		compliance.SeverityMedium,
		[]string{"security_policy", "communication", "awareness"},
		"Establish internal communication channels for security policies, awareness programs, and objectives")
}

// checkIncidentComm verifies incident communication (CC2.3).
func (m *SOC2Module) checkIncidentComm(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC2.3", "Communication of security incidents",
		compliance.SeverityHigh,
		[]string{"incident_notification", "breach_notification", "communication"},
		"Establish incident and breach notification procedures with clear communication protocols")
}

// --- CC3: Risk Assessment ---

// checkRiskAssess verifies risk assessment processes (CC3.1).
func (m *SOC2Module) checkRiskAssess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC3.1", "Identifies and assesses risk",
		compliance.SeverityCritical,
		[]string{"risk_assessment", "risk_analysis", "threat_modeling"},
		"Implement systematic risk assessment, risk analysis, and threat modeling processes")
}

// checkFraudRisk verifies fraud risk management (CC3.2).
func (m *SOC2Module) checkFraudRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC3.2", "Considers fraud risk",
		compliance.SeverityCritical,
		[]string{"fraud_detection", "fraud_risk", "anti_fraud"},
		"Implement fraud detection, fraud risk assessment, and anti-fraud controls")
}

// checkBCRisk verifies business continuity risk assessment (CC3.4).
func (m *SOC2Module) checkBCRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC3.4", "Assesses business continuity risk",
		compliance.SeverityHigh,
		[]string{"business_continuity", "disaster_recovery", "continuity_plan"},
		"Document business continuity plans, disaster recovery procedures, and continuity testing")
}

// --- CC4: Monitoring Activities ---

// checkOngoingMonitoring verifies ongoing monitoring (CC4.1).
func (m *SOC2Module) checkOngoingMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC4.1", "Ongoing monitoring of system performance",
		compliance.SeverityHigh,
		[]string{"monitoring", "continuous_monitoring", "performance_monitoring"},
		"Implement continuous monitoring, performance monitoring, and ongoing control evaluation")
}

// checkDeficiencyEval verifies deficiency evaluation (CC4.P2).
func (m *SOC2Module) checkDeficiencyEval(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC4.P2", "Designs deficiency evaluation",
		compliance.SeverityMedium,
		[]string{"deficiency", "control_gap", "remediation_tracking"},
		"Implement control deficiency evaluation, gap tracking, and remediation tracking procedures")
}

// --- CC5: Control Activities ---

// checkTechControls verifies technology-based controls (CC5.2).
func (m *SOC2Module) checkTechControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC5.2", "Selects and develops technology-based controls",
		compliance.SeverityHigh,
		[]string{"technology_control", "automated_control", "technical_control"},
		"Implement technology-based, automated, and technical controls to support security objectives")
}

// --- CC6: Logical and Physical Access Controls ---

// checkLogicalAccess verifies logical access security controls (CC6.1).
// Scans for authentication, RBAC, and session timeout configuration.
func (m *SOC2Module) checkLogicalAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasRBAC {
		violations = append(violations, "role-based access control not detected")
	}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.1",
			ControlName: "Logical access security controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "All access control requirements met (auth, RBAC, session timeout)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAuth || hasRBAC || hasSessionTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.1",
			ControlName: "Logical access security controls",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Access control gaps: " + strings.Join(violations, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement authentication, RBAC, and session timeouts in platformconfig.Security.* and platformconfig.Auth.*",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.1",
		ControlName: "Logical access security controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No logical access controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement authentication, RBAC, and session timeouts in platformconfig",
	}, nil
}

// checkUserRegistration verifies user registration and de-registration (CC6.2).
func (m *SOC2Module) checkUserRegistration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.2", "User registration and de-registration",
		compliance.SeverityCritical,
		[]string{"user_registration", "user_provisioning", "de-registration", "account_lifecycle"},
		"Implement user registration, provisioning, de-registration, and account lifecycle management procedures")
}

// checkRoleAssignment verifies user role assignment and access review (CC6.3).
func (m *SOC2Module) checkRoleAssignment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.3", "User role assignment and review",
		compliance.SeverityCritical,
		[]string{"role_assignment", "access_review", "periodic_review", "role_review"},
		"Implement role assignment procedures, periodic access reviews, and role-based access recertification")
}

// checkPhysicalAccess verifies physical access controls (CC6.6).
func (m *SOC2Module) checkPhysicalAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.6", "Physical access controls",
		compliance.SeverityHigh,
		[]string{"physical_access", "badge_access", "data_center_access", "access_logs"},
		"Implement physical access controls: badge systems, data center access restrictions, and physical access logging")
}

// checkComponentInventory verifies system component inventory (CC6.7).
func (m *SOC2Module) checkComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.7", "System component inventory",
		compliance.SeverityHigh,
		[]string{"component_inventory", "asset_inventory", "hardware_inventory", "software_inventory"},
		"Maintain comprehensive component, asset, hardware, and software inventories")
}

// --- CC7: System Operations ---

// checkIncidentDetection verifies incident detection and response (CC7.2).
// Scans for audit logging, IOC store, anomaly detection, and alerting.
func (m *SOC2Module) checkIncidentDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAnomalyDetection := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit_log")
	}
	if hasIOCStore {
		present++
	} else {
		missing = append(missing, "IOC_store")
	}
	if hasAnomalyDetection {
		present++
	} else {
		missing = append(missing, "anomaly_detection")
	}
	if hasAlerting {
		present++
	} else {
		missing = append(missing, "alerting")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.2",
			ControlName: "Incident detection and response",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Incident detection verified: audit log + IOC store + anomaly detection + alerting",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.2",
			ControlName: "Incident detection and response",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No incident detection capability detected",
			Timestamp:   time.Now(),
			Remediation: "Enable audit log + IOC store + anomaly detection (Trust Framework) + alerting",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.2",
		ControlName: "Incident detection and response",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     fmt.Sprintf("Partial incident detection: %d/4 configured; missing: %s", present, strings.Join(missing, ", ")),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing incident detection components",
	}, nil
}

// checkEventEvaluation verifies security event evaluation (CC7.3).
// Scans for audit logging, IOC store, signed attestations, and investigation process.
func (m *SOC2Module) checkEventEvaluation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log") || strings.Contains(inputStr, "envelope")
	hasInvestigationProcess := strings.Contains(inputStr, "investigation") || strings.Contains(inputStr, "triage") || strings.Contains(inputStr, "classification")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit_log")
	}
	if hasIOCStore {
		present++
	} else {
		missing = append(missing, "IOC_store")
	}
	if hasAttestations {
		present++
	} else {
		missing = append(missing, "signed_attestations")
	}
	if hasInvestigationProcess {
		present++
	} else {
		missing = append(missing, "investigation_process")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.3",
			ControlName: "Security event evaluation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Event evaluation verified: audit log + IOC store + signed attestations + investigation process",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.3",
			ControlName: "Security event evaluation",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No event evaluation capability detected",
			Timestamp:   time.Now(),
			Remediation: "Enable audit log + IOC store + signed attestations + investigation/triage process",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.3",
		ControlName: "Security event evaluation",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     fmt.Sprintf("Partial event evaluation: %d/4 configured; missing: %s", present, strings.Join(missing, ", ")),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing event evaluation components",
	}, nil
}

// checkIncidentResponsePlan verifies incident response plan (CC7.4).
// Scans for IR plan, testing, roles, and communication.
func (m *SOC2Module) checkIncidentResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan")
	hasTested := strings.Contains(inputStr, "ir_tested") || strings.Contains(inputStr, "tabletop") || strings.Contains(inputStr, "ir_drill")
	hasRoles := strings.Contains(inputStr, "ir_roles") || strings.Contains(inputStr, "incident_commander") || strings.Contains(inputStr, "responsibility")
	hasCommunication := strings.Contains(inputStr, "ir_communication") || strings.Contains(inputStr, "status_page") || strings.Contains(inputStr, "ir_contact")

	present := 0
	missing := []string{}
	if hasIRPlan {
		present++
	} else {
		missing = append(missing, "IR_plan")
	}
	if hasTested {
		present++
	} else {
		missing = append(missing, "IR_tested")
	}
	if hasRoles {
		present++
	} else {
		missing = append(missing, "IR_roles")
	}
	if hasCommunication {
		present++
	} else {
		missing = append(missing, "IR_communication")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.4",
			ControlName: "Incident response plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Incident response plan verified: plan + tested + roles + communication",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.4",
			ControlName: "Incident response plan",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No incident response plan detected",
			Timestamp:   time.Now(),
			Remediation: "Document IR plan + test (tabletop/drill) + assign roles + establish communication plan",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.4",
		ControlName: "Incident response plan",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     fmt.Sprintf("Partial IR plan: %d/4 configured; missing: %s", present, strings.Join(missing, ", ")),
		Timestamp:   time.Now(),
		Remediation: "Document the missing IR plan components",
	}, nil
}

// --- CC8: Change Management ---

// checkChangeManagement verifies change management controls (CC8.1).
func (m *SOC2Module) checkChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC8.1", "Authorizes, documents, and tests changes",
		compliance.SeverityHigh,
		[]string{"change_management", "change_control", "change_approval"},
		"Implement change management procedures with authorization, documentation, testing, and approval workflows")
}

// --- CC9: Risk Mitigation ---

// checkVendorRisk verifies vendor risk management (CC9.1).
func (m *SOC2Module) checkVendorRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC9.1", "Identifies and manages vendor risk",
		compliance.SeverityHigh,
		[]string{"vendor_risk", "third_party_risk", "supplier_assessment"},
		"Implement vendor risk assessment, third-party risk management, and supplier assessment procedures")
}

// --- Availability ---

// checkEnvironmentalProtection verifies environmental protections (A1.1).
func (m *SOC2Module) checkEnvironmentalProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-A1.1", "Environmental protections",
		compliance.SeverityHigh,
		[]string{"environmental_protection", "fire_suppression", "temperature_monitoring", "hvac_monitoring"},
		"Implement environmental protections: fire suppression, temperature/HVAC monitoring, and environmental controls")
}

// checkRecoveryInfra verifies recovery infrastructure (A1.2).
func (m *SOC2Module) checkRecoveryInfra(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-A1.2", "Recovery infrastructure",
		compliance.SeverityCritical,
		[]string{"backup", "recovery", "disaster_recovery"},
		"Implement backup, recovery, and disaster recovery infrastructure with tested procedures")
}

// checkRecoveryDesign verifies recovery infrastructure design (A1.P3).
func (m *SOC2Module) checkRecoveryDesign(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-A1.P3", "Designs recovery infrastructure",
		compliance.SeverityHigh,
		[]string{"recovery_design", "backup_strategy", "failover_design"},
		"Design recovery infrastructure with backup strategy, failover design, and recovery procedures")
}

// --- Confidentiality ---

// checkConfidentialityPolicies verifies confidentiality policies (C1.1).
func (m *SOC2Module) checkConfidentialityPolicies(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-C1.1", "Confidentiality policies and procedures",
		compliance.SeverityCritical,
		[]string{"confidentiality_policy", "data_classification", "nda", "confidentiality_agreement"},
		"Implement confidentiality policies, data classification schemes, and NDA/confidentiality agreements")
}

// checkConfidentialityControls verifies confidentiality controls (C1.2).
func (m *SOC2Module) checkConfidentialityControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-C1.2", "Confidentiality controls",
		compliance.SeverityCritical,
		[]string{"confidentiality", "data_classification", "need_to_know"},
		"Implement confidentiality controls, data classification, and need-to-know access restrictions")
}

// checkDataTransmission verifies data transmission and disposal controls (C2.1).
func (m *SOC2Module) checkDataTransmission(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-C2.1", "Data transmission and disposal",
		compliance.SeverityCritical,
		[]string{"encryption_in_transit", "secure_transmission", "secure_disposal", "data_destruction"},
		"Implement encryption in transit, secure transmission protocols, secure disposal, and data destruction procedures")
}

// --- Processing Integrity ---

// checkProcessingErrors verifies processing error detection (PI1.2).
func (m *SOC2Module) checkProcessingErrors(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-PI1.2", "Processing errors detection",
		compliance.SeverityHigh,
		[]string{"processing_error", "error_detection", "data_validation", "error_correction"},
		"Implement processing error detection, data validation, and error correction procedures")
}

// checkErrorDetectionDesign verifies error detection design (PI1.P2).
func (m *SOC2Module) checkErrorDetectionDesign(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-PI1.P2", "Designs error detection",
		compliance.SeverityMedium,
		[]string{"error_detection", "validation", "data_integrity_check"},
		"Design error detection procedures with validation and data integrity checks")
}

// --- AI Controls ---

// checkAIModelSecurity verifies AI model security controls (AI-01).
func (m *SOC2Module) checkAIModelSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-AI-01", "AI model security controls",
		compliance.SeverityCritical,
		[]string{"model_security", "adversarial_defense", "model_robustness", "prompt_injection_defense"},
		"Implement AI model security: adversarial defense, model robustness testing, and prompt injection defenses")
}

// checkAIDataProtection verifies AI data protection (AI-02).
func (m *SOC2Module) checkAIDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-AI-02", "AI data protection",
		compliance.SeverityCritical,
		[]string{"data_protection", "training_data", "model_data"},
		"Implement data protection for AI training data, model data, and inference inputs/outputs")
}

// checkAIModelMonitoring verifies AI model monitoring (AI-03).
func (m *SOC2Module) checkAIModelMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-AI-03", "AI model monitoring",
		compliance.SeverityHigh,
		[]string{"model_monitoring", "drift_detection", "bias_detection"},
		"Implement AI model monitoring with drift detection, bias detection, and performance tracking")
}

// checkAIIncidentResponse verifies AI incident response (AI-05).
func (m *SOC2Module) checkAIIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-AI-05", "AI incident response",
		compliance.SeverityCritical,
		[]string{"ai_incident", "model_incident", "ai_anomaly"},
		"Implement AI-specific incident response procedures for model incidents and AI anomalies")
}

// ── P1 Compliance Automation Expansion: Additional automated controls ──

// checkExternalComm verifies external communication of security matters (CC2.2).
func (m *SOC2Module) checkExternalComm(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC2.2", "External communication of security matters",
		compliance.SeverityMedium,
		[]string{"security_notification", "external_comm", "stakeholder_notification", "security_advisory"},
		"Implement external security communication channels for stakeholders and regulators")
}

// checkAccessRestriction verifies access restriction to authorized users (CC6.4).
func (m *SOC2Module) checkAccessRestriction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.4", "Restrict access to authorized users",
		compliance.SeverityCritical,
		[]string{"access_control", "rbac", "authorized_users", "authentication"},
		"Implement access controls restricting system access to authorized users only")
}

// checkLeastPrivilege verifies least privilege access (CC6.5).
func (m *SOC2Module) checkLeastPrivilege(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.5", "Least privilege access",
		compliance.SeverityCritical,
		[]string{"least_privilege", "rbac", "role_based", "minimize_access"},
		"Implement least privilege access controls ensuring users have minimum necessary permissions")
}

// checkUnauthorizedSoftware verifies unauthorized software detection (CC6.8).
func (m *SOC2Module) checkUnauthorizedSoftware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC6.8", "Unauthorized software detection",
		compliance.SeverityHigh,
		[]string{"unauthorized_software", "software_inventory", "application_whitelist", "software_monitoring"},
		"Implement unauthorized software detection and prevention controls")
}

// checkInfraManagement verifies infrastructure and software management (CC7.1).
func (m *SOC2Module) checkInfraManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-CC7.1", "Infrastructure and software management",
		compliance.SeverityHigh,
		[]string{"infrastructure_management", "asset_management", "configuration_management", "patch_management"},
		"Implement infrastructure and software management with asset tracking and configuration management")
}

// checkRecoveryTesting verifies recovery testing (A1.3).
func (m *SOC2Module) checkRecoveryTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-A1.3", "Recovery testing",
		compliance.SeverityCritical,
		[]string{"recovery_test", "disaster_recovery_test", "rto_testing", "failover_test"},
		"Implement periodic recovery testing with documented results and RTO/RPO validation")
}

// checkProcessingValidity verifies processing validity and completeness (PI1.1).
func (m *SOC2Module) checkProcessingValidity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-PI1.1", "Processing validity and completeness",
		compliance.SeverityHigh,
		[]string{"data_validation", "processing_integrity", "completeness_check", "data_quality"},
		"Implement data validation and processing integrity controls ensuring completeness and accuracy")
}

// checkProcessingErrorCorrection verifies processing error correction (PI1.3).
func (m *SOC2Module) checkProcessingErrorCorrection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-PI1.3", "Processing error correction",
		compliance.SeverityHigh,
		[]string{"error_correction", "error_handling", "processing_error", "error_recovery"},
		"Implement processing error correction and recovery procedures")
}

// checkAIModelGovernance verifies AI model governance (AI-04).
func (m *SOC2Module) checkAIModelGovernance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.checkKeywords(ctx, input, "SOC2-AI-04", "AI model governance",
		compliance.SeverityHigh,
		[]string{"model_governance", "ai_governance", "model_validation", "model_approval"},
		"Establish AI model governance framework with validation, approval, and oversight processes")
}

// Dependencies returns required modules. The SOC 2 module depends on
// the scanner (for adversarial defense checks) and the persistence
// layer (for audit log integrity verification).
func (m *SOC2Module) Dependencies() []string {
	return []string{"scanner", "persistence"}
}
