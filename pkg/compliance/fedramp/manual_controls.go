// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Manual Controls (Customer Responsibility)
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Controls that are primarily process, policy,
// HR, or physical controls. AegisGate generates the technical evidence
// artifacts (audit logs, scan results, attestations) that customers
// attach to their FedRAMP A&A packages, but the controls themselves
// require customer documentation, training, or physical implementation.
//
// v3.6.0: 13 controls promoted from manual to automated in
// promoted_checkfuncs_v2.go (AC-8, AC-20, IA-9, IA-11, SC-40,
// IR-2, IR-3, SA-8, CP-3, CP-4, CP-6, CP-7, CP-8).
// 25 new controls added in promoted_checkfuncs_v2.go.
//
// Remaining 30 controls are genuinely customer-responsibility:
//   - Writing policies and procedures
//   - Managing personnel security
//   - Creating program management documentation
//
// AegisGate provides the evidence package that makes demonstrating
// compliance faster and more auditable.
//
// =========================================================================

package fedramp

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerManualControls wires the 30 remaining evidence-mapped controls
// that are genuinely the customer's responsibility (policy, procedure,
// HR, physical, program management). 13 controls were promoted to
// automated in v3.6.0 (promoted_checkfuncs_v2.go).
func (m *FedRAMPModule) registerManualControls() {
	// --- AC: Access Control (19 manual controls for remaining AC controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-1",
		Name:        "Access Control Policy and Procedures",
		Description: "FedRAMP AC-1: Organization develops, documents, and disseminates an access control policy. AegisGate generates RBAC policies, session logs, and access audit evidence for the customer's AC-1 documentation.",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-1", "FedRAMP Moderate AC-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-4",
		Name:        "Information Flow Enforcement",
		Description: "FedRAMP AC-4: Information flow enforcement between systems. AegisGate's protocol pillars (HTTP, MCP, A2A, ACP, ANP) enforce information flow boundaries. Customer documents the policy.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInfoFlowEnforcement,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-4", "FedRAMP Moderate AC-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-5",
		Name:        "Separation of Duties",
		Description: "FedRAMP AC-5: Separation of duties for conflicting responsibilities. AegisGate's RBAC supports role-based separation. Customer defines the duty assignments.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSeparationOfDuties,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-5", "FedRAMP Moderate AC-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-7",
		Name:        "Unsuccessful Login Attempts",
		Description: "FedRAMP AC-7: Enforces limits on unsuccessful login attempts. AegisGate's rate limiting and session management provide the enforcement evidence for AC-7.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkUnsuccessfulLogin,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-7", "FedRAMP Moderate AC-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-8",
		Name:        "System Use Notification",
		Description: "FedRAMP AC-8: System use notification before granting access. AegisGate's login banner and API authentication provide notification evidence for AC-8.",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSystemUseNotification,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-8", "FedRAMP Moderate AC-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-10",
		Name:        "Concurrent Session Control",
		Description: "FedRAMP AC-10: Limits concurrent sessions per account. AegisGate's session management enforces configurable session limits per user and role.",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkConcurrentSessionControl,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-10", "FedRAMP Moderate AC-10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-11",
		Name:        "Session Lock",
		Description: "FedRAMP AC-11: Session lock after inactivity. AegisGate's session timeout and idle timeout enforce session locks for AC-11.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionLock,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-11", "FedRAMP Moderate AC-11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-12",
		Name:        "Session Termination",
		Description: "FedRAMP AC-12: Automatic session termination. AegisGate's session management and Trust Framework EndSession provide termination evidence.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionTermination,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-12", "FedRAMP Moderate AC-12"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-20",
		Name:        "Use of External Systems",
		Description: "FedRAMP AC-20: Limits use of external systems. AegisGate's trust framework and capability contracts manage external system interactions for AC-20.",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkUseOfExternalSystems,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-20", "FedRAMP Moderate AC-20"},
	})

	// --- AU: Audit and Accountability (5 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-1",
		Name:        "Audit and Accountability Policy and Procedures",
		Description: "FedRAMP AU-1: Organization develops, documents, and disseminates an audit and accountability policy. AegisGate generates hash-chain audit logs as evidence for the customer's AU-1 documentation.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-1", "FedRAMP Moderate AU-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-4",
		Name:        "Audit Log Storage Capacity",
		Description: "FedRAMP AU-4: Audit log storage capacity defined and managed. AegisGate's persistence layer supports configurable retention periods (7-90 days by tier) for AU-4.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuditLogStorage,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-4", "FedRAMP Moderate AU-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-5",
		Name:        "Response to Audit Processing Failures",
		Description: "FedRAMP AU-5: Alert on audit processing failures. AegisGate's audit pipeline generates alerts for processing failures for AU-5.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkResponseToAuditFailures,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-5", "FedRAMP Moderate AU-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-7",
		Name:        "Audit Record Reduction and Report Generation",
		Description: "FedRAMP AU-7: Audit record reduction and report generation. AegisGate's audit search API (POST /api/v1/audit/search) provides this capability for AU-7.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuditRecordReduction,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-7", "FedRAMP Moderate AU-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-11",
		Name:        "Audit Log Retention",
		Description: "FedRAMP AU-11: Audit log retention period defined. AegisGate's per-tier retention (7 days Community, 30 Developer, 90 Professional, 365 Enterprise) provides AU-11 evidence.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuditLogRetention,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-11", "FedRAMP Moderate AU-11"},
	})

	// --- IA: Identification and Authentication (5 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-1",
		Name:        "Identification and Authentication Policy and Procedures",
		Description: "FedRAMP IA-1: Organization develops, documents, and disseminates an identification and authentication policy. AegisGate generates auth audit logs for the customer's IA-1 documentation.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-1", "FedRAMP Moderate IA-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-4",
		Name:        "Identifier Management",
		Description: "FedRAMP IA-4: Organization manages system identifiers. AegisGate's trust framework identity system provides unique per-agent identifiers for IA-4.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkIdentifierMgmt,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-4", "FedRAMP Moderate IA-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-9",
		Name:        "Identification and Authentication (Non-Organizational Users)",
		Description: "FedRAMP IA-9: Non-organizational users identified and authenticated. AegisGate's API key and token-based authentication for external users provides IA-9 evidence.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkNonOrganizationalUserAuth,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-9", "FedRAMP Moderate IA-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-10",
		Name:        "Identification and Authentication (Adversary Detection)",
		Description: "FedRAMP IA-10: Adversary identification. AegisGate's IOC store and anomaly detection detect adversary behavior.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAdversaryDetection,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-10", "FedRAMP Moderate IA-10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-11",
		Name:        "Re-Authentication",
		Description: "FedRAMP IA-11: Re-authentication for privileged actions. AegisGate's MFA enforcement for privileged operations provides IA-11 evidence.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkReAuthentication,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-11", "FedRAMP Moderate IA-11"},
	})

	// --- SC: System and Communications Protection (4 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-1",
		Name:        "System and Communications Protection Policy",
		Description: "FedRAMP SC-1: Organization develops, documents, and disseminates a system and communications protection policy. AegisGate generates TLS, boundary, and encryption evidence for SC-1 documentation.",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-1", "FedRAMP Moderate SC-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-6",
		Name:        "Protection of Information at System Boundaries",
		Description: "FedRAMP SC-6: Protection of information at system boundaries. AegisGate's 5 protocol pillars enforce boundary protection between trust zones.",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkBoundaryProtectionSC6,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-6", "FedRAMP Moderate SC-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-22",
		Name:        "Fail-Safe Network",
		Description: "FedRAMP SC-22: Fail-safe network communications. AegisGate's fail-closed security architecture (default-deny) verifies fail-safe behavior.",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkFailSafeNetwork,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-22", "FedRAMP Moderate SC-22"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-40",
		Name:        "Wireless Link Protection",
		Description: "FedRAMP SC-40: Wireless link protection. AegisGate's TLS 1.2+ requirement for all communications (including wireless) provides SC-40 evidence.",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkWirelessLinkProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-40", "FedRAMP Moderate SC-40"},
	})

	// --- IR: Incident Response (5 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-1",
		Name:        "Incident Response Policy and Procedures",
		Description: "FedRAMP IR-1: Organization develops, documents, and disseminates an incident response policy. AegisGate's incident engine and playbook execution provide evidence for IR-1 documentation.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-1", "FedRAMP Moderate IR-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-2",
		Name:        "Incident Response Training",
		Description: "FedRAMP IR-2: Incident response training for personnel. AegisGate's incident playbooks and SOC timeline provide training content for IR-2.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkIRTraining,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-2", "FedRAMP Moderate IR-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-3",
		Name:        "Incident Response Testing",
		Description: "FedRAMP IR-3: Incident response testing. AegisGate's adversarial benchmark suite and incident playbooks provide testing infrastructure for IR-3.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkIRTesting,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-3", "FedRAMP Moderate IR-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-10",
		Name:        "Incident Response Integration",
		Description: "FedRAMP IR-10: Integration of incident response with other organizational functions. AegisGate's SIEM dispatcher provides automated IR integration.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkIRIntegration,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-10", "FedRAMP Moderate IR-10"},
	})

	// --- SA: System and Services Acquisition (2 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-1",
		Name:        "System and Services Acquisition Policy",
		Description: "FedRAMP SA-1: Organization develops, documents, and disseminates a system and services acquisition policy. AegisGate generates AIBOM and supply chain evidence for SA-1 documentation.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-1", "FedRAMP Moderate SA-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-8",
		Name:        "Security Engineering Principles",
		Description: "FedRAMP SA-8: Security engineering principles applied in system development. AegisGate's fail-closed architecture, STRIDE threat model, and secure-by-design principles provide SA-8 evidence.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityEngineeringPrinciples,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-8", "FedRAMP Moderate SA-08"},
	})

	// --- CM: Configuration Management (4 manual controls for remaining CM controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-1",
		Name:        "Configuration Management Policy",
		Description: "FedRAMP CM-1: Organization develops, documents, and disseminates a configuration management policy. AegisGate generates config audit and CCM evidence for CM-1 documentation.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-1", "FedRAMP Moderate CM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-4",
		Name:        "Security Impact Analysis",
		Description: "FedRAMP CM-4: Security impact analysis for changes. AegisGate's CCM drift detection and compliance scan comparison provide impact analysis evidence for CM-4.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigMgmtImpactAnalysis,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-4", "FedRAMP Moderate CM-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-9",
		Name:        "Configuration Management Plan",
		Description: "FedRAMP CM-9: Configuration management plan developed and maintained. AegisGate's platform configuration subsystem provides the CM baseline.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkConfigurationManagementPlan,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-9", "FedRAMP Moderate CM-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-11",
		Name:        "Software Installation Restrictions",
		Description: "FedRAMP CM-11: Software installation restricted by policy. AegisGate's admin-only configuration and RBAC enforce installation restrictions.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSoftwareInstallationRestrictions,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-11", "FedRAMP Moderate CM-11"},
	})

	// --- RA: Risk Assessment (1 manual control) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-1",
		Name:        "Risk Assessment Policy",
		Description: "FedRAMP RA-1: Organization develops, documents, and disseminates a risk assessment policy. AegisGate generates compliance scan and threat model evidence for RA-1 documentation.",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-1", "FedRAMP Moderate RA-01"},
	})

	// --- CP: Contingency Planning (5 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-3",
		Name:        "Contingency Training",
		Description: "FedRAMP CP-3: Contingency training for personnel. AegisGate's incident playbooks and SOC timeline provide training content for CP-3.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkContingencyTraining,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-3", "FedRAMP Moderate CP-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-4",
		Name:        "Contingency Plan Testing",
		Description: "FedRAMP CP-4: Contingency plan testing. AegisGate's benchmark suite and incident playbooks can be used for contingency testing exercises.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkContingencyPlanTesting,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-4", "FedRAMP Moderate CP-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-6",
		Name:        "Alternate Storage Site",
		Description: "FedRAMP CP-6: Alternate storage site for backup. AegisGate's persistence layer supports PostgreSQL replication for CP-6 evidence.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAlternateStorageSite,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-6", "FedRAMP Moderate CP-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-7",
		Name:        "Alternate Processing Site",
		Description: "FedRAMP CP-7: Alternate processing site for system recovery. Customer is responsible for alternate site; AegisGate's self-hosted single-binary architecture supports rapid deployment at any site.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAlternateProcessingSite,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-7", "FedRAMP Moderate CP-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-8",
		Name:        "Telecommunications Services",
		Description: "FedRAMP CP-8: Telecommunications services for contingency operations. Customer is responsible for telecom redundancy; AegisGate supports multiple API endpoints for CP-8.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkTelecomServices,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-8", "FedRAMP Moderate CP-08"},
	})

	// --- PS: Personnel Security (3 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PS-1",
		Name:        "Personnel Security Policy",
		Description: "FedRAMP PS-1: Organization develops, documents, and disseminates a personnel security policy. Customer is responsible for HR processes; AegisGate generates RBAC evidence for PS-1.",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PS-1", "FedRAMP Moderate PS-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PS-2",
		Name:        "Position Risk Designation",
		Description: "FedRAMP PS-2: Position risk designation for all positions. Customer is responsible for position categorization; AegisGate's RBAC role assignments provide technical position mapping.",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PS-2", "FedRAMP Moderate PS-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PS-3",
		Name:        "Personnel Screening",
		Description: "FedRAMP PS-3: Personnel screening before granting access. Customer is responsible for background checks; AegisGate's RBAC and MFA enforcement provide technical access controls for PS-3.",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PS-3", "FedRAMP Moderate PS-03"},
	})

	// --- PM: Program Management (2 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PM-1",
		Name:        "Information Security Program Plan",
		Description: "FedRAMP PM-1: Organization develops and implements an information security program plan. Customer is responsible for the program plan; AegisGate generates compliance scan evidence across all frameworks for PM-1.",
		Category:    "Program Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PM-1", "FedRAMP Moderate PM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PM-14",
		Name:        "Security and Privacy Personnel",
		Description: "FedRAMP PM-14: Security and privacy personnel at all levels. Customer is responsible for staffing; AegisGate generates role-based access evidence for PM-14.",
		Category:    "Program Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PM-14", "FedRAMP Moderate PM-14"},
	})

	// --- PL: Planning (2 manual controls) ---
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PL-1",
		Name:        "Security Planning Policy",
		Description: "FedRAMP PL-1: Organization develops, documents, and disseminates a security planning policy. Customer is responsible for the policy; AegisGate generates threat model and compliance evidence for PL-1.",
		Category:    "Planning",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PL-1", "FedRAMP Moderate PL-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PL-2",
		Name:        "System Security Plan",
		Description: "FedRAMP PL-2: System security plan developed and maintained. Customer is responsible for the SSP; AegisGate generates the technical evidence (scan results, attestations, IOC store) for the customer's PL-2 SSP.",
		Category:    "Planning",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PL-2", "FedRAMP Moderate PL-02"},
	})
}
