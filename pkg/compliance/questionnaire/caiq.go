// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CAIQ (Consensus Assessments Initiative
// Questionnaire) Question Bank
// =========================================================================
//
// caiq.go defines the CAIQ question bank with 150+ questions across 5
// categories: Cloud Security, Compliance, Data Privacy, Incident
// Response, and Risk Management. These questions align with the
// Cloud Security Alliance (CSA) CAIQ v4 framework and are used for
// cloud vendor assessments.
//
// Each question has an ID (CAIQ-XXX-NNN format), category, and
// question text. Answers are populated at runtime by the
// QuestionnaireEngine based on compliance scan results.
//
// Reference: Cloud Security Alliance CAIQ v4.0.1
//
// =========================================================================

package questionnaire

// buildCAIQBank constructs the full CAIQ question bank with 150 questions
// across 5 categories: Cloud Security (35), Compliance (30), Data Privacy (30),
// Incident Response (30), and Risk Management (25).
func buildCAIQBank() []Question {
	questions := make([]Question, 0, 150)

	// ================================================================
	// Cloud Security (CAIQ-CS-001 through CAIQ-CS-035) — 35 questions
	// ================================================================
	cloudSecurityQuestions := []Question{
		{ID: "CAIQ-CS-001", Category: "Cloud Security", Text: "Are all user accounts required to use multi-factor authentication (MFA) for cloud service access?"},
		{ID: "CAIQ-CS-002", Category: "Cloud Security", Text: "Is role-based access control (RBAC) implemented to enforce the principle of least privilege?"},
		{ID: "CAIQ-CS-003", Category: "Cloud Security", Text: "Are IAM policies reviewed and updated on a regular schedule?"},
		{ID: "CAIQ-CS-004", Category: "Cloud Security", Text: "Are dormant or unused cloud accounts disabled within a defined time period?"},
		{ID: "CAIQ-CS-005", Category: "Cloud Security", Text: "Is data at rest encrypted using AES-256 or equivalent encryption in all cloud storage services?"},
		{ID: "CAIQ-CS-006", Category: "Cloud Security", Text: "Is data in transit encrypted using TLS 1.2 or higher for all cloud communications?"},
		{ID: "CAIQ-CS-007", Category: "Cloud Security", Text: "Are customer-managed encryption keys (BYOK/CMEK) supported?"},
		{ID: "CAIQ-CS-008", Category: "Cloud Security", Text: "Is a web application firewall (WAF) deployed for all internet-facing cloud applications?"},
		{ID: "CAIQ-CS-009", Category: "Cloud Security", Text: "Are network security groups (NSGs) or equivalent firewall rules configured to restrict inbound and outbound traffic?"},
		{ID: "CAIQ-CS-010", Category: "Cloud Security", Text: "Is network segmentation implemented to isolate workloads and environments?"},
		{ID: "CAIQ-CS-011", Category: "Cloud Security", Text: "Are vulnerability scans performed regularly on cloud infrastructure and applications?"},
		{ID: "CAIQ-CS-012", Category: "Cloud Security", Text: "Is container image security scanning performed before deployment to production?"},
		{ID: "CAIQ-CS-013", Category: "Cloud Security", Text: "Are cloud resources tagged and organized following a defined naming and tagging convention?"},
		{ID: "CAIQ-CS-014", Category: "Cloud Security", Text: "Is infrastructure-as-code (IaC) used for provisioning cloud resources?"},
		{ID: "CAIQ-CS-015", Category: "Cloud Security", Text: "Are IaC templates scanned for security misconfigurations before deployment?"},
		{ID: "CAIQ-CS-016", Category: "Cloud Security", Text: "Are cloud security posture management (CSPM) tools deployed to detect misconfigurations?"},
		{ID: "CAIQ-CS-017", Category: "Cloud Security", Text: "Is privileged access to cloud management consoles monitored and logged?"},
		{ID: "CAIQ-CS-018", Category: "Cloud Security", Text: "Are cloud API keys rotated on a regular schedule?"},
		{ID: "CAIQ-CS-019", Category: "Cloud Security", Text: "Is a secrets management solution used for storing and distributing cloud credentials?"},
		{ID: "CAIQ-CS-020", Category: "Cloud Security", Text: "Are cloud audit logs enabled for all services and retained for a minimum of 12 months?"},
		{ID: "CAIQ-CS-021", Category: "Cloud Security", Text: "Is a SIEM or equivalent log aggregation solution used for cloud security monitoring?"},
		{ID: "CAIQ-CS-022", Category: "Cloud Security", Text: "Are endpoint detection and response (EDR) solutions deployed on all compute instances?"},
		{ID: "CAIQ-CS-023", Category: "Cloud Security", Text: "Are security patches applied to cloud infrastructure within defined SLA timelines?"},
		{ID: "CAIQ-CS-024", Category: "Cloud Security", Text: "Is database encryption (TDE or equivalent) enabled for all managed databases?"},
		{ID: "CAIQ-CS-025", Category: "Cloud Security", Text: "Are cloud storage buckets and containers configured with appropriate access controls?"},
		{ID: "CAIQ-CS-026", Category: "Cloud Security", Text: "Is cloud resource deletion protection enabled for critical resources?"},
		{ID: "CAIQ-CS-027", Category: "Cloud Security", Text: "Are cloud-native security services (e.g., GuardDuty, Security Center) enabled?"},
		{ID: "CAIQ-CS-028", Category: "Cloud Security", Text: "Is mutual TLS (mTLS) used for service-to-service communication within the cloud environment?"},
		{ID: "CAIQ-CS-029", Category: "Cloud Security", Text: "Are cloud workloads protected by runtime security controls?"},
		{ID: "CAIQ-CS-030", Category: "Cloud Security", Text: "Is DNS query logging enabled for cloud environments?"},
		{ID: "CAIQ-CS-031", Category: "Cloud Security", Text: "Are cloud network flow logs enabled and monitored?"},
		{ID: "CAIQ-CS-032", Category: "Cloud Security", Text: "Is automated remediation configured for critical security misconfigurations?"},
		{ID: "CAIQ-CS-033", Category: "Cloud Security", Text: "Are cloud service health events monitored and integrated with incident alerting?"},
		{ID: "CAIQ-CS-034", Category: "Cloud Security", Text: "Is single sign-on (SSO) integrated with cloud service authentication?"},
		{ID: "CAIQ-CS-035", Category: "Cloud Security", Text: "Are conditional access policies enforced for cloud resource access?"},
	}
	questions = append(questions, cloudSecurityQuestions...)

	// ================================================================
	// Compliance (CAIQ-CMP-001 through CAIQ-CMP-030) — 30 questions
	// ================================================================
	complianceQuestions := []Question{
		{ID: "CAIQ-CMP-001", Category: "Compliance", Text: "Is a compliance framework (e.g., SOC 2, ISO 27001, PCI-DSS) adopted and maintained?"},
		{ID: "CAIQ-CMP-002", Category: "Compliance", Text: "Are compliance controls mapped to regulatory requirements and continuously monitored?"},
		{ID: "CAIQ-CMP-003", Category: "Compliance", Text: "Are audit trails maintained for all compliance-relevant activities?"},
		{ID: "CAIQ-CMP-004", Category: "Compliance", Text: "Are external audits conducted by qualified third parties at least annually?"},
		{ID: "CAIQ-CMP-005", Category: "Compliance", Text: "Are internal audits performed to assess compliance posture between external audits?"},
		{ID: "CAIQ-CMP-006", Category: "Compliance", Text: "Are compliance findings tracked to remediation with defined owners and timelines?"},
		{ID: "CAIQ-CMP-007", Category: "Compliance", Text: "Is regulatory reporting automated and delivered within required timelines?"},
		{ID: "CAIQ-CMP-008", Category: "Compliance", Text: "Are policies and procedures reviewed and updated at least annually?"},
		{ID: "CAIQ-CMP-009", Category: "Compliance", Text: "Is change management enforced for all production changes with documented approvals?"},
		{ID: "CAIQ-CMP-010", Category: "Compliance", Text: "Are third-party vendors assessed for compliance before onboarding and reviewed annually?"},
		{ID: "CAIQ-CMP-011", Category: "Compliance", Text: "Are compliance training programs provided to all employees upon hire and annually thereafter?"},
		{ID: "CAIQ-CMP-012", Category: "Compliance", Text: "Is a compliance officer or team designated with authority and accountability?"},
		{ID: "CAIQ-CMP-013", Category: "Compliance", Text: "Are compliance exceptions documented, risk-assessed, and approved by appropriate management?"},
		{ID: "CAIQ-CMP-014", Category: "Compliance", Text: "Is there a formal process for monitoring changes in applicable regulations and standards?"},
		{ID: "CAIQ-CMP-015", Category: "Compliance", Text: "Are cloud services and infrastructure compliant with regional data residency requirements?"},
		{ID: "CAIQ-CMP-016", Category: "Compliance", Text: "Is continuous compliance monitoring implemented with automated drift detection?"},
		{ID: "CAIQ-CMP-017", Category: "Compliance", Text: "Are SOC 2 Type II reports made available to customers upon request?"},
		{ID: "CAIQ-CMP-018", Category: "Compliance", Text: "Are data processing agreements (DPAs) executed with all customers and subprocessors?"},
		{ID: "CAIQ-CMP-019", Category: "Compliance", Text: "Is there a documented information security policy approved by senior management?"},
		{ID: "CAIQ-CMP-020", Category: "Compliance", Text: "Are acceptable use policies (AUP) defined and enforced for all system users?"},
		{ID: "CAIQ-CMP-021", Category: "Compliance", Text: "Are background checks performed on employees with access to sensitive data?"},
		{ID: "CAIQ-CMP-022", Category: "Compliance", Text: "Are security clearances verified and maintained for personnel in trusted roles?"},
		{ID: "CAIQ-CMP-023", Category: "Compliance", Text: "Is there a documented process for handling compliance violations and disciplinary actions?"},
		{ID: "CAIQ-CMP-024", Category: "Compliance", Text: "Are evidence repositories maintained with version control for audit readiness?"},
		{ID: "CAIQ-CMP-025", Category: "Compliance", Text: "Is there a formal risk acceptance process for exceptions to compliance requirements?"},
		{ID: "CAIQ-CMP-026", Category: "Compliance", Text: "Are cloud compliance benchmarks (CIS, etc.) continuously assessed?"},
		{ID: "CAIQ-CMP-027", Category: "Compliance", Text: "Are incident response and compliance processes integrated to ensure regulatory reporting?"},
		{ID: "CAIQ-CMP-028", Category: "Compliance", Text: "Is asset inventory maintained and reconciled with compliance scope?"},
		{ID: "CAIQ-CMP-029", Category: "Compliance", Text: "Are cloud service configurations validated against compliance benchmarks on a continuous basis?"},
		{ID: "CAIQ-CMP-030", Category: "Compliance", Text: "Is a compliance dashboard available to management for real-time visibility?"},
	}
	questions = append(questions, complianceQuestions...)

	// ================================================================
	// Data Privacy (CAIQ-DP-001 through CAIQ-DP-030) — 30 questions
	// ================================================================
	dataPrivacyQuestions := []Question{
		{ID: "CAIQ-DP-001", Category: "Data Privacy", Text: "Is a comprehensive privacy policy published and updated at least annually?"},
		{ID: "CAIQ-DP-002", Category: "Data Privacy", Text: "Is explicit consent obtained from data subjects before collecting personal data?"},
		{ID: "CAIQ-DP-003", Category: "Data Privacy", Text: "Are data subject access requests (DSARs) processed within regulatory timeframes?"},
		{ID: "CAIQ-DP-004", Category: "Data Privacy", Text: "Is the right to erasure (right to be forgotten) supported with verified deletion procedures?"},
		{ID: "CAIQ-DP-005", Category: "Data Privacy", Text: "Are Data Protection Impact Assessments (DPIAs) performed for high-risk processing?"},
		{ID: "CAIQ-DP-006", Category: "Data Privacy", Text: "Is a Data Protection Officer (DPO) or privacy lead designated?"},
		{ID: "CAIQ-DP-007", Category: "Data Privacy", Text: "Are data retention policies defined for all categories of personal data?"},
		{ID: "CAIQ-DP-008", Category: "Data Privacy", Text: "Are automated data deletion controls implemented to enforce retention policies?"},
		{ID: "CAIQ-DP-009", Category: "Data Privacy", Text: "Is data classification applied to identify and protect personal data?"},
		{ID: "CAIQ-DP-010", Category: "Data Privacy", Text: "Is data masking or pseudonymization applied in development and testing environments?"},
		{ID: "CAIQ-DP-011", Category: "Data Privacy", Text: "Are cross-border data transfers governed by appropriate legal safeguards (SCCs, BCRs)?"},
		{ID: "CAIQ-DP-012", Category: "Data Privacy", Text: "Are data processing agreements executed with all subprocessors?"},
		{ID: "CAIQ-DP-013", Category: "Data Privacy", Text: "Is data minimization practiced — only collecting data necessary for the stated purpose?"},
		{ID: "CAIQ-DP-014", Category: "Data Privacy", Text: "Are privacy breach notification procedures in place that meet regulatory timelines?"},
		{ID: "CAIQ-DP-015", Category: "Data Privacy", Text: "Is privacy by design integrated into the software development lifecycle?"},
		{ID: "CAIQ-DP-016", Category: "Data Privacy", Text: "Are privacy impact assessments conducted before deploying new features or services?"},
		{ID: "CAIQ-DP-017", Category: "Data Privacy", Text: "Is there a process for handling and resolving privacy complaints from data subjects?"},
		{ID: "CAIQ-DP-018", Category: "Data Privacy", Text: "Are employees trained on data privacy obligations and handling procedures?"},
		{ID: "CAIQ-DP-019", Category: "Data Privacy", Text: "Are records of processing activities (ROPA) maintained as required by GDPR?"},
		{ID: "CAIQ-DP-020", Category: "Data Privacy", Text: "Is consent management implemented with verifiable records of consent?"},
		{ID: "CAIQ-DP-021", Category: "Data Privacy", Text: "Are cookie consent mechanisms implemented in compliance with ePrivacy regulations?"},
		{ID: "CAIQ-DP-022", Category: "Data Privacy", Text: "Is data portability supported in a machine-readable format?"},
		{ID: "CAIQ-DP-023", Category: "Data Privacy", Text: "Are privacy notices provided at the point of data collection?"},
		{ID: "CAIQ-DP-024", Category: "Data Privacy", Text: "Is special category data (health, biometric, etc.) subject to enhanced protection controls?"},
		{ID: "CAIQ-DP-025", Category: "Data Privacy", Text: "Are data subject rights (access, rectification, erasure, portability, objection) documented and operationalized?"},
		{ID: "CAIQ-DP-026", Category: "Data Privacy", Text: "Are automated decision-making and profiling disclosed to data subjects with opt-out options?"},
		{ID: "CAIQ-DP-027", Category: "Data Privacy", Text: "Is data anonymization applied where feasible to reduce privacy risk?"},
		{ID: "CAIQ-DP-028", Category: "Data Privacy", Text: "Are privacy governance metrics reported to senior management on a regular basis?"},
		{ID: "CAIQ-DP-029", Category: "Data Privacy", Text: "Are third-party data processors contractually obligated to maintain equivalent privacy standards?"},
		{ID: "CAIQ-DP-030", Category: "Data Privacy", Text: "Is data privacy compliance validated through regular internal and external assessments?"},
	}
	questions = append(questions, dataPrivacyQuestions...)

	// ================================================================
	// Incident Response (CAIQ-IR-001 through CAIQ-IR-030) — 30 questions
	// ================================================================
	incidentResponseQuestions := []Question{
		{ID: "CAIQ-IR-001", Category: "Incident Response", Text: "Is a documented incident response plan in place and approved by senior management?"},
		{ID: "CAIQ-IR-002", Category: "Incident Response", Text: "Are incident response roles and responsibilities clearly defined and communicated?"},
		{ID: "CAIQ-IR-003", Category: "Incident Response", Text: "Is there a dedicated incident response team with on-call rotation?"},
		{ID: "CAIQ-IR-004", Category: "Incident Response", Text: "Are security incidents classified by severity with defined SLAs for response?"},
		{ID: "CAIQ-IR-005", Category: "Incident Response", Text: "Is an automated alerting system in place for security event detection?"},
		{ID: "CAIQ-IR-006", Category: "Incident Response", Text: "Is a SIEM or equivalent solution deployed for log aggregation and threat detection?"},
		{ID: "CAIQ-IR-007", Category: "Incident Response", Text: "Are incident communication plans defined for internal and external stakeholders?"},
		{ID: "CAIQ-IR-008", Category: "Incident Response", Text: "Is there a process for notifying customers and regulators of security breaches?"},
		{ID: "CAIQ-IR-009", Category: "Incident Response", Text: "Are forensic analysis capabilities available for incident investigation?"},
		{ID: "CAIQ-IR-010", Category: "Incident Response", Text: "Are post-incident reviews conducted to identify root causes and improvement opportunities?"},
		{ID: "CAIQ-IR-011", Category: "Incident Response", Text: "Are lessons learned from incidents incorporated into updated response procedures?"},
		{ID: "CAIQ-IR-012", Category: "Incident Response", Text: "Are incident response procedures tested through tabletop exercises at least annually?"},
		{ID: "CAIQ-IR-013", Category: "Incident Response", Text: "Are incident response procedures tested through live simulation exercises?"},
		{ID: "CAIQ-IR-014", Category: "Incident Response", Text: "Is there a defined escalation path for incidents that exceed team capacity or severity thresholds?"},
		{ID: "CAIQ-IR-015", Category: "Incident Response", Text: "Are incident response metrics (MTTD, MTTR) tracked and reported?"},
		{ID: "CAIQ-IR-016", Category: "Incident Response", Text: "Is there a process for preserving and collecting digital evidence during incidents?"},
		{ID: "CAIQ-IR-017", Category: "Incident Response", Text: "Are incident response tools (EDR, SIEM, forensic tools) regularly tested and updated?"},
		{ID: "CAIQ-IR-018", Category: "Incident Response", Text: "Is there a coordination process with law enforcement for criminal incidents?"},
		{ID: "CAIQ-IR-019", Category: "Incident Response", Text: "Are third-party incident response retainer agreements in place?"},
		{ID: "CAIQ-IR-020", Category: "Incident Response", Text: "Is there a process for managing public relations during significant security incidents?"},
		{ID: "CAIQ-IR-021", Category: "Incident Response", Text: "Are incident response procedures aligned with business continuity plans?"},
		{ID: "CAIQ-IR-022", Category: "Incident Response", Text: "Is threat intelligence integrated into incident detection and response processes?"},
		{ID: "CAIQ-IR-023", Category: "Incident Response", Text: "Are security logs retained for a minimum of 12 months for incident investigation?"},
		{ID: "CAIQ-IR-024", Category: "Incident Response", Text: "Is there a process for sharing incident indicators of compromise (IOCs) with trusted partners?"},
		{ID: "CAIQ-IR-025", Category: "Incident Response", Text: "Are incident response playbooks documented for common incident types?"},
		{ID: "CAIQ-IR-026", Category: "Incident Response", Text: "Is there a process for tracking and managing vulnerabilities discovered during incidents?"},
		{ID: "CAIQ-IR-027", Category: "Incident Response", Text: "Are automated remediation workflows configured for known incident patterns?"},
		{ID: "CAIQ-IR-028", Category: "Incident Response", Text: "Is there a defined process for declaring and managing major incidents?"},
		{ID: "CAIQ-IR-029", Category: "Incident Response", Text: "Are incident response capabilities covered in cyber insurance policies?"},
		{ID: "CAIQ-IR-030", Category: "Incident Response", Text: "Are incident response procedures reviewed and updated after each significant incident?"},
	}
	questions = append(questions, incidentResponseQuestions...)

	// ================================================================
	// Risk Management (CAIQ-RM-001 through CAIQ-RM-025) — 25 questions
	// ================================================================
	riskManagementQuestions := []Question{
		{ID: "CAIQ-RM-001", Category: "Risk Management", Text: "Is a formal risk management framework (e.g., NIST RMF, ISO 31000) adopted and maintained?"},
		{ID: "CAIQ-RM-002", Category: "Risk Management", Text: "Are risk assessments performed at least annually and upon significant changes?"},
		{ID: "CAIQ-RM-003", Category: "Risk Management", Text: "Is a risk register maintained with identified risks, likelihood, impact, and mitigation plans?"},
		{ID: "CAIQ-RM-004", Category: "Risk Management", Text: "Are third-party vendor risks assessed before onboarding and reviewed at least annually?"},
		{ID: "CAIQ-RM-005", Category: "Risk Management", Text: "Are risk acceptance decisions documented and approved by appropriate management?"},
		{ID: "CAIQ-RM-006", Category: "Risk Management", Text: "Is threat modeling performed for critical systems and applications?"},
		{ID: "CAIQ-RM-007", Category: "Risk Management", Text: "Are business continuity and disaster recovery plans aligned with risk assessment findings?"},
		{ID: "CAIQ-RM-008", Category: "Risk Management", Text: "Are risk mitigation strategies reviewed for effectiveness on a regular schedule?"},
		{ID: "CAIQ-RM-009", Category: "Risk Management", Text: "Is risk appetite defined and communicated by senior management?"},
		{ID: "CAIQ-RM-010", Category: "Risk Management", Text: "Are residual risks tracked and reported to senior management?"},
		{ID: "CAIQ-RM-011", Category: "Risk Management", Text: "Are supply chain and third-party risks included in the risk management program?"},
		{ID: "CAIQ-RM-012", Category: "Risk Management", Text: "Are emerging risks (technology, regulatory, geopolitical) monitored and assessed?"},
		{ID: "CAIQ-RM-013", Category: "Risk Management", Text: "Are risk assessment methodologies consistent and repeatable across the organization?"},
		{ID: "CAIQ-RM-014", Category: "Risk Management", Text: "Is there a process for escalating high and critical risks to executive management?"},
		{ID: "CAIQ-RM-015", Category: "Risk Management", Text: "Are key risk indicators (KRIs) defined, monitored, and reported?"},
		{ID: "CAIQ-RM-016", Category: "Risk Management", Text: "Are insurance coverages (cyber liability, E&O) aligned with the risk profile?"},
		{ID: "CAIQ-RM-017", Category: "Risk Management", Text: "Are risk findings and mitigation status reported to the board or risk committee?"},
		{ID: "CAIQ-RM-018", Category: "Risk Management", Text: "Is there a process for managing and mitigating cloud-specific risks?"},
		{ID: "CAIQ-RM-019", Category: "Risk Management", Text: "Are quantitative risk analysis methods used in addition to qualitative assessments?"},
		{ID: "CAIQ-RM-020", Category: "Risk Management", Text: "Is there a formal exception management process for risk acceptances?"},
		{ID: "CAIQ-RM-021", Category: "Risk Management", Text: "Are regulatory and compliance risks included in the enterprise risk register?"},
		{ID: "CAIQ-RM-022", Category: "Risk Management", Text: "Are risk scenarios tested through tabletop exercises or simulations?"},
		{ID: "CAIQ-RM-023", Category: "Risk Management", Text: "Is there a process for continuous monitoring and real-time risk assessment?"},
		{ID: "CAIQ-RM-024", Category: "Risk Management", Text: "Are risk management policies and procedures reviewed and updated annually?"},
		{ID: "CAIQ-RM-025", Category: "Risk Management", Text: "Are risk management metrics and dashboards available for executive reporting?"},
	}
	questions = append(questions, riskManagementQuestions...)

	return questions
}
