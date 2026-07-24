// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SIG (Standardized Information Gathering)
// Question Bank
// =========================================================================
//
// sig.go defines the SIG question bank with 100+ questions across 5
// categories: Security, Availability, Processing Integrity,
// Confidentiality, and Privacy. These questions align with the
// AICPA Trust Services Criteria and are used for vendor risk
// assessments in cloud service procurement.
//
// Each question has an ID (SIG-XXX-NNN format), category, and
// question text. Answers are populated at runtime by the
// QuestionnaireEngine based on compliance scan results.
//
// Reference: AICPA Trust Services Criteria 2017 (revised 2022)
//
// =========================================================================

package questionnaire

// buildSIGBank constructs the full SIG question bank with 100 questions
// across 5 categories: Security (25), Availability (20), Processing
// Integrity (20), Confidentiality (20), and Privacy (15).
func buildSIGBank() []Question {
	questions := make([]Question, 0, 100)

	// ================================================================
	// Security (SIG-SEC-001 through SIG-SEC-025) — 25 questions
	// ================================================================
	securityQuestions := []Question{
		{ID: "SIG-SEC-001", Category: "Security", Text: "Are user identities uniquely identified and authenticated before granting access to information assets?"},
		{ID: "SIG-SEC-002", Category: "Security", Text: "Is multi-factor authentication (MFA) required for all user access to critical systems and data?"},
		{ID: "SIG-SEC-003", Category: "Security", Text: "Are user access rights provisioned based on the principle of least privilege?"},
		{ID: "SIG-SEC-004", Category: "Security", Text: "Are user access rights reviewed on a regular basis and upon role change?"},
		{ID: "SIG-SEC-005", Category: "Security", Text: "Is data encrypted at rest using AES-256 or equivalent encryption?"},
		{ID: "SIG-SEC-006", Category: "Security", Text: "Is data encrypted in transit using TLS 1.2 or higher?"},
		{ID: "SIG-SEC-007", Category: "Security", Text: "Are firewall and network segmentation controls in place to restrict unauthorized access?"},
		{ID: "SIG-SEC-008", Category: "Security", Text: "Is a web application firewall (WAF) deployed to protect against common web attacks?"},
		{ID: "SIG-SEC-009", Category: "Security", Text: "Are regular vulnerability scans performed on all internet-facing assets?"},
		{ID: "SIG-SEC-010", Category: "Security", Text: "Is penetration testing conducted at least annually by qualified third parties?"},
		{ID: "SIG-SEC-011", Category: "Security", Text: "Are security patches applied within defined SLA timelines based on severity?"},
		{ID: "SIG-SEC-012", Category: "Security", Text: "Is endpoint protection (EDR/anti-malware) deployed on all endpoints?"},
		{ID: "SIG-SEC-013", Category: "Security", Text: "Are audit logs generated for all system access and administrative actions?"},
		{ID: "SIG-SEC-014", Category: "Security", Text: "Are audit logs protected from tampering and retained for a minimum of 12 months?"},
		{ID: "SIG-SEC-015", Category: "Security", Text: "Is a Security Information and Event Management (SIEM) system used for log aggregation and analysis?"},
		{ID: "SIG-SEC-016", Category: "Security", Text: "Are security incidents detected and responded to within defined SLA timelines?"},
		{ID: "SIG-SEC-017", Category: "Security", Text: "Are privileged accounts managed through a Privileged Access Management (PAM) solution?"},
		{ID: "SIG-SEC-018", Category: "Security", Text: "Is API authentication enforced using OAuth 2.0 or equivalent standards?"},
		{ID: "SIG-SEC-019", Category: "Security", Text: "Are secrets and cryptographic keys managed through a dedicated key management service?"},
		{ID: "SIG-SEC-020", Category: "Security", Text: "Is network intrusion detection/prevention (IDS/IPS) deployed?"},
		{ID: "SIG-SEC-021", Category: "Security", Text: "Are security awareness training programs provided to all employees annually?"},
		{ID: "SIG-SEC-022", Category: "Security", Text: "Is a vulnerability disclosure / bug bounty program in place?"},
		{ID: "SIG-SEC-023", Category: "Security", Text: "Are secure software development lifecycle (SSDLC) practices followed?"},
		{ID: "SIG-SEC-024", Category: "Security", Text: "Is container image scanning performed before deployment to production?"},
		{ID: "SIG-SEC-025", Category: "Security", Text: "Are infrastructure-as-code templates scanned for security misconfigurations?"},
	}
	questions = append(questions, securityQuestions...)

	// ================================================================
	// Availability (SIG-AVL-001 through SIG-AVL-020) — 20 questions
	// ================================================================
	availabilityQuestions := []Question{
		{ID: "SIG-AVL-001", Category: "Availability", Text: "Is data backed up on a regular schedule with automated backup procedures?"},
		{ID: "SIG-AVL-002", Category: "Availability", Text: "Are backup restoration procedures tested at least annually?"},
		{ID: "SIG-AVL-003", Category: "Availability", Text: "Is a disaster recovery plan documented and communicated to relevant stakeholders?"},
		{ID: "SIG-AVL-004", Category: "Availability", Text: "Is the disaster recovery plan tested at least annually?"},
		{ID: "SIG-AVL-005", Category: "Availability", Text: "Are recovery time objectives (RTO) and recovery point objectives (RPO) defined and measured?"},
		{ID: "SIG-AVL-006", Category: "Availability", Text: "Is system redundancy implemented across multiple availability zones or regions?"},
		{ID: "SIG-AVL-007", Category: "Availability", Text: "Is load balancing implemented to distribute traffic across multiple instances?"},
		{ID: "SIG-AVL-008", Category: "Availability", Text: "Are uptime SLAs of 99.9% or higher committed to customers?"},
		{ID: "SIG-AVL-009", Category: "Availability", Text: "Is a business continuity plan (BCP) documented and maintained?"},
		{ID: "SIG-AVL-010", Category: "Availability", Text: "Is there a documented incident response plan for availability incidents?"},
		{ID: "SIG-AVL-011", Category: "Availability", Text: "Are real-time monitoring and alerting systems in place for service health?"},
		{ID: "SIG-AVL-012", Category: "Availability", Text: "Are change management procedures followed to minimize service disruptions?"},
		{ID: "SIG-AVL-013", Category: "Availability", Text: "Is capacity planning performed to ensure adequate resource provisioning?"},
		{ID: "SIG-AVL-014", Category: "Availability", Text: "Are automated scaling mechanisms in place to handle traffic spikes?"},
		{ID: "SIG-AVL-015", Category: "Availability", Text: "Is database replication implemented for high availability?"},
		{ID: "SIG-AVL-016", Category: "Availability", Text: "Are scheduled maintenance windows communicated to customers in advance?"},
		{ID: "SIG-AVL-017", Category: "Availability", Text: "Is a dedicated on-call rotation established for production incidents?"},
		{ID: "SIG-AVL-018", Category: "Availability", Text: "Are dependency risks (third-party services) identified and mitigated?"},
		{ID: "SIG-AVL-019", Category: "Availability", Text: "Is data integrity validation performed after backup restoration?"},
		{ID: "SIG-AVL-020", Category: "Availability", Text: "Are service health dashboards available to customers for transparency?"},
	}
	questions = append(questions, availabilityQuestions...)

	// ================================================================
	// Processing Integrity (SIG-PI-001 through SIG-PI-020) — 20 questions
	// ================================================================
	processingIntegrityQuestions := []Question{
		{ID: "SIG-PI-001", Category: "Processing Integrity", Text: "Are data processing controls in place to ensure completeness and accuracy of data?"},
		{ID: "SIG-PI-002", Category: "Processing Integrity", Text: "Are input validation controls implemented to prevent invalid data entry?"},
		{ID: "SIG-PI-003", Category: "Processing Integrity", Text: "Are data processing workflows documented and version controlled?"},
		{ID: "SIG-PI-004", Category: "Processing Integrity", Text: "Is change management enforced for all production data processing changes?"},
		{ID: "SIG-PI-005", Category: "Processing Integrity", Text: "Are data reconciliation procedures performed between source and processed outputs?"},
		{ID: "SIG-PI-006", Category: "Processing Integrity", Text: "Are automated data quality checks implemented in processing pipelines?"},
		{ID: "SIG-PI-007", Category: "Processing Integrity", Text: "Are error handling and exception processing procedures defined and tested?"},
		{ID: "SIG-PI-008", Category: "Processing Integrity", Text: "Is batch processing monitored for completeness with reconciliation reports?"},
		{ID: "SIG-PI-009", Category: "Processing Integrity", Text: "Are data lineage and provenance tracked throughout processing workflows?"},
		{ID: "SIG-PI-010", Category: "Processing Integrity", Text: "Is there a documented process for handling data processing failures?"},
		{ID: "SIG-PI-011", Category: "Processing Integrity", Text: "Are processing integrity controls tested as part of SOC 2 examinations?"},
		{ID: "SIG-PI-012", Category: "Processing Integrity", Text: "Are authorized business rules applied consistently in data processing?"},
		{ID: "SIG-PI-013", Category: "Processing Integrity", Text: "Is a segregation of duties enforced for data processing operations?"},
		{ID: "SIG-PI-014", Category: "Processing Integrity", Text: "Are processing logs maintained with sufficient detail for forensic analysis?"},
		{ID: "SIG-PI-015", Category: "Processing Integrity", Text: "Are data retention and disposal policies enforced to prevent unauthorized data accumulation?"},
		{ID: "SIG-PI-016", Category: "Processing Integrity", Text: "Is there a process for detecting and correcting data corruption?"},
		{ID: "SIG-PI-017", Category: "Processing Integrity", Text: "Are data transformation rules documented and tested for correctness?"},
		{ID: "SIG-PI-018", Category: "Processing Integrity", Text: "Is there a rollback mechanism for failed data processing operations?"},
		{ID: "SIG-PI-019", Category: "Processing Integrity", Text: "Are processing SLAs defined and monitored for adherence?"},
		{ID: "SIG-PI-020", Category: "Processing Integrity", Text: "Are integrity checksums or hashes used to verify data at rest and in transit?"},
	}
	questions = append(questions, processingIntegrityQuestions...)

	// ================================================================
	// Confidentiality (SIG-CON-001 through SIG-CON-020) — 20 questions
	// ================================================================
	confidentialityQuestions := []Question{
		{ID: "SIG-CON-001", Category: "Confidentiality", Text: "Is a data classification scheme implemented across all data stores?"},
		{ID: "SIG-CON-002", Category: "Confidentiality", Text: "Are access controls applied based on data classification levels?"},
		{ID: "SIG-CON-003", Category: "Confidentiality", Text: "Is encryption at rest enforced for all confidential and restricted data?"},
		{ID: "SIG-CON-004", Category: "Confidentiality", Text: "Is encryption in transit enforced for all data communications?"},
		{ID: "SIG-CON-005", Category: "Confidentiality", Text: "Are non-disclosure agreements (NDAs) required for all personnel with access to confidential data?"},
		{ID: "SIG-CON-006", Category: "Confidentiality", Text: "Is data masking or anonymization applied in non-production environments?"},
		{ID: "SIG-CON-007", Category: "Confidentiality", Text: "Are data loss prevention (DLP) controls implemented?"},
		{ID: "SIG-CON-008", Category: "Confidentiality", Text: "Are confidential document sharing and collaboration tools access-controlled?"},
		{ID: "SIG-CON-009", Category: "Confidentiality", Text: "Is physical access to data centers and server rooms restricted and monitored?"},
		{ID: "SIG-CON-010", Category: "Confidentiality", Text: "Are removable media controls enforced to prevent unauthorized data exfiltration?"},
		{ID: "SIG-CON-011", Category: "Confidentiality", Text: "Are printing controls in place to prevent unauthorized document reproduction?"},
		{ID: "SIG-CON-012", Category: "Confidentiality", Text: "Is key management performed using a dedicated hardware security module (HSM) or cloud KMS?"},
		{ID: "SIG-CON-013", Category: "Confidentiality", Text: "Are data retention policies enforced with automated deletion for expired data?"},
		{ID: "SIG-CON-014", Category: "Confidentiality", Text: "Are database-level access controls (row-level security) implemented where appropriate?"},
		{ID: "SIG-CON-015", Category: "Confidentiality", Text: "Is API access restricted with authentication and rate limiting?"},
		{ID: "SIG-CON-016", Category: "Confidentiality", Text: "Are secure disposal procedures followed for storage media and documents?"},
		{ID: "SIG-CON-017", Category: "Confidentiality", Text: "Is email encryption available and enforced for confidential communications?"},
		{ID: "SIG-CON-018", Category: "Confidentiality", Text: "Are screen lock policies enforced on all workstations?"},
		{ID: "SIG-CON-019", Category: "Confidentiality", Text: "Is tokenization used for sensitive data elements in application logs?"},
		{ID: "SIG-CON-020", Category: "Confidentiality", Text: "Are confidentiality controls reviewed and tested as part of SOC 2 examinations?"},
	}
	questions = append(questions, confidentialityQuestions...)

	// ================================================================
	// Privacy (SIG-PRI-001 through SIG-PRI-015) — 15 questions
	// ================================================================
	privacyQuestions := []Question{
		{ID: "SIG-PRI-001", Category: "Privacy", Text: "Is a publicly available privacy policy that describes data collection and processing practices?"},
		{ID: "SIG-PRI-002", Category: "Privacy", Text: "Is consent obtained from data subjects before collecting and processing personal data?"},
		{ID: "SIG-PRI-003", Category: "Privacy", Text: "Are data subject rights (access, rectification, erasure, portability) supported and processed within regulatory timeframes?"},
		{ID: "SIG-PRI-004", Category: "Privacy", Text: "Are Data Protection Impact Assessments (DPIAs) conducted for high-risk processing activities?"},
		{ID: "SIG-PRI-005", Category: "Privacy", Text: "Are data retention schedules defined and enforced for all personal data categories?"},
		{ID: "SIG-PRI-006", Category: "Privacy", Text: "Is a Data Protection Officer (DPO) or equivalent role designated?"},
		{ID: "SIG-PRI-007", Category: "Privacy", Text: "Are cross-border data transfers governed by appropriate legal mechanisms (SCCs, adequacy decisions)?"},
		{ID: "SIG-PRI-008", Category: "Privacy", Text: "Are data processing agreements in place with all third-party processors?"},
		{ID: "SIG-PRI-009", Category: "Privacy", Text: "Is personal data minimized to what is strictly necessary for the stated purpose?"},
		{ID: "SIG-PRI-010", Category: "Privacy", Text: "Are breach notification procedures in place that meet regulatory timelines (e.g., 72 hours under GDPR)?"},
		{ID: "SIG-PRI-011", Category: "Privacy", Text: "Are privacy impact assessments integrated into the development lifecycle?"},
		{ID: "SIG-PRI-012", Category: "Privacy", Text: "Is there a process for handling and responding to privacy complaints?"},
		{ID: "SIG-PRI-013", Category: "Privacy", Text: "Are employees trained on data privacy obligations and handling procedures?"},
		{ID: "SIG-PRI-014", Category: "Privacy", Text: "Are records of processing activities maintained as required by applicable privacy regulations?"},
		{ID: "SIG-PRI-015", Category: "Privacy", Text: "Is pseudonymization or anonymization applied to personal data where feasible?"},
	}
	questions = append(questions, privacyQuestions...)

	return questions
}
