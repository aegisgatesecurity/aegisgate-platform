// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX IS + OR Family Controls
// =========================================================================
//
// TISAX ISA Catalogue — Information Security (IS) and Organization & Risk
// (OR) family controls for AL2 assessment.
//
// IS family (14 controls):
//   IS-01  Information Security Policy      (automated)
//   IS-02  Security Organization             (evidence-mapped)
//   IS-03  Asset Management                  (automated)
//   IS-04  Access Control                    (automated)
//   IS-05  Cryptography                      (automated)
//   IS-06  Physical Security                  (evidence-mapped)
//   IS-07  Operations Security               (evidence-mapped)
//   IS-08  Communications Security           (automated)
//   IS-09  Vulnerability Management           (automated)
//   IS-10  Security Awareness Training        (evidence-mapped)
//   IS-11  Incident Response Planning         (automated)
//   IS-12  Business Continuity Management     (evidence-mapped)
//   IS-13  Supplier Security Assessment       (evidence-mapped)
//   IS-14  Compliance Monitoring              (automated)
//
// OR family (12 controls):
//   OR-01  Risk Assessment                   (automated)
//   OR-02  Risk Treatment                    (evidence-mapped)
//   OR-03  Supplier Relationships             (evidence-mapped)
//   OR-04  Business Continuity               (evidence-mapped)
//   OR-05  Legal Compliance                  (evidence-mapped)
//   OR-06  Human Resource Security           (evidence-mapped)
//   OR-07  Incident Management               (automated)
//   OR-08  Risk Monitoring & Review           (automated)
//   OR-09  Security Investment Planning       (evidence-mapped)
//   OR-10  Security Metrics & KPIs            (automated)
//   OR-11  Audit Management                   (evidence-mapped)
//   OR-12  Management Review Process          (evidence-mapped)
//
// =========================================================================

package tisax

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerISControls wires the Information Security family controls.
func (m *TISAXModule) registerISControls() {
	// IS-01: Information Security Policy (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-01",
		Name:        "Information Security Policy",
		Description: "TISAX IS-01: Information security policy documented and approved by management",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfoSecPolicy,
		References:  []string{"TISAX v6 AL2 ISA-01", "ISO 27001 A.5.1"},
	})

	// IS-02: Security Organization (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-02",
		Name:        "Security Organization",
		Description: "TISAX IS-02: Security organization structure and responsibilities defined",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-02", "ISO 27001 A.6.1"},
	})

	// IS-03: Asset Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-03",
		Name:        "Asset Management",
		Description: "TISAX IS-03: Information assets identified, classified, and inventoried",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAssetManagement,
		References:  []string{"TISAX v6 AL2 ISA-03", "ISO 27001 A.8.1"},
	})

	// IS-04: Access Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-04",
		Name:        "Access Control",
		Description: "TISAX IS-04: Access control policy enforced with least privilege and role-based access",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
		References:  []string{"TISAX v6 AL2 ISA-04", "ISO 27001 A.9.1"},
	})

	// IS-05: Cryptography (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-05",
		Name:        "Cryptography",
		Description: "TISAX IS-05: Cryptographic controls properly implemented for data protection",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptography,
		References:  []string{"TISAX v6 AL2 ISA-05", "ISO 27001 A.10.1"},
	})

	// IS-06: Physical Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-06",
		Name:        "Physical Security",
		Description: "TISAX IS-06: Physical access to information processing facilities controlled and monitored",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-06", "ISO 27001 A.11.1"},
	})

	// IS-07: Operations Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-07",
		Name:        "Operations Security",
		Description: "TISAX IS-07: Operational procedures documented and change management enforced",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-07", "ISO 27001 A.12.1"},
	})

	// IS-08: Communications Security (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-08",
		Name:        "Communications Security",
		Description: "TISAX IS-08: Network security controls and secure communication channels enforced",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCommsSecurity,
		References:  []string{"TISAX v6 AL2 ISA-08", "ISO 27001 A.13.1"},
	})

	// IS-09: Vulnerability Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-09",
		Name:        "Vulnerability Management",
		Description: "TISAX IS-09: Vulnerability identification, assessment, and remediation tracking",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnMgmt,
		References:  []string{"TISAX v6 AL2 ISA-09", "ISO 27001 A.8.8"},
	})

	// IS-10: Security Awareness Training (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-10",
		Name:        "Security Awareness Training",
		Description: "TISAX IS-10: Security awareness training program with periodic refreshers",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-10", "ISO 27001 A.6.3"},
	})

	// IS-11: Incident Response Planning (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-11",
		Name:        "Incident Response Planning",
		Description: "TISAX IS-11: Incident response plan documented with defined roles and escalation",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
		References:  []string{"TISAX v6 AL2 ISA-11", "ISO 27001 A.16.1"},
	})

	// IS-12: Business Continuity Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-12",
		Name:        "Business Continuity Management",
		Description: "TISAX IS-12: Business continuity management system with recovery objectives",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-12", "ISO 27001 A.17.1"},
	})

	// IS-13: Supplier Security Assessment (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-13",
		Name:        "Supplier Security Assessment",
		Description: "TISAX IS-13: Supplier and third-party security assessments conducted periodically",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-13", "ISO 27001 A.5.19"},
	})

	// IS-14: Compliance Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-IS-14",
		Name:        "Compliance Monitoring",
		Description: "TISAX IS-14: Continuous compliance monitoring and deviation tracking",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkComplianceMonitoring,
		References:  []string{"TISAX v6 AL2 ISA-14", "ISO 27001 A.5.36"},
	})
}

// registerORControls wires the Organization & Risk family controls.
func (m *TISAXModule) registerORControls() {
	// OR-01: Risk Assessment (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-01",
		Name:        "Risk Assessment",
		Description: "TISAX OR-01: Risk assessment methodology defined and applied to information assets",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"TISAX v6 AL2 ISA-09", "ISO 27001 A.8.2"},
	})

	// OR-02: Risk Treatment (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-02",
		Name:        "Risk Treatment",
		Description: "TISAX OR-02: Risk treatment plan documented with accepted, mitigated, or transferred risks",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-10", "ISO 27001 A.8.3"},
	})

	// OR-03: Supplier Relationships (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-03",
		Name:        "Supplier Relationships",
		Description: "TISAX OR-03: Supplier and third-party security requirements defined and monitored",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-11", "ISO 27001 A.15.1"},
	})

	// OR-04: Business Continuity (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-04",
		Name:        "Business Continuity",
		Description: "TISAX OR-04: Business continuity plans and disaster recovery procedures established",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-12", "ISO 27001 A.17.1"},
	})

	// OR-05: Legal Compliance (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-05",
		Name:        "Legal Compliance",
		Description: "TISAX OR-05: Legal, regulatory, and contractual requirements identified and met",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-13", "ISO 27001 A.18.1"},
	})

	// OR-06: Human Resource Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-06",
		Name:        "Human Resource Security",
		Description: "TISAX OR-06: Personnel security requirements including screening and terms of employment",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-14", "ISO 27001 A.7.1"},
	})

	// OR-07: Incident Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-07",
		Name:        "Incident Management",
		Description: "TISAX OR-07: Security incident management procedures and reporting channels established",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentMgmt,
		References:  []string{"TISAX v6 AL2 ISA-15", "ISO 27001 A.16.1"},
	})

	// OR-08: Risk Monitoring & Review (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-08",
		Name:        "Risk Monitoring & Review",
		Description: "TISAX OR-08: Ongoing risk monitoring and periodic review of risk landscape",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRiskMonitoring,
		References:  []string{"TISAX v6 AL2 ISA-16", "ISO 27001 A.8.2"},
	})

	// OR-09: Security Investment Planning (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-09",
		Name:        "Security Investment Planning",
		Description: "TISAX OR-09: Security investment planning and budget allocation documented",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-17", "ISO 27001 A.5.4"},
	})

	// OR-10: Security Metrics & KPIs (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-10",
		Name:        "Security Metrics & KPIs",
		Description: "TISAX OR-10: Security metrics and KPIs defined, tracked, and reported to management",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityMetrics,
		References:  []string{"TISAX v6 AL2 ISA-18", "ISO 27001 A.5.4"},
	})

	// OR-11: Audit Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-11",
		Name:        "Audit Management",
		Description: "TISAX OR-11: Internal and external audit program management with findings tracking",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-19", "ISO 27001 A.5.35"},
	})

	// OR-12: Management Review Process (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-OR-12",
		Name:        "Management Review Process",
		Description: "TISAX OR-12: Management review process for information security performance",
		Category:    "Organization & Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-20", "ISO 27001 A.5.5"},
	})
}

// --- IS Family CheckFunc implementations ---

// checkInfoSecPolicy verifies that an information security policy is
// documented and approved. Maps to TISAX IS-01.
func (m *TISAXModule) checkInfoSecPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := strings.Contains(inputStr, "security_policy") || strings.Contains(inputStr, "infosec_policy")
	hasApproved := strings.Contains(inputStr, "management_approved") || strings.Contains(inputStr, "approved") || strings.Contains(inputStr, "governance")
	hasCommunication := strings.Contains(inputStr, "policy_communicated") || strings.Contains(inputStr, "awareness") || strings.Contains(inputStr, "training")

	if hasPolicy && hasApproved {
		evidence := []string{}
		if hasPolicy {
			evidence = append(evidence, "Information security policy documented")
		}
		if hasApproved {
			evidence = append(evidence, "Policy approved by management")
		}
		if hasCommunication {
			evidence = append(evidence, "Policy communicated to personnel")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-01",
			ControlName: "Information Security Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Information security policy documented and approved",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPolicy {
		violations = append(violations, "information security policy not documented")
	}
	if !hasApproved {
		violations = append(violations, "policy not approved by management")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-01",
		ControlName: "Information Security Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information security policy gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Document an information security policy and obtain management approval (security_policy=true, management_approved=true)",
	}, nil
}

// checkAssetManagement verifies that information assets are identified,
// classified, and inventoried. Maps to TISAX IS-03.
func (m *TISAXModule) checkAssetManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "asset_inventory") || strings.Contains(inputStr, "inventory")
	hasClassification := strings.Contains(inputStr, "classification") || strings.Contains(inputStr, "data_classification")
	hasOwner := strings.Contains(inputStr, "asset_owner") || strings.Contains(inputStr, "owner") || strings.Contains(inputStr, "responsibility")

	if hasInventory && hasClassification && hasOwner {
		evidence := []string{
			"Asset inventory maintained",
			"Data classification applied",
			"Asset ownership assigned",
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-03",
			ControlName: "Asset Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Asset management controls verified (inventory, classification, ownership)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInventory {
		violations = append(violations, "asset inventory not maintained")
	}
	if !hasClassification {
		violations = append(violations, "data classification not applied")
	}
	if !hasOwner {
		violations = append(violations, "asset ownership not assigned")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-03",
		ControlName: "Asset Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Asset management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Maintain an asset inventory, apply data classification, and assign asset ownership",
	}, nil
}

// checkAccessControl verifies access control policy is enforced with
// least privilege and role-based access. Maps to TISAX IS-04.
func (m *TISAXModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := false
	for _, p := range m.accessPatterns {
		if p.MatchString(inputStr) {
			hasRBAC = true
			break
		}
	}
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimize") || strings.Contains(inputStr, "roles")

	if hasRBAC && hasAuth && hasLeastPrivilege {
		evidence := []string{
			"Role-based access control enforced",
			"Authentication enabled",
			"Least privilege principle applied",
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-04",
			ControlName: "Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Access control controls verified (RBAC, auth, least privilege)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "role-based access control not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not enabled")
	}
	if !hasLeastPrivilege {
		violations = append(violations, "least privilege principle not applied")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-04",
		ControlName: "Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC, authentication, and least privilege access controls",
	}, nil
}

// checkCryptography verifies cryptographic controls are properly
// implemented. Maps to TISAX IS-05.
func (m *TISAXModule) checkCryptography(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation")
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")

	if hasEncryption && hasKeyMgmt {
		evidence := []string{
			"Encryption controls verified",
			"Key management in place",
		}
		if hasTLS {
			evidence = append(evidence, "TLS enabled for communications")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-05",
			ControlName: "Cryptography",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic controls verified (encryption + key management)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryption {
		violations = append(violations, "encryption not properly configured")
	}
	if !hasKeyMgmt {
		violations = append(violations, "key management not in place")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-05",
		ControlName: "Cryptography",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable encryption (AES-256 or equivalent) and implement key management/rotation",
	}, nil
}

// checkCommsSecurity verifies network security and secure communications.
// Maps to TISAX IS-08.
func (m *TISAXModule) checkCommsSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasNetworkSeg := strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "segmentation")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled")

	if hasTLS && hasNetworkSeg && hasMonitoring {
		evidence := []string{
			"TLS/HTTPS enabled for communications",
			"Network segmentation enforced",
			"Network monitoring active",
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-08",
			ControlName: "Communications Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Communications security controls verified (TLS, segmentation, monitoring)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTLS {
		violations = append(violations, "TLS/HTTPS not enabled")
	}
	if !hasNetworkSeg {
		violations = append(violations, "network segmentation not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "network monitoring not active")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-08",
		ControlName: "Communications Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Communications security gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable TLS, configure network segmentation, and activate network monitoring",
	}, nil
}

// --- OR Family CheckFunc implementations ---

// checkRiskAssessment verifies that a risk assessment methodology is
// defined and applied. Maps to TISAX OR-01.
func (m *TISAXModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMethodology := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "risk_methodology")
	hasThreatModel := strings.Contains(inputStr, "threat_model") || strings.Contains(inputStr, "threat") || strings.Contains(inputStr, "vulnerability")
	hasRegister := strings.Contains(inputStr, "risk_register") || strings.Contains(inputStr, "risk_matrix") || strings.Contains(inputStr, "risk")

	if hasMethodology && hasThreatModel {
		evidence := []string{
			"Risk assessment methodology defined",
			"Threat modeling performed",
		}
		if hasRegister {
			evidence = append(evidence, "Risk register maintained")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-OR-01",
			ControlName: "Risk Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Risk assessment controls verified (methodology + threat modeling)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMethodology {
		violations = append(violations, "risk assessment methodology not defined")
	}
	if !hasThreatModel {
		violations = append(violations, "threat modeling not performed")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-OR-01",
		ControlName: "Risk Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Risk assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Define a risk assessment methodology and perform threat modeling",
	}, nil
}

// checkIncidentMgmt verifies security incident management procedures.
// Maps to TISAX OR-07.
func (m *TISAXModule) checkIncidentMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIncidentProc := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "incident_procedure") || strings.Contains(inputStr, "incident")
	hasIOCDetection := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "detection") || strings.Contains(inputStr, "monitoring")
	hasReporting := strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "alert")

	if hasIncidentProc && hasIOCDetection {
		evidence := []string{
			"Incident response procedures established",
			"IOC detection active",
		}
		if hasReporting {
			evidence = append(evidence, "Incident reporting channels defined")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-OR-07",
			ControlName: "Incident Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident management controls verified (procedures + IOC detection)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIncidentProc {
		violations = append(violations, "incident response procedures not established")
	}
	if !hasIOCDetection {
		violations = append(violations, "IOC detection not active")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-OR-07",
		ControlName: "Incident Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Establish incident response procedures and activate IOC detection",
	}, nil
}

// --- New IS Family CheckFunc implementations (IS-09 through IS-14) ---

// checkVulnMgmt verifies vulnerability identification, assessment, and
// remediation tracking. Maps to TISAX IS-09.
func (m *TISAXModule) checkVulnMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScan := strings.Contains(inputStr, "vulnerability_scan") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "cve")
	hasTracking := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "ticket")
	hasSeverity := strings.Contains(inputStr, "severity") || strings.Contains(inputStr, "cvss") || strings.Contains(inputStr, "risk_score")

	if hasScan && hasTracking {
		evidence := []string{
			"Vulnerability scanning configured",
			"Remediation tracking in place",
		}
		if hasSeverity {
			evidence = append(evidence, "Severity-based prioritization")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-09",
			ControlName: "Vulnerability Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability management verified (scanning + remediation tracking)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasTracking {
		violations = append(violations, "remediation tracking not in place")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-09",
		ControlName: "Vulnerability Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning and implement remediation tracking",
	}, nil
}

// checkIncidentResponsePlan verifies that an incident response plan is
// documented with defined roles and escalation. Maps to TISAX IS-11.
func (m *TISAXModule) checkIncidentResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "response_plan")
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "responsibilities") || strings.Contains(inputStr, "playbook")
	hasEscalation := strings.Contains(inputStr, "escalation") || strings.Contains(inputStr, "escalation_path") || strings.Contains(inputStr, "notification")

	if hasPlan && hasRoles {
		evidence := []string{
			"Incident response plan documented",
			"Roles and responsibilities defined",
		}
		if hasEscalation {
			evidence = append(evidence, "Escalation paths established")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-11",
			ControlName: "Incident Response Planning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response planning verified (plan + roles)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPlan {
		violations = append(violations, "incident response plan not documented")
	}
	if !hasRoles {
		violations = append(violations, "roles and responsibilities not defined")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-11",
		ControlName: "Incident Response Planning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident response planning gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Document an incident response plan with defined roles and escalation paths",
	}, nil
}

// checkComplianceMonitoring verifies continuous compliance monitoring and
// deviation tracking. Maps to TISAX IS-14.
func (m *TISAXModule) checkComplianceMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "compliance_monitoring") || strings.Contains(inputStr, "continuous_monitoring") || strings.Contains(inputStr, "monitoring")
	hasDeviations := strings.Contains(inputStr, "deviation") || strings.Contains(inputStr, "non_conformity") || strings.Contains(inputStr, "exceptions")
	hasReporting := strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "compliance_report")

	if hasMonitoring && (hasDeviations || hasReporting) {
		evidence := []string{
			"Compliance monitoring active",
		}
		if hasDeviations {
			evidence = append(evidence, "Deviation tracking in place")
		}
		if hasReporting {
			evidence = append(evidence, "Compliance reporting configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-IS-14",
			ControlName: "Compliance Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Compliance monitoring verified (monitoring + deviation tracking/reporting)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "compliance monitoring not active")
	}
	if !hasDeviations && !hasReporting {
		violations = append(violations, "deviation tracking and reporting not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-IS-14",
		ControlName: "Compliance Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Compliance monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable continuous compliance monitoring with deviation tracking and reporting",
	}, nil
}

// --- New OR Family CheckFunc implementations (OR-08, OR-10) ---

// checkRiskMonitoring verifies ongoing risk monitoring and periodic review.
// Maps to TISAX OR-08.
func (m *TISAXModule) checkRiskMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitor := strings.Contains(inputStr, "risk_monitoring") || strings.Contains(inputStr, "risk_review") || strings.Contains(inputStr, "monitoring")
	hasPeriodic := strings.Contains(inputStr, "periodic") || strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "annual") || strings.Contains(inputStr, "review")
	hasRegister := strings.Contains(inputStr, "risk_register") || strings.Contains(inputStr, "risk") || strings.Contains(inputStr, "risk_tracker")

	if hasMonitor && hasPeriodic {
		evidence := []string{
			"Risk monitoring configured",
			"Periodic review schedule established",
		}
		if hasRegister {
			evidence = append(evidence, "Risk register maintained")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-OR-08",
			ControlName: "Risk Monitoring & Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Risk monitoring verified (monitoring + periodic review)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitor {
		violations = append(violations, "risk monitoring not configured")
	}
	if !hasPeriodic {
		violations = append(violations, "periodic review schedule not established")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-OR-08",
		ControlName: "Risk Monitoring & Review",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Risk monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure risk monitoring with periodic review schedules",
	}, nil
}

// checkSecurityMetrics verifies that security metrics and KPIs are defined,
// tracked, and reported. Maps to TISAX OR-10.
func (m *TISAXModule) checkSecurityMetrics(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "metrics") || strings.Contains(inputStr, "kpi") || strings.Contains(inputStr, "security_metrics")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "reporting")
	hasMgmt := strings.Contains(inputStr, "management") || strings.Contains(inputStr, "board") || strings.Contains(inputStr, "review")

	if hasMetrics && hasTracking {
		evidence := []string{
			"Security metrics and KPIs defined",
			"Metrics tracking in place",
		}
		if hasMgmt {
			evidence = append(evidence, "Management reporting configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-OR-10",
			ControlName: "Security Metrics & KPIs",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security metrics verified (KPIs + tracking)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMetrics {
		violations = append(violations, "security metrics and KPIs not defined")
	}
	if !hasTracking {
		violations = append(violations, "metrics tracking not in place")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-OR-10",
		ControlName: "Security Metrics & KPIs",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security metrics gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Define security metrics/KPIs and implement tracking with management reporting",
	}, nil
}
