// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX IS + OR Family Controls
// =========================================================================
//
// TISAX ISA Catalogue — Information Security (IS) and Organization & Risk
// (OR) family controls for AL2 assessment.
//
// IS family (8 controls):
//   IS-01  Information Security Policy      (automated)
//   IS-02  Security Organization             (evidence-mapped)
//   IS-03  Asset Management                  (automated)
//   IS-04  Access Control                    (automated)
//   IS-05  Cryptography                      (automated)
//   IS-06  Physical Security                  (evidence-mapped)
//   IS-07  Operations Security               (evidence-mapped)
//   IS-08  Communications Security           (automated)
//
// OR family (7 controls):
//   OR-01  Risk Assessment                   (automated)
//   OR-02  Risk Treatment                    (evidence-mapped)
//   OR-03  Supplier Relationships             (evidence-mapped)
//   OR-04  Business Continuity               (evidence-mapped)
//   OR-05  Legal Compliance                  (evidence-mapped)
//   OR-06  Human Resource Security           (evidence-mapped)
//   OR-07  Incident Management               (automated)
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
