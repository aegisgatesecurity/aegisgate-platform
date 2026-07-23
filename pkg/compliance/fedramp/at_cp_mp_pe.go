// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP AT, CP, MP, PE Families
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Awareness & Training (AT), Contingency
// Planning (CP), Media Protection (MP), and Physical & Environmental
// Protection (PE) families for FedRAMP Moderate.
//
// AT in-scope controls (3):
//   AT-1  Security Awareness Training Policy  (evidence-mapped)
//   AT-2  Security Awareness Training          (evidence-mapped)
//   AT-3  Role-Based Security Training          (evidence-mapped)
//
// CP in-scope controls (3):
//   CP-1  Contingency Planning Policy           (evidence-mapped)
//   CP-2  Contingency Plan                       (evidence-mapped)
//   CP-9  System Backup                          (automated)
//
// MP in-scope controls (2):
//   MP-5  Media Transport                        (evidence-mapped)
//   MP-6  Media Sanitization                     (automated)
//
// PE in-scope controls (2):
//   PE-3  Physical Access Control                (evidence-mapped)
//   PE-20  Monitoring Physical Access             (evidence-mapped)
//
// These are primarily process/policy controls. AegisGate generates the
// technical evidence artifacts (audit logs, scan results, attestations)
// that customers attach to their FedRAMP A&A packages. The customer
// is responsible for the policy, training, and process documentation.
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerATControls wires the AT (Awareness & Training) family controls.
func (m *FedRAMPModule) registerATControls() {
	// AT-1: Security Awareness Training Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AT-1",
		Name:        "Security Awareness Training Policy and Procedures",
		Description: "FedRAMP AT-1: Organization develops, documents, and disseminates a security awareness training policy. AegisGate generates policy enforcement evidence (scan results, access audit logs) that the customer attaches to their AT-1 SSP section.",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 AT-1", "FedRAMP Moderate AT-01"},
	})

	// AT-2: Security Awareness Training (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AT-2",
		Name:        "Security Awareness Training",
		Description: "FedRAMP AT-2: Organization provides security awareness training to system users. AegisGate generates compliance scan evidence and training-relevant threat indicators (IOC store, ATLAS patterns) for the customer's AT-2 training program.",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 AT-2", "FedRAMP Moderate AT-02"},
	})

	// AT-3: Role-Based Security Training (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AT-3",
		Name:        "Role-Based Security Training",
		Description: "FedRAMP AT-3: Organization provides role-based security training for personnel with significant security responsibilities. AegisGate generates the threat intelligence and compliance evidence (incident reports, ATLAS patterns) for the customer's role-based training content.",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 AT-3", "FedRAMP Moderate AT-03"},
	})
}

// registerCPControls wires the CP (Contingency Planning) family controls.
func (m *FedRAMPModule) registerCPControls() {
	// CP-1: Contingency Planning Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-1",
		Name:        "Contingency Planning Policy and Procedures",
		Description: "FedRAMP CP-1: Organization develops, documents, and disseminates a contingency planning policy. AegisGate generates system configuration evidence (SBOM, audit logs, attestation chain) for the customer's CP-1 documentation.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-1", "FedRAMP Moderate CP-01"},
	})

	// CP-2: Contingency Plan (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-2",
		Name:        "Contingency Plan",
		Description: "FedRAMP CP-2: Organization develops a contingency plan for the information system. AegisGate provides system topology evidence (component inventory, dependency mapping, trust framework identity records) for the customer's CP-2 contingency plan.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-2", "FedRAMP Moderate CP-02"},
	})

	// CP-9: System Backup (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CP-9",
		Name:        "System Backup",
		Description: "FedRAMP CP-9: Organization conducts backups of system information. AegisGate's persistence layer supports data backup verification.",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemBackup,
		References:  []string{"NIST SP 800-53 Rev. 5 CP-9", "FedRAMP Moderate CP-09"},
	})
}

// registerMPControls wires the MP (Media Protection) family controls.
func (m *FedRAMPModule) registerMPControls() {
	// MP-5: Media Transport (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-MP-5",
		Name:        "Media Transport",
		Description: "FedRAMP MP-5: Organization controls and documents the transport of information system media. AegisGate generates evidence of data-in-transit encryption (TLS 1.2+, FIPS-approved ciphers) for the customer's MP-5 documentation.",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 MP-5", "FedRAMP Moderate MP-05"},
	})

	// MP-6: Media Sanitization (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-MP-6",
		Name:        "Media Sanitization",
		Description: "FedRAMP MP-6: Organization sanitizes media before disposal, reuse, or removal. AegisGate verifies that data-at-rest encryption and key management are in place, ensuring that media sanitization (key destruction) is effective.",
		Category:    "Media Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaSanitization,
		References:  []string{"NIST SP 800-53 Rev. 5 MP-6", "FedRAMP Moderate MP-06"},
	})
}

// registerPEControls wires the PE (Physical & Environmental Protection) family controls.
func (m *FedRAMPModule) registerPEControls() {
	// PE-3: Physical Access Control (evidence-mapped)
	// Note: Physical access is primarily a process/facility control. AegisGate
	// provides the logical access control evidence (RBAC, MFA, session logs)
	// that complements the physical access program.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PE-3",
		Name:        "Physical Access Control",
		Description: "FedRAMP PE-3: Organization enforces physical access authorizations. AegisGate provides logical access control evidence (RBAC policies, MFA enforcement, session timeout, access audit logs) that complements the customer's physical access program for PE-3.",
		Category:    "Physical and Environmental Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PE-3", "FedRAMP Moderate PE-03"},
	})

	// PE-20: Monitoring Physical Access (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-PE-20",
		Name:        "Monitoring Physical Access",
		Description: "FedRAMP PE-20: Organization monitors physical access. AegisGate generates audit log evidence of all logical access events (login, session, API calls) that complements the customer's physical monitoring for PE-20.",
		Category:    "Physical and Environmental Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 PE-20", "FedRAMP Moderate PE-20"},
	})
}

// --- CP Check Functions ---

func (m *FedRAMPModule) checkSystemBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "persistence") || strings.Contains(inputStr, "data_store")
	hasEncryption := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "encrypted") || strings.Contains(inputStr, "data_encrypted")
	hasSchedule := strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "backup_schedule") || strings.Contains(inputStr, "retention")

	if hasBackup && (hasEncryption || hasSchedule) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CP-9",
			ControlName: "System Backup",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System backup verified (persistence + encryption/schedule)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasBackup {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CP-9",
			ControlName: "System Backup",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Backup persistence detected but encryption or scheduling not configured",
			Timestamp:   time.Now(),
			Remediation: "Enable backup encryption (persistence.encryption_at_rest=true) and scheduled backups",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CP-9",
		ControlName: "System Backup",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No system backup mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Configure persistence backend (persistence.enabled=true) with encryption and backup schedule",
	}, nil
}

// --- MP Check Functions ---

func (m *FedRAMPModule) checkMediaSanitization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "disk_encryption")
	HasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_store") || strings.Contains(inputStr, "encryption_key")
	hasSanitization := strings.Contains(inputStr, "sanitiz") || strings.Contains(inputStr, "purge") || strings.Contains(inputStr, "destroy")

	if hasEncryptionAtRest && HasKeyMgmt {
		if hasSanitization {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "FedRAMP-MP-6",
				ControlName: "Media Sanitization",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Media sanitization verified (encryption + key management + sanitization policy)",
				Timestamp:   time.Now(),
			}, nil
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-MP-6",
			ControlName: "Media Sanitization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media sanitization effective via encryption-at-rest with key management (key destruction = effective sanitization per NIST SP 800-88)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryptionAtRest {
		violations = append(violations, "encryption at rest not configured")
	}
	if !HasKeyMgmt {
		violations = append(violations, "key management not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-MP-6",
		ControlName: "Media Sanitization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Media sanitization gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable encryption at rest (persistence.encryption_at_rest=true) and key management (security.key_management=true) per NIST SP 800-88",
	}, nil
}
