// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP IR + SA + SR Families
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Incident Response (IR), System and Services
// Acquisition (SA), and Supply Chain Risk Management (SR) families.
//
// IR in-scope controls (5):
//   IR-4  Incident Handling            (automated, Path C — new)
//   IR-5  Incident Monitoring           (automated, Path C — new)
//   IR-6  Incident Reporting            (automated, Path C — new)
//   IR-7  Incident Response Assistance  (evidence-mapped, Path C — new)
//   IR-8  Incident Response Plan        (evidence-mapped, Path C — new)
//
// SA in-scope controls (5):
//   SA-4  Acquisition Process          (evidence-mapped, Path C — new)
//   SA-5  Information System Documentation (evidence-mapped, Path C — new)
//   SA-9  External System Services      (evidence-mapped, Path C — new)
//   SA-11  Development Process         (evidence-mapped, Path C — new)
//   SA-22  Unsupported System Components (automated, Path C — new)
//
// SR in-scope controls (5):
//   SR-3  Supply Chain Controls         (evidence-mapped, Path C — new)
//   SR-4  Provenance                    (automated, Path C — new)
//   SR-6  Supplier Assessment           (evidence-mapped, Path C — new)
//   SR-8  Notification Agreements      (evidence-mapped, Path C — new)
//   SR-12  Supply Chain Risk Management (evidence-mapped, Path C — new)
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIRControls wires the IR family controls into the module.
func (m *FedRAMPModule) registerIRControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-4",
		Name:        "Incident Handling",
		Description: "FedRAMP IR-4: Incident handling implemented with detection, analysis, containment, eradication, and recovery",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentHandling,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-4", "FedRAMP Moderate IR-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-5",
		Name:        "Incident Monitoring",
		Description: "FedRAMP IR-5: Security incidents tracked and monitored from detection through resolution",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentMonitoring,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-5", "FedRAMP Moderate IR-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-6",
		Name:        "Incident Reporting",
		Description: "FedRAMP IR-6: Security incidents reported to authorized personnel and external authorities as required",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentReporting,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-6", "FedRAMP Moderate IR-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-7",
		Name:        "Incident Response Assistance",
		Description: "FedRAMP IR-7: Incident response assistance from external resources. AegisGate verifies SIEM dispatch and incident engine integration.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIRAssistance,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-7", "FedRAMP Moderate IR-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IR-8",
		Name:        "Incident Response Plan",
		Description: "FedRAMP IR-8: Incident response plan documented, tested, and updated. AegisGate verifies incident playbooks, audit timeline, and IOC store.",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkIRPlan,
		References:  []string{"NIST SP 800-53 Rev. 5 IR-8", "FedRAMP Moderate IR-08"},
	})
}

// registerSAControls wires the SA family controls into the module.
func (m *FedRAMPModule) registerSAControls() {
	// SA-4: Acquisition Process (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-4",
		Name:        "Acquisition Process",
		Description: "FedRAMP SA-4: Security requirements included in acquisition process. AegisGate verifies AIBOM and security assessment integration.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAcquisitionProcess,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-4", "FedRAMP Moderate SA-04"},
	})
	// SA-5: Information System Documentation (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-5",
		Name:        "Information System Documentation",
		Description: "FedRAMP SA-5: Security documentation maintained and available. AegisGate verifies compliance reports, SBOM, and attestation evidence.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSystemDocumentation,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-5", "FedRAMP Moderate SA-05"},
	})
	// SA-9: External System Services (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-9",
		Name:        "External System Services",
		Description: "FedRAMP SA-9: External system services meet security requirements. AegisGate verifies trust framework contracts and sub-processor tracking.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkExternalSystemServices,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-9", "FedRAMP Moderate SA-09"},
	})
	// SA-11: Development Process (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-11",
		Name:        "Development Process",
		Description: "FedRAMP SA-11: Security engineering practices in development. AegisGate verifies security scanning and SBOM attestation.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkDevelopmentProcess,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-11", "FedRAMP Moderate SA-11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SA-22",
		Name:        "Unsupported System Components",
		Description: "FedRAMP SA-22: Unsupported system components replaced or mitigated. AegisGate's SBOM and vulnerability scanning detect unsupported components.",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkUnsupportedComponents,
		References:  []string{"NIST SP 800-53 Rev. 5 SA-22", "FedRAMP Moderate SA-22"},
	})
}

// registerSRControls wires the SR family controls into the module.
func (m *FedRAMPModule) registerSRControls() {
	// SR-3: Supply Chain Controls (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SR-3",
		Name:        "Supply Chain Controls",
		Description: "FedRAMP SR-3: Supply chain controls implemented. AegisGate verifies AIBOM, vendor tracking, and attestation evidence.",
		Category:    "Supply Chain Risk Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSupplyChainControls,
		References:  []string{"NIST SP 800-53 Rev. 5 SR-3", "FedRAMP Moderate SR-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SR-4",
		Name:        "Provenance",
		Description: "FedRAMP SR-4: System and component provenance tracked. AegisGate's SBOM/AIBOM and trust attestations provide provenance evidence.",
		Category:    "Supply Chain Risk Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkProvenance,
		References:  []string{"NIST SP 800-53 Rev. 5 SR-4", "FedRAMP Moderate SR-04"},
	})
	// SR-6: Supplier Assessment (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SR-6",
		Name:        "Supplier Assessment",
		Description: "FedRAMP SR-6: Supplier assessment and monitoring. AegisGate verifies CVE tracking and SBOM for supplier assessment.",
		Category:    "Supply Chain Risk Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSupplierAssessment,
		References:  []string{"NIST SP 800-53 Rev. 5 SR-6", "FedRAMP Moderate SR-06"},
	})
	// SR-8: Notification Agreements (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SR-8",
		Name:        "Notification Agreements",
		Description: "FedRAMP SR-8: Notification agreements for supply chain events. AegisGate verifies SIEM dispatch and audit log notification.",
		Category:    "Supply Chain Risk Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkNotificationAgreements,
		References:  []string{"NIST SP 800-53 Rev. 5 SR-8", "FedRAMP Moderate SR-08"},
	})
	// SR-12: SCRM Plan (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SR-12",
		Name:        "Supply Chain Risk Management",
		Description: "FedRAMP SR-12: Supply chain risk management plan documented. AegisGate verifies AIBOM, vulnerability tracking, and attestation evidence.",
		Category:    "Supply Chain Risk Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSCRMPlan,
		References:  []string{"NIST SP 800-53 Rev. 5 SR-12", "FedRAMP Moderate SR-12"},
	})
}

// --- IR Check Functions ---

func (m *FedRAMPModule) checkIncidentHandling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIOC := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "indicator") || strings.Contains(inputStr, "threat")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "siem")
	hasResponse := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "response") || strings.Contains(inputStr, "block")

	if (hasIOC || hasAlerting) && hasResponse {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IR-4",
			ControlName: "Incident Handling",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident handling verified (threat detection + response)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIOC && !hasAlerting {
		violations = append(violations, "threat detection/alerting not detected")
	}
	if !hasResponse {
		violations = append(violations, "incident response mechanism not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IR-4",
		ControlName: "Incident Handling",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident handling gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable IOC store (ioc.enabled=true) and incident response (scanner.block_on_detection=true)",
	}, nil
}

func (m *FedRAMPModule) checkIncidentMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "audit_log")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "incident_tracking") || strings.Contains(inputStr, "ioc")

	if hasMonitoring && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IR-5",
			ControlName: "Incident Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident monitoring verified (monitoring + tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "incident monitoring not detected")
	}
	if !hasTracking {
		violations = append(violations, "incident tracking not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IR-5",
		ControlName: "Incident Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable monitoring (anomaly_detection.enabled=true) and incident tracking (ioc.enabled=true)",
	}, nil
}

func (m *FedRAMPModule) checkIncidentReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNotification := strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "reporting")
	hasSIEM := strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "siem_dispatcher") || strings.Contains(inputStr, "siem_integration")
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit") || strings.Contains(inputStr, "logging")

	if hasNotification && (hasSIEM || hasAuditLog) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IR-6",
			ControlName: "Incident Reporting",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident reporting verified (notifications + SIEM/audit log)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasNotification {
		violations = append(violations, "incident notification not configured")
	}
	if !hasSIEM && !hasAuditLog {
		violations = append(violations, "SIEM integration or audit logging not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IR-6",
		ControlName: "Incident Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident reporting gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable incident notification (notification.enabled=true) and SIEM integration or audit logging",
	}, nil
}

// --- SA Check Functions ---

func (m *FedRAMPModule) checkUnsupportedComponents(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "cyclonedx")
	hasVulnScan := strings.Contains(inputStr, "vuln") || strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "vulnerability")
	_ = strings.Contains(inputStr, "eol")

	if hasSBOM && hasVulnScan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SA-22",
			ControlName: "Unsupported System Components",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Unsupported component detection verified (SBOM + vulnerability scanning)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasSBOM || hasVulnScan {
		partial := "SBOM"
		if !hasSBOM {
			partial = "vulnerability scanning"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SA-22",
			ControlName: "Unsupported System Components",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial unsupported component detection (" + partial + " detected, missing " + map[bool]string{true: "vulnerability scanning", false: "SBOM"}[hasSBOM] + ")",
			Timestamp:   time.Now(),
			Remediation: "Enable both SBOM/AIBOM generation and vulnerability scanning for full unsupported component detection",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SA-22",
		ControlName: "Unsupported System Components",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No unsupported component detection mechanism found",
		Timestamp:   time.Now(),
		Remediation: "Enable AIBOM generation (aibom.enabled=true) and vulnerability scanning (scanner.enabled=true)",
	}, nil
}

// --- SR Check Functions ---

func (m *FedRAMPModule) checkProvenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "cyclonedx")
	hasAttestation := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "trust") || strings.Contains(inputStr, "signature")
	hasVCS := strings.Contains(inputStr, "git") || strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "commit")

	if hasSBOM && (hasAttestation || hasVCS) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SR-4",
			ControlName: "Provenance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Component provenance verified (SBOM + attestation/VCS)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasSBOM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SR-4",
			ControlName: "Provenance",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "SBOM detected but provenance attestation incomplete",
			Timestamp:   time.Now(),
			Remediation: "Enable trust framework attestations (trust.enabled=true) for component provenance tracking",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SR-4",
		ControlName: "Provenance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No provenance tracking mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Enable AIBOM generation (aibom.enabled=true) and trust framework (trust.enabled=true)",
	}, nil
}
