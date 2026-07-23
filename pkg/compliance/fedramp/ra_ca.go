// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP RA + CA Families
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Risk Assessment (RA) and Assessment,
// Authorization, and Monitoring (CA) families.
//
// RA in-scope controls (4):
//   RA-3  Risk Assessment             (automated, Path C — new)
//   RA-5  Vulnerability Scanning      (automated, Path C — new)
//   RA-6  Technical Surveillance       (automated, Path C — new)
//   RA-7  Risk Response                (evidence-mapped, Path C — new)
//
// CA in-scope controls (4):
//   CA-2  Assessments                 (evidence-mapped, Path C — new)
//   CA-7  Continuous Monitoring       (automated, Path C — new)
//   CA-8  Penetration Testing          (evidence-mapped, Path C — new)
//   CA-9  Internal Connections          (evidence-mapped, Path C — new)
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerRAControls wires the RA family controls into the module.
func (m *FedRAMPModule) registerRAControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-3",
		Name:        "Risk Assessment",
		Description: "FedRAMP RA-3: Risk assessment conducted at defined intervals and when changes occur",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-3", "FedRAMP Moderate RA-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-5",
		Name:        "Vulnerability Scanning",
		Description: "FedRAMP RA-5: Vulnerability scanning performed at defined intervals and when new threats emerge",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityScanning,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-5", "FedRAMP Moderate RA-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-6",
		Name:        "Technical Surveillance",
		Description: "FedRAMP RA-6: Technical surveillance of systems for indicators of compromise and anomalous activity",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTechnicalSurveillance,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-6", "FedRAMP Moderate RA-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-7",
		Name:        "Risk Response",
		Description: "FedRAMP RA-7: Risk response actions documented and tracked. AegisGate's compliance scan and drift detection provide risk evidence.",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-7", "FedRAMP Moderate RA-07"},
	})

	// RA-4: Vulnerability Remediation (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-4",
		Name:        "Vulnerability Remediation",
		Description: "FedRAMP RA-4: Vulnerabilities remediated within defined timeframes based on severity",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityRemediation,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-4", "FedRAMP Moderate RA-04"},
	})

	// RA-9: Criticality Analysis (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-RA-9",
		Name:        "Criticality Analysis",
		Description: "FedRAMP RA-9: Organization conducts a criticality analysis for system components. AegisGate's trust framework scoring and component inventory provide the evidence for RA-9.",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 RA-9", "FedRAMP Moderate RA-09"},
	})
}

// registerCAControls wires the CA family controls into the module.
func (m *FedRAMPModule) registerCAControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-2",
		Name:        "Assessments",
		Description: "FedRAMP CA-2: Security assessments conducted by independent assessors. AegisGate generates the compliance scan evidence for the customer's CA-2 package.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-2", "FedRAMP Moderate CA-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-7",
		Name:        "Continuous Monitoring",
		Description: "FedRAMP CA-7: Continuous monitoring program for security controls. AegisGate's CCM scheduler and drift detection provide automated monitoring.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-7", "FedRAMP Moderate CA-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-8",
		Name:        "Penetration Testing",
		Description: "FedRAMP CA-8: Penetration testing at defined intervals. AegisGate's scanner provides continuous scanning; annual pentest is customer's responsibility.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-8", "FedRAMP Moderate CA-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-9",
		Name:        "Internal Connections",
		Description: "FedRAMP CA-9: Internal connections between system components authorized and documented. AegisGate's AIBOM and trust framework attestations provide the evidence.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-9", "FedRAMP Moderate CA-09"},
	})

	// CA-1: Assessment and Authorization Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-1",
		Name:        "Assessment and Authorization Policy and Procedures",
		Description: "FedRAMP CA-1: Organization develops, documents, and disseminates an assessment and authorization policy. AegisGate generates compliance scan evidence for the customer's CA-1 documentation.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-1", "FedRAMP Moderate CA-01"},
	})

	// CA-3: System Interconnections (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-3",
		Name:        "System Interconnections",
		Description: "FedRAMP CA-3: System interconnections authorized and documented. AegisGate's trust framework identity and capability contracts provide the interconnection evidence for CA-3.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-3", "FedRAMP Moderate CA-03"},
	})

	// CA-5: Plan of Action and Milestones (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CA-5",
		Name:        "Plan of Action and Milestones",
		Description: "FedRAMP CA-5: Plan of Action and Milestones (POA&M) for security weaknesses. AegisGate's compliance scan drift detection and CCM provide the evidence for tracking POA&M items.",
		Category:    "Assessment, Authorization, and Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 CA-5", "FedRAMP Moderate CA-05"},
	})
}

// --- RA Check Functions ---

func (m *FedRAMPModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScan := strings.Contains(inputStr, "scan") || strings.Contains(inputStr, "compliance") || strings.Contains(inputStr, "assessment")
	hasThreatModel := strings.Contains(inputStr, "threat") || strings.Contains(inputStr, "risk") || strings.Contains(inputStr, "threat_model")
	hasSchedule := strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "scheduler") || strings.Contains(inputStr, "ccm")

	if hasScan && (hasThreatModel || hasSchedule) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-3",
			ControlName: "Risk Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Risk assessment verified (scanning + threat model/schedule)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasScan {
		violations = append(violations, "compliance scanning not configured")
	}
	if !hasThreatModel && !hasSchedule {
		violations = append(violations, "risk assessment schedule or threat model not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-RA-3",
		ControlName: "Risk Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Risk assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable compliance scanning (compliance.scan=true) and scheduled assessments (ccm.enabled=true)",
	}, nil
}

func (m *FedRAMPModule) checkVulnerabilityScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "vuln") || strings.Contains(inputStr, "vulnerability")
	hasSchedule := strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "ccm") || strings.Contains(inputStr, "continuous")
	_ = strings.Contains(inputStr, "report")

	if hasScanner && hasSchedule {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-5",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanning verified (scanner + scheduled scans)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasScanner {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-5",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanner detected but no scheduled scan cadence configured",
			Timestamp:   time.Now(),
			Remediation: "Enable scheduled scanning (ccm.enabled=true) for continuous vulnerability assessment",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-RA-5",
		ControlName: "Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No vulnerability scanning mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner (scanner.enabled=true) and CCM scheduled scans (ccm.enabled=true)",
	}, nil
}

func (m *FedRAMPModule) checkTechnicalSurveillance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIOC := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "indicator") || strings.Contains(inputStr, "threat_intelligence")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "anomaly_detection") || strings.Contains(inputStr, "behavior")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "audit_log")

	if (hasIOC || hasAnomaly) && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-6",
			ControlName: "Technical Surveillance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Technical surveillance verified (IOC/anomaly detection + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIOC && !hasAnomaly {
		violations = append(violations, "threat/IOC detection not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "security monitoring not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-RA-6",
		ControlName: "Technical Surveillance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Technical surveillance gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable IOC store (ioc.enabled=true), anomaly detection, and security monitoring (monitoring.enabled=true)",
	}, nil
}

// --- CA Check Functions ---

func (m *FedRAMPModule) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCCM := strings.Contains(inputStr, "ccm") || strings.Contains(inputStr, "continuous") || strings.Contains(inputStr, "schedule")
	hasScan := strings.Contains(inputStr, "scan") || strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "compliance")
	_ = strings.Contains(inputStr, "dashboard")

	if hasCCM && hasScan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CA-7",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Continuous monitoring verified (CCM + compliance scanning)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasCCM || hasScan {
		partial := "CCM"
		if !hasCCM {
			partial = "scanning"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CA-7",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial continuous monitoring (" + partial + " detected)",
			Timestamp:   time.Now(),
			Remediation: "Enable both CCM (ccm.enabled=true) and compliance scanning (scanner.enabled=true) for full continuous monitoring",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CA-7",
		ControlName: "Continuous Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No continuous monitoring mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Enable CCM (ccm.enabled=true) and compliance scanning (scanner.enabled=true) for FedRAMP CA-7",
	}, nil
}

// checkVulnerabilityRemediation verifies vulnerability remediation SLAs. Maps to RA-4.
func (m *FedRAMPModule) checkVulnerabilityRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "vuln") || strings.Contains(inputStr, "vulnerability")
	hasSLA := strings.Contains(inputStr, "sla") || strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "sla_enabled")
	hasTracking := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "audit_log")

	if hasVulnScan && hasSLA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-4",
			ControlName: "Vulnerability Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability remediation verified (scanning + SLA tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasVulnScan && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-RA-4",
			ControlName: "Vulnerability Remediation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanning detected but SLA tracking not configured",
			Timestamp:   time.Now(),
			Remediation: "Enable SLA tracking (sla.enabled=true) for vulnerability remediation timeframes",
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasSLA && !hasTracking {
		violations = append(violations, "remediation SLA tracking not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-RA-4",
		ControlName: "Vulnerability Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability remediation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning (scanner.enabled=true) and SLA tracking (sla.enabled=true)",
	}, nil
}
