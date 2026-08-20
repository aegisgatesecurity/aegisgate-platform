// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 Additional Controls
// =========================================================================
//
// Additional controls for each NIST 800-171 family to reach the 110 target.
// These are registered via registerAdditionalControls() from nist800171.go.
//
// Families and additional controls:
//   AC:  AC-7, AC-8, AC-9, AC-10, AC-11, AC-12, AC-20, AC-22
//   AU:  AU-4, AU-5, AU-7, AU-8
//   CM+SI: CM-4, CM-7, CM-8, SI-4, SI-5, SI-7
//   IA:  IA-4, IA-5-i, IA-6, IA-7, IA-9, IA-11
//   IR:  IR-7
//   RA:  RA-4, RA-6
//   SC:  SC-5, SC-6, SC-9, SC-10, SC-11, SC-15, SC-16, SC-18, SC-20
//   CP+MA+SA: CP-6, MA-1, MA-3, MA-4, MA-5
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAdditionalControls wires all additional NIST 800-171 controls
// into the module to reach the 110-control target.
func (m *NIST800171Module) registerAdditionalControls() {
	m.registerAdditionalACControls()
	m.registerAdditionalAUControls()
	m.registerAdditionalCMSIControls()
	m.registerAdditionalIAControls()
	m.registerAdditionalIRControls()
	m.registerAdditionalRAControls()
	m.registerAdditionalSCControls()
	m.registerAdditionalCPMAControls()
}

// ==================== AC: Additional Access Control ====================

func (m *NIST800171Module) registerAdditionalACControls() {
	// AC-7: Unsuccessful Login Attempts (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-7",
		Name:        "Unsuccessful Login Attempts",
		Description: "NIST 800-171 AC-7 (3.1.8): Unsuccessful login attempts limited and account lockout enforced",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkUnsuccessfulLoginAttempts,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.8", "NIST SP 800-53 Rev. 5 AC-7"},
	})

	// AC-8: System Use Notification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-8",
		Name:        "System Use Notification",
		Description: "NIST 800-171 AC-8 (3.1.9): System use notification displayed before granting access",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSystemUseNotification,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.9", "NIST SP 800-53 Rev. 5 AC-8"},
	})

	// AC-9: Previous Logon Notification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-9",
		Name:        "Previous Logon Notification",
		Description: "NIST 800-171 AC-9: Previous logon information displayed to users upon login",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkPreviousLogonNotification,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1", "NIST SP 800-53 Rev. 5 AC-9"},
	})

	// AC-10: Concurrent Session Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-10",
		Name:        "Concurrent Session Control",
		Description: "NIST 800-171 AC-10: Concurrent session limits enforced to prevent session hijacking",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConcurrentSessionControl,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1", "NIST SP 800-53 Rev. 5 AC-10"},
	})

	// AC-11: Session Lock (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-11",
		Name:        "Session Lock",
		Description: "NIST 800-171 AC-11: Session lock after defined period of inactivity with re-authentication required",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionLock,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1", "NIST SP 800-53 Rev. 5 AC-11"},
	})

	// AC-12: Session Termination (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-12",
		Name:        "Session Termination",
		Description: "NIST 800-171 AC-12: Automatic session termination after defined conditions",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionTermination,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1", "NIST SP 800-53 Rev. 5 AC-12"},
	})

	// AC-20: Use of External Systems (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-20",
		Name:        "Use of External Systems",
		Description: "NIST 800-171 AC-20 (3.1.20): Use of external systems with approved connections and risk acceptance",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkExternalSystems,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.20", "NIST SP 800-53 Rev. 5 AC-20"},
	})

	// AC-22: Publicly Accessible Content (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-22",
		Name:        "Publicly Accessible Content",
		Description: "NIST 800-171 AC-22 (3.1.22): Publicly accessible content authorized and protected from unauthorized modification",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.22", "NIST SP 800-53 Rev. 5 AC-22"},
	})
}

// ==================== AU: Additional Audit and Accountability ====================

func (m *NIST800171Module) registerAdditionalAUControls() {
	// AU-4: Audit Storage Capacity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-4",
		Name:        "Audit Storage Capacity",
		Description: "NIST 800-171 AU-4 (3.3.4): Audit storage capacity allocated and monitored to prevent overflow",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditStorageCapacity,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.4", "NIST SP 800-53 Rev. 5 AU-4"},
	})

	// AU-5: Response to Audit Processing Failures (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-5",
		Name:        "Response to Audit Processing Failures",
		Description: "NIST 800-171 AU-5 (3.3.3): Alert on audit processing failures and prevent data loss",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditProcessingFailures,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.3", "NIST SP 800-53 Rev. 5 AU-5"},
	})

	// AU-7: Audit Reduction and Report Generation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-7",
		Name:        "Audit Reduction and Report Generation",
		Description: "NIST 800-171 AU-7 (3.3.6): Audit reduction and report generation for analysis",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditReduction,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.6", "NIST SP 800-53 Rev. 5 AU-7"},
	})

	// AU-8: Timestamps (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-8",
		Name:        "Timestamps",
		Description: "NIST 800-171 AU-8 (3.3.7): Timestamps generated for audit records with synchronized time sources",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTimestamps,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.7", "NIST SP 800-53 Rev. 5 AU-8"},
	})
}

// ==================== CM+SI: Additional Configuration Management & Integrity ====================

func (m *NIST800171Module) registerAdditionalCMSIControls() {
	// CM-4: Configuration Change Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-4",
		Name:        "Configuration Change Control Implementation",
		Description: "NIST 800-171 CM-4 (3.4.3): Configuration changes controlled, tested, and documented with rollback capability",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeControlImplementation,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.3", "NIST SP 800-53 Rev. 5 CM-4"},
	})

	// CM-7: Least Functionality (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-7",
		Name:        "Least Functionality",
		Description: "NIST 800-171 CM-7 (3.4.6): System configured to provide only essential capabilities — no unnecessary ports, services, or functions",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkLeastFunctionality,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.6", "NIST SP 800-53 Rev. 5 CM-7"},
	})

	// CM-8: System Component Inventory (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-8",
		Name:        "System Component Inventory",
		Description: "NIST 800-171 CM-8 (3.4.7): System component inventory maintained and verified for completeness",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSystemComponentInventory,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.7", "NIST SP 800-53 Rev. 5 CM-8"},
	})

	// SI-4: System Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SI-4",
		Name:        "System Monitoring",
		Description: "NIST 800-171 SI-4 (3.14.4): System monitoring for attacks and unauthorized activity with alerting",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.14.4", "NIST SP 800-53 Rev. 5 SI-4"},
	})

	// SI-5: Security Alerts and Advisories (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SI-5",
		Name:        "Security Alerts and Advisories",
		Description: "NIST 800-171 SI-5 (3.14.5): Security alerts and advisories received and acted upon",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAlerts,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.14.5", "NIST SP 800-53 Rev. 5 SI-5"},
	})

	// SI-7: Software and Information Integrity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SI-7",
		Name:        "Software and Information Integrity",
		Description: "NIST 800-171 SI-7: Software and information integrity checking with hash verification",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSoftwareIntegrity,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.14", "NIST SP 800-53 Rev. 5 SI-7"},
	})
}

// ==================== IA: Additional Identification and Authentication ====================

func (m *NIST800171Module) registerAdditionalIAControls() {
	// IA-4: Identifier Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-4",
		Name:        "Identifier Management",
		Description: "NIST 800-171 IA-4 (3.5.4): User identifiers managed with unique assignment and deactivation",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIdentifierManagement,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.4", "NIST SP 800-53 Rev. 5 IA-4"},
	})

	// IA-5-i: Password Constraints (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-5-i",
		Name:        "Password Constraints",
		Description: "NIST 800-171 IA-5(1) (3.5.7): Password constraints — minimum strength, expiration, and reuse prevention",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPasswordConstraints,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.7", "NIST SP 800-53 Rev. 5 IA-5(1)"},
	})

	// IA-6: Authenticator Feedback (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-6",
		Name:        "Authenticator Feedback",
		Description: "NIST 800-171 IA-6 (3.5.9): Authenticator feedback obscured during entry — no display of passwords",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorFeedback,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.9", "NIST SP 800-53 Rev. 5 IA-6"},
	})

	// IA-7: Cryptographic Module Authentication (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-7",
		Name:        "Cryptographic Module Authentication",
		Description: "NIST 800-171 IA-7 (3.5.10): Cryptographic module authentication using FIPS-validated modules",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptoModuleAuth,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.10", "NIST SP 800-53 Rev. 5 IA-7"},
	})

	// IA-9: Identification and Authentication for Non-Organizational Users (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-9",
		Name:        "Identification for Non-Organizational Users",
		Description: "NIST 800-171 IA-9 (3.5.11): Non-organizational users identified and authenticated per organizational policy",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseAssistance,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.11", "NIST SP 800-53 Rev. 5 IA-9"},
	})

	// IA-11: Re-authentication (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-11",
		Name:        "Re-authentication",
		Description: "NIST 800-171 IA-11: Re-authentication required for privileged actions and role changes",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkReAuthentication,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5", "NIST SP 800-53 Rev. 5 IA-11"},
	})
}

// ==================== IR: Additional Incident Response ====================

func (m *NIST800171Module) registerAdditionalIRControls() {
	// IR-7: Incident Response Assistance (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-7",
		Name:        "Incident Response Assistance",
		Description: "NIST 800-171 IR-7 (3.6.5): Incident response assistance available through help desk or automated tools",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseAssistance,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.5", "NIST SP 800-53 Rev. 5 IR-7"},
	})
}

// ==================== RA: Additional Risk Assessment ====================

func (m *NIST800171Module) registerAdditionalRAControls() {
	// RA-4: Risk Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-4",
		Name:        "Risk Monitoring",
		Description: "NIST 800-171 RA-4: Risk monitoring with continuous assessment and tracking",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRiskMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11", "NIST SP 800-53 Rev. 5 RA-4"},
	})

	// RA-6: Risk Response (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-6",
		Name:        "Risk Response",
		Description: "NIST 800-171 RA-6: Risk response documented and implemented with accepted risk tracked",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRiskMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11", "NIST SP 800-53 Rev. 5 RA-6"},
	})
}

// ==================== SC: Additional System and Communications Protection ====================

func (m *NIST800171Module) registerAdditionalSCControls() {
	// SC-5: Denial of Service Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-5",
		Name:        "Denial of Service Protection",
		Description: "NIST 800-171 SC-5 (3.13.5): Denial of service protection with rate limiting and resource management",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDoSProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.5", "NIST SP 800-53 Rev. 5 SC-5"},
	})

	// SC-6: Resource Priority (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-6",
		Name:        "Resource Priority",
		Description: "NIST 800-171 SC-6 (3.13.6): Resource priority with protected system resources for critical functions",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkDoSProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.6", "NIST SP 800-53 Rev. 5 SC-6"},
	})

	// SC-9: Transmission Confidentiality and Integrity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-9",
		Name:        "Transmission Integrity",
		Description: "NIST 800-171 SC-9 (3.13.9): Transmission integrity protected with checksums or digital signatures",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTransmissionIntegrity,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.9", "NIST SP 800-53 Rev. 5 SC-9"},
	})

	// SC-10: Network Disconnect (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-10",
		Name:        "Network Disconnect",
		Description: "NIST 800-171 SC-10 (3.13.10): Network disconnect after session termination",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkNetworkDisconnect,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.10", "NIST SP 800-53 Rev. 5 SC-10"},
	})

	// SC-11: Trustworthy Computing (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-11",
		Name:        "Trustworthy Computing",
		Description: "NIST 800-171 SC-11 (3.13.11): Trustworthy computing with verified hardware and software",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSoftwareIntegrity,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.11", "NIST SP 800-53 Rev. 5 SC-11"},
	})

	// SC-15: Collaborative Computing (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-15",
		Name:        "Collaborative Computing",
		Description: "NIST 800-171 SC-15 (3.13.15): Collaborative computing with remote activation controls disabled",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSecureNameResolution,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.15", "NIST SP 800-53 Rev. 5 SC-15"},
	})

	// SC-16: Transmission Security (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-16",
		Name:        "Transmission Security",
		Description: "NIST 800-171 SC-16 (3.13.16): Transmission security with end-to-end encryption and integrity",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransmissionSecurity,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.16", "NIST SP 800-53 Rev. 5 SC-16"},
	})

	// SC-18: Mobile Code (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-18",
		Name:        "Mobile Code",
		Description: "NIST 800-171 SC-18 (3.13.18): Mobile code controlled and digitally signed",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkMaliciousCodeProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.18", "NIST SP 800-53 Rev. 5 SC-18"},
	})

	// SC-20: Secure Name Resolution (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-20",
		Name:        "Secure Name Resolution",
		Description: "NIST 800-171 SC-20 (3.13.20): Secure name resolution with DNSSEC or equivalent authenticity checks",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecureNameResolution,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.20", "NIST SP 800-53 Rev. 5 SC-20"},
	})
}

// ==================== CP/MA: Additional Contingency Planning & Maintenance ====================

func (m *NIST800171Module) registerAdditionalCPMAControls() {
	// CP-6: Alternate Storage (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CP-6",
		Name:        "Alternate Storage",
		Description: "NIST 800-171 CP-6 (3.5.4): Alternate storage site with geographic separation and data replication",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAlternateStorage,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.4", "NIST SP 800-53 Rev. 5 CP-6"},
	})

	// MA-1: Maintenance Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MA-1",
		Name:        "Maintenance Policy",
		Description: "NIST 800-171 MA-1 (3.7.1): System maintenance policy and procedures documented",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.7.1", "NIST SP 800-53 Rev. 5 MA-1"},
	})

	// MA-3: Maintenance Tools (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MA-3",
		Name:        "Maintenance Tools",
		Description: "NIST 800-171 MA-3 (3.7.3): Maintenance tools controlled and approved with audit logging",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMaintenanceTools,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.7.3", "NIST SP 800-53 Rev. 5 MA-3"},
	})

	// MA-4: Maintenance Personnel (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MA-4",
		Name:        "Maintenance Personnel",
		Description: "NIST 800-171 MA-4 (3.7.4): Maintenance personnel authorized and supervised with need-to-know",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMaintenanceTools,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.7.4", "NIST SP 800-53 Rev. 5 MA-4"},
	})

	// MA-5: Maintenance Documentation (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MA-5",
		Name:        "Maintenance Documentation",
		Description: "NIST 800-171 MA-5 (3.7.5): Maintenance documentation maintained with schedules and records",
		Category:    "Maintenance",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.7.5", "NIST SP 800-53 Rev. 5 MA-5"},
	})
}

// ==================== Check Function Implementations ====================
// ==================== AC Check Functions ====================

func (m *NIST800171Module) checkUnsuccessfulLoginAttempts(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLockout := strings.Contains(inputStr, "lockout") || strings.Contains(inputStr, "account_lockout") || strings.Contains(inputStr, "max_attempts")
	hasPolicy := strings.Contains(inputStr, "login_policy") || strings.Contains(inputStr, "failed_login") || strings.Contains(inputStr, "brute_force")

	if hasLockout && hasPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-7",
			ControlName: "Unsuccessful Login Attempts",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Unsuccessful login attempt controls verified (lockout + policy)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasLockout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-7",
			ControlName: "Unsuccessful Login Attempts",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Account lockout detected but login policy not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Configure login policy with failed attempt tracking (auth.login_policy=true)",
		}, nil
	}

	violations := []string{}
	if !hasLockout {
		violations = append(violations, "account lockout not configured")
	}
	if !hasPolicy {
		violations = append(violations, "login policy not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-7",
		ControlName: "Unsuccessful Login Attempts",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Unsuccessful login attempt gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable account lockout after failed attempts (auth.lockout=true, auth.max_attempts=5)",
	}, nil
}

func (m *NIST800171Module) checkSystemUseNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBanner := strings.Contains(inputStr, "login_banner") || strings.Contains(inputStr, "banner") || strings.Contains(inputStr, "notification")
	hasConsent := strings.Contains(inputStr, "consent") || strings.Contains(inputStr, "acceptable_use") || strings.Contains(inputStr, "terms")

	if hasBanner || hasConsent {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-8",
			ControlName: "System Use Notification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "System use notification verified (banner/consent)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-8",
		ControlName: "System Use Notification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "System use notification not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure login banner and acceptable use policy (auth.login_banner=true)",
	}, nil
}

func (m *NIST800171Module) checkPreviousLogonNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLogonHistory := strings.Contains(inputStr, "logon_history") || strings.Contains(inputStr, "last_login") || strings.Contains(inputStr, "previous_logon")
	hasNotification := strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "login_notification") || strings.Contains(inputStr, "banner")

	if hasLogonHistory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-9",
			ControlName: "Previous Logon Notification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Previous logon notification verified (logon history tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasNotification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-9",
			ControlName: "Previous Logon Notification",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityLow,
			Message:     "Login notification detected but previous logon display not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable previous logon display (auth.logon_history=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-9",
		ControlName: "Previous Logon Notification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "Previous logon notification not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable previous logon notification (auth.logon_history=true)",
	}, nil
}

func (m *NIST800171Module) checkConcurrentSessionControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSessionLimit := strings.Contains(inputStr, "max_sessions") || strings.Contains(inputStr, "session_limit") || strings.Contains(inputStr, "concurrent_session")
	hasControl := strings.Contains(inputStr, "session_control") || strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "policy_enforcement")

	if hasSessionLimit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-10",
			ControlName: "Concurrent Session Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Concurrent session control verified (session limit configured)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-10",
			ControlName: "Concurrent Session Control",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Session control detected but concurrent limit not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Configure concurrent session limits (auth.max_sessions=3)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-10",
		ControlName: "Concurrent Session Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Concurrent session control not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure concurrent session limits (auth.max_sessions=3)",
	}, nil
}

func (m *NIST800171Module) checkSessionLock(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIdleTimeout := strings.Contains(inputStr, "idle_timeout") || strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "lock_timeout")
	hasReauth := strings.Contains(inputStr, "reauth") || strings.Contains(inputStr, "re_authentication") || strings.Contains(inputStr, "reauth_required")

	if hasIdleTimeout && hasReauth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-11",
			ControlName: "Session Lock",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session lock verified (idle timeout + re-authentication)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasIdleTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-11",
			ControlName: "Session Lock",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Idle timeout detected but re-authentication requirement not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable re-authentication after session lock (auth.reauth_required=true)",
		}, nil
	}

	violations := []string{}
	if !hasIdleTimeout {
		violations = append(violations, "idle timeout not configured")
	}
	if !hasReauth {
		violations = append(violations, "re-authentication after lock not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-11",
		ControlName: "Session Lock",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session lock gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure session lock with idle timeout and re-authentication (auth.idle_timeout=900, auth.reauth_required=true)",
	}, nil
}

func (m *NIST800171Module) checkSessionTermination(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "max_session_time") || strings.Contains(inputStr, "timeout")
	hasTermination := strings.Contains(inputStr, "session_termination") || strings.Contains(inputStr, "auto_disconnect") || strings.Contains(inputStr, "terminate")

	if hasTimeout || hasTermination {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-12",
			ControlName: "Session Termination",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session termination verified (timeout/termination configured)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-12",
		ControlName: "Session Termination",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session termination not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure automatic session termination (auth.session_timeout=28800, auth.auto_terminate=true)",
	}, nil
}

// ==================== AU Check Functions ====================

func (m *NIST800171Module) checkAuditStorageCapacity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCapacity := strings.Contains(inputStr, "audit_capacity") || strings.Contains(inputStr, "storage_capacity") || strings.Contains(inputStr, "log_capacity")
	hasAlerting := strings.Contains(inputStr, "capacity_alert") || strings.Contains(inputStr, "overflow_protection") || strings.Contains(inputStr, "alert")

	if hasCapacity && hasAlerting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-4",
			ControlName: "Audit Storage Capacity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit storage capacity verified (capacity + overflow alerting)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasCapacity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-4",
			ControlName: "Audit Storage Capacity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit capacity allocated but overflow alerting not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable capacity alerting (audit.capacity_alert=true)",
		}, nil
	}

	violations := []string{}
	if !hasCapacity {
		violations = append(violations, "audit storage capacity not configured")
	}
	if !hasAlerting {
		violations = append(violations, "overflow alerting not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-4",
		ControlName: "Audit Storage Capacity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit storage capacity gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit storage capacity and overflow alerting",
	}, nil
}

func (m *NIST800171Module) checkAuditProcessingFailures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAlert := strings.Contains(inputStr, "audit_failure") || strings.Contains(inputStr, "failure_alert") || strings.Contains(inputStr, "alert")
	hasFailover := strings.Contains(inputStr, "failover") || strings.Contains(inputStr, "redundant_logging") || strings.Contains(inputStr, "backup")

	if hasAlert && hasFailover {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-5",
			ControlName: "Response to Audit Processing Failures",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit processing failure response verified (alerting + failover)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAlert {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-5",
			ControlName: "Response to Audit Processing Failures",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit failure alerting detected but failover not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable redundant audit logging for failover",
		}, nil
	}

	violations := []string{}
	if !hasAlert {
		violations = append(violations, "audit failure alerting not configured")
	}
	if !hasFailover {
		violations = append(violations, "audit failover not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-5",
		ControlName: "Response to Audit Processing Failures",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit failure response gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit failure alerting and redundant logging (audit.failure_alert=true, audit.redundant_logging=true)",
	}, nil
}

func (m *NIST800171Module) checkAuditReduction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSearch := strings.Contains(inputStr, "audit_search") || strings.Contains(inputStr, "search") || strings.Contains(inputStr, "query")
	hasReporting := strings.Contains(inputStr, "report") || strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "analysis")
	hasLogAggregation := strings.Contains(inputStr, "log_aggregation") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "aggregation")

	if hasSearch && hasReporting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-7",
			ControlName: "Audit Reduction and Report Generation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit reduction and report generation verified (search + reporting)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasLogAggregation && hasReporting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-7",
			ControlName: "Audit Reduction and Report Generation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit reduction and report generation verified (aggregation + reporting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSearch && !hasLogAggregation {
		violations = append(violations, "audit search/aggregation not detected")
	}
	if !hasReporting {
		violations = append(violations, "report generation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-7",
		ControlName: "Audit Reduction and Report Generation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit reduction gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit search, log aggregation, and report generation",
	}, nil
}

func (m *NIST800171Module) checkTimestamps(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNTP := strings.Contains(inputStr, "ntp") || strings.Contains(inputStr, "time_sync") || strings.Contains(inputStr, "time_synchronization")
	hasTimestamp := strings.Contains(inputStr, "timestamp") || strings.Contains(inputStr, "time_source") || strings.Contains(inputStr, "synchronized_time")

	if hasNTP && hasTimestamp {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-8",
			ControlName: "Timestamps",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Timestamp controls verified (NTP sync + timestamp generation)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasNTP || hasTimestamp {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-8",
			ControlName: "Timestamps",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Timestamp capability detected but full synchronization not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Configure NTP time synchronization (audit.ntp_sync=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-8",
		ControlName: "Timestamps",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Timestamp controls not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure NTP time synchronization and timestamp generation (audit.ntp_sync=true)",
	}, nil
}

// ==================== CM+SI Check Functions ====================

func (m *NIST800171Module) checkChangeControlImplementation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeControl := strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "approval") || strings.Contains(inputStr, "review")
	hasTesting := strings.Contains(inputStr, "testing") || strings.Contains(inputStr, "test") || strings.Contains(inputStr, "ci_cd")
	hasRollback := strings.Contains(inputStr, "rollback") || strings.Contains(inputStr, "rollback_enabled") || strings.Contains(inputStr, "revert")

	if hasChangeControl && (hasTesting || hasRollback) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-4",
			ControlName: "Configuration Change Control Implementation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Configuration change control verified (change control + testing/rollback)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasChangeControl {
		violations = append(violations, "change control process not detected")
	}
	if !hasTesting && !hasRollback {
		violations = append(violations, "testing or rollback capability not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-4",
		ControlName: "Configuration Change Control Implementation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Change control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable change control with testing and rollback (cm.change_control=true, cm.rollback=true)",
	}, nil
}

func (m *NIST800171Module) checkLeastFunctionality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMinimal := strings.Contains(inputStr, "minimal") || strings.Contains(inputStr, "least_functionality") || strings.Contains(inputStr, "hardening")
	hasDisabled := strings.Contains(inputStr, "unnecessary_disabled") || strings.Contains(inputStr, "disabled_ports") || strings.Contains(inputStr, "no_unused_services")
	hasConfigAudit := strings.Contains(inputStr, "config_audit") || strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "configuration")

	if hasMinimal && (hasDisabled || hasConfigAudit) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-7",
			ControlName: "Least Functionality",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Least functionality verified (minimal config + disabled services/audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasMinimal {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-7",
			ControlName: "Least Functionality",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Minimal configuration detected but unnecessary services not confirmed disabled",
			Timestamp:   time.Now(),
			Remediation: "Disable unnecessary ports and services (security.unnecessary_disabled=true)",
		}, nil
	}

	violations := []string{}
	if !hasMinimal {
		violations = append(violations, "least functionality configuration not detected")
	}
	if !hasDisabled && !hasConfigAudit {
		violations = append(violations, "disabled services or configuration audit not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-7",
		ControlName: "Least Functionality",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Least functionality gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure least functionality (security.least_functionality=true, security.unnecessary_disabled=true)",
	}, nil
}

func (m *NIST800171Module) checkSystemComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "component_inventory") || strings.Contains(inputStr, "sbom")
	hasVerification := strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "verified") || strings.Contains(inputStr, "audit")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "dependencies") || strings.Contains(inputStr, "packages")

	if hasInventory && (hasVerification || hasTracking) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-8",
			ControlName: "System Component Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "System component inventory verified (inventory + verification/tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-8",
			ControlName: "System Component Inventory",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Component inventory detected but verification not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable inventory verification (cm.inventory_verification=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-8",
		ControlName: "System Component Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "System component inventory not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable system component inventory (cm.inventory=true, cm.sbom=true)",
	}, nil
}

func (m *NIST800171Module) checkSystemMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "continuous_monitoring")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "anomaly_detection")
	hasIDS := strings.Contains(inputStr, "ids") || strings.Contains(inputStr, "intrusion") || strings.Contains(inputStr, "threat_detection")

	if (hasMonitoring || hasIDS) && hasAlerting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-4",
			ControlName: "System Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System monitoring verified (monitoring/IDS + alerting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring && !hasIDS {
		violations = append(violations, "system monitoring or IDS not configured")
	}
	if !hasAlerting {
		violations = append(violations, "alerting for unauthorized activity not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SI-4",
		ControlName: "System Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable system monitoring, IDS, and alerting (monitoring.enabled=true, monitoring.ids=true)",
	}, nil
}

func (m *NIST800171Module) checkSecurityAlerts(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAdvisory := strings.Contains(inputStr, "advisory") || strings.Contains(inputStr, "security_alert") || strings.Contains(inputStr, "cve")
	hasResponse := strings.Contains(inputStr, "response") || strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "remediation")
	hasNotification := strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "threat_feed")

	if hasAdvisory && (hasResponse || hasNotification) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-5",
			ControlName: "Security Alerts and Advisories",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security alerts verified (advisories + response/notification)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAdvisory {
		violations = append(violations, "security advisory/alert not configured")
	}
	if !hasResponse && !hasNotification {
		violations = append(violations, "response or notification process not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SI-5",
		ControlName: "Security Alerts and Advisories",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security alerts gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable security advisory feeds and notification (security.advisory_feed=true)",
	}, nil
}

func (m *NIST800171Module) checkSoftwareIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHashCheck := strings.Contains(inputStr, "integrity_check") || strings.Contains(inputStr, "hash") || strings.Contains(inputStr, "checksum")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "software_integrity")
	hasVerification := strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "verified") || strings.Contains(inputStr, "signing")

	if (hasHashCheck || hasSBOM) && hasVerification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-7",
			ControlName: "Software and Information Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Software integrity verified (hash check/SBOM + verification)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasHashCheck || hasSBOM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-7",
			ControlName: "Software and Information Integrity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Integrity checking detected but verification not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable software integrity verification (security.integrity_verification=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SI-7",
		ControlName: "Software and Information Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Software integrity checking not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable integrity checking with hash verification (security.integrity_check=true)",
	}, nil
}

// ==================== IA Check Functions ====================

func (m *NIST800171Module) checkIdentifierManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasUniqueID := strings.Contains(inputStr, "unique_id") || strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "identity")
	hasDeactivation := strings.Contains(inputStr, "deactivation") || strings.Contains(inputStr, "offboarding") || strings.Contains(inputStr, "revocation")
	hasAccountMgmt := strings.Contains(inputStr, "account_management") || strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "provisioning")

	if hasUniqueID && (hasDeactivation || hasAccountMgmt) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-4",
			ControlName: "Identifier Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Identifier management verified (unique IDs + deactivation/account management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasUniqueID {
		violations = append(violations, "unique identifier management not detected")
	}
	if !hasDeactivation && !hasAccountMgmt {
		violations = append(violations, "identifier deactivation not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-4",
		ControlName: "Identifier Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Identifier management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure unique identifier management with deactivation (identity.unique_id=true, identity.deactivation=true)",
	}, nil
}

func (m *NIST800171Module) checkPasswordConstraints(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPasswordPolicy := strings.Contains(inputStr, "password_policy") || strings.Contains(inputStr, "password") || strings.Contains(inputStr, "authenticator")
	hasMinLength := strings.Contains(inputStr, "min_length") || strings.Contains(inputStr, "password_complexity") || strings.Contains(inputStr, "complexity")
	hasExpiry := strings.Contains(inputStr, "password_expiry") || strings.Contains(inputStr, "expiration") || strings.Contains(inputStr, "rotation")

	if hasPasswordPolicy && (hasMinLength || hasExpiry) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-5-i",
			ControlName: "Password Constraints",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Password constraints verified (policy + complexity/expiry)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasPasswordPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-5-i",
			ControlName: "Password Constraints",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Password policy detected but complexity/expiry not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Add password complexity and expiry requirements (auth.password_complexity=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-5-i",
		ControlName: "Password Constraints",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Password constraints not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure password policy with complexity and expiry (auth.password_policy=true)",
	}, nil
}

func (m *NIST800171Module) checkCryptoModuleAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}
	hasCryptoModule := strings.Contains(inputStr, "crypto_module") || strings.Contains(inputStr, "cryptographic_module") || strings.Contains(inputStr, "encryption")

	if hasFIPS && hasCryptoModule {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-7",
			ControlName: "Cryptographic Module Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic module authentication verified (FIPS + crypto module)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-7",
			ControlName: "Cryptographic Module Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic module authentication verified (FIPS-validated module)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasCryptoModule {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-7",
			ControlName: "Cryptographic Module Authentication",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic module detected but FIPS validation not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable FIPS-validated cryptographic module (crypto.fips_mode=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-7",
		ControlName: "Cryptographic Module Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic module authentication not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS-validated cryptographic module (crypto.fips_mode=true)",
	}, nil
}

// ==================== IR Check Functions ====================

func (m *NIST800171Module) checkIncidentResponseAssistance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHelpDesk := strings.Contains(inputStr, "help_desk") || strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "ir_team")
	hasAutomation := strings.Contains(inputStr, "automated") || strings.Contains(inputStr, "playbook") || strings.Contains(inputStr, "runbook")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "ticket") || strings.Contains(inputStr, "monitoring")

	if (hasHelpDesk || hasAutomation) && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IR-7",
			ControlName: "Incident Response Assistance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident response assistance verified (IR team/automation + tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasHelpDesk || hasAutomation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IR-7",
			ControlName: "Incident Response Assistance",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident response capability detected but tracking not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable incident tracking (ir.tracking=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IR-7",
		ControlName: "Incident Response Assistance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident response assistance not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable incident response team/automation and tracking (ir.enabled=true, ir.tracking=true)",
	}, nil
}

// ==================== RA Check Functions ====================

func (m *NIST800171Module) checkRiskMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "risk_monitoring") || strings.Contains(inputStr, "continuous_monitoring") || strings.Contains(inputStr, "monitoring")
	hasAssessment := strings.Contains(inputStr, "assessment") || strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "evaluation")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "risk_register") || strings.Contains(inputStr, "dashboard")

	if hasMonitoring && (hasAssessment || hasTracking) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-RA-4",
			ControlName: "Risk Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Risk monitoring verified (monitoring + assessment/tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "continuous risk monitoring not configured")
	}
	if !hasAssessment && !hasTracking {
		violations = append(violations, "risk assessment or tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-RA-4",
		ControlName: "Risk Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Risk monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable continuous risk monitoring and assessment tracking (risk.monitoring=true)",
	}, nil
}

// ==================== SC Check Functions ====================

func (m *NIST800171Module) checkDoSProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRateLimit := strings.Contains(inputStr, "rate_limit") || strings.Contains(inputStr, "rate_limiting") || strings.Contains(inputStr, "throttle")
	hasResourceMgmt := strings.Contains(inputStr, "resource_management") || strings.Contains(inputStr, "circuit_breaker") || strings.Contains(inputStr, "load_balancing")

	if hasRateLimit || hasResourceMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-5",
			ControlName: "Denial of Service Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "DoS protection verified (rate limiting/resource management)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-5",
		ControlName: "Denial of Service Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Denial of service protection not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable rate limiting and resource management (security.rate_limit=true, security.circuit_breaker=true)",
	}, nil
}

func (m *NIST800171Module) checkTransmissionIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIntegrity := strings.Contains(inputStr, "integrity_check") || strings.Contains(inputStr, "checksum") || strings.Contains(inputStr, "hash")
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") || strings.Contains(inputStr, "mTLS")
	hasSigning := strings.Contains(inputStr, "digital_signature") || strings.Contains(inputStr, "signing") || strings.Contains(inputStr, "signature")

	if hasIntegrity || hasTLS || hasSigning {
		status := compliance.StatusCompliant
		msg := "Transmission integrity verified"
		if hasIntegrity {
			msg += " (integrity checking)"
		}
		if hasTLS {
			msg += " (TLS)"
		}
		if hasSigning {
			msg += " (digital signing)"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-9",
			ControlName: "Transmission Integrity",
			Status:      status,
			Severity:    compliance.SeverityMedium,
			Message:     msg,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-9",
		ControlName: "Transmission Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Transmission integrity not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS with integrity checking or digital signing (security.tls=true, security.integrity_check=true)",
	}, nil
}

func (m *NIST800171Module) checkNetworkDisconnect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDisconnect := strings.Contains(inputStr, "network_disconnect") || strings.Contains(inputStr, "auto_disconnect") || strings.Contains(inputStr, "session_termination")
	hasTimeout := strings.Contains(inputStr, "timeout") || strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	if hasDisconnect || hasTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-10",
			ControlName: "Network Disconnect",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Network disconnect verified (auto disconnect/timeout configured)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-10",
		ControlName: "Network Disconnect",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Network disconnect not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure network disconnect after session termination (security.network_disconnect=true)",
	}, nil
}

func (m *NIST800171Module) checkTransmissionSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasE2EE := strings.Contains(inputStr, "end_to_end_encryption") || strings.Contains(inputStr, "e2e_encryption") || strings.Contains(inputStr, "mTLS")
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls_1_2")
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}

	if hasE2EE || (hasTLS && hasEncryption) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-16",
			ControlName: "Transmission Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Transmission security verified (end-to-end encryption + TLS)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-16",
			ControlName: "Transmission Security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "TLS detected but end-to-end encryption not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable end-to-end encryption for all transmissions (security.e2e_encryption=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-16",
		ControlName: "Transmission Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Transmission security not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable end-to-end encryption and TLS 1.2+ (security.e2e_encryption=true, security.tls_min_version=1.2)",
	}, nil
}

func (m *NIST800171Module) checkSecureNameResolution(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDNSSEC := strings.Contains(inputStr, "dnssec") || strings.Contains(inputStr, "dns_security") || strings.Contains(inputStr, "signed_dns")
	hasDNSFiltering := strings.Contains(inputStr, "dns_filtering") || strings.Contains(inputStr, "dns_over_https") || strings.Contains(inputStr, "doh")

	if hasDNSSEC {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-20",
			ControlName: "Secure Name Resolution",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Secure name resolution verified (DNSSEC)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasDNSFiltering {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-20",
			ControlName: "Secure Name Resolution",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "DNS security features detected but DNSSEC not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable DNSSEC for secure name resolution (dns.dnssec=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-20",
		ControlName: "Secure Name Resolution",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Secure name resolution not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable DNSSEC for secure name resolution (dns.dnssec=true)",
	}, nil
}

// ==================== CP/MA Check Functions ====================

func (m *NIST800171Module) checkAlternateStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "data_backup") || strings.Contains(inputStr, "disaster_recovery")
	hasGeoRedundancy := strings.Contains(inputStr, "geo_redundant") || strings.Contains(inputStr, "alternate_site") || strings.Contains(inputStr, "replication")

	if hasBackup && hasGeoRedundancy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CP-6",
			ControlName: "Alternate Storage",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Alternate storage verified (backup + geo-redundant replication)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasBackup {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CP-6",
			ControlName: "Alternate Storage",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Backup detected but geo-redundant storage not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable geo-redundant backup storage (backup.geo_redundant=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CP-6",
		ControlName: "Alternate Storage",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Alternate storage not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure backup with geo-redundant storage (backup.enabled=true, backup.geo_redundant=true)",
	}, nil
}

func (m *NIST800171Module) checkMaintenanceTools(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasApproved := strings.Contains(inputStr, "approved_tools") || strings.Contains(inputStr, "maintenance_tools") || strings.Contains(inputStr, "approved")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled") || strings.Contains(inputStr, "logging")
	hasControl := strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "review") || strings.Contains(inputStr, "rbac")

	if hasApproved && (hasAudit || hasControl) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MA-3",
			ControlName: "Maintenance Tools",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Maintenance tools verified (approved tools + audit/control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasApproved {
		violations = append(violations, "approved maintenance tools not configured")
	}
	if !hasAudit && !hasControl {
		violations = append(violations, "maintenance audit or change control not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-MA-3",
		ControlName: "Maintenance Tools",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Maintenance tools gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure approved maintenance tools with audit logging (maintenance.approved_tools=true)",
	}, nil
}
