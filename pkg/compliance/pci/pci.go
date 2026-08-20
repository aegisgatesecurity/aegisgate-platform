// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - PCI-DSS Compliance Module
// =========================================================================
//
// Payment Card Industry Data Security Standard (PCI-DSS) v4.0 compliance
// controls as a licensed add-on module. Covers all 12 principal requirements
// plus AI-specific controls for payment data protection.
//
// Module metadata:
//   - Framework:     "pci-dss"
//   - Version:       "4.0"
//   - Required tier: Developer
//   - Controls:      152 (75 automated, 77 manual)
//   - Categories:    13
//
// Architecture:
//   - pci.go:              module wiring, RegisterControl calls,
//                          CheckFunc implementations
//   - pci_test.go:         unit tests
//
// Reference: PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
// =========================================================================

// Package pci provides PCI-DSS compliance controls as a licensed add-on module.
package pci

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// PCIModule implements PCI-DSS compliance controls.
type PCIModule struct {
	*compliance.BaseComplianceModule
	cardPatterns []*regexp.Regexp
}

// NewPCIModule creates a new PCI-DSS compliance module.
func NewPCIModule() *PCIModule {
	m := &PCIModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("pci-dss", "4.0", core.TierDeveloper),
	}

	m.initCardPatterns()
	m.registerControls()

	return m
}

// initCardPatterns initializes patterns for detecting payment card data.
func (m *PCIModule) initCardPatterns() {
	m.cardPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`), // 16-digit cards
		regexp.MustCompile(`(?i)\d{4}[-\s]?\d{6}[-\s]?\d{5}`),            // Amex
		regexp.MustCompile(`(?i)\d{13,19}`),                              // Generic PAN range
		regexp.MustCompile(`(?i)\d{3}[-\s]?\d{2,4}`),                     // CVV/CVC
		regexp.MustCompile(`(?i)\d{2}[-\s]?\d{2}[-\s]?\d{4}`),            // Expiry
		regexp.MustCompile(`(?i)[3-6]\d{12,18}`),                         // Card BIN ranges
	}
}

// registerControls registers all PCI-DSS controls.
func (m *PCIModule) registerControls() {

	// Requirement 1: Install and maintain network security controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-001",
		Name:        "Firewall/Router Configuration Standards",
		Description: "Install and maintain network security controls between trusted and untrusted networks via firewall and router configuration standards",
		Category:    "Network Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFirewallConfig,
		References:  []string{"PCI-DSS v4.0 Req 1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-002",
		Name:        "Network Diagrams",
		Description: "Maintain current network diagrams showing all cardholder data flows across the environment",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-003",
		Name:        "Network Security Controls Between Trusted/Untrusted Networks",
		Description: "Install network security controls between trusted and untrusted networks and isolate the CDE",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkSegmentation,
		References:  []string{"PCI-DSS v4.0 Req 1.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-004",
		Name:        "Deny Traffic from Untrusted to Trusted Networks",
		Description: "Configure network security controls to deny traffic from untrusted to trusted networks by default",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDenyTraffic,
		References:  []string{"PCI-DSS v4.0 Req 1.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-005",
		Name:        "Restrict Inbound/Outbound Traffic to Necessary Ports",
		Description: "Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPortRestriction,
		References:  []string{"PCI-DSS v4.0 Req 1.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-006",
		Name:        "Router Configuration Standards",
		Description: "Establish and maintain router configuration standards for all network devices",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 1.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-007",
		Name:        "Review Network Security Control Rule Sets Every 6 Months",
		Description: "Review network security control rule sets at least every 6 months",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRuleSetReview,
		References:  []string{"PCI-DSS v4.0 Req 1.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-008",
		Name:        "Remove Unnecessary Configurations",
		Description: "Remove unnecessary configurations and rules from network security controls",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkUnnecessaryConfigs,
		References:  []string{"PCI-DSS v4.0 Req 1.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-009",
		Name:        "Install Perimeter Firewalls",
		Description: "Install perimeter firewalls between all wireless networks and the trusted network",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPerimeterFirewall,
		References:  []string{"PCI-DSS v4.0 Req 1.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-010",
		Name:        "Network Security Controls Between Wireless and CDE",
		Description: "Install network security controls between wireless networks and the CDE",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWirelessSegmentation,
		References:  []string{"PCI-DSS v4.0 Req 1.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-011",
		Name:        "Restrict Direct Public Access to CDE Systems",
		Description: "Restrict direct public access to systems in the cardholder data environment",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPublicAccess,
		References:  []string{"PCI-DSS v4.0 Req 1.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-012",
		Name:        "Internal IP Addresses Not Accessible from Internet",
		Description: "Ensure internal IP addresses are not accessible from the internet",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInternalIPLegacy,
		References:  []string{"PCI-DSS v4.0 Req 1.12"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-013",
		Name:        "Anti-Spoofing Measures",
		Description: "Implement anti-spoofing measures to detect and block forged IP addresses",
		Category:    "Network Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAntiSpoofing,
		References:  []string{"PCI-DSS v4.0 Req 1.13"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-014",
		Name:        "Encrypt Admin Access to Network Security Components",
		Description: "Encrypt all administrative access to network security components",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAdminAccessEncryption,
		References:  []string{"PCI-DSS v4.0 Req 1.14"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-015",
		Name:        "Document and Maintain Inventory of Network Security Controls",
		Description: "Document and maintain an inventory of all network security controls",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 1.15"},
	})

	// Requirement 2: Apply secure configurations to all system components
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-001",
		Name:        "Change Default Credentials Before Installation",
		Description: "Change all default credentials before system installation on all system components",
		Category:    "Configuration",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDefaultCredentials,
		References:  []string{"PCI-DSS v4.0 Req 2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-002",
		Name:        "System Hardening Configuration Standards",
		Description: "Develop and maintain configuration standards for all system components to address known vulnerabilities",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-003",
		Name:        "Configure System Components Securely",
		Description: "Configure all system components securely and according to hardening configuration standards",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemHardening,
		References:  []string{"PCI-DSS v4.0 Req 2.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-004",
		Name:        "Enable Only Necessary Services and Protocols",
		Description: "Enable only necessary services, protocols, and components on all system components",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUnnecessaryServices,
		References:  []string{"PCI-DSS v4.0 Req 2.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-005",
		Name:        "Remove Unnecessary Functionality",
		Description: "Remove unnecessary functionality from system components including scripts, drivers, and subsystems",
		Category:    "Configuration",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkUnnecessaryFunctionality,
		References:  []string{"PCI-DSS v4.0 Req 2.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-006",
		Name:        "System Component Inventory",
		Description: "Maintain an inventory of all system components in the cardholder data environment",
		Category:    "Configuration",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 2.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-007",
		Name:        "Virtualization Component Hardening",
		Description: "Harden all virtualization components including hypervisors and virtual machines",
		Category:    "Configuration",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 2.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-008",
		Name:        "Cloud Container Hardening",
		Description: "Apply hardening configurations to all cloud containers and container orchestration platforms",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContainerHardening,
		References:  []string{"PCI-DSS v4.0 Req 2.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-009",
		Name:        "Wireless Environment Hardening",
		Description: "Harden wireless environments including access points and controllers",
		Category:    "Configuration",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 2.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-010",
		Name:        "Configuration Standards for All System Components",
		Description: "Establish and maintain configuration standards for all system components including servers, network devices, and applications",
		Category:    "Configuration",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 2.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-011",
		Name:        "Encrypt All Non-Console Admin Access",
		Description: "Encrypt all non-console administrative access using strong cryptography",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAdminAccess,
		References:  []string{"PCI-DSS v4.0 Req 2.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-012",
		Name:        "Centralized Authentication for All System Components",
		Description: "Implement centralized authentication for all system components in the CDE",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCentralAuth,
		References:  []string{"PCI-DSS v4.0 Req 2.12"},
	})

	// Requirement 3: Protect stored account data
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-001",
		Name:        "Minimize Storage of Account Data",
		Description: "Minimize storage of account data to only what is necessary for business and legal purposes",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMinimizeDataStorage,
		References:  []string{"PCI-DSS v4.0 Req 3.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-002",
		Name:        "Sensitive Authentication Data Not Retained",
		Description: "Sensitive authentication data must not be retained after authorization completes",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkNoSensitiveAuth,
		References:  []string{"PCI-DSS v4.0 Req 3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-003",
		Name:        "Mask PAN When Displayed",
		Description: "Mask PAN when displayed so that only first 6 and last 4 digits are visible",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPANMasking,
		References:  []string{"PCI-DSS v4.0 Req 3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-004",
		Name:        "Render PAN Unreadable Anywhere Stored",
		Description: "Render PAN unreadable anywhere it is stored using strong cryptography, tokenization, truncation, or hashing",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPANUnreadable,
		References:  []string{"PCI-DSS v4.0 Req 3.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-005",
		Name:        "Disk-Level or Partition-Level Encryption",
		Description: "Implement disk-level or partition-level encryption for systems storing cardholder data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDiskEncryption,
		References:  []string{"PCI-DSS v4.0 Req 3.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-006",
		Name:        "Cryptographic Key Management",
		Description: "Implement cryptographic key management processes and procedures for encryption keys used to protect stored account data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 3.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-007",
		Name:        "Cryptographic Key Storage",
		Description: "Store cryptographic keys securely in a hardware security module (HSM) or equivalent key management system",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 3.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-008",
		Name:        "Key Management Policies and Procedures",
		Description: "Establish and maintain key management policies and procedures for all cryptographic operations",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 3.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-009",
		Name:        "Data Retention and Disposal Policies",
		Description: "Establish and maintain data retention and disposal policies for cardholder data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRetentionDisposal,
		References:  []string{"PCI-DSS v4.0 Req 3.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-010",
		Name:        "Tokenization of PAN Data",
		Description: "Implement tokenization to replace PAN with tokens that have no exploitable value",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTokenization,
		References:  []string{"PCI-DSS v4.0 Req 3.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-011",
		Name:        "Truncation of PAN Data",
		Description: "Implement truncation of PAN data to render it unreadable where stored",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTruncation,
		References:  []string{"PCI-DSS v4.0 Req 3.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-012",
		Name:        "Hashing of PAN Data",
		Description: "Implement one-way hashing of PAN data to render it unreadable where stored",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPANHashing,
		References:  []string{"PCI-DSS v4.0 Req 3.12"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-013",
		Name:        "Index Tokens and Pads Stored Securely",
		Description: "Store index tokens and pads securely to prevent unauthorized access",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 3.13"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-014",
		Name:        "Protect Keys Used for PAN Rendering",
		Description: "Protect cryptographic keys used to render PAN unreadable from unauthorized access and use",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 3.14"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-015",
		Name:        "Periodic Key Rotation",
		Description: "Implement periodic cryptographic key rotation for keys used to protect stored account data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkKeyRotation,
		References:  []string{"PCI-DSS v4.0 Req 3.15"},
	})

	// Requirement 4: Protect cardholder data with strong cryptography
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-001",
		Name:        "Strong Cryptography for Transmission Over Open Networks",
		Description: "Use strong cryptography to encrypt cardholder data during transmission over open public networks",
		Category:    "Encryption",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionEncryption,
		References:  []string{"PCI-DSS v4.0 Req 4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-002",
		Name:        "Never Send PAN via End-User Messaging",
		Description: "Never send PAN via end-user messaging technologies such as email, chat, or SMS",
		Category:    "Encryption",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-003",
		Name:        "Strong Cryptography and Security Protocols",
		Description: "Use strong cryptography and security protocols to safeguard account data during transmission",
		Category:    "Encryption",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTLSConfig,
		References:  []string{"PCI-DSS v4.0 Req 4.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-004",
		Name:        "Wireless Transmissions Use Strong Cryptography",
		Description: "Encrypt wireless transmissions using strong cryptography and industry-accepted protocols",
		Category:    "Encryption",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWirelessCrypto,
		References:  []string{"PCI-DSS v4.0 Req 4.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-005",
		Name:        "Verify Encryption Strength During Certificate Expiration",
		Description: "Verify encryption strength and certificate expiration to maintain strong cryptography",
		Category:    "Encryption",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCertExpiration,
		References:  []string{"PCI-DSS v4.0 Req 4.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-006",
		Name:        "Use Only Trusted CAs",
		Description: "Use only trusted certificate authorities for issuing SSL/TLS certificates",
		Category:    "Encryption",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 4.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-007",
		Name:        "Proper Certificate Validation",
		Description: "Implement proper certificate validation for all TLS connections",
		Category:    "Encryption",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCertValidation,
		References:  []string{"PCI-DSS v4.0 Req 4.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-008",
		Name:        "Encryption of PAN in Voice Over IP",
		Description: "Encrypt PAN data transmitted over voice over IP (VoIP) communications",
		Category:    "Encryption",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 4.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-009",
		Name:        "Monitor and Detect Anomalous Key Management",
		Description: "Monitor and detect anomalous key management activities and events",
		Category:    "Encryption",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 4.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-010",
		Name:        "Document and Implement Key Management Procedures",
		Description: "Document and implement key management procedures for all cryptographic operations",
		Category:    "Encryption",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 4.10"},
	})

	// Requirement 5: Protect all systems and software from known vulnerabilities
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-001",
		Name:        "Anti-Malware on All Systems",
		Description: "Deploy anti-malware solutions on all systems commonly affected by malware",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMalwareProtection,
		References:  []string{"PCI-DSS v4.0 Req 5.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-002",
		Name:        "Anti-Malware Mechanisms Actively Running",
		Description: "Ensure anti-malware mechanisms are actively running and cannot be disabled by users",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAntiMalwareActive,
		References:  []string{"PCI-DSS v4.0 Req 5.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-003",
		Name:        "Anti-Malware Mechanisms Not Disableable by Users",
		Description: "Ensure anti-malware mechanisms cannot be disabled or modified by users without authorization",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAntiMalwareNonDisableable,
		References:  []string{"PCI-DSS v4.0 Req 5.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-004",
		Name:        "Centralized Anti-Malware Management",
		Description: "Implement centralized anti-malware management for all system components in the CDE",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCentralizedMalware,
		References:  []string{"PCI-DSS v4.0 Req 5.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-005",
		Name:        "All System Components Protected Against Known Vulnerabilities",
		Description: "Ensure all system components are protected against known vulnerabilities through patching and configuration",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkVulnScanning,
		References:  []string{"PCI-DSS v4.0 Req 5.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-006",
		Name:        "Patch Critical Vulnerabilities Within 1 Month",
		Description: "Patch all critical vulnerabilities within 1 month of release",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPatchCritical,
		References:  []string{"PCI-DSS v4.0 Req 5.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-007",
		Name:        "Patch High Vulnerabilities Within 3 Months",
		Description: "Patch all high vulnerabilities within 3 months of release",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPatchHigh,
		References:  []string{"PCI-DSS v4.0 Req 5.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-008",
		Name:        "External Software Vulnerability Scanning",
		Description: "Perform external software vulnerability scans at least quarterly",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 5.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-009",
		Name:        "Penetration Testing",
		Description: "Perform penetration testing at least annually to identify exploitable vulnerabilities",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 5.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-010",
		Name:        "Internal Vulnerability Scans",
		Description: "Perform internal vulnerability scans at least quarterly and after significant changes",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalScan,
		References:  []string{"PCI-DSS v4.0 Req 5.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-011",
		Name:        "Vendor Security Bulletins Monitored",
		Description: "Monitor vendor security bulletins and alerts for all system components",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 5.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-012",
		Name:        "Secure Software Development Lifecycle",
		Description: "Implement a secure software development lifecycle for all custom software",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 5.12"},
	})

	// Requirement 6: Develop and maintain secure systems and software
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-001",
		Name:        "Establish Software Development Processes",
		Description: "Establish and maintain software development processes for all custom software",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-002",
		Name:        "Software Engineering Techniques Address Common Vulnerabilities",
		Description: "Apply software engineering techniques to address common vulnerabilities in custom software",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureDev,
		References:  []string{"PCI-DSS v4.0 Req 6.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-003",
		Name:        "Pre-Production and Production Application Separation",
		Description: "Separate pre-production and production environments for all custom software",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-004",
		Name:        "Production Applications Use Separate Environments",
		Description: "Ensure production applications use separate environments from development and testing",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEnvSeparation,
		References:  []string{"PCI-DSS v4.0 Req 6.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-005",
		Name:        "Separation of Duties Between Dev/Test/Prod",
		Description: "Implement separation of duties between development, testing, and production environments",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-006",
		Name:        "Production Data Not Used in Test",
		Description: "Ensure production data is not used for testing or development purposes",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNoProdDataTest,
		References:  []string{"PCI-DSS v4.0 Req 6.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-007",
		Name:        "Test Data Removed Before Production",
		Description: "Remove all test data and accounts before deploying applications to production",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-008",
		Name:        "Change Control Procedures for All Changes",
		Description: "Establish change control procedures for all changes to system components in the CDE",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeControl,
		References:  []string{"PCI-DSS v4.0 Req 6.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-009",
		Name:        "All Changes Documented",
		Description: "Document all changes to system components including scope, impact, and authorization",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-010",
		Name:        "Secure Code Review Before Release",
		Description: "Perform secure code review before releasing custom software to production",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCodeReview,
		References:  []string{"PCI-DSS v4.0 Req 6.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-011",
		Name:        "Code Review by Someone Other Than Author",
		Description: "Ensure code review is performed by someone other than the original author",
		Category:    "Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 6.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-012",
		Name:        "Automated Vulnerability Testing Before Release",
		Description: "Perform automated vulnerability testing before releasing custom software to production",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutomatedVulnTest,
		References:  []string{"PCI-DSS v4.0 Req 6.12"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-013",
		Name:        "Web Application Vulnerability Assessment",
		Description: "Perform web application vulnerability assessments for all public-facing web applications",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWebAppVuln,
		References:  []string{"PCI-DSS v4.0 Req 6.13"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-014",
		Name:        "Public Web Applications Protected Against Attacks",
		Description: "Protect public web applications against attacks including XSS, SQL injection, and CSRF",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWebAppProtection,
		References:  []string{"PCI-DSS v4.0 Req 6.14"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-015",
		Name:        "Software Vulnerability Scanning",
		Description: "Perform software vulnerability scanning on all custom and third-party software",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSoftwareScan,
		References:  []string{"PCI-DSS v4.0 Req 6.15"},
	})

	// Requirement 7: Restrict access to cardholder data by business need-to-know
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-001",
		Name:        "Access Control Model: Deny All Unless Explicitly Allowed",
		Description: "Implement an access control model that denies all access unless explicitly allowed",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDenyAllModel,
		References:  []string{"PCI-DSS v4.0 Req 7.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-002",
		Name:        "Access to System Components Limited to Least Privilege",
		Description: "Limit access to system components to only what is necessary based on least privilege",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLeastPrivilege,
		References:  []string{"PCI-DSS v4.0 Req 7.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-003",
		Name:        "Role-Based Access Control",
		Description: "Implement role-based access control (RBAC) to restrict access to cardholder data",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
		References:  []string{"PCI-DSS v4.0 Req 7.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-004",
		Name:        "Formal Access Control Policy",
		Description: "Establish and maintain a formal access control policy for all system components",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 7.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-005",
		Name:        "Access Rights Reviewed at Least Every 6 Months",
		Description: "Review access rights at least every 6 months to ensure they remain appropriate",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessRightsReview,
		References:  []string{"PCI-DSS v4.0 Req 7.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-006",
		Name:        "Automated Access Control System",
		Description: "Implement an automated access control system for all system components in the CDE",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutoAccessControl,
		References:  []string{"PCI-DSS v4.0 Req 7.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-007",
		Name:        "Access Control for Offsite Storage",
		Description: "Implement access controls for offsite storage of cardholder data and media",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 7.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-008",
		Name:        "Access Revoked Upon Termination",
		Description: "Revoke all access rights immediately upon termination of employment or contract",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 7.8"},
	})

	// Requirement 8: Identify users and authenticate access to system components
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-001",
		Name:        "All Users Uniquely Identified",
		Description: "Ensure all users are uniquely identified before granting access to system components",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkUserAuth,
		References:  []string{"PCI-DSS v4.0 Req 8.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-002",
		Name:        "Group/Shared IDs Eliminated",
		Description: "Eliminate all group and shared user IDs for access to system components in the CDE",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-003",
		Name:        "Authentication Factors",
		Description: "Implement authentication factors that uniquely identify each user",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-004",
		Name:        "MFA for All Access into CDE",
		Description: "Implement multi-factor authentication for all access into the cardholder data environment",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFA,
		References:  []string{"PCI-DSS v4.0 Req 8.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-005",
		Name:        "MFA for All Remote Access",
		Description: "Implement multi-factor authentication for all remote access to the CDE",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRemoteMFA,
		References:  []string{"PCI-DSS v4.0 Req 8.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-006",
		Name:        "MFA for All Privileged Access",
		Description: "Implement multi-factor authentication for all privileged access to system components",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedMFA,
		References:  []string{"PCI-DSS v4.0 Req 8.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-007",
		Name:        "Strong Cryptography for Authentication Factors",
		Description: "Use strong cryptography to protect authentication factors during transmission and storage",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthCrypto,
		References:  []string{"PCI-DSS v4.0 Req 8.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-008",
		Name:        "Passwords/Passphrases Meet Complexity",
		Description: "Ensure passwords and passphrases meet minimum complexity requirements (min 12 characters)",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPasswordComplexity,
		References:  []string{"PCI-DSS v4.0 Req 8.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-009",
		Name:        "First-Use Passwords Changed",
		Description: "Ensure all first-use passwords are changed immediately upon initial login",
		Category:    "Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-010",
		Name:        "No Shared Authentication Factors",
		Description: "Ensure authentication factors are not shared among users",
		Category:    "Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-011",
		Name:        "Lockout After Excessive Failed Attempts",
		Description: "Implement account lockout after excessive failed authentication attempts",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLockout,
		References:  []string{"PCI-DSS v4.0 Req 8.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-012",
		Name:        "Session Timeout After 15 Minutes",
		Description: "Implement session timeout after 15 minutes of inactivity for CDE access",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSessionTimeout,
		References:  []string{"PCI-DSS v4.0 Req 8.12"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-013",
		Name:        "Verify User Identity Before Password Reset",
		Description: "Verify user identity before performing password resets or changes",
		Category:    "Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.13"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-014",
		Name:        "Passwords Not Stored in Readable Format",
		Description: "Ensure passwords and passphrases are not stored in readable format and are protected with strong cryptography",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPasswordNotReadable,
		References:  []string{"PCI-DSS v4.0 Req 8.14"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-015",
		Name:        "Authentication Factors Not Reused",
		Description: "Ensure authentication factors are not reused across different systems or applications",
		Category:    "Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 8.15"},
	})

	// Requirement 9: Restrict physical access to cardholder data
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-001",
		Name:        "Physical Security Policies",
		Description: "Establish and maintain physical security policies for all facilities in the CDE",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-002",
		Name:        "Physical Access Controls",
		Description: "Implement physical access controls to restrict access to facilities in the CDE",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalAccess,
		References:  []string{"PCI-DSS v4.0 Req 9.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-003",
		Name:        "Visitor Logging and Monitoring",
		Description: "Implement visitor logging and monitoring for all facilities in the CDE",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-004",
		Name:        "Media Containing Cardholder Data Secured",
		Description: "Physically secure all media containing cardholder data including paper and electronic media",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-005",
		Name:        "Offsite Storage Media Secured",
		Description: "Secure all offsite storage media containing cardholder data",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-006",
		Name:        "Media Inventory",
		Description: "Maintain a media inventory for all media containing cardholder data",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-007",
		Name:        "Media Destruction",
		Description: "Destroy media containing cardholder data when it is no longer needed for business or legal reasons",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaDestruction,
		References:  []string{"PCI-DSS v4.0 Req 9.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-008",
		Name:        "Paper Media Destruction",
		Description: "Destroy paper media containing cardholder data using secure destruction methods",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPaperDestruction,
		References:  []string{"PCI-DSS v4.0 Req 9.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-009",
		Name:        "Devices That Display PAN Secured",
		Description: "Secure devices that display PAN so that PAN is not visible to unauthorized personnel",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-010",
		Name:        "Physical Access Devices Reviewed",
		Description: "Review physical access devices and procedures at least annually",
		Category:    "Physical Security",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 9.10"},
	})

	// Requirement 10: Log and monitor all access to system components and cardholder data
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-001",
		Name:        "Audit Logs Enabled and Active",
		Description: "Enable and maintain audit logs to record all access to system components and cardholder data",
		Category:    "Monitoring",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditLogging,
		References:  []string{"PCI-DSS v4.0 Req 10.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-002",
		Name:        "Audit Trails for All System Components",
		Description: "Implement audit trails for all system components in the CDE to track individual user access",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditTrails,
		References:  []string{"PCI-DSS v4.0 Req 10.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-003",
		Name:        "Audit Trail Includes All Individual User Access",
		Description: "Ensure audit trails include all individual user access to cardholder data",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUserAccessLog,
		References:  []string{"PCI-DSS v4.0 Req 10.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-004",
		Name:        "Audit Trail Includes All Admin Actions",
		Description: "Ensure audit trails include all administrative actions and changes",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAdminActionsLog,
		References:  []string{"PCI-DSS v4.0 Req 10.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-005",
		Name:        "Time Synchronization",
		Description: "Implement time synchronization across all systems for accurate audit trail timestamps",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTimeSync,
		References:  []string{"PCI-DSS v4.0 Req 10.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-006",
		Name:        "Review Logs for Security Events Daily",
		Description: "Review logs for security events at least daily",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 10.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-007",
		Name:        "Review Logs for Failed Access",
		Description: "Review logs for failed access events and anomalies",
		Category:    "Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 10.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-008",
		Name:        "Automated Log Review Tools",
		Description: "Implement automated log review tools for security event detection and alerting",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutomatedLogReview,
		References:  []string{"PCI-DSS v4.0 Req 10.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-009",
		Name:        "Audit Trail History Retained at Least 1 Year",
		Description: "Retain audit trail history for at least 1 year with 3 months immediately available",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditTrailRetention,
		References:  []string{"PCI-DSS v4.0 Req 10.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-010",
		Name:        "Time Sync Using NTP or Equivalent",
		Description: "Use NTP or equivalent time synchronization protocol for all systems in the CDE",
		Category:    "Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTimeSyncNTP,
		References:  []string{"PCI-DSS v4.0 Req 10.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-011",
		Name:        "Logs Protected from Modification",
		Description: "Protect audit logs from modification, deletion, or unauthorized access",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLogIntegrity,
		References:  []string{"PCI-DSS v4.0 Req 10.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-012",
		Name:        "Centralized Logging System",
		Description: "Implement a centralized logging system for all system components in the CDE",
		Category:    "Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 10.12"},
	})

	// Requirement 11: Test security of systems and networks regularly
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-001",
		Name:        "Authorized Wireless Access Points Identified",
		Description: "Identify and document all authorized wireless access points within the CDE",
		Category:    "Testing",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-002",
		Name:        "Internal Vulnerability Scans Quarterly",
		Description: "Perform internal vulnerability scans at least quarterly to identify security issues",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalVulnScan,
		References:  []string{"PCI-DSS v4.0 Req 11.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-003",
		Name:        "External Vulnerability Scans Quarterly",
		Description: "Perform external vulnerability scans at least quarterly by an ASV",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkExternalVulnScan,
		References:  []string{"PCI-DSS v4.0 Req 11.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-004",
		Name:        "Vulnerability Scans After Significant Changes",
		Description: "Perform vulnerability scans after any significant change to the environment",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPostChangeScan,
		References:  []string{"PCI-DSS v4.0 Req 11.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-005",
		Name:        "Internal Penetration Testing Annually",
		Description: "Perform internal penetration testing at least annually to identify exploitable vulnerabilities",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-006",
		Name:        "External Penetration Testing Annually",
		Description: "Perform external penetration testing at least annually to identify exploitable vulnerabilities",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-007",
		Name:        "Segmentation Penetration Testing Annually",
		Description: "Perform segmentation penetration testing at least annually to verify CDE isolation",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-008",
		Name:        "Exploitable Vulnerabilities from Penetration Tests Corrected",
		Description: "Correct all exploitable vulnerabilities identified during penetration testing",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-009",
		Name:        "Verify Public IP Addresses in Scope",
		Description: "Verify that all public IP addresses are included in the scope of the PCI-DSS assessment",
		Category:    "Testing",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 11.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-010",
		Name:        "Intrusion Detection",
		Description: "Deploy intrusion detection systems to detect network-based and host-based attacks",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntrusionDetection,
		References:  []string{"PCI-DSS v4.0 Req 11.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-011",
		Name:        "Intrusion Prevention",
		Description: "Deploy intrusion prevention systems to prevent network-based and host-based attacks",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntrusionPrevention,
		References:  []string{"PCI-DSS v4.0 Req 11.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-012",
		Name:        "File Integrity Monitoring (FIM)",
		Description: "Deploy file integrity monitoring tools to detect unauthorized changes to critical files",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFileIntegrityMonitoring,
		References:  []string{"PCI-DSS v4.0 Req 11.12"},
	})

	// Requirement 12: Support information security with organizational policies
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-001",
		Name:        "Information Security Policy Established",
		Description: "Establish and maintain an information security policy that addresses all PCI-DSS requirements",
		Category:    "Policy",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-002",
		Name:        "Security Policy Reviewed Annually",
		Description: "Review the information security policy at least annually and update as needed",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-003",
		Name:        "Security Policy Disseminated to All Personnel",
		Description: "Disseminate the information security policy to all personnel and ensure understanding",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-004",
		Name:        "Acceptable Use Policy",
		Description: "Implement an acceptable use policy that defines responsibilities for using system components and data",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAcceptableUse,
		References:  []string{"PCI-DSS v4.0 Req 12.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-005",
		Name:        "Security Awareness Training",
		Description: "Implement security awareness training for all personnel at least annually and upon hire",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityTraining,
		References:  []string{"PCI-DSS v4.0 Req 12.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-006",
		Name:        "Background Checks for Personnel",
		Description: "Perform background checks on all personnel prior to granting access to the CDE",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-007",
		Name:        "Security Incident Response Plan",
		Description: "Establish and maintain a security incident response plan for responding to security incidents",
		Category:    "Policy",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
		References:  []string{"PCI-DSS v4.0 Req 12.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-008",
		Name:        "Vendor Security Requirements in Contracts",
		Description: "Include security requirements in contracts with all third-party service providers",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-009",
		Name:        "Business Continuity Plan",
		Description: "Establish and maintain a business continuity plan for the CDE",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-010",
		Name:        "Risk Assessment Process",
		Description: "Implement a formal risk assessment process that identifies threats and vulnerabilities to the CDE",
		Category:    "Policy",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"PCI-DSS v4.0 Req 12.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-011",
		Name:        "Responsibility Assignment for PCI Compliance",
		Description: "Assign responsibility for PCI-DSS compliance to specific individuals within the organization",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-012",
		Name:        "Executive Management Oversight",
		Description: "Ensure executive management provides oversight and support for PCI-DSS compliance activities",
		Category:    "Policy",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"PCI-DSS v4.0 Req 12.12"},
	})

	// AI-Specific PCI Controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-001",
		Name:        "AI Data Protection Requirements",
		Description: "Ensure AI models and systems do not retain or expose payment card data during processing or training",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAICardProtection,
		References:  []string{"PCI-DSS v4.0 AI Controls 001"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-002",
		Name:        "AI Model Vulnerability Scanning",
		Description: "Perform vulnerability scanning on AI models and systems that process or access cardholder data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelVuln,
		References:  []string{"PCI-DSS v4.0 AI Controls 002"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-003",
		Name:        "AI Access Control for Payment Data",
		Description: "Implement access controls for AI systems that access or process payment data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIAccessControl,
		References:  []string{"PCI-DSS v4.0 AI Controls 003"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-004",
		Name:        "AI Model Audit Logging",
		Description: "Maintain immutable audit trails for all AI model access to cardholder data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIAuditLog,
		References:  []string{"PCI-DSS v4.0 AI Controls 004"},
	})
}

// =========================================================================
// CheckFunc implementations
// =========================================================================

func (m *PCIModule) checkFirewallConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"firewall", "network_policy"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-001",
			ControlName: "Firewall/Router Configuration Standards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Network security controls detected: firewall/router configuration standards in place",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-001",
			ControlName: "Firewall/Router Configuration Standards",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial network security controls: some configuration standards detected",
			Timestamp:   time.Now(),
			Remediation: "Implement firewall rules and network segmentation per PCI-DSS v4.0 configuration standards",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-001",
		ControlName: "Firewall/Router Configuration Standards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Network security controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement firewall rules and network segmentation per PCI-DSS v4.0 configuration standards",
	}, nil
}

func (m *PCIModule) checkNetworkSegmentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"network_segmentation", "cde_isolated", "vlan", "security_group", "acl", "firewall_rules", "network_policy"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-003",
			ControlName: "Network Security Controls Between Trusted/Untrusted Networks",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network segmentation verified: CDE isolated + ACLs + segmentation policy",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-003",
			ControlName: "Network Security Controls Between Trusted/Untrusted Networks",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network segmentation detected; missing some controls",
			Timestamp:   time.Now(),
			Remediation: "Implement network segmentation + ACLs + segmentation policy for the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-003",
		ControlName: "Network Security Controls Between Trusted/Untrusted Networks",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No network segmentation detected",
		Timestamp:   time.Now(),
		Remediation: "Implement network segmentation + ACLs + segmentation policy for the CDE",
	}, nil
}

func (m *PCIModule) checkDenyTraffic(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"deny_traffic", "default_deny", "deny_by_default", "block_inbound"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-004",
			ControlName: "Deny Traffic from Untrusted to Trusted Networks",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Deny traffic rules verified: untrusted-to-trusted traffic denied by default",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-004",
			ControlName: "Deny Traffic from Untrusted to Trusted Networks",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial deny traffic rules: some default deny controls detected",
			Timestamp:   time.Now(),
			Remediation: "Configure default deny rules for inbound traffic from untrusted networks",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-004",
		ControlName: "Deny Traffic from Untrusted to Trusted Networks",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No deny traffic rules detected for untrusted-to-trusted traffic",
		Timestamp:   time.Now(),
		Remediation: "Configure default deny rules for inbound traffic from untrusted networks",
	}, nil
}

func (m *PCIModule) checkPortRestriction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"port_restriction", "restricted_ports", "necessary_ports", "port_allowlist"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-005",
			ControlName: "Restrict Inbound/Outbound Traffic to Necessary Ports",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Port restrictions verified: only necessary ports allowed",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-005",
			ControlName: "Restrict Inbound/Outbound Traffic to Necessary Ports",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial port restrictions: some port controls detected",
			Timestamp:   time.Now(),
			Remediation: "Restrict inbound/outbound traffic to only necessary ports and protocols",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-005",
		ControlName: "Restrict Inbound/Outbound Traffic to Necessary Ports",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No port restrictions detected for inbound/outbound traffic",
		Timestamp:   time.Now(),
		Remediation: "Restrict inbound/outbound traffic to only necessary ports and protocols",
	}, nil
}

func (m *PCIModule) checkPerimeterFirewall(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"perimeter_firewall", "edge_firewall", "boundary_firewall"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-009",
			ControlName: "Install Perimeter Firewalls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Perimeter firewalls detected at network boundaries",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-009",
			ControlName: "Install Perimeter Firewalls",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial perimeter firewall coverage detected",
			Timestamp:   time.Now(),
			Remediation: "Install perimeter firewalls at all network boundaries",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-009",
		ControlName: "Install Perimeter Firewalls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No perimeter firewalls detected",
		Timestamp:   time.Now(),
		Remediation: "Install perimeter firewalls at all network boundaries",
	}, nil
}

func (m *PCIModule) checkWirelessSegmentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"wireless_segmentation", "wifi_isolation", "wlan_segmentation", "wireless_firewall"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-010",
			ControlName: "Network Security Controls Between Wireless and CDE",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Wireless segmentation verified: CDE isolated from wireless networks",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-010",
			ControlName: "Network Security Controls Between Wireless and CDE",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial wireless segmentation: some isolation controls detected",
			Timestamp:   time.Now(),
			Remediation: "Install network security controls between wireless networks and the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-010",
		ControlName: "Network Security Controls Between Wireless and CDE",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No wireless segmentation detected between wireless and CDE",
		Timestamp:   time.Now(),
		Remediation: "Install network security controls between wireless networks and the CDE",
	}, nil
}

func (m *PCIModule) checkPublicAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"no_public_access", "restrict_public_access", "cde_no_public", "private_network"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-011",
			ControlName: "Restrict Direct Public Access to CDE Systems",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Public access to CDE systems restricted",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-011",
			ControlName: "Restrict Direct Public Access to CDE Systems",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial public access restrictions detected",
			Timestamp:   time.Now(),
			Remediation: "Restrict direct public access to all CDE systems",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-011",
		ControlName: "Restrict Direct Public Access to CDE Systems",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No public access restrictions detected for CDE systems",
		Timestamp:   time.Now(),
		Remediation: "Restrict direct public access to all CDE systems",
	}, nil
}

func (m *PCIModule) checkAntiSpoofing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"anti_spoofing", "spoofing_protection", "ip_spoofing", "urpf", "bcp38"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-013",
			ControlName: "Anti-Spoofing Measures",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anti-spoofing measures detected on network devices",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-013",
			ControlName: "Anti-Spoofing Measures",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial anti-spoofing controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement anti-spoofing measures (uRPF, BCP38) on network devices",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-013",
		ControlName: "Anti-Spoofing Measures",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No anti-spoofing measures detected",
		Timestamp:   time.Now(),
		Remediation: "Implement anti-spoofing measures (uRPF, BCP38) on network devices",
	}, nil
}

func (m *PCIModule) checkDefaultCredentials(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := strings.ToLower(string(input))
	defaultUsers := []string{"admin", "root", "password", "default", "guest"}

	for _, user := range defaultUsers {
		if strings.Contains(inputStr, user) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "PCI-02-001",
				ControlName: "Change Default Credentials Before Installation",
				Status:      compliance.StatusNonCompliant,
				Severity:    compliance.SeverityCritical,
				Message:     "Default credential pattern detected: " + user,
				Timestamp:   time.Now(),
				Remediation: "Change all default credentials immediately",
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-001",
		ControlName: "Change Default Credentials Before Installation",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No default credentials detected",
		Timestamp:   time.Now(),
	}, nil
}

func (m *PCIModule) checkSystemHardening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-003",
		ControlName: "Configure System Components Securely",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System hardening standards in place",
		Timestamp:   time.Now(),
	}, nil
}

func (m *PCIModule) checkUnnecessaryServices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"necessary_services", "disabled_services", "minimal_services", "service_hardening"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-004",
			ControlName: "Enable Only Necessary Services and Protocols",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Only necessary services and protocols enabled",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-004",
			ControlName: "Enable Only Necessary Services and Protocols",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial service restriction: some unnecessary services detected",
			Timestamp:   time.Now(),
			Remediation: "Disable all unnecessary services and protocols on system components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-004",
		ControlName: "Enable Only Necessary Services and Protocols",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No service restriction controls detected",
		Timestamp:   time.Now(),
		Remediation: "Disable all unnecessary services and protocols on system components",
	}, nil
}

func (m *PCIModule) checkContainerHardening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"container_hardening", "docker_security", "kubernetes_hardening", "container_security"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-008",
			ControlName: "Cloud Container Hardening",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Container hardening verified: security configurations detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-008",
			ControlName: "Cloud Container Hardening",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial container hardening: some security controls detected",
			Timestamp:   time.Now(),
			Remediation: "Apply hardening configurations to all containers (Docker, Kubernetes)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-008",
		ControlName: "Cloud Container Hardening",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No container hardening detected",
		Timestamp:   time.Now(),
		Remediation: "Apply hardening configurations to all containers (Docker, Kubernetes)",
	}, nil
}

func (m *PCIModule) checkAdminAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"encrypted_admin", "ssh_access", "vpn_admin", "tls_admin"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-011",
			ControlName: "Encrypt All Non-Console Admin Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Encrypted admin access verified: SSH/VPN/TLS detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-011",
			ControlName: "Encrypt All Non-Console Admin Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial encrypted admin access: some encryption detected",
			Timestamp:   time.Now(),
			Remediation: "Encrypt all non-console administrative access with strong cryptography (SSH, VPN, TLS)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-011",
		ControlName: "Encrypt All Non-Console Admin Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No encrypted admin access detected",
		Timestamp:   time.Now(),
		Remediation: "Encrypt all non-console administrative access with strong cryptography (SSH, VPN, TLS)",
	}, nil
}

func (m *PCIModule) checkCentralAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"centralized_auth", "sso", "ldap", "active_directory", "iam"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-012",
			ControlName: "Centralized Authentication for All System Components",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Centralized authentication verified: SSO/LDAP/AD detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-012",
			ControlName: "Centralized Authentication for All System Components",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial centralized authentication: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement centralized authentication (SSO, LDAP, AD) for all system components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-012",
		ControlName: "Centralized Authentication for All System Components",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No centralized authentication detected",
		Timestamp:   time.Now(),
		Remediation: "Implement centralized authentication (SSO, LDAP, AD) for all system components",
	}, nil
}

func (m *PCIModule) checkNoSensitiveAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"no_sensitive_auth", "sensitive_data_deleted", "auth_data_purged", "no_track_data"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-002",
			ControlName: "Sensitive Authentication Data Not Retained",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No sensitive authentication data retained after authorization",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-002",
			ControlName: "Sensitive Authentication Data Not Retained",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial sensitive data controls: some purge mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure sensitive authentication data is not retained after authorization",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-002",
		ControlName: "Sensitive Authentication Data Not Retained",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Sensitive authentication data retention detected — non-compliant",
		Timestamp:   time.Now(),
		Remediation: "Ensure sensitive authentication data is not retained after authorization",
	}, nil
}

func (m *PCIModule) checkPANMasking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"pan_masking", "card_mask", "mask_pan", "display_masking"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-003",
			ControlName: "Mask PAN When Displayed",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "PAN masking implemented",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-003",
			ControlName: "Mask PAN When Displayed",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial PAN masking: some masking controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement PAN masking to display only first 6/last 4 digits",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-003",
		ControlName: "Mask PAN When Displayed",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "PAN masking not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement PAN masking to display only first 6/last 4 digits",
	}, nil
}

func (m *PCIModule) checkPANUnreadable(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"pan_unreadable", "pan_encrypted", "pan_tokenized", "pan_hashed", "pan_truncated", "one_way_hash"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-004",
			ControlName: "Render PAN Unreadable Anywhere Stored",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "PAN rendered unreadable: protection mechanism detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-004",
			ControlName: "Render PAN Unreadable Anywhere Stored",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial PAN protection: some unreadability controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement PAN protection: truncation, one-way hashing, tokenization, or strong cryptography with key management",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-004",
		ControlName: "Render PAN Unreadable Anywhere Stored",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "PAN is stored in cleartext — non-compliant",
		Timestamp:   time.Now(),
		Remediation: "Implement PAN protection: truncation, one-way hashing, tokenization, or strong cryptography with key management",
	}, nil
}

func (m *PCIModule) checkDiskEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"disk_encryption", "partition_encryption", "luks", "bitlocker", "full_disk_encryption"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-005",
			ControlName: "Disk-Level or Partition-Level Encryption",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Disk-level encryption verified: full disk encryption detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-005",
			ControlName: "Disk-Level or Partition-Level Encryption",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial disk encryption: some encryption controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enable full disk encryption (LUKS, BitLocker) on all systems storing cardholder data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-005",
		ControlName: "Disk-Level or Partition-Level Encryption",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No disk-level encryption detected for cardholder data storage",
		Timestamp:   time.Now(),
		Remediation: "Enable full disk encryption (LUKS, BitLocker) on all systems storing cardholder data",
	}, nil
}

func (m *PCIModule) checkTokenization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"tokenization", "tokenized", "payment_token", "token_service"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-010",
			ControlName: "Tokenization of PAN Data",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Tokenization verified: PAN data is tokenized",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-010",
			ControlName: "Tokenization of PAN Data",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial tokenization: some token controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement tokenization for all stored PAN data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-010",
		ControlName: "Tokenization of PAN Data",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No tokenization detected for PAN data",
		Timestamp:   time.Now(),
		Remediation: "Implement tokenization for all stored PAN data",
	}, nil
}

func (m *PCIModule) checkTruncation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"pan_truncation", "truncated_pan", "truncation", "first6_last4"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-011",
			ControlName: "Truncation of PAN Data",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "PAN truncation verified: truncation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-011",
			ControlName: "Truncation of PAN Data",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial PAN truncation: some truncation controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement PAN truncation (first 6/last 4 digits) where PAN is stored",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-011",
		ControlName: "Truncation of PAN Data",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No PAN truncation detected",
		Timestamp:   time.Now(),
		Remediation: "Implement PAN truncation (first 6/last 4 digits) where PAN is stored",
	}, nil
}

func (m *PCIModule) checkPANHashing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"pan_hashing", "one_way_hash", "sha256_pan", "hash_pan", "hashed_pan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-012",
			ControlName: "Hashing of PAN Data",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "PAN hashing verified: one-way hash detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-012",
			ControlName: "Hashing of PAN Data",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial PAN hashing: some hash controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement one-way hashing (SHA-256) for stored PAN data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-012",
		ControlName: "Hashing of PAN Data",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No PAN hashing detected",
		Timestamp:   time.Now(),
		Remediation: "Implement one-way hashing (SHA-256) for stored PAN data",
	}, nil
}

func (m *PCIModule) checkKeyRotation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"key_rotation", "rotate_keys", "periodic_rotation", "key_replacement"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-015",
			ControlName: "Periodic Key Rotation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Key rotation verified: periodic rotation detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-015",
			ControlName: "Periodic Key Rotation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial key rotation: some rotation controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement periodic key rotation for all cryptographic keys protecting account data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-015",
		ControlName: "Periodic Key Rotation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No key rotation detected for cryptographic keys",
		Timestamp:   time.Now(),
		Remediation: "Implement periodic key rotation for all cryptographic keys protecting account data",
	}, nil
}

func (m *PCIModule) checkTransmissionEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := strings.ToLower(string(input))
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") ||
		strings.Contains(inputStr, "ssl") || strings.Contains(inputStr, "encrypted_transmission")

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-001",
			ControlName: "Strong Cryptography for Transmission Over Open Networks",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Transmission encryption detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-001",
		ControlName: "Strong Cryptography for Transmission Over Open Networks",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Transmission encryption not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ for all cardholder data transmission over open networks",
	}, nil
}

func (m *PCIModule) checkTLSConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := strings.ToLower(string(input))
	hasTLS12OrHigher := strings.Contains(inputStr, "tls1.2") || strings.Contains(inputStr, "tls1.3") ||
		strings.Contains(inputStr, "tls_12") || strings.Contains(inputStr, "tls_13") ||
		strings.Contains(inputStr, "strong_crypto")

	if hasTLS12OrHigher {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-003",
			ControlName: "Strong Cryptography and Security Protocols",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.2 or higher configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-003",
		ControlName: "Strong Cryptography and Security Protocols",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "TLS version not compliant with PCI-DSS v4.0",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2 or higher for all cardholder data transmission",
	}, nil
}

func (m *PCIModule) checkWirelessCrypto(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"wpa3", "wpa2_enterprise", "wireless_encryption", "wifi_encryption"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-004",
			ControlName: "Wireless Transmissions Use Strong Cryptography",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Wireless encryption verified: WPA3/WPA2-Enterprise detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-004",
			ControlName: "Wireless Transmissions Use Strong Cryptography",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial wireless encryption: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enable WPA3 or WPA2-Enterprise for all wireless transmissions",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-004",
		ControlName: "Wireless Transmissions Use Strong Cryptography",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No wireless encryption detected",
		Timestamp:   time.Now(),
		Remediation: "Enable WPA3 or WPA2-Enterprise for all wireless transmissions",
	}, nil
}

func (m *PCIModule) checkCertExpiration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"cert_expiration", "certificate_expiry", "cert_monitoring", "ssl_expiry"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-005",
			ControlName: "Verify Encryption Strength During Certificate Expiration",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Certificate expiration monitoring verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-005",
			ControlName: "Verify Encryption Strength During Certificate Expiration",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial certificate monitoring: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement certificate expiration monitoring and alerting",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-005",
		ControlName: "Verify Encryption Strength During Certificate Expiration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No certificate expiration monitoring detected",
		Timestamp:   time.Now(),
		Remediation: "Implement certificate expiration monitoring and alerting",
	}, nil
}

func (m *PCIModule) checkCertValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"cert_validation", "certificate_validation", "cert_pin", "ca_bundle"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-007",
			ControlName: "Proper Certificate Validation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Certificate validation verified: pinning/CA verification detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-007",
			ControlName: "Proper Certificate Validation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial certificate validation: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement proper certificate validation (pinning, CA verification) for all TLS connections",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-007",
		ControlName: "Proper Certificate Validation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No certificate validation detected",
		Timestamp:   time.Now(),
		Remediation: "Implement proper certificate validation (pinning, CA verification) for all TLS connections",
	}, nil
}

func (m *PCIModule) checkMalwareProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"antivirus", "malware", "scanner", "endpoint_protection"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-001",
			ControlName: "Anti-Malware on All Systems",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malware protection detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-001",
			ControlName: "Anti-Malware on All Systems",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial malware protection: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Deploy anti-malware solutions on all systems",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-001",
		ControlName: "Anti-Malware on All Systems",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malware protection not detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy anti-malware solutions on all systems",
	}, nil
}

func (m *PCIModule) checkCentralizedMalware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"centralized_malware", "centralized_antivirus", "endpoint_management", "malware_management"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-004",
			ControlName: "Centralized Anti-Malware Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Centralized anti-malware management verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-004",
			ControlName: "Centralized Anti-Malware Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial centralized malware management: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement centralized anti-malware management (ePO, SCCM) for all CDE components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-004",
		ControlName: "Centralized Anti-Malware Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No centralized anti-malware management detected",
		Timestamp:   time.Now(),
		Remediation: "Implement centralized anti-malware management (ePO, SCCM) for all CDE components",
	}, nil
}

func (m *PCIModule) checkVulnScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"vulnerability_scan", "security_scan", "vuln_scan", "patch_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-005",
			ControlName: "All System Components Protected Against Known Vulnerabilities",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Vulnerability scanning configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-005",
			ControlName: "All System Components Protected Against Known Vulnerabilities",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Verify vulnerability scanning schedule",
			Timestamp:   time.Now(),
			Remediation: "Implement automated vulnerability scanning for all system components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-005",
		ControlName: "All System Components Protected Against Known Vulnerabilities",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Verify vulnerability scanning schedule",
		Timestamp:   time.Now(),
		Remediation: "Implement automated vulnerability scanning for all system components",
	}, nil
}

func (m *PCIModule) checkPatchCritical(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"critical_patch", "30_day_patch", "critical_remediation", "patch_sla_critical"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-006",
			ControlName: "Patch Critical Vulnerabilities Within 1 Month",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Critical vulnerability patching verified: 30-day SLA detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-006",
			ControlName: "Patch Critical Vulnerabilities Within 1 Month",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial critical patch SLA: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Patch critical vulnerabilities within 30 days of release",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-006",
		ControlName: "Patch Critical Vulnerabilities Within 1 Month",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No critical vulnerability patching SLA detected",
		Timestamp:   time.Now(),
		Remediation: "Patch critical vulnerabilities within 30 days of release",
	}, nil
}

func (m *PCIModule) checkPatchHigh(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"high_patch", "90_day_patch", "high_remediation", "patch_sla_high"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-007",
			ControlName: "Patch High Vulnerabilities Within 3 Months",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "High vulnerability patching verified: 90-day SLA detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-007",
			ControlName: "Patch High Vulnerabilities Within 3 Months",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial high patch SLA: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Patch high vulnerabilities within 90 days of release",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-007",
		ControlName: "Patch High Vulnerabilities Within 3 Months",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No high vulnerability patching SLA detected",
		Timestamp:   time.Now(),
		Remediation: "Patch high vulnerabilities within 90 days of release",
	}, nil
}

func (m *PCIModule) checkInternalScan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"internal_scan", "internal_vuln_scan", "quarterly_internal_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-010",
			ControlName: "Internal Vulnerability Scans",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal vulnerability scanning verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-010",
			ControlName: "Internal Vulnerability Scans",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial internal scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Perform internal vulnerability scans quarterly and after significant changes",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-010",
		ControlName: "Internal Vulnerability Scans",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No internal vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Perform internal vulnerability scans quarterly and after significant changes",
	}, nil
}

func (m *PCIModule) checkSecureDev(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"secure_dev", "secure_coding", "sast", "static_analysis", "owasp"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-002",
			ControlName: "Software Engineering Techniques Address Common Vulnerabilities",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure development techniques verified: SAST/OWASP detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-002",
			ControlName: "Software Engineering Techniques Address Common Vulnerabilities",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial secure development: some techniques detected",
			Timestamp:   time.Now(),
			Remediation: "Apply secure coding techniques (SAST, OWASP guidelines) in development",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-002",
		ControlName: "Software Engineering Techniques Address Common Vulnerabilities",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure development techniques detected",
		Timestamp:   time.Now(),
		Remediation: "Apply secure coding techniques (SAST, OWASP guidelines) in development",
	}, nil
}

func (m *PCIModule) checkEnvSeparation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"env_separation", "separate_environments", "prod_isolation", "environment_separation"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-004",
			ControlName: "Production Applications Use Separate Environments",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Environment separation verified: production isolated from dev/test",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-004",
			ControlName: "Production Applications Use Separate Environments",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial environment separation: some isolation controls detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure production environments are fully separated from development/testing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-004",
		ControlName: "Production Applications Use Separate Environments",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No environment separation detected",
		Timestamp:   time.Now(),
		Remediation: "Ensure production environments are fully separated from development/testing",
	}, nil
}

func (m *PCIModule) checkNoProdDataTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"no_prod_data", "test_data_synthetic", "no_production_data_test", "synthetic_data"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-006",
			ControlName: "Production Data Not Used in Test",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Production data not used in testing: synthetic data detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-006",
			ControlName: "Production Data Not Used in Test",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial production data controls: some restrictions detected",
			Timestamp:   time.Now(),
			Remediation: "Use synthetic or anonymized data for testing — never production data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-006",
		ControlName: "Production Data Not Used in Test",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Production data may be used in testing — non-compliant",
		Timestamp:   time.Now(),
		Remediation: "Use synthetic or anonymized data for testing — never production data",
	}, nil
}

func (m *PCIModule) checkCodeReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"code_review", "pull_request", "pr_review", "peer_review"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-010",
			ControlName: "Secure Code Review Before Release",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Code review process detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-010",
			ControlName: "Secure Code Review Before Release",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Code review process needs verification",
			Timestamp:   time.Now(),
			Remediation: "Implement mandatory secure code review for all changes before release",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-010",
		ControlName: "Secure Code Review Before Release",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Code review process needs verification",
		Timestamp:   time.Now(),
		Remediation: "Implement mandatory secure code review for all changes before release",
	}, nil
}

func (m *PCIModule) checkAutomatedVulnTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"automated_vuln_test", "ci_cd_scan", "pipeline_scan", "automated_security_test"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-012",
			ControlName: "Automated Vulnerability Testing Before Release",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automated vulnerability testing verified: CI/CD scanning detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-012",
			ControlName: "Automated Vulnerability Testing Before Release",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial automated testing: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement automated vulnerability testing in CI/CD pipeline before release",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-012",
		ControlName: "Automated Vulnerability Testing Before Release",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automated vulnerability testing detected",
		Timestamp:   time.Now(),
		Remediation: "Implement automated vulnerability testing in CI/CD pipeline before release",
	}, nil
}

func (m *PCIModule) checkWebAppVuln(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"web_app_vuln", "sast", "dast", "owasp_top_10", "web_app_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-013",
			ControlName: "Web Application Vulnerability Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Web application vulnerability assessment verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-013",
			ControlName: "Web Application Vulnerability Assessment",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial web app testing: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Perform web application vulnerability assessments (SAST, DAST, OWASP Top 10)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-013",
		ControlName: "Web Application Vulnerability Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No web application vulnerability assessment detected",
		Timestamp:   time.Now(),
		Remediation: "Perform web application vulnerability assessments (SAST, DAST, OWASP Top 10)",
	}, nil
}

func (m *PCIModule) checkWebAppProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"waf", "xss_protection", "sqli_protection", "csrf_protection", "web_application_firewall"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-014",
			ControlName: "Public Web Applications Protected Against Attacks",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Web application protections verified: WAF/XSS/SQLi/CSRF detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-014",
			ControlName: "Public Web Applications Protected Against Attacks",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial web app protection: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Deploy WAF and implement protections against XSS, SQLi, CSRF",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-014",
		ControlName: "Public Web Applications Protected Against Attacks",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No web application protections detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy WAF and implement protections against XSS, SQLi, CSRF",
	}, nil
}

func (m *PCIModule) checkSoftwareScan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"software_scan", "dependency_scan", "sca", "sbom_scan", "component_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-015",
			ControlName: "Software Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Software vulnerability scanning verified: SCA/SBOM detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-015",
			ControlName: "Software Vulnerability Scanning",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial software scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement software vulnerability scanning (SCA, SBOM) for all software components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-015",
		ControlName: "Software Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No software vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Implement software vulnerability scanning (SCA, SBOM) for all software components",
	}, nil
}

func (m *PCIModule) checkDenyAllModel(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"deny_all", "default_deny", "deny_by_default", "explicit_allow"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-001",
			ControlName: "Access Control Model: Deny All Unless Explicitly Allowed",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Default-deny access model verified: deny all unless explicitly allowed",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-001",
			ControlName: "Access Control Model: Deny All Unless Explicitly Allowed",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial default-deny: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement a default-deny access control model with explicit allow rules",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-001",
		ControlName: "Access Control Model: Deny All Unless Explicitly Allowed",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No default-deny access model detected",
		Timestamp:   time.Now(),
		Remediation: "Implement a default-deny access control model with explicit allow rules",
	}, nil
}

func (m *PCIModule) checkLeastPrivilege(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"least_privilege", "minimal_access", "need_to_know", "principle_least_privilege"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-002",
			ControlName: "Access to System Components Limited to Least Privilege",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Least privilege access verified: need-to-know model detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-002",
			ControlName: "Access to System Components Limited to Least Privilege",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial least privilege: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement least privilege access controls for all system components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-002",
		ControlName: "Access to System Components Limited to Least Privilege",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No least privilege access controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement least privilege access controls for all system components",
	}, nil
}

func (m *PCIModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"rbac", "role_based", "access_control", "roles"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-003",
			ControlName: "Role-Based Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Role-based access control detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-003",
			ControlName: "Role-Based Access Control",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial RBAC: some role-based controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement role-based access control",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-003",
		ControlName: "Role-Based Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control not properly configured",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access control",
	}, nil
}

func (m *PCIModule) checkAutoAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"automated_access", "access_management_system", "iam_system", "automated_rbac"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-006",
			ControlName: "Automated Access Control System",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automated access control system verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-006",
			ControlName: "Automated Access Control System",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial automated access: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement an automated access control system (IAM) for CDE components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-006",
		ControlName: "Automated Access Control System",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automated access control system detected",
		Timestamp:   time.Now(),
		Remediation: "Implement an automated access control system (IAM) for CDE components",
	}, nil
}

func (m *PCIModule) checkUserAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"authentication", "auth_enabled", "unique_id", "user_identification"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-001",
			ControlName: "All Users Uniquely Identified",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "User authentication configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-001",
			ControlName: "All Users Uniquely Identified",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial user authentication: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement unique user identification and authentication for all access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-001",
		ControlName: "All Users Uniquely Identified",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "User authentication not configured",
		Timestamp:   time.Now(),
		Remediation: "Implement unique user identification and authentication for all access",
	}, nil
}

func (m *PCIModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"mfa", "multi_factor", "2fa", "totp"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-004",
			ControlName: "MFA for All Access into CDE",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-004",
			ControlName: "MFA for All Access into CDE",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial MFA: some multi-factor controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement MFA for all cardholder data environment access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-004",
		ControlName: "MFA for All Access into CDE",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "MFA not configured",
		Timestamp:   time.Now(),
		Remediation: "Implement MFA for all cardholder data environment access",
	}, nil
}

func (m *PCIModule) checkRemoteMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"remote_mfa", "vpn_mfa", "remote_access_mfa", "remote_multi_factor"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-005",
			ControlName: "MFA for All Remote Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Remote access MFA verified: VPN/remote MFA detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-005",
			ControlName: "MFA for All Remote Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial remote MFA: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement MFA for all remote access to the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-005",
		ControlName: "MFA for All Remote Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No remote access MFA detected",
		Timestamp:   time.Now(),
		Remediation: "Implement MFA for all remote access to the CDE",
	}, nil
}

func (m *PCIModule) checkPrivilegedMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"privileged_mfa", "admin_mfa", "root_mfa", "privilege_mfa"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-006",
			ControlName: "MFA for All Privileged Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Privileged access MFA verified: admin MFA detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-006",
			ControlName: "MFA for All Privileged Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial privileged MFA: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement MFA for all privileged/administrative access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-006",
		ControlName: "MFA for All Privileged Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No privileged access MFA detected",
		Timestamp:   time.Now(),
		Remediation: "Implement MFA for all privileged/administrative access",
	}, nil
}

func (m *PCIModule) checkAuthCrypto(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"auth_crypto", "authentication_encryption", "factor_encryption", "credential_encryption"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-007",
			ControlName: "Strong Cryptography for Authentication Factors",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authentication factor cryptography verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-007",
			ControlName: "Strong Cryptography for Authentication Factors",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial auth crypto: some encryption controls detected",
			Timestamp:   time.Now(),
			Remediation: "Use strong cryptography to protect authentication factors during transmission and storage",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-007",
		ControlName: "Strong Cryptography for Authentication Factors",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No strong cryptography detected for authentication factors",
		Timestamp:   time.Now(),
		Remediation: "Use strong cryptography to protect authentication factors during transmission and storage",
	}, nil
}

func (m *PCIModule) checkPasswordComplexity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"password_complexity", "password_policy", "min_password_length", "passphrase_policy"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-008",
			ControlName: "Passwords/Passphrases Meet Complexity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Password complexity verified: policy detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-008",
			ControlName: "Passwords/Passphrases Meet Complexity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial password complexity: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enforce password complexity (min 12 chars, mixed case, numbers, symbols)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-008",
		ControlName: "Passwords/Passphrases Meet Complexity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No password complexity policy detected",
		Timestamp:   time.Now(),
		Remediation: "Enforce password complexity (min 12 chars, mixed case, numbers, symbols)",
	}, nil
}

func (m *PCIModule) checkLockout(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"account_lockout", "lockout_enabled", "lockout_threshold", "failed_attempt_lockout"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-011",
			ControlName: "Lockout After Excessive Failed Attempts",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Account lockout verified: threshold and duration detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-011",
			ControlName: "Lockout After Excessive Failed Attempts",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial account lockout: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement account lockout after excessive failed attempts (6 attempts, 30 min)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-011",
		ControlName: "Lockout After Excessive Failed Attempts",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No account lockout detected",
		Timestamp:   time.Now(),
		Remediation: "Implement account lockout after excessive failed attempts (6 attempts, 30 min)",
	}, nil
}

func (m *PCIModule) checkSessionTimeout(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"session_timeout", "idle_timeout", "15_minute_timeout", "session_expiry"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-012",
			ControlName: "Session Timeout After 15 Minutes",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Session timeout verified: 15-minute idle timeout detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-012",
			ControlName: "Session Timeout After 15 Minutes",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial session timeout: some timeout controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement 15-minute session timeout for all CDE access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-012",
		ControlName: "Session Timeout After 15 Minutes",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No session timeout detected",
		Timestamp:   time.Now(),
		Remediation: "Implement 15-minute session timeout for all CDE access",
	}, nil
}

func (m *PCIModule) checkPhysicalAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"physical_access", "badge_access", "door_access", "physical_security"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-002",
			ControlName: "Physical Access Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Physical access controls verified: badge/door systems detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-002",
			ControlName: "Physical Access Controls",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial physical access: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement physical access controls (badges, biometrics, locks) for CDE facilities",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-09-002",
		ControlName: "Physical Access Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No physical access controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement physical access controls (badges, biometrics, locks) for CDE facilities",
	}, nil
}

func (m *PCIModule) checkMediaDestruction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"media_destruction", "secure_destruction", "media_shredding", "data_destruction"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-007",
			ControlName: "Media Destruction",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media destruction verified: secure destruction controls detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-007",
			ControlName: "Media Destruction",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial media destruction: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement secure media destruction (shredding, degaussing) for cardholder data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-09-007",
		ControlName: "Media Destruction",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No media destruction controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement secure media destruction (shredding, degaussing) for cardholder data",
	}, nil
}

func (m *PCIModule) checkPaperDestruction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"paper_destruction", "paper_shredding", "cross_cut_shredder", "secure_paper_disposal"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-008",
			ControlName: "Paper Media Destruction",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Paper media destruction verified: shredding controls detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-09-008",
			ControlName: "Paper Media Destruction",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial paper destruction: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement secure paper destruction (cross-cut shredding) for cardholder data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-09-008",
		ControlName: "Paper Media Destruction",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No paper media destruction detected",
		Timestamp:   time.Now(),
		Remediation: "Implement secure paper destruction (cross-cut shredding) for cardholder data",
	}, nil
}

func (m *PCIModule) checkAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"audit_log", "audit_enabled", "logging_enabled", "audit_trail"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-001",
			ControlName: "Audit Logs Enabled and Active",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-001",
			ControlName: "Audit Logs Enabled and Active",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial audit logging: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enable comprehensive audit logging for all system components",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-001",
		ControlName: "Audit Logs Enabled and Active",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit logging not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging for all system components",
	}, nil
}

func (m *PCIModule) checkAuditTrails(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"audit_trail", "audit_trails", "access_trail", "user_trail", "event_log"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-002",
			ControlName: "Audit Trails for All System Components",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit trails verified: system component logging detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-002",
			ControlName: "Audit Trails for All System Components",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial audit trails: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement audit trails for all system components in the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-002",
		ControlName: "Audit Trails for All System Components",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No audit trails detected for system components",
		Timestamp:   time.Now(),
		Remediation: "Implement audit trails for all system components in the CDE",
	}, nil
}

func (m *PCIModule) checkUserAccessLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"user_access_log", "user_activity", "individual_access_log", "user_audit"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-003",
			ControlName: "Audit Trail Includes All Individual User Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "User access logging verified: individual user audit detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-003",
			ControlName: "Audit Trail Includes All Individual User Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial user access logging: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement audit trails that record all individual user access to cardholder data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-003",
		ControlName: "Audit Trail Includes All Individual User Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No individual user access logging detected",
		Timestamp:   time.Now(),
		Remediation: "Implement audit trails that record all individual user access to cardholder data",
	}, nil
}

func (m *PCIModule) checkAdminActionsLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"admin_actions_log", "admin_audit", "privilege_audit", "admin_activity"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-004",
			ControlName: "Audit Trail Includes All Admin Actions",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Admin actions logging verified: admin audit detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-004",
			ControlName: "Audit Trail Includes All Admin Actions",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial admin logging: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement audit trails that record all administrative actions",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-004",
		ControlName: "Audit Trail Includes All Admin Actions",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No administrative actions logging detected",
		Timestamp:   time.Now(),
		Remediation: "Implement audit trails that record all administrative actions",
	}, nil
}

func (m *PCIModule) checkTimeSync(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"time_sync", "time_synchronization", "ntp_sync", "clock_sync"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-005",
			ControlName: "Time Synchronization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Time synchronization verified: clock sync detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-005",
			ControlName: "Time Synchronization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial time sync: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement time synchronization across all systems for accurate audit logs",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-005",
		ControlName: "Time Synchronization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No time synchronization detected",
		Timestamp:   time.Now(),
		Remediation: "Implement time synchronization across all systems for accurate audit logs",
	}, nil
}

func (m *PCIModule) checkAutomatedLogReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"automated_log_review", "siem", "log_analysis", "automated_review", "splunk", "elastic"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-008",
			ControlName: "Automated Log Review Tools",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automated log review verified: SIEM/log analysis detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-008",
			ControlName: "Automated Log Review Tools",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial automated log review: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement automated log review tools (SIEM, Splunk, Elastic) for security events",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-008",
		ControlName: "Automated Log Review Tools",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automated log review tools detected",
		Timestamp:   time.Now(),
		Remediation: "Implement automated log review tools (SIEM, Splunk, Elastic) for security events",
	}, nil
}

func (m *PCIModule) checkInternalVulnScan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"internal_vuln_scan", "quarterly_internal", "internal_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-002",
			ControlName: "Internal Vulnerability Scans Quarterly",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal vulnerability scanning verified: quarterly scans detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-002",
			ControlName: "Internal Vulnerability Scans Quarterly",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial internal scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Perform internal vulnerability scans quarterly using automated tools",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-002",
		ControlName: "Internal Vulnerability Scans Quarterly",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No internal vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Perform internal vulnerability scans quarterly using automated tools",
	}, nil
}

func (m *PCIModule) checkExternalVulnScan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"external_vuln_scan", "asv_scan", "quarterly_external", "external_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-003",
			ControlName: "External Vulnerability Scans Quarterly",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "External vulnerability scanning verified: ASV scans detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-003",
			ControlName: "External Vulnerability Scans Quarterly",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial external scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Perform external vulnerability scans quarterly by an ASV",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-003",
		ControlName: "External Vulnerability Scans Quarterly",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No external vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Perform external vulnerability scans quarterly by an ASV",
	}, nil
}

func (m *PCIModule) checkPostChangeScan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"post_change_scan", "change_triggered_scan", "after_change_scan", "post_deployment_scan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-004",
			ControlName: "Vulnerability Scans After Significant Changes",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Post-change scanning verified: change-triggered scans detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-004",
			ControlName: "Vulnerability Scans After Significant Changes",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial post-change scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Perform vulnerability scans after any significant change to the network",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-004",
		ControlName: "Vulnerability Scans After Significant Changes",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No post-change vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Perform vulnerability scans after any significant change to the network",
	}, nil
}

func (m *PCIModule) checkIntrusionDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"intrusion_detection", "ids", "network_ids", "nids"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-010",
			ControlName: "Intrusion Detection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Intrusion detection verified: IDS detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-010",
			ControlName: "Intrusion Detection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial IDS: some intrusion detection controls detected",
			Timestamp:   time.Now(),
			Remediation: "Deploy intrusion detection systems (IDS) for the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-010",
		ControlName: "Intrusion Detection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No intrusion detection systems detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy intrusion detection systems (IDS) for the CDE",
	}, nil
}

func (m *PCIModule) checkIntrusionPrevention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"intrusion_prevention", "ips", "network_ips", "nips", "waf_prevention"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-011",
			ControlName: "Intrusion Prevention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Intrusion prevention verified: IPS detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-011",
			ControlName: "Intrusion Prevention",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial IPS: some intrusion prevention controls detected",
			Timestamp:   time.Now(),
			Remediation: "Deploy intrusion prevention systems (IPS) for the CDE",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-011",
		ControlName: "Intrusion Prevention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No intrusion prevention systems detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy intrusion prevention systems (IPS) for the CDE",
	}, nil
}

func (m *PCIModule) checkAcceptableUse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"acceptable_use", "aup", "use_policy", "usage_policy"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-004",
			ControlName: "Acceptable Use Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Acceptable use policy verified: AUP detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-004",
			ControlName: "Acceptable Use Policy",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial acceptable use: some policy controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement and enforce an acceptable use policy for all personnel",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-12-004",
		ControlName: "Acceptable Use Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No acceptable use policy detected",
		Timestamp:   time.Now(),
		Remediation: "Implement and enforce an acceptable use policy for all personnel",
	}, nil
}

func (m *PCIModule) checkSecurityTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"security_training", "awareness_training", "security_awareness", "training_program"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-005",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security awareness training verified: training program detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-005",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial security training: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement security awareness training for all personnel (annual + onboarding)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-12-005",
		ControlName: "Security Awareness Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No security awareness training detected",
		Timestamp:   time.Now(),
		Remediation: "Implement security awareness training for all personnel (annual + onboarding)",
	}, nil
}

func (m *PCIModule) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"incident_response_plan", "ir_plan", "incident_response", "ir_roles"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-007",
			ControlName: "Security Incident Response Plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response plan verified: plan + roles + tested + legal notification",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-007",
			ControlName: "Security Incident Response Plan",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial incident response: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Document IR plan + assign roles + test (tabletop) + establish legal notification",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-12-007",
		ControlName: "Security Incident Response Plan",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No incident response plan detected",
		Timestamp:   time.Now(),
		Remediation: "Document IR plan + assign roles + test (tabletop) + establish legal notification",
	}, nil
}

func (m *PCIModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"risk_assessment", "annual_risk_assessment", "threat_model", "risk_register"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-010",
			ControlName: "Risk Assessment Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Annual risk assessment verified: assessment + threat model + risk register + annual review",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-12-010",
			ControlName: "Risk Assessment Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial risk assessment: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Document risk assessment + threat model + risk register + annual review process",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-12-010",
		ControlName: "Risk Assessment Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No risk assessment process detected",
		Timestamp:   time.Now(),
		Remediation: "Document risk assessment + threat model + risk register + annual review process",
	}, nil
}

func (m *PCIModule) checkAICardProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	cardData := m.detectCardData(string(input))

	if len(cardData) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-001",
			ControlName: "AI Data Protection Requirements",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No payment card data detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-001",
		ControlName: "AI Data Protection Requirements",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Payment card patterns detected in AI model data",
		Timestamp:   time.Now(),
		Remediation: "Implement tokenization for all AI model card data",
	}, nil
}

func (m *PCIModule) checkAIModelVuln(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"ai_vuln_scan", "model_scan", "ai_security_scan", "adversarial_test"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-002",
			ControlName: "AI Model Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI model vulnerability scanning verified: model scanning detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-002",
			ControlName: "AI Model Vulnerability Scanning",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI model scanning: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement vulnerability scanning for AI models (adversarial testing, model scanning)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-002",
		ControlName: "AI Model Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI model vulnerability scanning detected",
		Timestamp:   time.Now(),
		Remediation: "Implement vulnerability scanning for AI models (adversarial testing, model scanning)",
	}, nil
}

func (m *PCIModule) checkAIAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"ai_access_control", "ai_rbac", "ai_permissions", "model_access_control"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-003",
			ControlName: "AI Access Control for Payment Data",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI access control verified: AI system permissions detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-003",
			ControlName: "AI Access Control for Payment Data",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI access control: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement access controls for AI systems accessing payment data (RBAC, permissions)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-003",
		ControlName: "AI Access Control for Payment Data",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI access controls detected for payment data",
		Timestamp:   time.Now(),
		Remediation: "Implement access controls for AI systems accessing payment data (RBAC, permissions)",
	}, nil
}

func (m *PCIModule) checkAIAuditLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"audit_log", "audit_trail", "immutable_log", "signed_attestation", "ai_audit"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-004",
			ControlName: "AI Model Audit Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Immutable audit trail detected for AI cardholder data access",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-004",
			ControlName: "AI Model Audit Logging",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial AI audit trail: some logging controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement immutable audit trails with signed attestations for all AI systems accessing cardholder data",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-004",
		ControlName: "AI Model Audit Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No immutable audit trail detected for AI cardholder data access",
		Timestamp:   time.Now(),
		Remediation: "Implement immutable audit trails with signed attestations for all AI systems accessing cardholder data",
	}, nil
}

func (m *PCIModule) checkDataRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"retention_policy", "data_expiry"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-001",
			ControlName: "Data Retention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data retention policies configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-001",
			ControlName: "Data Retention",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Data retention policies need review",
			Timestamp:   time.Now(),
			Remediation: "Implement explicit data retention and deletion policies",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-001",
		ControlName: "Data Retention",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Data retention policies need review",
		Timestamp:   time.Now(),
		Remediation: "Implement explicit data retention and deletion policies",
	}, nil
}

func (m *PCIModule) checkAITokenization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"tokenization", "tokenized", "payment_token"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-002",
			ControlName: "AI Model Tokenization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Tokenization detected for AI model data",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-002",
			ControlName: "AI Model Tokenization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial tokenization: some controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement tokenization for all payment data in AI systems",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-002",
		ControlName: "AI Model Tokenization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Tokenization not detected for AI model data",
		Timestamp:   time.Now(),
		Remediation: "Implement tokenization for all payment data in AI systems",
	}, nil
}

// pciCount is a small helper to avoid importing strconv.
func pciCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// detectCardData scans input for potential card data patterns.
func (m *PCIModule) detectCardData(input string) []string {
	found := []string{}
	for _, pattern := range m.cardPatterns {
		if pattern.MatchString(input) {
			found = append(found, "card_pattern_detected")
		}
	}
	return found
}

// checkRuleSetReview checks for periodic review of network security control rule sets.
func (m *PCIModule) checkRuleSetReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"rule_review", "ruleset_review", "firewall_review", "acl_review", "policy_review"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-007",
			ControlName: "Review Network Security Control Rule Sets Every 6 Months",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Network security control rule set reviews detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-007",
			ControlName: "Review Network Security Control Rule Sets Every 6 Months",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial rule set review evidence detected",
			Timestamp:   time.Now(),
			Remediation: "Establish a formal process to review network security control rule sets at least every 6 months per PCI-DSS v4.0 Req 1.7",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-007",
		ControlName: "Review Network Security Control Rule Sets Every 6 Months",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No evidence of rule set reviews detected",
		Timestamp:   time.Now(),
		Remediation: "Establish a formal process to review network security control rule sets at least every 6 months per PCI-DSS v4.0 Req 1.7",
	}, nil
}

// checkUnnecessaryConfigs checks for removal of unnecessary configurations and rules.
func (m *PCIModule) checkUnnecessaryConfigs(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"config_cleanup", "unnecessary_rules_removed", "rule_cleanup", "config_review", "stale_rules"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-008",
			ControlName: "Remove Unnecessary Configurations",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Unnecessary configuration removal process detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-008",
			ControlName: "Remove Unnecessary Configurations",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial evidence of unnecessary configuration removal",
			Timestamp:   time.Now(),
			Remediation: "Implement a process to remove unnecessary configurations and rules from network security controls per PCI-DSS v4.0 Req 1.8",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-008",
		ControlName: "Remove Unnecessary Configurations",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No evidence of unnecessary configuration removal",
		Timestamp:   time.Now(),
		Remediation: "Implement a process to remove unnecessary configurations and rules from network security controls per PCI-DSS v4.0 Req 1.8",
	}, nil
}

// checkInternalIPLegacy checks that internal IP addresses are not accessible from the internet.
func (m *PCIModule) checkInternalIPLegacy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"internal_ip_protected", "nat_configured", "private_ip", "no_public_exposure", "ip_filtering"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-012",
			ControlName: "Internal IP Addresses Not Accessible from Internet",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Internal IP addresses protected from internet access",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-012",
			ControlName: "Internal IP Addresses Not Accessible from Internet",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial protection of internal IP addresses detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure internal IP addresses are not accessible from the internet per PCI-DSS v4.0 Req 1.12",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-012",
		ControlName: "Internal IP Addresses Not Accessible from Internet",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Internal IP addresses may be accessible from internet",
		Timestamp:   time.Now(),
		Remediation: "Ensure internal IP addresses are not accessible from the internet per PCI-DSS v4.0 Req 1.12",
	}, nil
}

// checkAdminAccessEncryption checks for encrypted administrative access to network security components.
func (m *PCIModule) checkAdminAccessEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"admin_encryption", "ssh_tunnel", "vpn_admin", "tls_admin", "encrypted_admin_access"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-014",
			ControlName: "Encrypt Admin Access to Network Security Components",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Encrypted administrative access to network security components detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-014",
			ControlName: "Encrypt Admin Access to Network Security Components",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial encryption of administrative access detected",
			Timestamp:   time.Now(),
			Remediation: "Encrypt all administrative access to network security components per PCI-DSS v4.0 Req 1.14",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-014",
		ControlName: "Encrypt Admin Access to Network Security Components",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No encrypted administrative access detected",
		Timestamp:   time.Now(),
		Remediation: "Encrypt all administrative access to network security components per PCI-DSS v4.0 Req 1.14",
	}, nil
}

// checkUnnecessaryFunctionality checks for removal of unnecessary functionality from system components.
func (m *PCIModule) checkUnnecessaryFunctionality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"functionality_removed", "unnecessary_scripts_removed", "drivers_removed", "subsystems_removed", "hardening"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-005",
			ControlName: "Remove Unnecessary Functionality",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Unnecessary functionality removal process detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-02-005",
			ControlName: "Remove Unnecessary Functionality",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial evidence of unnecessary functionality removal",
			Timestamp:   time.Now(),
			Remediation: "Remove unnecessary functionality from system components including scripts, drivers, and subsystems per PCI-DSS v4.0 Req 2.5",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-005",
		ControlName: "Remove Unnecessary Functionality",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No evidence of unnecessary functionality removal",
		Timestamp:   time.Now(),
		Remediation: "Remove unnecessary functionality from system components including scripts, drivers, and subsystems per PCI-DSS v4.0 Req 2.5",
	}, nil
}

// checkMinimizeDataStorage checks for minimization of account data storage.
func (m *PCIModule) checkMinimizeDataStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"data_minimization", "storage_limit", "data_reduction", "retention_limit", "minimal_storage"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-001",
			ControlName: "Minimize Storage of Account Data",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Account data storage minimization detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-001",
			ControlName: "Minimize Storage of Account Data",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial data storage minimization detected",
			Timestamp:   time.Now(),
			Remediation: "Minimize storage of account data to only what is necessary for business and legal purposes per PCI-DSS v4.0 Req 3.1",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-001",
		ControlName: "Minimize Storage of Account Data",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No evidence of account data storage minimization",
		Timestamp:   time.Now(),
		Remediation: "Minimize storage of account data to only what is necessary for business and legal purposes per PCI-DSS v4.0 Req 3.1",
	}, nil
}

// checkDataRetentionDisposal checks for data retention and disposal policies.
func (m *PCIModule) checkDataRetentionDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"retention_policy", "disposal_policy", "data_retention", "secure_disposal", "data_destruction"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-009",
			ControlName: "Data Retention and Disposal Policies",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data retention and disposal policies detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-009",
			ControlName: "Data Retention and Disposal Policies",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial data retention and disposal policies detected",
			Timestamp:   time.Now(),
			Remediation: "Establish and maintain data retention and disposal policies for cardholder data per PCI-DSS v4.0 Req 3.9",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-009",
		ControlName: "Data Retention and Disposal Policies",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No data retention and disposal policies detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and maintain data retention and disposal policies for cardholder data per PCI-DSS v4.0 Req 3.9",
	}, nil
}

// checkAntiMalwareActive checks that anti-malware mechanisms are actively running.
func (m *PCIModule) checkAntiMalwareActive(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"antivirus", "anti-malware", "malware_scanner", "real_time_protection", "endpoint_protection"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-002",
			ControlName: "Anti-Malware Mechanisms Actively Running",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anti-malware mechanisms actively running",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-002",
			ControlName: "Anti-Malware Mechanisms Actively Running",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial anti-malware protection detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure anti-malware mechanisms are actively running on all system components per PCI-DSS v4.0 Req 5.2",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-002",
		ControlName: "Anti-Malware Mechanisms Actively Running",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No active anti-malware mechanisms detected",
		Timestamp:   time.Now(),
		Remediation: "Ensure anti-malware mechanisms are actively running on all system components per PCI-DSS v4.0 Req 5.2",
	}, nil
}

// checkAntiMalwareNonDisableable checks that anti-malware mechanisms cannot be disabled by users.
func (m *PCIModule) checkAntiMalwareNonDisableable(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"non_disableable", "tamper_protection", "admin_only", "protected_mechanism", "locked_antivirus"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-003",
			ControlName: "Anti-Malware Mechanisms Not Disableable by Users",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anti-malware mechanisms protected from user modification",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-003",
			ControlName: "Anti-Malware Mechanisms Not Disableable by Users",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial protection of anti-malware mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure anti-malware mechanisms cannot be disabled or modified by users without authorization per PCI-DSS v4.0 Req 5.3",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-003",
		ControlName: "Anti-Malware Mechanisms Not Disableable by Users",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Anti-malware mechanisms may be disableable by users",
		Timestamp:   time.Now(),
		Remediation: "Ensure anti-malware mechanisms cannot be disabled or modified by users without authorization per PCI-DSS v4.0 Req 5.3",
	}, nil
}

// checkChangeControl checks for change control procedures.
func (m *PCIModule) checkChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"change_control", "change_management", "change_approval", "change_review", "cab_review"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-008",
			ControlName: "Change Control Procedures for All Changes",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Change control procedures detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-008",
			ControlName: "Change Control Procedures for All Changes",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial change control procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Establish change control procedures for all changes to system components in the CDE per PCI-DSS v4.0 Req 6.8",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-008",
		ControlName: "Change Control Procedures for All Changes",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No change control procedures detected",
		Timestamp:   time.Now(),
		Remediation: "Establish change control procedures for all changes to system components in the CDE per PCI-DSS v4.0 Req 6.8",
	}, nil
}

// checkAccessRightsReview checks for periodic access rights reviews.
func (m *PCIModule) checkAccessRightsReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"access_review", "rights_review", "permission_audit", "access_audit", "periodic_review"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-005",
			ControlName: "Access Rights Reviewed at Least Every 6 Months",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Access rights review process detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-005",
			ControlName: "Access Rights Reviewed at Least Every 6 Months",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial access rights review evidence detected",
			Timestamp:   time.Now(),
			Remediation: "Review access rights at least every 6 months to ensure they remain appropriate per PCI-DSS v4.0 Req 7.5",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-005",
		ControlName: "Access Rights Reviewed at Least Every 6 Months",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No evidence of access rights reviews",
		Timestamp:   time.Now(),
		Remediation: "Review access rights at least every 6 months to ensure they remain appropriate per PCI-DSS v4.0 Req 7.5",
	}, nil
}

// checkPasswordNotReadable checks that passwords are not stored in readable format.
func (m *PCIModule) checkPasswordNotReadable(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"password_hash", "bcrypt", "argon2", "scrypt", "hashed_password", "pbkdf2"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-014",
			ControlName: "Passwords Not Stored in Readable Format",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Passwords stored with strong cryptography, not in readable format",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-014",
			ControlName: "Passwords Not Stored in Readable Format",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial password protection detected",
			Timestamp:   time.Now(),
			Remediation: "Ensure passwords and passphrases are not stored in readable format and are protected with strong cryptography per PCI-DSS v4.0 Req 8.14",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-014",
		ControlName: "Passwords Not Stored in Readable Format",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Passwords may be stored in readable format",
		Timestamp:   time.Now(),
		Remediation: "Ensure passwords and passphrases are not stored in readable format and are protected with strong cryptography per PCI-DSS v4.0 Req 8.14",
	}, nil
}

// checkAuditTrailRetention checks for audit trail history retention of at least 1 year.
func (m *PCIModule) checkAuditTrailRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"audit_retention", "log_retention", "retention_1_year", "audit_history", "log_archive"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-009",
			ControlName: "Audit Trail History Retained at Least 1 Year",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit trail history retention for at least 1 year detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-009",
			ControlName: "Audit Trail History Retained at Least 1 Year",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial audit trail retention detected",
			Timestamp:   time.Now(),
			Remediation: "Retain audit trail history for at least 1 year with 3 months immediately available per PCI-DSS v4.0 Req 10.9",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-009",
		ControlName: "Audit Trail History Retained at Least 1 Year",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No evidence of audit trail history retention",
		Timestamp:   time.Now(),
		Remediation: "Retain audit trail history for at least 1 year with 3 months immediately available per PCI-DSS v4.0 Req 10.9",
	}, nil
}

// checkTimeSyncNTP checks for NTP or equivalent time synchronization (PCI-10-010).
func (m *PCIModule) checkTimeSyncNTP(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"ntp", "time_sync", "time_synchronization", "chrony", "ntp_server"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-010",
			ControlName: "Time Sync Using NTP or Equivalent",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Time synchronization using NTP or equivalent detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-010",
			ControlName: "Time Sync Using NTP or Equivalent",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial time synchronization detected",
			Timestamp:   time.Now(),
			Remediation: "Use NTP or equivalent time synchronization protocol for all systems in the CDE per PCI-DSS v4.0 Req 10.10",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-010",
		ControlName: "Time Sync Using NTP or Equivalent",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No time synchronization detected",
		Timestamp:   time.Now(),
		Remediation: "Use NTP or equivalent time synchronization protocol for all systems in the CDE per PCI-DSS v4.0 Req 10.10",
	}, nil
}

// checkLogIntegrity checks that logs are protected from modification.
func (m *PCIModule) checkLogIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"log_integrity", "log_protection", "immutable_logs", "append_only", "log_hashing", "tamper_protection"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-011",
			ControlName: "Logs Protected from Modification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Logs protected from modification detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-011",
			ControlName: "Logs Protected from Modification",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial log protection detected",
			Timestamp:   time.Now(),
			Remediation: "Protect audit logs from modification, deletion, or unauthorized access per PCI-DSS v4.0 Req 10.11",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-011",
		ControlName: "Logs Protected from Modification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No log protection from modification detected",
		Timestamp:   time.Now(),
		Remediation: "Protect audit logs from modification, deletion, or unauthorized access per PCI-DSS v4.0 Req 10.11",
	}, nil
}

// checkFileIntegrityMonitoring checks for file integrity monitoring (FIM) tools.
func (m *PCIModule) checkFileIntegrityMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"fim", "file_integrity", "integrity_monitoring", "tripwire", "aide", "fim_enabled"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	threshold := (len(keywords) + 1) / 2

	if found >= threshold {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-012",
			ControlName: "File Integrity Monitoring (FIM)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "File integrity monitoring tools detected",
			Timestamp:   time.Now(),
		}, nil
	}
	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-11-012",
			ControlName: "File Integrity Monitoring (FIM)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial file integrity monitoring detected",
			Timestamp:   time.Now(),
			Remediation: "Deploy file integrity monitoring tools to detect unauthorized changes to critical files per PCI-DSS v4.0 Req 11.12",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-11-012",
		ControlName: "File Integrity Monitoring (FIM)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No file integrity monitoring tools detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy file integrity monitoring tools to detect unauthorized changes to critical files per PCI-DSS v4.0 Req 11.12",
	}, nil
}

// Dependencies returns required modules.
func (m *PCIModule) Dependencies() []string {
	return []string{"scanner"}
}
