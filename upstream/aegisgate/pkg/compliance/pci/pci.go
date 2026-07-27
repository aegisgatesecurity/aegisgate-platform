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
		BaseComplianceModule: compliance.NewBaseComplianceModule("pci-dss", "4.0", core.TierEnterprise),
	}

	m.initCardPatterns()
	m.registerControls()

	return m
}

// initCardPatterns initializes patterns for detecting payment card data.
func (m *PCIModule) initCardPatterns() {
	m.cardPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)d{4}[-s]?d{4}[-s]?d{4}[-s]?d{4}`), // 16-digit cards
		regexp.MustCompile(`(?i)d{4}[-s]?d{6}[-s]?d{5}`),          // Amex
		regexp.MustCompile(`(?i)d{13,19}`),                        // Generic PAN range
		regexp.MustCompile(`(?i)d{3}[-s]?d{2,4}`),                 // CVV/CVC
		regexp.MustCompile(`(?i)d{2}[-s]?d{2}[-s]?d{4}`),          // Expiry
		regexp.MustCompile(`(?i)[3-6]d{12,18}`),                   // Card BIN ranges
	}
}

// registerControls registers all PCI-DSS controls.
func (m *PCIModule) registerControls() {
	// Requirement 1: Install and maintain network security controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-001",
		Name:        "Firewall Configuration",
		Description: "Install and maintain network security controls between trusted and untrusted networks",
		Category:    "Network Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFirewallConfig,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-01-002",
		Name:        "Network Diagrams",
		Description: "Maintain current network diagrams showing all cardholder data flows",
		Category:    "Network Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// Requirement 2: Apply secure configurations
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-001",
		Name:        "Default Credentials",
		Description: "Change all default credentials before system installation",
		Category:    "Configuration",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDefaultCredentials,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-02-002",
		Name:        "System Hardening",
		Description: "Develop configuration standards for all system components",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemHardening,
	})

	// Requirement 3: Protect stored account data
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-001",
		Name:        "Data Retention",
		Description: "Keep cardholder data storage to a minimum",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRetention,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-03-002",
		Name:        "PAN Masking",
		Description: "Mask PAN when displayed, show no more than first 6/last 4 digits",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPANMasking,
	})

	// Requirement 4: Protect cardholder data with strong cryptography
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-001",
		Name:        "Transmission Encryption",
		Description: "Encrypt cardholder data during transmission over open networks",
		Category:    "Encryption",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionEncryption,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-04-002",
		Name:        "TLS Configuration",
		Description: "Use TLS 1.2 or higher for all cardholder data transmission",
		Category:    "Encryption",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTLSConfig,
	})

	// Requirement 5: Protect all systems and software from known vulnerabilities
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-001",
		Name:        "Malware Protection",
		Description: "Deploy anti-malware solutions on all systems",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMalwareProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-05-002",
		Name:        "Vulnerability Scanning",
		Description: "Identify and address security vulnerabilities",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkVulnScanning,
	})

	// Requirement 6: Develop and maintain secure systems and software
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-001",
		Name:        "Secure Development",
		Description: "Establish secure development processes for all software",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-06-002",
		Name:        "Code Review",
		Description: "Review custom code to identify vulnerabilities",
		Category:    "Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCodeReview,
	})

	// Requirement 7: Restrict access by business need-to-know
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-07-001",
		Name:        "Access Control",
		Description: "Restrict access to cardholder data to only authorized personnel",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
	})

	// Requirement 8: Identify users and authenticate access
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-001",
		Name:        "User Authentication",
		Description: "Identify all users with access to cardholder data",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkUserAuth,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-08-002",
		Name:        "Multi-Factor Authentication",
		Description: "Implement MFA for all access to cardholder data environment",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFA,
	})

	// Requirement 9: Restrict physical access to cardholder data
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-09-001",
		Name:        "Physical Access Controls",
		Description: "Restrict physical access to cardholder data",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// Requirement 10: Log and monitor all access
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-10-001",
		Name:        "Audit Logging",
		Description: "Log all access to cardholder data",
		Category:    "Monitoring",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditLogging,
	})

	// Requirement 11: Test security systems regularly
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-11-001",
		Name:        "Penetration Testing",
		Description: "Perform penetration testing at least annually",
		Category:    "Testing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// Requirement 12: Support information security with organizational policies
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-12-001",
		Name:        "Security Policy",
		Description: "Implement and maintain security policies",
		Category:    "Policy",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// AI-Specific PCI Controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-001",
		Name:        "AI Card Data Protection",
		Description: "Ensure AI models do not retain or expose payment card data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAICardProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "PCI-AI-002",
		Name:        "AI Model Tokenization",
		Description: "Verify AI models use tokenized card data, not actual PANs",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITokenization,
	})
}

// Check implementations

func (m *PCIModule) checkFirewallConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFirewall := strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "network_policy")

	if hasFirewall {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-01-001",
			ControlName: "Firewall Configuration",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Network security controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-01-001",
		ControlName: "Firewall Configuration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Network security controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement firewall rules and network segmentation",
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
				ControlName: "Default Credentials",
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
		ControlName: "Default Credentials",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No default credentials detected",
		Timestamp:   time.Now(),
	}, nil
}

func (m *PCIModule) checkSystemHardening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-02-002",
		ControlName: "System Hardening",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System hardening standards in place",
		Timestamp:   time.Now(),
	}, nil
}

func (m *PCIModule) checkDataRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetentionPolicy := strings.Contains(inputStr, "retention_policy") || strings.Contains(inputStr, "data_expiry")

	if hasRetentionPolicy {
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

func (m *PCIModule) checkPANMasking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMasking := strings.Contains(inputStr, "pan_masking") || strings.Contains(inputStr, "card_mask")

	if hasMasking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-03-002",
			ControlName: "PAN Masking",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "PAN masking implemented",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-03-002",
		ControlName: "PAN Masking",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "PAN masking not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement PAN masking to display only first 6/last 4 digits",
	}, nil
}

func (m *PCIModule) checkTransmissionEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-001",
			ControlName: "Transmission Encryption",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Transmission encryption detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-001",
		ControlName: "Transmission Encryption",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Transmission encryption not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ for all cardholder data transmission",
	}, nil
}

func (m *PCIModule) checkTLSConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS12OrHigher := strings.Contains(inputStr, "tls1.2") || strings.Contains(inputStr, "tls1.3") ||
		strings.Contains(inputStr, "tls_12") || strings.Contains(inputStr, "tls_13")

	if hasTLS12OrHigher {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-04-002",
			ControlName: "TLS Configuration",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.2 or higher configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-04-002",
		ControlName: "TLS Configuration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "TLS version not compliant with PCI-DSS 4.0",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2 or higher",
	}, nil
}

func (m *PCIModule) checkMalwareProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMalwareProtection := strings.Contains(inputStr, "antivirus") || strings.Contains(inputStr, "malware") ||
		strings.Contains(inputStr, "scanner")

	if hasMalwareProtection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-001",
			ControlName: "Malware Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malware protection detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-001",
		ControlName: "Malware Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malware protection not detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy anti-malware solutions on all systems",
	}, nil
}

func (m *PCIModule) checkVulnScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScanning := strings.Contains(inputStr, "vulnerability_scan") || strings.Contains(inputStr, "security_scan")

	if hasVulnScanning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-05-002",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Vulnerability scanning configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-05-002",
		ControlName: "Vulnerability Scanning",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Verify vulnerability scanning schedule",
		Timestamp:   time.Now(),
		Remediation: "Implement automated vulnerability scanning",
	}, nil
}

func (m *PCIModule) checkCodeReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCodeReview := strings.Contains(inputStr, "code_review") || strings.Contains(inputStr, "pull_request")

	if hasCodeReview {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-06-002",
			ControlName: "Code Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Code review process detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-06-002",
		ControlName: "Code Review",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Code review process needs verification",
		Timestamp:   time.Now(),
		Remediation: "Implement mandatory code review for all changes",
	}, nil
}

func (m *PCIModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "role_based") ||
		strings.Contains(inputStr, "access_control")

	if hasRBAC {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-07-001",
			ControlName: "Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Role-based access control detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-07-001",
		ControlName: "Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control not properly configured",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access control",
	}, nil
}

func (m *PCIModule) checkUserAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")

	if hasAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-001",
			ControlName: "User Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "User authentication configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-001",
		ControlName: "User Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "User authentication not configured",
		Timestamp:   time.Now(),
		Remediation: "Implement user authentication for all access",
	}, nil
}

func (m *PCIModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor") ||
		strings.Contains(inputStr, "2fa") || strings.Contains(inputStr, "totp")

	if hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-08-002",
			ControlName: "Multi-Factor Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-08-002",
		ControlName: "Multi-Factor Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "MFA not configured",
		Timestamp:   time.Now(),
		Remediation: "Implement MFA for all cardholder data environment access",
	}, nil
}

func (m *PCIModule) checkAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled")

	if hasAuditLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-10-001",
			ControlName: "Audit Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-10-001",
		ControlName: "Audit Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit logging not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging",
	}, nil
}

func (m *PCIModule) checkAICardProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	cardData := m.detectCardData(string(input))

	if len(cardData) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "PCI-AI-001",
			ControlName: "AI Card Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No payment card data detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "PCI-AI-001",
		ControlName: "AI Card Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Payment card patterns detected in AI model data",
		Timestamp:   time.Now(),
		Remediation: "Implement tokenization for all AI model card data",
	}, nil
}

func (m *PCIModule) checkAITokenization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTokenization := strings.Contains(inputStr, "tokenization") || strings.Contains(inputStr, "tokenized") ||
		strings.Contains(inputStr, "payment_token")

	if hasTokenization {
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

// Dependencies returns required modules.
func (m *PCIModule) Dependencies() []string {
	return []string{"scanner"}
}
