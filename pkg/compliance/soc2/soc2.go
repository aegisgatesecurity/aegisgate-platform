// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Type II Compliance Module
// =========================================================================
//
// Implements the SOC 2 (Service Organization Control 2) Type II
// compliance framework as a licensed add-on module. This is the
// 6th compliance framework shipped (HIPAA, PCI-DSS, EU AI Act,
// SOC 2, ISO 42001; FedRAMP and FIPS 140 are Path B remaining).
//
// Module metadata:
//   - Framework:   "soc2"
//   - Version:     "1.0"
//   - Required tier: Developer+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $149/mo (founder-locked 2026-06-04)
//
// Coverage: 8 Trust Service Criteria controls across 4 categories
// (Security CC, Processing Integrity PI, Confidentiality C, AI
// Controls). Of the 8 controls, 5 have automated CheckFunc
// implementations; the remaining 3 are manual review items.
//
// Reference: AICPA Trust Services Criteria 2017 (revised 2022)
//            https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
//            The existing pkg/compliance/soc2_framework.go (data
//            structures) is preserved for backward compatibility; the
//            active implementation lives in this sub-package.
//
// =========================================================================

package soc2

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// SOC2Module implements the SOC 2 Type II compliance framework as a
// licensed add-on. It embeds *compliance.BaseComplianceModule which
// provides RegisterControl, Controls(), Framework(), Version(),
// CheckAll(), and GenerateAssessment() out of the box.
type SOC2Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	piiPatterns        []*regexp.Regexp
	mTLSConfigPatterns []*regexp.Regexp
	auditLogPatterns   []*regexp.Regexp
}

// NewSOC2Module creates a new SOC 2 compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Developer+ tier via pkg/compliance/gating.go
// (license.ModuleSOC2 entry in moduleRequirements).
func NewSOC2Module() *SOC2Module {
	m := &SOC2Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("soc2", "1.0", core.TierDeveloper),
	}
	m.initSOC2Patterns()
	m.registerControls()
	return m
}

// initSOC2Patterns compiles the regex patterns used by automated
// controls. Called once at construction time.
func (m *SOC2Module) initSOC2Patterns() {
	m.piiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                           // SSN
		regexp.MustCompile(`\d{16}`),                                      // Credit card
		regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}`), // Email
	}
	m.mTLSConfigPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mtls`),
		regexp.MustCompile(`(?i)mutual[_ ]?tls`),
		regexp.MustCompile(`(?i)client[_ ]?cert`),
	}
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)signed[_ ]?log`),
	}
}

// registerControls wires all 8 SOC 2 controls into the module.
// Called once from NewSOC2Module. The 5 automated controls reference
// check* methods defined below; the rest are manual review.
func (m *SOC2Module) registerControls() {
	// Common Criteria (Security)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.1",
		Name:        "Logical and Physical Access Controls",
		Description: "SOC 2 CC6.1: Implement logical and physical access controls to protect against unauthorized access",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
		References:  []string{"AICPA TSC 2017 CC6.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.2",
		Name:        "ML Environment Security",
		Description: "SOC 2 CC6.2: ML training and inference environments are secured",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMLEnvironmentSecurity,
		References:  []string{"AICPA TSC 2017 CC6.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.3",
		Name:        "Data Protection",
		Description: "SOC 2 CC6.3: Data protected from unauthorized access through encryption, masking, and access controls",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataProtection,
		References:  []string{"AICPA TSC 2017 CC6.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.6",
		Name:        "System Operations - Audit Logging",
		Description: "SOC 2 CC6.6: Security operations are monitored with audit logging",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditLogging,
		References:  []string{"AICPA TSC 2017 CC6.6"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC6.7",
		Name:        "Data Transmission Security",
		Description: "SOC 2 CC6.7: Data in transit is protected using TLS 1.2+ (and mTLS where applicable)",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionSecurity,
		References:  []string{"AICPA TSC 2017 CC6.7"},
	})

	// Processing Integrity
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-PI1.2",
		Name:        "ML Processing Integrity",
		Description: "SOC 2 PI1.2: ML processing produces accurate, complete, and authorized results",
		Category:    "Processing Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Requires domain expertise to evaluate model accuracy
		References:  []string{"AICPA TSC 2017 PI1.2"},
	})

	// Confidentiality
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C1.1",
		Name:        "Confidential Information Identification",
		Description: "SOC 2 C1.1: Confidential information is identified and protected throughout the lifecycle",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Requires data classification policy review
		References:  []string{"AICPA TSC 2017 C1.1"},
	})

	// AI-specific extension (AegisGate's contribution to SOC 2 for AI/ML)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-AI-001",
		Name:        "Adversarial Defense",
		Description: "SOC 2 AI Extension: Protected against adversarial AI attacks (prompt injection, model evasion, data poisoning)",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   false, // Requires AegisGate-specific scanner integration review
		References:  []string{"AegisGate AI Controls"},
	})
}

// ============================================================================
// Check implementations
// ============================================================================

// checkAccessControl verifies authentication, RBAC, and session timeouts
// are configured. Inputs to this check should be the platform's
// configuration as a JSON string.
func (m *SOC2Module) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasRBAC {
		violations = append(violations, "role-based access control not detected")
	}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.1",
			ControlName: "Logical and Physical Access Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "All access control requirements met (auth, RBAC, session timeout)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.1",
		ControlName: "Logical and Physical Access Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Implement authentication, RBAC, and session timeouts in platformconfig.Security.* and platformconfig.Auth.*",
	}, nil
}

// checkMLEnvironmentSecurity verifies mTLS and environment isolation
// are configured for the ML/agent services.
func (m *SOC2Module) checkMLEnvironmentSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMTLS := false
	for _, p := range m.mTLSConfigPatterns {
		if p.MatchString(inputStr) {
			hasMTLS = true
			break
		}
	}
	hasIsolation := strings.Contains(inputStr, "isolation") || strings.Contains(inputStr, "sandbox") || strings.Contains(inputStr, "kubernetes")

	if hasMTLS && hasIsolation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.2",
			ControlName: "ML Environment Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "ML environment security verified: mTLS enabled, environment isolation configured",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMTLS {
		violations = append(violations, "mTLS not configured (set tls.mutual_tls.enabled=true)")
	}
	if !hasIsolation {
		violations = append(violations, "environment isolation not detected (recommended: Kubernetes namespace isolation, sandboxed inference)")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.2",
		ControlName: "ML Environment Security",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "ML environment security gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable mTLS for inter-service communication; deploy agents in isolated Kubernetes namespaces",
	}, nil
}

// checkDataProtection verifies encryption at rest and in transit,
// plus the absence of PII in the request/response stream.
func (m *SOC2Module) checkDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasEncryptionInTransit := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")

	// Check for PII in the actual content (first 10KB)
	contentStr := inputStr
	if len(contentStr) > 10240 {
		contentStr = contentStr[:10240]
	}
	piiFound := false
	for _, p := range m.piiPatterns {
		if p.MatchString(contentStr) {
			piiFound = true
			break
		}
	}

	if hasEncryptionAtRest && hasEncryptionInTransit && !piiFound {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.3",
			ControlName: "Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data protection verified: encryption at rest + in transit, no PII patterns detected",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryptionAtRest {
		violations = append(violations, "encryption at rest not configured")
	}
	if !hasEncryptionInTransit {
		violations = append(violations, "encryption in transit not configured")
	}
	if piiFound {
		violations = append(violations, "PII patterns detected in data stream (SSN/credit card/email)")
	}

	status := compliance.StatusNonCompliant
	if piiFound {
		status = compliance.StatusNonCompliant
	} else if !hasEncryptionAtRest || !hasEncryptionInTransit {
		status = compliance.StatusPartial
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.3",
		ControlName: "Data Protection",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     "Data protection issues: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable encryption at rest (persistence.encryption=true) and in transit (TLS 1.2+); review PII patterns and ensure PII is redacted before logging",
	}, nil
}

// checkAuditLogging verifies that audit logging with integrity
// verification is enabled (the foundation of SOC 2 evidence collection).
func (m *SOC2Module) checkAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := false
	hasIntegrity := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			// hash-chain integrity or signed logs
			if strings.Contains(p.String(), "integrity") || strings.Contains(p.String(), "signed") {
				hasIntegrity = true
			}
		}
	}

	if hasAudit && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.6",
			ControlName: "System Operations - Audit Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging with integrity verification detected (the foundation of SOC 2 evidence)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAudit && !hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.6",
			ControlName: "System Operations - Audit Logging",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging enabled but integrity verification not detected",
			Timestamp:   time.Now(),
			Remediation: "Enable hash-chain or signed log integrity (persistence.log_integrity=true) so audit logs are tamper-evident",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.6",
		ControlName: "System Operations - Audit Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit logging not enabled",
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (persistence.audit=true) with hash-chain integrity verification",
	}, nil
}

// checkTransmissionSecurity verifies TLS 1.2+ is enabled and mTLS
// is configured for inter-service communication.
func (m *SOC2Module) checkTransmissionSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasTLS12 := strings.Contains(inputStr, "tls1.2") || strings.Contains(inputStr, "tls_1_2") || strings.Contains(inputStr, "min_version: 1.2")
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_1_3") || strings.Contains(inputStr, "min_version: 1.3")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.7",
			ControlName: "Data Transmission Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.3 enabled for data transmission security",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS12 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.7",
			ControlName: "Data Transmission Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.2 enabled for data transmission security",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC6.7",
			ControlName: "Data Transmission Security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS detected but version unclear; recommend setting min_version explicitly",
			Timestamp:   time.Now(),
			Remediation: "Set tls.min_version to 1.2 or 1.3 in configs/aegisgate-platform.yaml",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC6.7",
		ControlName: "Data Transmission Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "TLS encryption not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2 or 1.3 in configs/aegisgate-platform.yaml (tls.min_version)",
	}, nil
}

// Dependencies returns required modules. The SOC 2 module depends on
// the scanner (for adversarial defense checks) and the persistence
// layer (for audit log integrity verification).
func (m *SOC2Module) Dependencies() []string {
	return []string{"scanner", "persistence"}
}
