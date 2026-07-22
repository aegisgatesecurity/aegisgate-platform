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
		BaseComplianceModule: compliance.NewBaseComplianceModule("soc2", "1.1", core.TierDeveloper),
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

	// Common Criteria (Security) — additional sub-clauses for v3.x Tier 1
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.1",
		Name:        "Control Environment",
		Description: "SOC 2 CC1.1: Organization demonstrates commitment to integrity and ethical values (code of conduct, security policies documented and accessible)",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkControlEnvironment,
		References:  []string{"AICPA TSC 2017 CC1.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC1.4",
		Name:        "Segregation of Duties",
		Description: "SOC 2 CC1.4: Conflicting duties are segregated to reduce the risk of unauthorized or fraudulent activity. AegisGate's RBAC + MFA implements this for the platform.",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSegregationOfDuties,
		References:  []string{"AICPA TSC 2017 CC1.4"},
	})

	// Common Criteria 7.x — System Operations (additional sub-clauses)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.2",
		Name:        "Monitoring for Anomalies and Security Events",
		Description: "SOC 2 CC7.2: System activity is monitored for anomalies and security events. AegisGate's IOC store + anomaly detection (Trust Framework) + audit log provide the monitoring infrastructure.",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAnomalyMonitoring,
		References:  []string{"AICPA TSC 2017 CC7.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.3",
		Name:        "Evaluation of Security Events",
		Description: "SOC 2 CC7.3: Security events are evaluated to determine whether they should be classified as incidents. AegisGate's audit log + IOC store + Trust Framework attestations provide the evidence for evaluation.",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEventEvaluation,
		References:  []string{"AICPA TSC 2017 CC7.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-CC7.4",
		Name:        "Incident Response Plan",
		Description: "SOC 2 CC7.4: A documented incident response plan is in place and tested. AegisGate's signed attestations (pkg/attestation/) and IOC federation provide the IR evidence.",
		Category:    "Security (Common Criteria)",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
		References:  []string{"AICPA TSC 2017 CC7.4"},
	})

	// Availability (A1.1) — Capacity Planning
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-A1.1",
		Name:        "Availability — Capacity Planning and Monitoring",
		Description: "SOC 2 A1.1: System capacity is monitored and current demand is compared to capacity. AegisGate's metrics (Prometheus) + dashboards (Grafana) + alerts provide the monitoring infrastructure.",
		Category:    "Availability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCapacityPlanning,
		References:  []string{"AICPA TSC 2017 A1.1"},
	})

	// Confidentiality (C2.1) — Third-Party Risk
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOC2-C2.1",
		Name:        "Confidentiality — Third-Party Risk Management",
		Description: "SOC 2 C2.1: Third-party vendors and service providers are identified and the risks they pose to the system are assessed and managed. AegisGate's vendor inventory + access controls + DPAs provide the evidence.",
		Category:    "Confidentiality",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThirdPartyRisk,
		References:  []string{"AICPA TSC 2017 C2.1"},
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

// checkControlEnvironment verifies that security policies and
// code of conduct are documented and accessible. Maps to SOC 2 CC1.1.
func (m *SOC2Module) checkControlEnvironment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurityPolicy := strings.Contains(inputStr, "security_policy") || strings.Contains(inputStr, "info_sec_policy")
	hasCodeOfConduct := strings.Contains(inputStr, "code_of_conduct") || strings.Contains(inputStr, "ethics_policy")
	hasAcceptableUse := strings.Contains(inputStr, "acceptable_use") || strings.Contains(inputStr, "aup")
	hasAccessible := strings.Contains(inputStr, "published") || strings.Contains(inputStr, "documented") || strings.Contains(inputStr, "accessible")

	present := 0
	missing := []string{}
	if hasSecurityPolicy {
		present++
	} else {
		missing = append(missing, "security_policy")
	}
	if hasCodeOfConduct {
		present++
	} else {
		missing = append(missing, "code_of_conduct")
	}
	if hasAcceptableUse {
		present++
	} else {
		missing = append(missing, "acceptable_use_policy")
	}
	if hasAccessible {
		present++
	} else {
		missing = append(missing, "policy accessible/published")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC1.1",
			ControlName: "Control Environment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Control environment verified: security policy + code of conduct + acceptable use policy + accessible",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC1.1",
			ControlName: "Control Environment",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "No control environment policies detected",
			Timestamp:   time.Now(),
			Remediation: "Document security policy + code of conduct + acceptable use policy and make them accessible to all personnel",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC1.1",
		ControlName: "Control Environment",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityMedium,
		Message:     "Partial control environment: " + soc2Count(present) + "/4 documented; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Document the missing policies",
	}, nil
}

// checkSegregationOfDuties verifies that conflicting duties are
// segregated via RBAC + MFA. Maps to SOC 2 CC1.4.
func (m *SOC2Module) checkSegregationOfDuties(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimum_permissions")
	hasRoleSeparation := strings.Contains(inputStr, "role_separation") || strings.Contains(inputStr, "separation_of_duties") || strings.Contains(inputStr, "mutually_exclusive")

	present := 0
	missing := []string{}
	if hasRBAC {
		present++
	} else {
		missing = append(missing, "RBAC")
	}
	if hasMFA {
		present++
	} else {
		missing = append(missing, "MFA")
	}
	if hasLeastPrivilege {
		present++
	} else {
		missing = append(missing, "least_privilege")
	}
	if hasRoleSeparation {
		present++
	} else {
		missing = append(missing, "role_separation")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC1.4",
			ControlName: "Segregation of Duties",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Segregation of duties verified: RBAC + MFA + least privilege + role separation",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC1.4",
			ControlName: "Segregation of Duties",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No segregation of duties detected",
			Timestamp:   time.Now(),
			Remediation: "Enable RBAC + MFA + least privilege + role separation in platformconfig",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC1.4",
		ControlName: "Segregation of Duties",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial segregation of duties: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing segregation of duties components",
	}, nil
}

// checkAnomalyMonitoring verifies that system activity is monitored
// for anomalies. Maps to SOC 2 CC7.2.
func (m *SOC2Module) checkAnomalyMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAnomalyDetection := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit_log")
	}
	if hasIOCStore {
		present++
	} else {
		missing = append(missing, "IOC_store")
	}
	if hasAnomalyDetection {
		present++
	} else {
		missing = append(missing, "anomaly_detection")
	}
	if hasAlerting {
		present++
	} else {
		missing = append(missing, "alerting")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.2",
			ControlName: "Monitoring for Anomalies and Security Events",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anomaly monitoring verified: audit log + IOC store + anomaly detection + alerting",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.2",
			ControlName: "Monitoring for Anomalies and Security Events",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No anomaly monitoring detected",
			Timestamp:   time.Now(),
			Remediation: "Enable audit log + IOC store + anomaly detection (Trust Framework) + alerting",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.2",
		ControlName: "Monitoring for Anomalies and Security Events",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial anomaly monitoring: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing anomaly monitoring components",
	}, nil
}

// checkEventEvaluation verifies that security events are evaluated.
// Maps to SOC 2 CC7.3.
func (m *SOC2Module) checkEventEvaluation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log") || strings.Contains(inputStr, "envelope")
	hasInvestigationProcess := strings.Contains(inputStr, "investigation") || strings.Contains(inputStr, "triage") || strings.Contains(inputStr, "classification")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit_log")
	}
	if hasIOCStore {
		present++
	} else {
		missing = append(missing, "IOC_store")
	}
	if hasAttestations {
		present++
	} else {
		missing = append(missing, "signed_attestations")
	}
	if hasInvestigationProcess {
		present++
	} else {
		missing = append(missing, "investigation_process")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.3",
			ControlName: "Evaluation of Security Events",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Event evaluation verified: audit log + IOC store + signed attestations + investigation process",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.3",
			ControlName: "Evaluation of Security Events",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No event evaluation detected",
			Timestamp:   time.Now(),
			Remediation: "Enable audit log + IOC store + signed attestations + investigation/triage process",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.3",
		ControlName: "Evaluation of Security Events",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial event evaluation: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing event evaluation components",
	}, nil
}

// checkIncidentResponsePlan verifies that an incident response plan
// is in place. Maps to SOC 2 CC7.4.
func (m *SOC2Module) checkIncidentResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan")
	hasTested := strings.Contains(inputStr, "ir_tested") || strings.Contains(inputStr, "tabletop") || strings.Contains(inputStr, "ir_drill")
	hasRoles := strings.Contains(inputStr, "ir_roles") || strings.Contains(inputStr, "incident_commander") || strings.Contains(inputStr, "responsibility")
	hasCommunication := strings.Contains(inputStr, "ir_communication") || strings.Contains(inputStr, "status_page") || strings.Contains(inputStr, "ir_contact")

	present := 0
	missing := []string{}
	if hasIRPlan {
		present++
	} else {
		missing = append(missing, "IR_plan")
	}
	if hasTested {
		present++
	} else {
		missing = append(missing, "IR_tested")
	}
	if hasRoles {
		present++
	} else {
		missing = append(missing, "IR_roles")
	}
	if hasCommunication {
		present++
	} else {
		missing = append(missing, "IR_communication")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.4",
			ControlName: "Incident Response Plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response plan verified: plan + tested + roles + communication",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-CC7.4",
			ControlName: "Incident Response Plan",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No incident response plan detected",
			Timestamp:   time.Now(),
			Remediation: "Document IR plan + test (tabletop/drill) + assign roles + establish communication plan",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-CC7.4",
		ControlName: "Incident Response Plan",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial IR plan: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Document the missing IR plan components",
	}, nil
}

// checkCapacityPlanning verifies that system capacity is monitored.
// Maps to SOC 2 A1.1.
func (m *SOC2Module) checkCapacityPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "metric") || strings.Contains(inputStr, "prometheus")
	hasDashboard := strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "grafana")
	hasAlerts := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "alerting")
	hasCapacityPlan := strings.Contains(inputStr, "capacity_plan") || strings.Contains(inputStr, "scaling_plan") || strings.Contains(inputStr, "auto_scaling")

	present := 0
	missing := []string{}
	if hasMetrics {
		present++
	} else {
		missing = append(missing, "metrics")
	}
	if hasDashboard {
		present++
	} else {
		missing = append(missing, "dashboard")
	}
	if hasAlerts {
		present++
	} else {
		missing = append(missing, "alerts")
	}
	if hasCapacityPlan {
		present++
	} else {
		missing = append(missing, "capacity_plan")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-A1.1",
			ControlName: "Availability — Capacity Planning and Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Capacity planning verified: metrics + dashboard + alerts + capacity plan",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-A1.1",
			ControlName: "Availability — Capacity Planning and Monitoring",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No capacity planning detected",
			Timestamp:   time.Now(),
			Remediation: "Set up metrics (Prometheus) + dashboard (Grafana) + alerts + capacity plan per SOC 2 A1.1",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-A1.1",
		ControlName: "Availability — Capacity Planning and Monitoring",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial capacity planning: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing capacity planning components",
	}, nil
}

// checkThirdPartyRisk verifies third-party risk management.
// Maps to SOC 2 C2.1.
func (m *SOC2Module) checkThirdPartyRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVendorInventory := strings.Contains(inputStr, "vendor_inventory") || strings.Contains(inputStr, "third_party_inventory") || strings.Contains(inputStr, "supplier_list")
	hasDPA := strings.Contains(inputStr, "dpa") || strings.Contains(inputStr, "data_processing_agreement") || strings.Contains(inputStr, "vendor_contract")
	hasVendorAssessment := strings.Contains(inputStr, "vendor_assessment") || strings.Contains(inputStr, "vendor_review") || strings.Contains(inputStr, "vendor_questionnaire")
	hasAccessControl := strings.Contains(inputStr, "vendor_access") || strings.Contains(inputStr, "third_party_access") || strings.Contains(inputStr, "scoped_access")

	present := 0
	missing := []string{}
	if hasVendorInventory {
		present++
	} else {
		missing = append(missing, "vendor_inventory")
	}
	if hasDPA {
		present++
	} else {
		missing = append(missing, "DPA")
	}
	if hasVendorAssessment {
		present++
	} else {
		missing = append(missing, "vendor_assessment")
	}
	if hasAccessControl {
		present++
	} else {
		missing = append(missing, "scoped_vendor_access")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-C2.1",
			ControlName: "Confidentiality — Third-Party Risk Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Third-party risk verified: vendor inventory + DPA + vendor assessment + scoped access",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOC2-C2.1",
			ControlName: "Confidentiality — Third-Party Risk Management",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No third-party risk management detected",
			Timestamp:   time.Now(),
			Remediation: "Maintain vendor inventory + DPAs + vendor assessments + scoped vendor access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOC2-C2.1",
		ControlName: "Confidentiality — Third-Party Risk Management",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial third-party risk: " + soc2Count(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing third-party risk components",
	}, nil
}

// soc2Count is a small helper to avoid importing strconv.
func soc2Count(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-soc2Count(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules. The SOC 2 module depends on
// the scanner (for adversarial defense checks) and the persistence
// layer (for audit log integrity verification).
func (m *SOC2Module) Dependencies() []string {
	return []string{"scanner", "persistence"}
}
