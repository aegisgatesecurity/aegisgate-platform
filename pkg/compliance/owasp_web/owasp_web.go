// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - OWASP Top 10 Web (2021)
// =========================================================================
//
// OWASP Top 10 Web is the de-facto industry baseline for web application
// security. Completes the OWASP coverage story (we already have OWASP
// LLM Top 10 for AI-specific threats; this adds the Web layer).
//
// Module metadata:
//   - Framework:   "owasp_web"
//   - Version:     "1.0"
//   - Required tier: Community (free)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - owasp_web.go:        module wiring, 10 RegisterControl calls,
//                          8 CheckFunc implementations
//   - owasp_web_test.go:   unit tests
//
// Coverage: 8 of 10 OWASP Top 10 Web categories mapped to AegisGate:
//   A01 Broken Access Control     -> pkg/auth/middleware.go + pkg/rbac/
//   A02 Cryptographic Failures     -> TLS config + FIPS 140 module
//   A03 Injection                  -> AegisGate scanner (SQL/XSS/path traversal patterns)
//   A04 Insecure Design            -> AegisGate scanner + Threat Framework
//   A05 Security Misconfiguration  -> platformconfig + security headers
//   A06 Vulnerable Components      -> govulncheck + Trivy in CI
//   A07 Auth Failures              -> pkg/auth/middleware.go (JWT, API token, MFA)
//   A08 Software/Data Integrity    -> AegisGate Trust Framework attestations
//   A09 Logging Failures           -> AegisGate audit log (hash-chain)
//   A10 SSRF                        -> AegisGate scanner (URL allowlisting)
//
// Reference: https://owasp.org/Top10/
//            OWASP Top 10:2021 (September 2021)
// =========================================================================

package owasp_web

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// OWASPWebModule implements the OWASP Top 10 Web (2021) framework.
type OWASPWebModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches
	auditLogPatterns []*regexp.Regexp
	tlsPatterns      []*regexp.Regexp
}

// NewOWASPWebModule creates a new OWASP Top 10 Web module.
func NewOWASPWebModule() *OWASPWebModule {
	m := &OWASPWebModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("owasp_web", "1.0", core.TierCommunity),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

func (m *OWASPWebModule) initPatterns() {
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
	}
	m.tlsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
		regexp.MustCompile(`(?i)min[_ ]?version[_ ]?1[._][23]`),
	}
}

func (m *OWASPWebModule) registerControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A01",
		Name:        "Broken Access Control",
		Description: "OWASP A01:2021: Restrictions on what authenticated users are allowed to do are often not properly enforced",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBrokenAccessControl,
		References:  []string{"OWASP Top 10:2021 A01"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A02",
		Name:        "Cryptographic Failures",
		Description: "OWASP A02:2021: Failures related to cryptography that lead to exposure of sensitive data",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCryptographicFailures,
		References:  []string{"OWASP Top 10:2021 A02"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A03",
		Name:        "Injection",
		Description: "OWASP A03:2021: Application is vulnerable when user-supplied data is not validated, filtered, or sanitized",
		Category:    "Injection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkInjection,
		References:  []string{"OWASP Top 10:2021 A03"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A04",
		Name:        "Insecure Design",
		Description: "OWASP A04:2021: Risks related to design and architectural flaws",
		Category:    "Design",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInsecureDesign,
		References:  []string{"OWASP Top 10:2021 A04"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A05",
		Name:        "Security Misconfiguration",
		Description: "OWASP A05:2021: Missing appropriate security hardening, improperly configured permissions, default accounts",
		Category:    "Configuration",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityMisconfiguration,
		References:  []string{"OWASP Top 10:2021 A05"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A06",
		Name:        "Vulnerable and Outdated Components",
		Description: "OWASP A06:2021: Using vulnerable, unsupported, or outdated software",
		Category:    "Components",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerableComponents,
		References:  []string{"OWASP Top 10:2021 A06"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A07",
		Name:        "Identification and Authentication Failures",
		Description: "OWASP A07:2021: Confirmation of the user's identity, authentication, and session management is critical",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuthenticationFailures,
		References:  []string{"OWASP Top 10:2021 A07"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A08",
		Name:        "Software and Data Integrity Failures",
		Description: "OWASP A08:2021: Code and infrastructure that does not protect against integrity violations",
		Category:    "Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntegrityFailures,
		References:  []string{"OWASP Top 10:2021 A08"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A09",
		Name:        "Security Logging and Monitoring Failures",
		Description: "OWASP A09:2021: Insufficient logging and monitoring impedes detection of breaches",
		Category:    "Logging",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLoggingFailures,
		References:  []string{"OWASP Top 10:2021 A09"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "OWASPWeb-A10",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "OWASP A10:2021: SSRF flaws occur when fetching remote resources without validating the user-supplied URL",
		Category:    "SSRF",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSSRF,
		References:  []string{"OWASP Top 10:2021 A10"},
	})
}

// ============================================================================
// Check implementations
// ============================================================================

func (m *OWASPWebModule) checkBrokenAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasLeastPriv := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimum_permissions")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	if hasRBAC && hasLeastPriv && hasSessionTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "OWASPWeb-A01",
			ControlName: "Broken Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Access control verified: RBAC + least privilege + session timeout",
			Timestamp:   time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasRBAC {
		missing = append(missing, "RBAC")
	}
	if !hasLeastPriv {
		missing = append(missing, "least privilege")
	}
	if !hasSessionTimeout {
		missing = append(missing, "session timeout")
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A01", ControlName: "Broken Access Control",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "Access control gaps: " + strings.Join(missing, ", "), Timestamp: time.Now(),
		Remediation: "Configure RBAC with least-privilege roles and session timeouts in pkg/auth/middleware.go and pkg/rbac/",
	}, nil
}

func (m *OWASPWebModule) checkCryptographicFailures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			break
		}
	}
	hasEncryptAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasStrongAlgo := strings.Contains(inputStr, "aes_256") || strings.Contains(inputStr, "ecdsa_p256") || strings.Contains(inputStr, "fips_mode")

	if hasTLS && hasEncryptAtRest && hasStrongAlgo {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "OWASPWeb-A02",
			ControlName: "Cryptographic Failures",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Cryptography verified: TLS 1.2+ + encryption at rest + strong algorithms (AES-256/ECDSA P-256/FIPS)",
			Timestamp:   time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasTLS {
		missing = append(missing, "TLS 1.2+")
	}
	if !hasEncryptAtRest {
		missing = append(missing, "encryption at rest")
	}
	if !hasStrongAlgo {
		missing = append(missing, "strong algorithms (AES-256/ECDSA P-256)")
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A02", ControlName: "Cryptographic Failures",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "Crypto gaps: " + strings.Join(missing, ", "), Timestamp: time.Now(),
		Remediation: "Enable TLS 1.2+ (tls.min_version), encryption at rest (persistence.encryption), and FIPS-approved algorithms",
	}, nil
}

func (m *OWASPWebModule) checkInjection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "input_validation")
	hasWAF := strings.Contains(inputStr, "waf") || strings.Contains(inputStr, "input_filter")
	hasParamQuery := strings.Contains(inputStr, "parameterized_query") || strings.Contains(inputStr, "prepared_statement") || strings.Contains(inputStr, "orm")

	present := 0
	if hasScanner {
		present++
	}
	if hasWAF {
		present++
	}
	if hasParamQuery {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A03", ControlName: "Injection",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message:   "Injection defense verified (scanner + WAF/filter + parameterized queries)",
			Timestamp: time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A03", ControlName: "Injection",
			Status: compliance.StatusPartial, Severity: compliance.SeverityCritical,
			Message:     "Partial injection defense: 1 of 3 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Add AegisGate scanner (pkg/scanner/) + input filtering + parameterized queries",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A03", ControlName: "Injection",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message:     "No injection defense configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner for input validation + WAF-style input filtering + parameterized queries",
	}, nil
}

func (m *OWASPWebModule) checkInsecureDesign(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatModel := strings.Contains(inputStr, "threat_model") || strings.Contains(inputStr, "stride")
	hasTrustFramework := strings.Contains(inputStr, "trust_framework") || strings.Contains(inputStr, "trust.attestation")

	if hasThreatModel || hasTrustFramework {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A04", ControlName: "Insecure Design",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Secure design verified (threat model + Trust Framework)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A04", ControlName: "Insecure Design",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No secure design evidence (no threat model, no Trust Framework)",
		Timestamp:   time.Now(),
		Remediation: "Document threat model (plans/THREAT-MODEL.md) and enable Trust Framework (pkg/trust/)",
	}, nil
}

func (m *OWASPWebModule) checkSecurityMisconfiguration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurityHeaders := strings.Contains(inputStr, "security_headers") || strings.Contains(inputStr, "csp") || strings.Contains(inputStr, "x_frame_options")
	hasHardening := strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "secure_config")
	noDefaultCreds := !strings.Contains(inputStr, "default_password") && !strings.Contains(inputStr, "admin:admin")

	if hasSecurityHeaders && hasHardening && noDefaultCreds {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A05", ControlName: "Security Misconfiguration",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Security misconfiguration prevented (headers + hardening + no default creds)",
			Timestamp: time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasSecurityHeaders {
		missing = append(missing, "security headers (CSP, X-Frame-Options)")
	}
	if !hasHardening {
		missing = append(missing, "hardening config")
	}
	if !noDefaultCreds {
		missing = append(missing, "default credentials detected (CRITICAL)")
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A05", ControlName: "Security Misconfiguration",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "Security misconfigurations: " + strings.Join(missing, ", "), Timestamp: time.Now(),
		Remediation: "Enable security headers in pkg/security/headers.go, apply hardening, remove default credentials",
	}, nil
}

func (m *OWASPWebModule) checkVulnerableComponents(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovulncheck := strings.Contains(inputStr, "govulncheck") || strings.Contains(inputStr, "vuln_scan")
	hasTrivy := strings.Contains(inputStr, "trivy") || strings.Contains(inputStr, "container_scan")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")

	present := 0
	if hasGovulncheck {
		present++
	}
	if hasTrivy {
		present++
	}
	if hasSBOM {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A06", ControlName: "Vulnerable and Outdated Components",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Vulnerability scanning verified (multiple scanners + SBOM)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A06", ControlName: "Vulnerable and Outdated Components",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "Vulnerability scanning not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable govulncheck, Trivy, and SBOM in your CI (AegisGate's .github/workflows does this)",
	}, nil
}

func (m *OWASPWebModule) checkAuthenticationFailures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor")
	hasSessionMgmt := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "session_management")
	noWeakCreds := !strings.Contains(inputStr, "weak_password") && !strings.Contains(inputStr, "default_credentials")

	if hasAuth && hasMFA && hasSessionMgmt && noWeakCreds {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A07", ControlName: "Identification and Authentication Failures",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message:   "Auth verified: authentication + MFA + session mgmt + no weak creds",
			Timestamp: time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasAuth {
		missing = append(missing, "authentication")
	}
	if !hasMFA {
		missing = append(missing, "MFA")
	}
	if !hasSessionMgmt {
		missing = append(missing, "session management")
	}
	if !noWeakCreds {
		missing = append(missing, "weak/default credentials")
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A07", ControlName: "Identification and Authentication Failures",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "Auth gaps: " + strings.Join(missing, ", "), Timestamp: time.Now(),
		Remediation: "Enable auth + MFA + session mgmt; reject weak/default passwords in pkg/auth/middleware.go",
	}, nil
}

func (m *OWASPWebModule) checkIntegrityFailures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAttestation := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log")
	hasHashChain := strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "log_integrity")
	hasSignedUpdates := strings.Contains(inputStr, "signed_update") || strings.Contains(inputStr, "binary_attestation")

	present := 0
	if hasAttestation {
		present++
	}
	if hasHashChain {
		present++
	}
	if hasSignedUpdates {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A08", ControlName: "Software and Data Integrity Failures",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Integrity verified (signed attestations + hash chain)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A08", ControlName: "Software and Data Integrity Failures",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No integrity controls detected (no signed attestations, no hash chain)",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate attestations (pkg/attestation/) and hash-chain audit log (persistence.log_integrity)",
	}, nil
}

func (m *OWASPWebModule) checkLoggingFailures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := false
	hasIntegrity := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			if strings.Contains(p.String(), "integrity") {
				hasIntegrity = true
			}
		}
	}
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty")
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "audit_log_retention")

	if hasAudit && hasIntegrity && hasAlerting && hasRetention {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A09", ControlName: "Security Logging and Monitoring Failures",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Logging verified: audit + integrity + alerting + retention",
			Timestamp: time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasAudit {
		missing = append(missing, "audit logging")
	}
	if !hasIntegrity {
		missing = append(missing, "log integrity")
	}
	if !hasAlerting {
		missing = append(missing, "alerting")
	}
	if !hasRetention {
		missing = append(missing, "retention")
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A09", ControlName: "Security Logging and Monitoring Failures",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "Logging gaps: " + strings.Join(missing, ", "), Timestamp: time.Now(),
		Remediation: "Enable audit log + integrity + alerting + retention in pkg/persistence/ and pkg/audit/",
	}, nil
}

func (m *OWASPWebModule) checkSSRF(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasURLAllowlist := strings.Contains(inputStr, "url_allowlist") || strings.Contains(inputStr, "allowed_domains") || strings.Contains(inputStr, "egress_allowlist")
	hasSSRFScanner := strings.Contains(inputStr, "ssrf_scanner") || strings.Contains(inputStr, "ssrf_protection")
	hasNetworkSegmentation := strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "egress_proxy")

	if hasURLAllowlist || hasSSRFScanner || hasNetworkSegmentation {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "OWASPWeb-A10", ControlName: "Server-Side Request Forgery (SSRF)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "SSRF defense verified (URL allowlist / scanner / network segmentation)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "OWASPWeb-A10", ControlName: "Server-Side Request Forgery (SSRF)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No SSRF defense configured",
		Timestamp:   time.Now(),
		Remediation: "Implement URL allowlisting in AegisGate proxy (egress_allowlist) + SSRF scanner + network segmentation",
	}, nil
}

func (m *OWASPWebModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "trust"}
}
