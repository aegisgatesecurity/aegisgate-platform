// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 AC (Access Control) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Access Control family (AC)
// Controls for protecting CUI in nonfederal systems.
//
// In-scope AC controls (8 controls: 5 automated + 3 evidence-mapped):
//   AC-1  Access Control Policy and Procedures  (evidence-mapped)
//   AC-2  Account Management                     (automated)
//   AC-3  Access Enforcement                      (automated)
//   AC-6  Least Privilege                         (automated)
//   AC-14 Permitted Actions Without Auth          (automated)
//   AC-17 Remote Access                           (automated)
//   AC-4  Information Flow Enforcement             (evidence-mapped)
//   AC-5  Separation of Duties                    (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerACControls wires the AC family controls into the module.
func (m *NIST800171Module) registerACControls() {
	// AC-1: Access Control Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-1",
		Name:        "Access Control Policy and Procedures",
		Description: "NIST 800-171 AC-1 (3.1.1): Access control policy and procedures documented, reviewed, and disseminated to authorized individuals",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.1", "NIST SP 800-53 Rev. 5 AC-1"},
	})

	// AC-2: Account Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-2",
		Name:        "Account Management",
		Description: "NIST 800-171 AC-2 (3.1.2): Account management — identify and authenticate users, authorize access based on roles",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountManagement,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.2", "NIST SP 800-53 Rev. 5 AC-2"},
	})

	// AC-3: Access Enforcement (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-3",
		Name:        "Access Enforcement",
		Description: "NIST 800-171 AC-3 (3.1.1): Access policy enforced for all system accesses — RBAC or ABAC required, no bypass paths",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessEnforcement,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.1", "NIST SP 800-53 Rev. 5 AC-3"},
	})

	// AC-6: Least Privilege (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-6",
		Name:        "Least Privilege",
		Description: "NIST 800-171 AC-6 (3.1.5): Users authorized only for the access needed — role-based, no wildcard or default-admin roles",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLeastPrivilege,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.5", "NIST SP 800-53 Rev. 5 AC-6"},
	})

	// AC-14: Permitted Actions Without Identification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-14",
		Name:        "Permitted Actions Without Identification",
		Description: "NIST 800-171 AC-14 (3.1.14): Explicitly document which actions do not require identification — health check, public status, trust portal only",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkPermittedActionsWithoutAuth,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.14", "NIST SP 800-53 Rev. 5 AC-14"},
	})

	// AC-17: Remote Access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-17",
		Name:        "Remote Access",
		Description: "NIST 800-171 AC-17 (3.1.12): Remote access — MFA required, monitored, encrypted",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccess,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.12", "NIST SP 800-53 Rev. 5 AC-17"},
	})

	// AC-4: Information Flow Enforcement (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-4",
		Name:        "Information Flow Enforcement",
		Description: "NIST 800-171 AC-4 (3.1.4): Information flow enforcement — enforce authorized access to CUI based on policy, data segmentation between tenants",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.4", "NIST SP 800-53 Rev. 5 AC-4"},
	})

	// AC-5: Separation of Duties (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AC-5",
		Name:        "Separation of Duties",
		Description: "NIST 800-171 AC-5 (3.1.6): Separation of duties — no single individual controls all aspects of a function, dual authorization for sensitive operations",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.1.6", "NIST SP 800-53 Rev. 5 AC-5"},
	})
}

// checkAccountManagement verifies user account management is in place:
// unique IDs, RBAC, session timeouts. Maps to NIST 800-171 AC-2.
func (m *NIST800171Module) checkAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	if hasAuth && hasRBAC && hasSessionTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-2",
			ControlName: "Account Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Account management controls verified (auth, RBAC, session timeout)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured")
	}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-2",
		ControlName: "Account Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Account management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure auth, RBAC, and session timeouts in platformconfig.Auth.* and platformconfig.Security.*",
	}, nil
}

// checkAccessEnforcement verifies that an access policy is enforced for
// all system accesses (RBAC or ABAC, no bypass paths). Maps to AC-3.
func (m *NIST800171Module) checkAccessEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasABAC := strings.Contains(inputStr, "abac") || strings.Contains(inputStr, "attributes")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasEnforcement := strings.Contains(inputStr, "access_policy") || strings.Contains(inputStr, "policy_enforcement")

	if (hasRBAC || hasABAC) && hasAuth && hasEnforcement {
		msg := "Access enforcement controls verified (RBAC + auth + policy enforcement)"
		if hasABAC {
			msg = "Access enforcement controls verified (ABAC + auth + policy enforcement)"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-3",
			ControlName: "Access Enforcement",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     msg,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC && !hasABAC {
		violations = append(violations, "no RBAC or ABAC access control model detected")
	}
	if !hasAuth {
		violations = append(violations, "authentication not enabled")
	}
	if !hasEnforcement {
		violations = append(violations, "access policy enforcement not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-3",
		ControlName: "Access Enforcement",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access enforcement gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC (rbac.enabled=true) and access policy enforcement. Ensure all API endpoints require authentication.",
	}, nil
}

// checkLeastPrivilege verifies that users are authorized only for the
// access they need (no wildcard or default-admin roles). Maps to AC-6.
func (m *NIST800171Module) checkLeastPrivilege(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasNoWildcard := !strings.Contains(inputStr, "wildcard") && !strings.Contains(inputStr, "permit_all")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimize")
	hasRoleDef := strings.Contains(inputStr, "roles") && (strings.Contains(inputStr, "admin") || strings.Contains(inputStr, "user") || strings.Contains(inputStr, "viewer"))

	if hasRBAC && hasNoWildcard && (hasLeastPrivilege || hasRoleDef) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-6",
			ControlName: "Least Privilege",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Least privilege controls verified (RBAC with defined roles, no wildcard access)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured")
	}
	if !hasNoWildcard {
		violations = append(violations, "wildcard or permit_all access detected — violates least privilege")
	}
	if !hasLeastPrivilege && !hasRoleDef {
		violations = append(violations, "no defined role hierarchy detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-6",
		ControlName: "Least Privilege",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Least privilege gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC with defined roles (admin, user, viewer). Remove wildcard/permit_all access rules. Set least_privilege=true.",
	}, nil
}

// checkPermittedActionsWithoutAuth verifies that only explicitly
// documented actions can proceed without identification. Maps to AC-14.
func (m *NIST800171Module) checkPermittedActionsWithoutAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHealthCheck := strings.Contains(inputStr, "health_check") || strings.Contains(inputStr, "healthz")
	hasPublicStatus := strings.Contains(inputStr, "public_status") || strings.Contains(inputStr, "status_page")
	hasTrustPortal := strings.Contains(inputStr, "trust_portal") || strings.Contains(inputStr, "trust")
	hasNoUnauthWrite := !strings.Contains(inputStr, "unauth_write") && !strings.Contains(inputStr, "anonymous_write")

	if (hasHealthCheck || hasPublicStatus || hasTrustPortal) && hasNoUnauthWrite {
		actions := []string{}
		if hasHealthCheck {
			actions = append(actions, "health check endpoint")
		}
		if hasPublicStatus {
			actions = append(actions, "public status page")
		}
		if hasTrustPortal {
			actions = append(actions, "trust portal (read-only)")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-14",
			ControlName: "Permitted Actions Without Identification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Permitted unauthenticated actions documented: " + strings.Join(actions, ", "),
			Timestamp:   time.Now(),
		}, nil
	}

	if !hasNoUnauthWrite {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-14",
			ControlName: "Permitted Actions Without Identification",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Unauthenticated write actions detected — violates AC-14",
			Timestamp:   time.Now(),
			Remediation: "Remove all unauthenticated write endpoints. Only health checks, status pages, and trust portal (read-only) should be accessible without auth.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-14",
		ControlName: "Permitted Actions Without Identification",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityLow,
		Message:     "No explicit documentation of permitted unauthenticated actions detected",
		Timestamp:   time.Now(),
		Remediation: "Document permitted unauthenticated actions (health_check, public_status, trust_portal) in platformconfig.",
	}, nil
}

// checkRemoteAccess verifies remote access uses MFA + TLS + monitoring.
// Maps to NIST 800-171 AC-17.
func (m *NIST800171Module) checkRemoteAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := false
	for _, p := range m.mfaPatterns {
		if p.MatchString(inputStr) {
			hasMFA = true
			break
		}
	}
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging")

	if hasMFA && hasTLS && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AC-17",
			ControlName: "Remote Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Remote access controls verified (MFA + TLS + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMFA {
		violations = append(violations, "MFA not configured for remote access")
	}
	if !hasTLS {
		violations = append(violations, "TLS not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "remote access monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AC-17",
		ControlName: "Remote Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Remote access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable MFA for all remote access, require TLS 1.2+, enable audit logging for remote sessions",
	}, nil
}
