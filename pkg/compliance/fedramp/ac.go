// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP AC (Access Control) Family
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Access Control family (AC)
// FedRAMP Moderate baseline controls for AI/ML systems.
//
// In-scope AC controls (6 of 25 AC controls are scanner-checkable):
//   AC-2  Account Management           (automated, Path B)
//   AC-3  Access Enforcement           (automated, Path C — new)
//   AC-6  Least Privilege              (automated, Path C — new)
//   AC-14  Permitted Actions Without Auth (automated, Path C — new)
//   AC-17 Remote Access                (automated, Path B)
//   AC-24  Access Control Policy Support (evidence-mapped, Path C — new)
//
// Out-of-scope AC controls (process/HR/physical, not scanner concerns):
//   AC-1 Policy and Procedures, AC-4 Information Flow Enforcement,
//   AC-5 Separation of Duties, AC-7 Unsuccessful Login Attempts,
//   AC-8 System Use Notification, AC-9 Controlled Information,
//   AC-10 Concurrent Session Control, AC-11 Session Lock,
//   AC-12 Session Termination, AC-18 Wireless Access,
//   AC-19 Access Control for Mobile, AC-20 Use of External Systems,
//   AC-21 Information Sharing, AC-22 Publicly Accessible Content,
//   AC-23 Data Mining, AC-25 Reference Monitor
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerACControls wires the AC family controls into the module.
func (m *FedRAMPModule) registerACControls() {
	// AC-2: Account Management (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-2",
		Name:        "Account Management",
		Description: "FedRAMP AC-2: Account management — identify and authenticate users, authorize access based on roles",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountManagement,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-2", "FedRAMP Moderate AC-02"},
	})

	// AC-3: Access Enforcement (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-3",
		Name:        "Access Enforcement",
		Description: "FedRAMP AC-3: Access policy enforced for all system accesses — RBAC or ABAC required, no bypass paths",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessEnforcement,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-3", "FedRAMP Moderate AC-03"},
	})

	// AC-6: Least Privilege (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-6",
		Name:        "Least Privilege",
		Description: "FedRAMP AC-6: Users authorized only for the access needed — role-based, no wildcard or default-admin roles",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLeastPrivilege,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-6", "FedRAMP Moderate AC-06"},
	})

	// AC-14: Permitted Actions Without Identification (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-14",
		Name:        "Permitted Actions Without Identification",
		Description: "FedRAMP AC-14: Explicitly document which actions do not require identification — health check, public status, trust portal only",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkPermittedActionsWithoutAuth,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-14", "FedRAMP Moderate AC-14"},
	})

	// AC-17: Remote Access (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-17",
		Name:        "Remote Access",
		Description: "FedRAMP AC-17: Remote access — MFA required for remote access, monitored, encrypted",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccess,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-17", "FedRAMP Moderate AC-17"},
	})

	// AC-24: Access Control Policy Support (promoted v3.6.0)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AC-24",
		Name:        "Access Control Policy Support",
		Description: "FedRAMP AC-24: Complementary policy controls supporting the access control program. AegisGate verifies RBAC policy enforcement, session controls, and access audit evidence.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessControlPolicySupport,
		References:  []string{"NIST SP 800-53 Rev. 5 AC-24", "FedRAMP Moderate AC-24"},
	})
}

// checkAccountManagement verifies user account management is in place:
// unique IDs, RBAC, session timeouts. Maps to FedRAMP AC-2.
// Reuses SOC 2 CC6.1 logic. (Path B — carried forward)
func (m *FedRAMPModule) checkAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	if hasAuth && hasRBAC && hasSessionTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AC-2",
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
		ControlID:   "FedRAMP-AC-2",
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
func (m *FedRAMPModule) checkAccessEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasABAC := strings.Contains(inputStr, "abac") || strings.Contains(inputStr, "attributes")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasEnforcement := strings.Contains(inputStr, "access_policy") || strings.Contains(inputStr, "policy_enforcement")

	if (hasRBAC || hasABAC) && hasAuth && hasEnforcement {
		status := compliance.StatusCompliant
		msg := "Access enforcement controls verified (RBAC + auth + policy enforcement)"
		if hasABAC {
			msg = "Access enforcement controls verified (ABAC + auth + policy enforcement)"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AC-3",
			ControlName: "Access Enforcement",
			Status:      status,
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
		ControlID:   "FedRAMP-AC-3",
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
func (m *FedRAMPModule) checkLeastPrivilege(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasNoWildcard := !strings.Contains(inputStr, "wildcard") && !strings.Contains(inputStr, "permit_all")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimize")
	hasRoleDef := strings.Contains(inputStr, "roles") && (strings.Contains(inputStr, "admin") || strings.Contains(inputStr, "user") || strings.Contains(inputStr, "viewer"))

	if hasRBAC && hasNoWildcard && (hasLeastPrivilege || hasRoleDef) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AC-6",
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
		ControlID:   "FedRAMP-AC-6",
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
func (m *FedRAMPModule) checkPermittedActionsWithoutAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHealthCheck := strings.Contains(inputStr, "health_check") || strings.Contains(inputStr, "healthz")
	hasPublicStatus := strings.Contains(inputStr, "public_status") || strings.Contains(inputStr, "status_page")
	hasTrustPortal := strings.Contains(inputStr, "trust_portal") || strings.Contains(inputStr, "trust")
	hasNoUnauthWrite := !strings.Contains(inputStr, "unauth_write") && !strings.Contains(inputStr, "anonymous_write")

	unauthActions := 0
	if hasHealthCheck {
		unauthActions++
	}
	if hasPublicStatus {
		unauthActions++
	}
	if hasTrustPortal {
		unauthActions++
	}

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
			ControlID:   "FedRAMP-AC-14",
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
			ControlID:   "FedRAMP-AC-14",
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
		ControlID:   "FedRAMP-AC-14",
		ControlName: "Permitted Actions Without Identification",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityLow,
		Message:     "No explicit documentation of permitted unauthenticated actions detected",
		Timestamp:   time.Now(),
		Remediation: "Document permitted unauthenticated actions (health_check, public_status, trust_portal) in platformconfig.",
	}, nil
}

// checkRemoteAccess verifies remote access uses MFA + TLS + monitoring.
// Maps to FedRAMP AC-17. (Path B — carried forward)
func (m *FedRAMPModule) checkRemoteAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
			ControlID:   "FedRAMP-AC-17",
			ControlName: "Remote Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Remote access controls verified (MFA + TLS + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMFA {
		violations = append(violations, "MFA not configured for remote access (FedRAMP requires MFA)")
	}
	if !hasTLS {
		violations = append(violations, "TLS not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "remote access monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-AC-17",
		ControlName: "Remote Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Remote access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable MFA for all remote access (auth.mfa_required=true), require TLS 1.2+ for remote connections, enable audit logging for remote sessions",
	}, nil
}
