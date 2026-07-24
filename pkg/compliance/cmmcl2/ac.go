// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 AC (Access Control) Domain
// =========================================================================
//
// CMMC Level 2 — Access Control domain (AC)
// NIST SP 800-171 Rev. 2 §3.1 practices
//
// In-scope AC controls (8 of 22 AC practices are scanner-checkable):
//   AC.1.001  Limit system access                   (automated)
//   AC.2.001  Authorized users                       (evidence-mapped)
//   AC.2.002  Transaction & function control          (automated)
//   AC.2.003  Remote access control                   (automated)
//   AC.2.004  Role-based access control               (automated)
//   AC.2.005  Least privilege                        (evidence-mapped)
//   AC.2.006  Control CUI flow                        (evidence-mapped)
//   AC.2.007  Policy documentation                    (evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerACControls wires the AC domain controls into the module.
func (m *CMMCL2Module) registerACControls() {
	// AC.1.001: Limit system access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-01",
		Name:        "Limit System Access",
		Description: "CMMC L2 AC.1.001: Limit system access to authorized users, processes acting on behalf of authorized users, and devices",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLimitSystemAccess,
		References:  []string{"CMMC L2 AC.1.001", "NIST SP 800-171 §3.1.1"},
	})

	// AC.2.001: Authorized users (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-02",
		Name:        "Authorized Users",
		Description: "CMMC L2 AC.2.001: Authorize specific users to access specific systems and data. AegisGate generates the access authorization evidence for the customer's CMMC assessment.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AC.2.001", "NIST SP 800-171 §3.1.2"},
	})

	// AC.2.002: Transaction & function control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-03",
		Name:        "Transaction And Function Control",
		Description: "CMMC L2 AC.2.002: Control the flow of CUI in accordance with approved authorizations — RBAC or ABAC required",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransactionFunctionControl,
		References:  []string{"CMMC L2 AC.2.002", "NIST SP 800-171 §3.1.3"},
	})

	// AC.2.003: Remote access control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-04",
		Name:        "Remote Access Control",
		Description: "CMMC L2 AC.2.003: Control remote access sessions — MFA required, encrypted, monitored",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccessControl,
		References:  []string{"CMMC L2 AC.2.003", "NIST SP 800-171 §3.1.12"},
	})

	// AC.2.004: Role-based access control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-05",
		Name:        "Role Based Access Control",
		Description: "CMMC L2 AC.2.004: Employ role-based access control — defined roles with explicit permissions",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRoleBasedAccessControl,
		References:  []string{"CMMC L2 AC.2.004", "NIST SP 800-171 §3.1.7"},
	})

	// AC.2.005: Least privilege (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-06",
		Name:        "Least Privilege",
		Description: "CMMC L2 AC.2.005: Employ least privilege — users authorized only for access needed. AegisGate generates the privilege evidence for the customer's CMMC assessment.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AC.2.005", "NIST SP 800-171 §3.1.5"},
	})

	// AC.2.006: Control CUI flow (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-07",
		Name:        "Control CUI Flow",
		Description: "CMMC L2 AC.2.006: Control the flow of CUI in accordance with approved authorizations. AegisGate generates the data flow evidence for the customer's CMMC assessment.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AC.2.006", "NIST SP 800-171 §3.1.14"},
	})

	// AC.2.007: Policy documentation (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-08",
		Name:        "Policy Documentation",
		Description: "CMMC L2 AC.2.007: Document and disseminate access control policy. AegisGate generates the policy enforcement evidence for the customer's CMMC assessment.",
		Category:    "Access Control",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"CMMC L2 AC.2.007", "NIST SP 800-171 §3.1.1"},
	})

	// AC.2.008: Session control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-09",
		Name:        "Session Control",
		Description: "CMMC L2 AC.2.008: Control session timeouts and concurrent sessions for CUI access",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionControl,
		References:  []string{"CMMC L2 AC.2.008", "NIST SP 800-171 §3.1.9"},
	})

	// AC.2.009: Wireless access restrictions (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-10",
		Name:        "Wireless Access Restrictions",
		Description: "CMMC L2 AC.2.009: Restrict wireless access to authorized users and devices with authentication and encryption",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkWirelessAccessRestrictions,
		References:  []string{"CMMC L2 AC.2.009", "NIST SP 800-171 §3.1.16"},
	})

	// AC.2.010: Mobile device restrictions (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AC-11",
		Name:        "Mobile Device Restrictions",
		Description: "CMMC L2 AC.2.010: Restrict mobile device access to CUI. AegisGate generates the mobile device policy evidence for the customer's CMMC assessment.",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AC.2.010", "NIST SP 800-171 §3.1.18"},
	})
}

// checkLimitSystemAccess verifies system access is limited to authorized
// users, processes, and devices. Maps to CMMC L2 AC.1.001.
func (m *CMMCL2Module) checkLimitSystemAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasAccessControl := false
	for _, p := range m.accessPatterns {
		if p.MatchString(inputStr) {
			hasAccessControl = true
			break
		}
	}

	if hasAuth && hasRBAC && hasAccessControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AC-01",
			ControlName: "Limit System Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System access limited to authorized users (auth + RBAC + access control verified)",
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
	if !hasAccessControl {
		violations = append(violations, "access control policy not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AC-01",
		ControlName: "Limit System Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure authentication (auth_enabled=true), RBAC (rbac.enabled=true), and access control policy enforcement",
	}, nil
}

// checkTransactionFunctionControl verifies that CUI transactions are
// controlled per approved authorizations. Maps to CMMC L2 AC.2.002.
func (m *CMMCL2Module) checkTransactionFunctionControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasABAC := strings.Contains(inputStr, "abac") || strings.Contains(inputStr, "attributes")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasEnforcement := strings.Contains(inputStr, "access_policy") || strings.Contains(inputStr, "policy_enforcement")

	if (hasRBAC || hasABAC) && hasAuth && hasEnforcement {
		msg := "Transaction and function controls verified (RBAC + auth + policy enforcement)"
		if hasABAC {
			msg = "Transaction and function controls verified (ABAC + auth + policy enforcement)"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AC-03",
			ControlName: "Transaction And Function Control",
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
		ControlID:   "CMMCL2-AC-03",
		ControlName: "Transaction And Function Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Transaction and function control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC (rbac.enabled=true) and access policy enforcement. Ensure all transactions require authentication.",
	}, nil
}

// checkRemoteAccessControl verifies remote access uses MFA + TLS + monitoring.
// Maps to CMMC L2 AC.2.003.
func (m *CMMCL2Module) checkRemoteAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
			ControlID:   "CMMCL2-AC-04",
			ControlName: "Remote Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Remote access controls verified (MFA + TLS + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMFA {
		violations = append(violations, "MFA not configured for remote access (CMMC L2 requires MFA)")
	}
	if !hasTLS {
		violations = append(violations, "TLS not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "remote access monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AC-04",
		ControlName: "Remote Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Remote access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable MFA for all remote access (auth.mfa_required=true), require TLS 1.2+, enable audit logging for remote sessions",
	}, nil
}

// checkRoleBasedAccessControl verifies that RBAC is employed with defined
// roles and explicit permissions. Maps to CMMC L2 AC.2.004.
func (m *CMMCL2Module) checkRoleBasedAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasRoleDef := strings.Contains(inputStr, "roles") && (strings.Contains(inputStr, "admin") || strings.Contains(inputStr, "user") || strings.Contains(inputStr, "viewer"))
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimize")
	hasNoWildcard := !strings.Contains(inputStr, "wildcard") && !strings.Contains(inputStr, "permit_all")

	if hasRBAC && (hasRoleDef || hasLeastPrivilege) && hasNoWildcard {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AC-05",
			ControlName: "Role Based Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Role-based access control verified (RBAC with defined roles, no wildcard access)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured")
	}
	if !hasRoleDef && !hasLeastPrivilege {
		violations = append(violations, "no defined role hierarchy detected")
	}
	if !hasNoWildcard {
		violations = append(violations, "wildcard or permit_all access detected — violates RBAC")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AC-05",
		ControlName: "Role Based Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Role-based access control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC with defined roles (admin, user, viewer). Remove wildcard/permit_all access rules. Set least_privilege=true.",
	}, nil
}

// checkSessionControl verifies session timeout and concurrent session controls.
// Maps to CMMC L2 AC.2.008.
func (m *CMMCL2Module) checkSessionControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "timeout")
	hasConcurrent := strings.Contains(inputStr, "concurrent") || strings.Contains(inputStr, "concurrent_sessions") || strings.Contains(inputStr, "session_limit")

	if hasTimeout && hasConcurrent {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AC-09",
			ControlName: "Session Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session control verified (session timeout + concurrent session limits)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTimeout {
		violations = append(violations, "session timeout not configured")
	}
	if !hasConcurrent {
		violations = append(violations, "concurrent session limits not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AC-09",
		ControlName: "Session Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure session timeouts (session_timeout=900) and concurrent session limits (concurrent_sessions=1)",
	}, nil
}

// checkWirelessAccessRestrictions verifies wireless access is controlled
// with authentication and encryption. Maps to CMMC L2 AC.2.009.
func (m *CMMCL2Module) checkWirelessAccessRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasWirelessAuth := strings.Contains(inputStr, "wireless_auth") || strings.Contains(inputStr, "wifi_authentication") || strings.Contains(inputStr, "wireless")
	hasEncryption := strings.Contains(inputStr, "wpa3") || strings.Contains(inputStr, "wpa2") || strings.Contains(inputStr, "wireless_encryption") || strings.Contains(inputStr, "tls")

	if hasWirelessAuth && hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AC-10",
			ControlName: "Wireless Access Restrictions",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Wireless access restrictions verified (authentication + encryption)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasWirelessAuth {
		violations = append(violations, "wireless authentication not configured")
	}
	if !hasEncryption {
		violations = append(violations, "wireless encryption not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AC-10",
		ControlName: "Wireless Access Restrictions",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Wireless access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure wireless authentication (wireless_auth=wpa3) and encryption for all wireless access",
	}, nil
}
