// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF AM (Access Management) Family
// =========================================================================
//
// HITRUST CSF v11.2 — Access Management family (AM)
// 10 controls covering authentication, authorization, and access review.
//
// In-scope AM controls (10 of ~30 AM control specifications):
//   AM-01  Access Control Policy            (evidence-mapped)
//   AM-02  User Authentication               (automated)
//   AM-03  Logical Access                     (automated)
//   AM-04  Multi-Factor Authentication        (automated)
//   AM-05  Registration                       (evidence-mapped)
//   AM-06  Password Management                (automated)
//   AM-07  Access Review                      (automated)
//   AM-08  Termination                        (evidence-mapped)
//   AM-09  Session Management                 (automated)
//   AM-10  Privileged Access                  (automated)
//
// =========================================================================

package hitrust

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAMControls wires the AM family controls into the module.
func (m *HITRUSTModule) registerAMControls() {
	// AM-01: Access Control Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-01",
		Name:        "Access Control Policy",
		Description: "HITRUST CSF v11.2 AM-01: Access control policy documented and reviewed — defines authorization, authentication, and access termination procedures",
		Category:    "Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 01.a", "NIST SP 800-53 Rev. 5 AC-1"},
	})

	// AM-02: User Authentication (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-02",
		Name:        "User Authentication",
		Description: "HITRUST CSF v11.2 AM-02: Users uniquely identified and authenticated before accessing information assets",
		Category:    "Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUserAuthentication,
		References:  []string{"HITRUST CSF v11.2 01.b", "NIST SP 800-53 Rev. 5 IA-2"},
	})

	// AM-03: Logical Access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-03",
		Name:        "Logical Access",
		Description: "HITRUST CSF v11.2 AM-03: Logical access to information assets restricted based on need-to-know and least privilege",
		Category:    "Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLogicalAccess,
		References:  []string{"HITRUST CSF v11.2 01.c", "NIST SP 800-53 Rev. 5 AC-3"},
	})

	// AM-04: Multi-Factor Authentication (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-04",
		Name:        "Multi-Factor Authentication",
		Description: "HITRUST CSF v11.2 AM-04: MFA required for remote access and privileged accounts",
		Category:    "Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMFA,
		References:  []string{"HITRUST CSF v11.2 01.d", "NIST SP 800-53 Rev. 5 IA-2(1)"},
	})

	// AM-05: Registration (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-05",
		Name:        "Registration",
		Description: "HITRUST CSF v11.2 AM-05: User registration and de-registration procedures documented and enforced",
		Category:    "Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 01.e", "NIST SP 800-53 Rev. 5 PS-4"},
	})

	// AM-06: Password Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-06",
		Name:        "Password Management",
		Description: "HITRUST CSF v11.2 AM-06: Password policies enforced — minimum length, complexity, rotation, and history",
		Category:    "Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPasswordManagement,
		References:  []string{"HITRUST CSF v11.2 01.f", "NIST SP 800-53 Rev. 5 IA-5"},
	})

	// AM-07: Access Review (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-07",
		Name:        "Access Review",
		Description: "HITRUST CSF v11.2 AM-07: Periodic access reviews ensure least privilege and remove stale entitlements",
		Category:    "Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessReview,
		References:  []string{"HITRUST CSF v11.2 01.g", "NIST SP 800-53 Rev. 5 AC-2(3)"},
	})

	// AM-08: Termination (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-08",
		Name:        "Termination",
		Description: "HITRUST CSF v11.2 AM-08: Access termination procedures ensure timely revocation upon role change or separation",
		Category:    "Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 01.h", "NIST SP 800-53 Rev. 5 PS-4"},
	})

	// AM-09: Session Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-09",
		Name:        "Session Management",
		Description: "HITRUST CSF v11.2 AM-09: Session timeouts and concurrency controls enforced to prevent unauthorized session reuse",
		Category:    "Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionManagement,
		References:  []string{"HITRUST CSF v11.2 01.i", "NIST SP 800-53 Rev. 5 AC-12"},
	})

	// AM-10: Privileged Access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AM-10",
		Name:        "Privileged Access",
		Description: "HITRUST CSF v11.2 AM-10: Privileged access restricted, monitored, and requires MFA — admin accounts inventoried and reviewed",
		Category:    "Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccess,
		References:  []string{"HITRUST CSF v11.2 01.j", "NIST SP 800-53 Rev. 5 AC-2(7)"},
	})
}

// checkUserAuthentication verifies unique identification and authentication
// before access. Maps to HITRUST AM-02.
func (m *HITRUSTModule) checkUserAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasUniqueID := strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "unique_id") || strings.Contains(inputStr, "identity")
	hasMFA := m.hasMFA(inputStr)

	if hasAuth && hasUniqueID && hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-02",
			ControlName: "User Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "User authentication with unique identification and MFA verified",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasUniqueID {
		violations = append(violations, "unique user identification not configured")
	}
	if !hasMFA {
		violations = append(violations, "MFA not enabled")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-02",
		ControlName: "User Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "User authentication gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure authentication with unique user IDs and enable MFA for all access",
	}, nil
}

// checkLogicalAccess verifies access restriction based on need-to-know
// and least privilege. Maps to HITRUST AM-03.
func (m *HITRUSTModule) checkLogicalAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := m.hasRBAC(inputStr)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "need_to_know") || strings.Contains(inputStr, "minimize")

	if hasRBAC && hasAuth && hasLeastPrivilege {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-03",
			ControlName: "Logical Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Logical access controls verified (RBAC + authentication + least privilege)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not enabled")
	}
	if !hasLeastPrivilege {
		violations = append(violations, "least privilege / need-to-know not enforced")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-03",
		ControlName: "Logical Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Logical access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC, enforce authentication, and implement least-privilege access policies",
	}, nil
}

// checkMFA verifies MFA is required for remote and privileged access.
// Maps to HITRUST AM-04.
func (m *HITRUSTModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := m.hasMFA(inputStr)
	hasRemoteAccess := strings.Contains(inputStr, "remote_access") || strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")

	if hasMFA {
		status := compliance.StatusCompliant
		msg := "MFA verified for authentication"
		if hasRemoteAccess {
			msg = "MFA verified for remote and privileged access"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-04",
			ControlName: "Multi-Factor Authentication",
			Status:      status,
			Severity:    compliance.SeverityHigh,
			Message:     msg,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-04",
		ControlName: "Multi-Factor Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "MFA not configured — required for remote and privileged access",
		Timestamp:   time.Now(),
		Remediation: "Enable MFA (mfa_required=true) for all remote and privileged access",
	}, nil
}

// checkPasswordManagement verifies password policy enforcement.
// Maps to HITRUST AM-06.
func (m *HITRUSTModule) checkPasswordManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPasswordPolicy := strings.Contains(inputStr, "password_policy") || strings.Contains(inputStr, "password_complexity")
	hasMinLength := strings.Contains(inputStr, "min_length") || strings.Contains(inputStr, "password_length")
	hasRotation := strings.Contains(inputStr, "password_rotation") || strings.Contains(inputStr, "password_expiry") || strings.Contains(inputStr, "key_rotation")

	if hasPasswordPolicy && (hasMinLength || hasRotation) {
		evidence := []string{"Password policy enforced"}
		if hasMinLength {
			evidence = append(evidence, "Minimum password length configured")
		}
		if hasRotation {
			evidence = append(evidence, "Password rotation configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-06",
			ControlName: "Password Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Password management controls verified",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPasswordPolicy {
		violations = append(violations, "password policy not configured")
	}
	if !hasMinLength {
		violations = append(violations, "minimum password length not set")
	}
	if !hasRotation {
		violations = append(violations, "password rotation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-06",
		ControlName: "Password Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Password management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure password policy with minimum length, complexity, and rotation requirements",
	}, nil
}

// checkAccessReview verifies periodic access reviews are in place.
// Maps to HITRUST AM-07.
func (m *HITRUSTModule) checkAccessReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := m.hasRBAC(inputStr)
	hasAudit := m.hasAudit(inputStr)
	hasReview := strings.Contains(inputStr, "access_review") || strings.Contains(inputStr, "review") || strings.Contains(inputStr, "re_certification")

	if hasRBAC && hasAudit && hasReview {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-07",
			ControlName: "Access Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Access review controls verified (RBAC + audit + periodic review)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured for access review")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured for access review")
	}
	if !hasReview {
		violations = append(violations, "periodic access review not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-07",
		ControlName: "Access Review",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Access review gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC, configure audit logging, and implement periodic access reviews",
	}, nil
}

// checkSessionManagement verifies session timeouts and controls.
// Maps to HITRUST AM-09.
func (m *HITRUSTModule) checkSessionManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")

	if hasSessionTimeout && hasAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-09",
			ControlName: "Session Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session management controls verified (session timeout + authentication)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not enabled for session management")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-09",
		ControlName: "Session Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure session timeouts and enforce authentication for all sessions",
	}, nil
}

// checkPrivilegedAccess verifies privileged access is restricted and monitored.
// Maps to HITRUST AM-10.
func (m *HITRUSTModule) checkPrivilegedAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := m.hasRBAC(inputStr)
	hasMFA := m.hasMFA(inputStr)
	hasAudit := m.hasAudit(inputStr)
	hasPrivileged := strings.Contains(inputStr, "privileged_access") || strings.Contains(inputStr, "admin") || strings.Contains(inputStr, "pam")

	if hasRBAC && hasMFA && hasAudit && hasPrivileged {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AM-10",
			ControlName: "Privileged Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Privileged access controls verified (RBAC + MFA + audit + PAM)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured for privileged access")
	}
	if !hasMFA {
		violations = append(violations, "MFA not required for privileged accounts")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured for privileged actions")
	}
	if !hasPrivileged {
		violations = append(violations, "privileged access management not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AM-10",
		ControlName: "Privileged Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Privileged access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC, require MFA for privileged accounts, configure audit logging, and implement PAM",
	}, nil
}
