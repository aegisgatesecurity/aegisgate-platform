// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 IA (Identification and
// Authentication) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Identification and Authentication family (IA)
// Controls for protecting CUI in nonfederal systems.
//
// In-scope IA controls (5 controls: 3 automated + 2 evidence-mapped):
//   IA-1  Identification and Authentication Policy/Procedures  (evidence-mapped)
//   IA-2  User Identification and Authentication                 (automated)
//   IA-3  Device Identification and Authentication               (evidence-mapped)
//   IA-5  Authenticator Management                                (automated)
//   IA-8  Non-organizational User Identification                 (automated)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIAControls wires the IA family controls into the module.
func (m *NIST800171Module) registerIAControls() {
	// IA-1: Identification and Authentication Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-1",
		Name:        "Identification and Authentication Policy and Procedures",
		Description: "NIST 800-171 IA-1 (3.5.1): Identification and authentication policy and procedures documented, reviewed, and disseminated",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.1", "NIST SP 800-53 Rev. 5 IA-1"},
	})

	// IA-2: User Identification and Authentication (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-2",
		Name:        "User Identification and Authentication",
		Description: "NIST 800-171 IA-2 (3.5.2): User identification and authentication — unique IDs, MFA for privileged access",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUserIdentification,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.2", "NIST SP 800-53 Rev. 5 IA-2"},
	})

	// IA-3: Device Identification and Authentication (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-3",
		Name:        "Device Identification and Authentication",
		Description: "NIST 800-171 IA-3 (3.5.3): Device identification and authentication — unique device identifiers, mTLS, API keys for non-human actors",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.3", "NIST SP 800-53 Rev. 5 IA-3"},
	})

	// IA-5: Authenticator Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-5",
		Name:        "Authenticator Management",
		Description: "NIST 800-171 IA-5 (3.5.6): Authenticator management — password policies, key rotation, credential lifecycle",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorMgmt,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.6", "NIST SP 800-53 Rev. 5 IA-5"},
	})

	// IA-8: Non-organizational User Identification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IA-8",
		Name:        "Non-organizational User Identification",
		Description: "NIST 800-171 IA-8 (3.5.8): Non-organizational user identification — external users authenticated via SSO, federation, or MFA",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkNonOrgUserIdentification,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.8", "NIST SP 800-53 Rev. 5 IA-8"},
	})
}

// checkUserIdentification verifies that unique user IDs and MFA for
// privileged access are configured. Maps to IA-2.
func (m *NIST800171Module) checkUserIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasMFA := false
	for _, p := range m.mfaPatterns {
		if p.MatchString(inputStr) {
			hasMFA = true
			break
		}
	}
	hasUniqueID := strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "unique_id") || strings.Contains(inputStr, "identity")

	if hasAuth && hasMFA && hasUniqueID {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-2",
			ControlName: "User Identification and Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "User identification and authentication verified (auth + MFA + unique IDs)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasMFA {
		violations = append(violations, "MFA not configured for privileged access")
	}
	if !hasUniqueID {
		violations = append(violations, "unique user identification not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-2",
		ControlName: "User Identification and Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "User identification gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable authentication, MFA for privileged access, and unique user identifiers",
	}, nil
}

// checkAuthenticatorMgmt verifies authenticator management is in place:
// password policies, key rotation, credential lifecycle. Maps to IA-5.
func (m *NIST800171Module) checkAuthenticatorMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPasswordPolicy := strings.Contains(inputStr, "password_policy") || strings.Contains(inputStr, "password") || strings.Contains(inputStr, "authenticator")
	hasKeyRotation := strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "rotation")
	hasCredMgmt := strings.Contains(inputStr, "credential") || strings.Contains(inputStr, "lifecycle") || strings.Contains(inputStr, "secret_management")

	if hasPasswordPolicy && (hasKeyRotation || hasCredMgmt) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-5",
			ControlName: "Authenticator Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authenticator management verified (password policy + key rotation/credential management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPasswordPolicy {
		violations = append(violations, "password policy not configured")
	}
	if !hasKeyRotation && !hasCredMgmt {
		violations = append(violations, "key rotation or credential management not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-5",
		ControlName: "Authenticator Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authenticator management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure password policy (auth.password_policy=true) and key rotation (security.key_rotation=true)",
	}, nil
}

// checkNonOrgUserIdentification verifies external users are authenticated
// via SSO, federation, or MFA. Maps to IA-8.
func (m *NIST800171Module) checkNonOrgUserIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSSO := strings.Contains(inputStr, "sso") || strings.Contains(inputStr, "federation") || strings.Contains(inputStr, "oidc")
	hasMFA := false
	for _, p := range m.mfaPatterns {
		if p.MatchString(inputStr) {
			hasMFA = true
			break
		}
	}
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")

	if (hasSSO || hasMFA) && hasAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IA-8",
			ControlName: "Non-organizational User Identification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Non-organizational user identification verified (SSO/federation + auth)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSSO && !hasMFA {
		violations = append(violations, "SSO, federation, or MFA for external users not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not enabled")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IA-8",
		ControlName: "Non-organizational User Identification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Non-organizational user identification gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable SSO/federation (sso.enabled=true) or MFA for external/non-organizational users",
	}, nil
}

// checkAuthenticatorFeedback verifies authenticator feedback. Maps to NIST800171-IA-6.
func (m *NIST800171Module) checkAuthenticatorFeedback(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFeedback := strings.Contains(inputStr, "authenticator_feedback") || strings.Contains(inputStr, "password_masking") || strings.Contains(inputStr, "feedback_protection")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled") || strings.Contains(inputStr, "password_policy")
	hasPolicy := strings.Contains(inputStr, "policy") || strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")
	if hasFeedback && hasAuth && hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IA-6", ControlName: "Authenticator Feedback", Status: compliance.StatusCompliant, Severity: compliance.SeverityLow, Message: "Authenticator feedback verified (feedback + auth + policy)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasFeedback {
		violations = append(violations, "authenticator feedback not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasPolicy {
		violations = append(violations, "policy not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IA-6", ControlName: "Authenticator Feedback", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityLow, Message: "Authenticator feedback gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure authenticator feedback with auth and policy"}, nil
}

// checkReAuthentication verifies re-authentication config. Maps to NIST800171-IA-11.
func (m *NIST800171Module) checkReAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReAuth := strings.Contains(inputStr, "re_authentication") || strings.Contains(inputStr, "reauth") || strings.Contains(inputStr, "session_reauth")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled") || strings.Contains(inputStr, "mfa")
	hasTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout") || strings.Contains(inputStr, "reauth_timeout")
	if hasReAuth && hasAuth && hasTimeout {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IA-11", ControlName: "Re-authentication", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Re-authentication verified (reauth + auth + timeout)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasReAuth {
		violations = append(violations, "re-authentication not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasTimeout {
		violations = append(violations, "timeout not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IA-11", ControlName: "Re-authentication", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Re-authentication gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure re-authentication with session timeout"}, nil
}
