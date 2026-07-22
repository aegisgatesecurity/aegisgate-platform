// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP IA (Identification & Authentication) Family
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Identification and Authentication family (IA)
// FedRAMP Moderate baseline controls for AI/ML systems.
//
// In-scope IA controls (6 of 11 IA controls are scanner-checkable):
//   IA-2  Identification and Authentication (Users) (automated, Path B)
//   IA-3  Device Identification and Authentication     (automated, Path C — new)
//   IA-5  Authenticator Management                   (automated, Path C — new)
//   IA-6  Authenticator Feedback                     (automated, Path C — new)
//   IA-7  Cryptographic Module Authentication        (automated, Path C — new)
//   IA-8  Non-Organizational Users                   (evidence-mapped, Path C — new)
//
// Out-of-scope IA controls (process/organizational):
//   IA-1 Policy and Procedures, IA-4 Identifier Management,
//   IA-9 Internal Accounts, IA-10 Adaptive Authentication,
//   IA-11 Re-authentication
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIAControls wires the IA family controls into the module.
func (m *FedRAMPModule) registerIAControls() {
	// IA-2: Identification and Authentication (Users) (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-2",
		Name:        "Identification and Authentication (Users)",
		Description: "FedRAMP IA-2: Users are uniquely identified and authenticated; MFA for privileged accounts",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFA,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-2", "FedRAMP Moderate IA-02"},
	})

	// IA-3: Device Identification and Authentication (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-3",
		Name:        "Device Identification and Authentication",
		Description: "FedRAMP IA-3: Devices uniquely identified and authenticated before establishing connections; API keys, mTLS, or device certificates",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDeviceAuth,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-3", "FedRAMP Moderate IA-03"},
	})

	// IA-5: Authenticator Management (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-5",
		Name:        "Authenticator Management",
		Description: "FedRAMP IA-5: Authenticators (passwords, tokens, certificates) managed throughout their lifecycle",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorMgmt,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-5", "FedRAMP Moderate IA-05"},
	})

	// IA-6: Authenticator Feedback (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-6",
		Name:        "Authenticator Feedback",
		Description: "FedRAMP IA-6: Authentication feedback obscures authenticator content (no password echo, masked input fields)",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorFeedback,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-6", "FedRAMP Moderate IA-06"},
	})

	// IA-7: Cryptographic Module Authentication (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-7",
		Name:        "Cryptographic Module Authentication",
		Description: "FedRAMP IA-7: Cryptographic modules meet FIPS 140-2/140-3 requirements for authentication",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptoModuleAuth,
		References:  []string{"NIST SP 800-53 Rev. 5 IA-7", "FedRAMP Moderate IA-07"},
	})

	// IA-8: Non-Organizational Users (Path C — new, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-IA-8",
		Name:        "Non-Organizational Users",
		Description: "FedRAMP IA-8: Non-organizational users (external, federated) uniquely identified and authenticated. AegisGate's multi-tenant isolation and SSO integration provide the evidence.",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false, // Evidence-mapped
		References:  []string{"NIST SP 800-53 Rev. 5 IA-8", "FedRAMP Moderate IA-08"},
	})
}

// checkMFA verifies multi-factor authentication is configured for
// privileged users. Maps to FedRAMP IA-2. (Path B)
func (m *FedRAMPModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := false
	for _, p := range m.mfaPatterns {
		if p.MatchString(inputStr) {
			hasMFA = true
			break
		}
	}
	hasPrivileged := strings.Contains(inputStr, "admin") || strings.Contains(inputStr, "privileged")

	if hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-2",
			ControlName: "Identification and Authentication (Users)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Multi-factor authentication configured",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{"MFA not configured"}
	if !hasPrivileged {
		violations = append(violations, "no privileged user accounts detected (admin role may be using default password)")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IA-2",
		ControlName: "Identification and Authentication (Users)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "MFA not configured: " + strings.Join(violations, "; "),
		Timestamp:   time.Now(),
		Remediation: "Enable MFA for all users (auth.mfa_required=true); MFA is required for FedRAMP Moderate IA-2",
	}, nil
}

// checkDeviceAuth verifies devices are authenticated before
// establishing connections. Maps to IA-3.
func (m *FedRAMPModule) checkDeviceAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAPIKey := strings.Contains(inputStr, "api_key") || strings.Contains(inputStr, "api_keys") || strings.Contains(inputStr, "token_auth")
	hasMTLS := strings.Contains(inputStr, "mtls") || strings.Contains(inputStr, "mutual_tls") || strings.Contains(inputStr, "client_cert")
	hasDeviceID := strings.Contains(inputStr, "device_id") || strings.Contains(inputStr, "device_auth") || strings.Contains(inputStr, "agent_id")

	if (hasAPIKey || hasMTLS) && hasDeviceID {
		method := "API keys"
		if hasMTLS {
			method = "mTLS"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-3",
			ControlName: "Device Identification and Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Device authentication configured (" + method + " + device identification)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAPIKey || hasMTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-3",
			ControlName: "Device Identification and Authentication",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Device authentication mechanism detected but device identification incomplete",
			Timestamp:   time.Now(),
			Remediation: "Configure device identification (agent_id, device_id) alongside authentication mechanism",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IA-3",
		ControlName: "Device Identification and Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No device authentication mechanism detected",
		Timestamp:   time.Now(),
		Remediation: "Configure mTLS, API key authentication, or device certificates for all connecting devices",
	}, nil
}

// checkAuthenticatorMgmt verifies authenticator lifecycle management.
// Maps to IA-5.
func (m *FedRAMPModule) checkAuthenticatorMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPasswordPolicy := strings.Contains(inputStr, "password_policy") || strings.Contains(inputStr, "password") || strings.Contains(inputStr, "min_password")
	hasRotation := strings.Contains(inputStr, "rotation") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "token_expiry")
	hasExpiry := strings.Contains(inputStr, "expiry") || strings.Contains(inputStr, "expiration") || strings.Contains(inputStr, "session_timeout")

	if hasPasswordPolicy && (hasRotation || hasExpiry) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-5",
			ControlName: "Authenticator Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authenticator management verified (password policy + rotation/expiry)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPasswordPolicy {
		violations = append(violations, "password policy not configured")
	}
	if !hasRotation && !hasExpiry {
		violations = append(violations, "authenticator rotation/expiry not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IA-5",
		ControlName: "Authenticator Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authenticator management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure password policy, key rotation, and session/token expiry in platformconfig",
	}, nil
}

// checkAuthenticatorFeedback verifies that authentication feedback
// obscures authenticator content. Maps to IA-6.
func (m *FedRAMPModule) checkAuthenticatorFeedback(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMasking := strings.Contains(inputStr, "mask") || strings.Contains(inputStr, "masked") || strings.Contains(inputStr, "password_masking")
	hasNoEcho := strings.Contains(inputStr, "no_echo") || strings.Contains(inputStr, "hide_password") || strings.Contains(inputStr, "redact")
	hasSecureDisplay := strings.Contains(inputStr, "secure_input") || strings.Contains(inputStr, "feedback_obscured")

	if hasMasking || hasNoEcho || hasSecureDisplay {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-6",
			ControlName: "Authenticator Feedback",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Authenticator feedback obscuring configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IA-6",
		ControlName: "Authenticator Feedback",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "Authenticator feedback obscuring not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable password masking and authenticator feedback obscuring (security.password_masking=true)",
	}, nil
}

// checkCryptoModuleAuth verifies cryptographic modules meet FIPS
// requirements for authentication. Maps to IA-7.
func (m *FedRAMPModule) checkCryptoModuleAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "hsm")

	if hasFIPS && (hasTLS || hasKeyMgmt) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-7",
			ControlName: "Cryptographic Module Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic module authentication verified (FIPS mode + TLS/key management)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-IA-7",
			ControlName: "Cryptographic Module Authentication",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "FIPS mode enabled but cryptographic module authentication incomplete",
			Timestamp:   time.Now(),
			Remediation: "Ensure TLS and key management are configured alongside FIPS mode",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-IA-7",
		ControlName: "Cryptographic Module Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FIPS 140 mode not detected — cryptographic module authentication not verified",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS 140 mode (tls.fips.enabled=true) for FedRAMP-approved cryptographic modules",
	}, nil
}
