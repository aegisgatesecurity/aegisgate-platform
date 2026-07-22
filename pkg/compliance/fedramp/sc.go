// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP SC (System & Communications Protection) Family
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — System and Communications Protection family (SC)
// FedRAMP Moderate baseline controls for AI/ML systems.
//
// In-scope SC controls (7 of 51 SC controls are scanner-checkable):
//   SC-4  Information in Shared Resources       (automated, Path C — new)
//   SC-7  Boundary Protection                   (automated, Path C — new)
//   SC-8  Transmission Confidentiality & Integrity (automated, Path B)
//   SC-12 Cryptographic Key Establishment        (automated, Path C — new)
//   SC-13 Cryptographic Protection               (automated, Path C — new)
//   SC-23 Session Protection                     (automated, Path C — new)
//   SC-28 Protection of Information at Rest      (automated, Path C — new)
//
// Out-of-scope SC controls (process/infrastructure):
//   SC-1 Policy, SC-2 Access Control Policy, SC-5 Denial of Service,
//   SC-6 Resource Priority, SC-9 Trusted Path, SC-10 Network Disconnect,
//   SC-11 Trusted Path, SC-15 Collaborative Computing, SC-17 Public Key,
//   SC-18 Mobile Code, SC-19 Voice Over IP, SC-20 Secure Name Resolution,
//   SC-21 Architecture and Provisioning, SC-22 Fail-Safe Network,
//   SC-24 Fail-Safe Communication, SC-26 Confidentiality of Stored Info,
//   SC-29 Honeypots, SC-30 Concealment, SC-31 Covert Channel Analysis,
//   SC-32 System Partitioning, SC-33 Transmission Path, SC-34 Non-Modifiable Program,
//   SC-35 Loss of Communications, SC-36 Distributed Processing,
//   SC-37 Out-of-Band Channel, SC-38 Operations Security, SC-39 Port and Service,
//   SC-40 Wireless Link, SC-41 Physical Isolation, SC-42 Cryptographic Infrastructure,
//   SC-43 Use of Cryptography, SC-44 Information Sharing
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerSCControls wires the SC family controls into the module.
func (m *FedRAMPModule) registerSCControls() {
	// SC-4: Information in Shared Resources (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-4",
		Name:        "Information in Shared Resources",
		Description: "FedRAMP SC-4: Information in shared system resources protected from unauthorized access — multi-tenant isolation",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSharedResources,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-4", "FedRAMP Moderate SC-04"},
	})

	// SC-7: Boundary Protection (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-7",
		Name:        "Boundary Protection",
		Description: "FedRAMP SC-7: System boundary protected — firewall rules, network segmentation, DMZ for AI gateway",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBoundaryProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-7", "FedRAMP Moderate SC-07"},
	})

	// SC-8: Transmission Confidentiality and Integrity (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-8",
		Name:        "Transmission Confidentiality and Integrity",
		Description: "FedRAMP SC-8: Information transmitted across the system boundary is protected (TLS 1.2+ minimum, FIPS-approved ciphers)",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-8", "FedRAMP Moderate SC-08"},
	})

	// SC-12: Cryptographic Key Establishment (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-12",
		Name:        "Cryptographic Key Establishment",
		Description: "FedRAMP SC-12: Cryptographic key establishment and management in accordance with policy",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptoKeyEstablishment,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-12", "FedRAMP Moderate SC-12"},
	})

	// SC-13: Cryptographic Protection (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-13",
		Name:        "Cryptographic Protection",
		Description: "FedRAMP SC-13: FIPS-validated or NSA-approved cryptographic modules used for all protected information",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCryptoProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-13", "FedRAMP Moderate SC-13"},
	})

	// SC-23: Session Protection (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-23",
		Name:        "Session Protection",
		Description: "FedRAMP SC-23: Communication sessions protected from hijacking — session tokens, timeout, re-authentication",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-23", "FedRAMP Moderate SC-23"},
	})

	// SC-28: Protection of Information at Rest (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SC-28",
		Name:        "Protection of Information at Rest",
		Description: "FedRAMP SC-28: Information at rest protected by encryption — data store encryption, volume encryption, key management",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataAtRest,
		References:  []string{"NIST SP 800-53 Rev. 5 SC-28", "FedRAMP Moderate SC-28"},
	})
}

// checkSharedResources verifies multi-tenant isolation for shared resources.
// Maps to SC-4.
func (m *FedRAMPModule) checkSharedResources(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIsolation := strings.Contains(inputStr, "multi_tenant") || strings.Contains(inputStr, "tenant_isolation") || strings.Contains(inputStr, "isolation")
	hasDataSegregate := strings.Contains(inputStr, "data_segregation") || strings.Contains(inputStr, "segregation") || strings.Contains(inputStr, "namespace")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")

	if hasIsolation && (hasDataSegregate || hasRBAC) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-4",
			ControlName: "Information in Shared Resources",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Multi-tenant isolation and data segregation verified",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIsolation {
		violations = append(violations, "multi-tenant isolation not configured")
	}
	if !hasDataSegregate && !hasRBAC {
		violations = append(violations, "data segregation mechanism not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-4",
		ControlName: "Information in Shared Resources",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Shared resource protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable multi-tenant isolation (persistence.tenant_isolation=true) and data segregation (rbac.enabled=true)",
	}, nil
}

// checkBoundaryProtection verifies system boundary protection.
// Maps to SC-7.
func (m *FedRAMPModule) checkBoundaryProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFirewall := strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "rate_limiting") || strings.Contains(inputStr, "ip_allowlist")
	hasDMZ := strings.Contains(inputStr, "dmz") || strings.Contains(inputStr, "proxy") || strings.Contains(inputStr, "gateway")
	hasEgressFilter := strings.Contains(inputStr, "egress_filter") || strings.Contains(inputStr, "outbound_filter") || strings.Contains(inputStr, "network_policy")

	if (hasFirewall || hasDMZ) && hasEgressFilter {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-7",
			ControlName: "Boundary Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System boundary protection verified (firewall/proxy + egress filtering)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasFirewall && !hasDMZ {
		violations = append(violations, "no firewall/proxy detected at system boundary")
	}
	if !hasEgressFilter {
		violations = append(violations, "no egress filtering detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-7",
		ControlName: "Boundary Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Boundary protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure firewall rules or proxy gateway at system boundary, enable egress filtering (security.egress_filter=true)",
	}, nil
}

// checkTransmissionProtection verifies TLS 1.2+ with FIPS-approved
// ciphers. Maps to FedRAMP SC-8 and to FIPS 140-004. (Path B)
func (m *FedRAMPModule) checkTransmissionProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := false
	hasTLS12 := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			if strings.Contains(p.String(), "1[._]") {
				if strings.Contains(inputStr, "1.3") || strings.Contains(inputStr, "1_3") || strings.Contains(inputStr, "1.2") || strings.Contains(inputStr, "1_2") {
					hasTLS12 = true
				}
			}
		}
	}
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}

	if hasTLS12 && hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-8",
			ControlName: "Transmission Confidentiality and Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Transmission protected (TLS 1.2+ with FIPS-approved ciphers)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS12 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-8",
			ControlName: "Transmission Confidentiality and Integrity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.2+ enabled but FIPS mode not detected (FedRAMP recommends FIPS-approved ciphers)",
			Timestamp:   time.Now(),
			Remediation: "Enable FIPS 140 mode (tls.fips.enabled=true) for FedRAMP-approved ciphers",
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-8",
			ControlName: "Transmission Confidentiality and Integrity",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS detected but version below 1.2",
			Timestamp:   time.Now(),
			Remediation: "Set tls.min_version to 1.2 or 1.3 in configs/aegisgate-platform.yaml",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-8",
		ControlName: "Transmission Confidentiality and Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No TLS encryption detected",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2 or 1.3 in configs/aegisgate-platform.yaml",
	}, nil
}

// checkCryptoKeyEstablishment verifies cryptographic key management.
// Maps to SC-12.
func (m *FedRAMPModule) checkCryptoKeyEstablishment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "key_store")
	_ = strings.Contains(inputStr, "key_expiry")
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}

	if hasKeyMgmt && hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-12",
			ControlName: "Cryptographic Key Establishment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic key establishment and management verified (FIPS + key management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasKeyMgmt {
		violations = append(violations, "key management not configured")
	}
	if !hasFIPS {
		violations = append(violations, "FIPS 140 mode not detected (FedRAMP requires FIPS-validated key establishment)")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-12",
		ControlName: "Cryptographic Key Establishment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Key establishment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS 140 mode (tls.fips.enabled=true) and configure key management (security.key_management=true)",
	}, nil
}

// checkCryptoProtection verifies FIPS-validated cryptographic modules.
// Maps to SC-13.
func (m *FedRAMPModule) checkCryptoProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")

	if hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-13",
			ControlName: "Cryptographic Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "FIPS-validated cryptographic modules in use",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-13",
			ControlName: "Cryptographic Protection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS in use but FIPS 140 validation not detected",
			Timestamp:   time.Now(),
			Remediation: "Enable FIPS 140 mode (tls.fips.enabled=true) for FedRAMP-required cryptographic validation",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-13",
		ControlName: "Cryptographic Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No cryptographic protection detected",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS 140 mode and TLS 1.2+ for all communications",
	}, nil
}

// checkSessionProtection verifies session protection mechanisms.
// Maps to SC-23.
func (m *FedRAMPModule) checkSessionProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout") || strings.Contains(inputStr, "timeout")
	hasSessionToken := strings.Contains(inputStr, "session_token") || strings.Contains(inputStr, "csrf") || strings.Contains(inputStr, "csrf_token")
	hasReauth := strings.Contains(inputStr, "reauth") || strings.Contains(inputStr, "re_authentication") || strings.Contains(inputStr, "mfa")

	if hasSessionTimeout && (hasSessionToken || hasReauth) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-23",
			ControlName: "Session Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session protection verified (timeout + CSRF/re-authentication)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}
	if !hasSessionToken && !hasReauth {
		violations = append(violations, "CSRF protection or re-authentication not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-23",
		ControlName: "Session Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure session timeouts (security.session_timeout) and CSRF protection (security.csrf_enabled=true)",
	}, nil
}

// checkDataAtRest verifies encryption of data at rest. Maps to SC-28.
func (m *FedRAMPModule) checkDataAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "disk_encryption")
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_store") || strings.Contains(inputStr, "encryption_key")

	if hasEncryptionAtRest && hasKeyMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-28",
			ControlName: "Protection of Information at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data at rest encryption verified (encryption + key management)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SC-28",
			ControlName: "Protection of Information at Rest",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Data encryption at rest detected but key management not configured",
			Timestamp:   time.Now(),
			Remediation: "Configure encryption key management (security.key_management=true) alongside data encryption",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SC-28",
		ControlName: "Protection of Information at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data at rest encryption not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable data encryption at rest (persistence.encryption_at_rest=true) and configure key management",
	}, nil
}
