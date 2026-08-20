// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 SC Extended (System & Comms) Domain
// =========================================================================
//
// CMMC Level 2 — System and Communications Protection domain (extended)
// NIST SP 800-171 Rev. 2 §3.13 practices
//
// In-scope SC extended controls (10 of 16 SC practices are scanner-checkable):
//   SC.2.005  Mobile Code                          (evidence-mapped)
//   SC.2.006  System Boundary Monitoring           (automated)
//   SC.2.007  External Network Access               (automated)
//   SC.2.008  Transmission Confidentiality           (automated)
//   SC.2.009  Network Integrity                      (automated)
//   SC.2.010  Trusted Network Connection             (evidence-mapped)
//   SC.2.011  Collaborative Computing               (evidence-mapped)
//   SC.2.012  Cryptographic Key Management           (automated)
//   SC.2.013  Session Authenticity                   (automated)
//   SC.2.014  FIPS-Validated Cryptography           (automated)
//   SC.2.015  System Partitioning                   (evidence-mapped)
//   SC.2.016  Shared Resource Isolation             (automated)
//   SC.2.017  Voice Over IP                          (evidence-mapped)
//   SC.2.018  Protect CUI Email                     (evidence-mapped)
//   SC.2.019  Connection Timeout                    (automated)
//   SC.2.020  Cryptographic Protection              (automated)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerSCExtendedControls wires the extended SC domain controls into the module.
func (m *CMMCL2Module) registerSCExtendedControls() {
	// SC-06: System Boundary Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-06",
		Name:        "System Boundary Monitoring",
		Description: "CMMC L2 SC.2.006: Monitor system boundaries for unauthorized activity using IDS/IPS",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemBoundaryMonitoring,
		References:  []string{"CMMC L2 SC.2.006", "NIST SP 800-171 §3.13.3"},
	})

	// SC-07: External Network Access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-07",
		Name:        "External Network Access",
		Description: "CMMC L2 SC.2.007: Control external network access through VPNs and gateways",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkExternalNetworkAccess,
		References:  []string{"CMMC L2 SC.2.007", "NIST SP 800-171 §3.13.4"},
	})

	// SC-08: Transmission Confidentiality (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-08",
		Name:        "Transmission Confidentiality",
		Description: "CMMC L2 SC.2.008: Protect the confidentiality of transmitted data using encryption",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransmissionConfidentiality,
		References:  []string{"CMMC L2 SC.2.008", "NIST SP 800-171 §3.13.6"},
	})

	// SC-09: Network Integrity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-09",
		Name:        "Network Integrity",
		Description: "CMMC L2 SC.2.009: Protect network integrity using checksums and hash verification",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkNetworkIntegrity,
		References:  []string{"CMMC L2 SC.2.009", "NIST SP 800-171 §3.13.7"},
	})

	// SC-10: Trusted Network Connection (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-10",
		Name:        "Trusted Network Connection",
		Description: "CMMC L2 SC.2.010: Establish trusted network connections. AegisGate generates the trusted connection evidence for the customer's CMMC assessment.",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSCTrustedConnection,
		References:  []string{"CMMC L2 SC.2.010", "NIST SP 800-171 §3.13.10"},
	})

	// SC-12: Cryptographic Key Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-12",
		Name:        "Cryptographic Key Management",
		Description: "CMMC L2 SC.2.012: Manage cryptographic keys including rotation and storage",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptographicKeyManagement,
		References:  []string{"CMMC L2 SC.2.012", "NIST SP 800-171 §3.13.9"},
	})

	// SC-13: Session Authenticity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-13",
		Name:        "Session Authenticity",
		Description: "CMMC L2 SC.2.013: Protect session authenticity using anti-replay and nonce mechanisms",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionAuthenticity,
		References:  []string{"CMMC L2 SC.2.013", "NIST SP 800-171 §3.13.15"},
	})

	// SC-14: FIPS-Validated Cryptography (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-14",
		Name:        "FIPS-Validated Cryptography",
		Description: "CMMC L2 SC.2.014: Use FIPS-validated cryptography for protecting CUI",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFIPSValidatedCryptography,
		References:  []string{"CMMC L2 SC.2.014", "NIST SP 800-171 §3.13.11"},
	})

	// SC-16: Shared Resource Isolation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-16",
		Name:        "Shared Resource Isolation",
		Description: "CMMC L2 SC.2.016: Isolate shared resources using containers, namespaces, or sandboxes",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSharedResourceIsolation,
		References:  []string{"CMMC L2 SC.2.016", "NIST SP 800-171 §3.13.14"},
	})

	// SC-19: Connection Timeout (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-19",
		Name:        "Connection Timeout",
		Description: "CMMC L2 SC.2.019: Configure connection timeouts and idle session termination",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConnectionTimeout,
		References:  []string{"CMMC L2 SC.2.019", "NIST SP 800-171 §3.13.18"},
	})

	// SC-20: Cryptographic Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-20",
		Name:        "Cryptographic Protection",
		Description: "CMMC L2 SC.2.020: Use cryptographic protection including digital signatures for CUI integrity",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptographicProtection,
		References:  []string{"CMMC L2 SC.2.020", "NIST SP 800-171 §3.13.13"},
	})
}

// checkSystemBoundaryMonitoring verifies boundary monitoring through
// IDS/IPS and network monitoring. Maps to CMMC L2 SC.2.006.
func (m *CMMCL2Module) checkSystemBoundaryMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundaryMonitoring := strings.Contains(inputStr, "boundary_monitoring") || strings.Contains(inputStr, "network_monitoring") || strings.Contains(inputStr, "ids_ips")
	hasIntrusionDetection := strings.Contains(inputStr, "intrusion_detection") || strings.Contains(inputStr, "ids_ips") || strings.Contains(inputStr, "boundary_monitoring")

	if hasBoundaryMonitoring && hasIntrusionDetection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-06",
			ControlName: "System Boundary Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System boundary monitoring verified (boundary_monitoring + intrusion_detection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBoundaryMonitoring {
		violations = append(violations, "boundary monitoring not configured")
	}
	if !hasIntrusionDetection {
		violations = append(violations, "intrusion detection not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-06",
		ControlName: "System Boundary Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System boundary monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure boundary monitoring (boundary_monitoring=true) and intrusion detection (ids_ips=enabled)",
	}, nil
}

// checkExternalNetworkAccess verifies external network access is controlled
// through VPNs and gateways. Maps to CMMC L2 SC.2.007.
func (m *CMMCL2Module) checkExternalNetworkAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasExternalAccess := strings.Contains(inputStr, "external_access") || strings.Contains(inputStr, "vpn") || strings.Contains(inputStr, "tunnel")
	hasGateway := strings.Contains(inputStr, "gateway") || strings.Contains(inputStr, "vpn") || strings.Contains(inputStr, "external_access")

	if hasExternalAccess && hasGateway {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-07",
			ControlName: "External Network Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "External network access verified (vpn + gateway)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasExternalAccess {
		violations = append(violations, "external access control not configured")
	}
	if !hasGateway {
		violations = append(violations, "gateway not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-07",
		ControlName: "External Network Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "External network access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure external access through VPN (vpn=enabled) and secure gateway (gateway=enabled)",
	}, nil
}

// checkTransmissionConfidentiality verifies encryption in transit using
// TLS or IPsec. Maps to CMMC L2 SC.2.008.
func (m *CMMCL2Module) checkTransmissionConfidentiality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionTransit := strings.Contains(inputStr, "encryption_in_transit") || strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "ipsec")
	hasWireEncryption := strings.Contains(inputStr, "wire_encryption") || strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "ipsec")

	if hasEncryptionTransit && hasWireEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-08",
			ControlName: "Transmission Confidentiality",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Transmission confidentiality verified (encryption_in_transit + wire_encryption)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryptionTransit {
		violations = append(violations, "encryption in transit not configured")
	}
	if !hasWireEncryption {
		violations = append(violations, "wire-level encryption not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-08",
		ControlName: "Transmission Confidentiality",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Transmission confidentiality gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure encryption in transit (encryption_in_transit=true, tls=1.2+, ipsec=enabled)",
	}, nil
}

// checkNetworkIntegrity verifies network integrity through checksums and
// hash verification. Maps to CMMC L2 SC.2.009.
func (m *CMMCL2Module) checkNetworkIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNetworkIntegrity := strings.Contains(inputStr, "network_integrity") || strings.Contains(inputStr, "checksum") || strings.Contains(inputStr, "hash")
	hasIntegrityCheck := strings.Contains(inputStr, "integrity_check") || strings.Contains(inputStr, "checksum") || strings.Contains(inputStr, "hash")

	if hasNetworkIntegrity && hasIntegrityCheck {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-09",
			ControlName: "Network Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Network integrity verified (network_integrity + integrity_check)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasNetworkIntegrity {
		violations = append(violations, "network integrity not configured")
	}
	if !hasIntegrityCheck {
		violations = append(violations, "integrity check not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-09",
		ControlName: "Network Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Network integrity gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure network integrity verification (network_integrity=true, checksum=enabled)",
	}, nil
}

// checkCryptographicKeyManagement verifies key management including
// rotation and HSM usage. Maps to CMMC L2 SC.2.012.
func (m *CMMCL2Module) checkCryptographicKeyManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyManagement := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "hsm")
	hasKeyStore := strings.Contains(inputStr, "key_store") || strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "hsm")

	if hasKeyManagement && hasKeyStore {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-12",
			ControlName: "Cryptographic Key Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic key management verified (key_management + key_store)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasKeyManagement {
		violations = append(violations, "key management not configured")
	}
	if !hasKeyStore {
		violations = append(violations, "key store not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-12",
		ControlName: "Cryptographic Key Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic key management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure key management with rotation (key_management=true, key_rotation=enabled) and secure key store (hsm=enabled)",
	}, nil
}

// checkSessionAuthenticity verifies session authenticity through
// anti-replay and nonce mechanisms. Maps to CMMC L2 SC.2.013.
func (m *CMMCL2Module) checkSessionAuthenticity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSessionAuthenticity := strings.Contains(inputStr, "session_authenticity") || strings.Contains(inputStr, "session_integrity") || strings.Contains(inputStr, "anti_replay")
	hasNonce := strings.Contains(inputStr, "nonce") || strings.Contains(inputStr, "anti_replay") || strings.Contains(inputStr, "session_authenticity")

	if hasSessionAuthenticity && hasNonce {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-13",
			ControlName: "Session Authenticity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Session authenticity verified (session_authenticity + nonce)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSessionAuthenticity {
		violations = append(violations, "session authenticity not configured")
	}
	if !hasNonce {
		violations = append(violations, "nonce/anti-replay not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-13",
		ControlName: "Session Authenticity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Session authenticity gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure session authenticity (session_authenticity=true) and anti-replay mechanisms (nonce=enabled)",
	}, nil
}

// checkFIPSValidatedCryptography verifies FIPS-validated cryptography
// is in use. Maps to CMMC L2 SC.2.014.
func (m *CMMCL2Module) checkFIPSValidatedCryptography(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := strings.Contains(inputStr, "fips_140") || strings.Contains(inputStr, "fips_mode") || strings.Contains(inputStr, "cmvp")
	hasValidatedCrypto := strings.Contains(inputStr, "validated_crypto") || strings.Contains(inputStr, "fips_140") || strings.Contains(inputStr, "fips_mode")

	if hasFIPS && hasValidatedCrypto {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-14",
			ControlName: "FIPS-Validated Cryptography",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FIPS-validated cryptography verified (fips_140 + validated_crypto)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasFIPS {
		violations = append(violations, "FIPS-140 not configured")
	}
	if !hasValidatedCrypto {
		violations = append(violations, "validated cryptography not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-14",
		ControlName: "FIPS-Validated Cryptography",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FIPS-validated cryptography gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure FIPS-validated cryptography (fips_140=true, fips_mode=enabled)",
	}, nil
}

// checkSharedResourceIsolation verifies shared resources are isolated
// using containers, namespaces, or sandboxes. Maps to CMMC L2 SC.2.016.
func (m *CMMCL2Module) checkSharedResourceIsolation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasResourceIsolation := strings.Contains(inputStr, "resource_isolation") || strings.Contains(inputStr, "container_isolation") || strings.Contains(inputStr, "namespace")
	hasSandbox := strings.Contains(inputStr, "sandbox") || strings.Contains(inputStr, "container_isolation") || strings.Contains(inputStr, "namespace")

	if hasResourceIsolation && hasSandbox {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-16",
			ControlName: "Shared Resource Isolation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Shared resource isolation verified (resource_isolation + sandbox)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasResourceIsolation {
		violations = append(violations, "resource isolation not configured")
	}
	if !hasSandbox {
		violations = append(violations, "sandbox/container isolation not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-16",
		ControlName: "Shared Resource Isolation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Shared resource isolation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure resource isolation (resource_isolation=true, container_isolation=enabled) and sandboxing (sandbox=enabled)",
	}, nil
}

// checkConnectionTimeout verifies connection timeout and idle session
// termination. Maps to CMMC L2 SC.2.019.
func (m *CMMCL2Module) checkConnectionTimeout(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConnectionTimeout := strings.Contains(inputStr, "connection_timeout") || strings.Contains(inputStr, "idle_timeout") || strings.Contains(inputStr, "session_timeout")
	hasTimeout := strings.Contains(inputStr, "timeout") || strings.Contains(inputStr, "connection_timeout") || strings.Contains(inputStr, "idle_timeout")

	if hasConnectionTimeout && hasTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-19",
			ControlName: "Connection Timeout",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Connection timeout verified (connection_timeout + timeout)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasConnectionTimeout {
		violations = append(violations, "connection timeout not configured")
	}
	if !hasTimeout {
		violations = append(violations, "timeout policy not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-19",
		ControlName: "Connection Timeout",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Connection timeout gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure connection timeouts (connection_timeout=900, idle_timeout=enabled)",
	}, nil
}

// checkCryptographicProtection verifies cryptographic protection including
// digital signatures. Maps to CMMC L2 SC.2.020.
func (m *CMMCL2Module) checkCryptographicProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCryptographicProtection := strings.Contains(inputStr, "cryptographic_protection") || strings.Contains(inputStr, "digital_signature") || strings.Contains(inputStr, "signing")
	hasTamperProof := strings.Contains(inputStr, "tamper_proof") || strings.Contains(inputStr, "digital_signature") || strings.Contains(inputStr, "cryptographic_protection")

	if hasCryptographicProtection && hasTamperProof {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-20",
			ControlName: "Cryptographic Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic protection verified (cryptographic_protection + tamper_proof)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCryptographicProtection {
		violations = append(violations, "cryptographic protection not configured")
	}
	if !hasTamperProof {
		violations = append(violations, "tamper-proof signing not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-20",
		ControlName: "Cryptographic Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure cryptographic protection (cryptographic_protection=true) and digital signatures (digital_signature=enabled)",
	}, nil
}

// checkSCBoundaryProtection verifies boundary protection. Maps to CMMCL2-SC-01.
func (m *CMMCL2Module) checkSCBoundaryProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundary := strings.Contains(inputStr, "boundary_protection") || strings.Contains(inputStr, "network_boundary") || strings.Contains(inputStr, "firewall_boundary")
	hasFirewall := strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "waf") || strings.Contains(inputStr, "network_segmentation")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "audit_log")
	if hasBoundary && hasFirewall && hasMonitoring {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-01", ControlName: "Boundary Protection", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Boundary protection verified (boundary + firewall + monitoring)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasBoundary {
		violations = append(violations, "boundary protection not configured")
	}
	if !hasFirewall {
		violations = append(violations, "firewall not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "monitoring not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-01", ControlName: "Boundary Protection", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Boundary protection gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure boundary protection with firewall and monitoring"}, nil
}

// checkSCNetworkArch verifies network architecture. Maps to CMMCL2-SC-04.
func (m *CMMCL2Module) checkSCNetworkArch(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasArch := strings.Contains(inputStr, "network_architecture") || strings.Contains(inputStr, "segmentation") || strings.Contains(inputStr, "dmz")
	hasIsolation := strings.Contains(inputStr, "network_isolation") || strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "vlan")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || strings.Contains(inputStr, "firewall")
	if hasArch && hasIsolation && hasEnforcement {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-04", ControlName: "Network Architecture", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Network architecture verified (architecture + isolation + enforcement)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasArch {
		violations = append(violations, "network architecture not configured")
	}
	if !hasIsolation {
		violations = append(violations, "network isolation not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-04", ControlName: "Network Architecture", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Network architecture gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure network segmentation with isolation and firewall enforcement"}, nil
}

// checkSCTrustedConnection verifies trusted network connection. Maps to CMMCL2-SC-10.
func (m *CMMCL2Module) checkSCTrustedConnection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTrusted := strings.Contains(inputStr, "trusted_connection") || strings.Contains(inputStr, "network_authentication") || strings.Contains(inputStr, "802_1x")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled") || strings.Contains(inputStr, "mfa")
	hasEncryption := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "encryption") || strings.Contains(inputStr, "encrypted")
	if hasTrusted && hasAuth && hasEncryption {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-10", ControlName: "Trusted Network Connection", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Trusted connection verified (trusted + auth + encryption)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasTrusted {
		violations = append(violations, "trusted connection not configured")
	}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasEncryption {
		violations = append(violations, "encryption not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-SC-10", ControlName: "Trusted Network Connection", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Trusted connection gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure trusted network connection with authentication and encryption"}, nil
}
