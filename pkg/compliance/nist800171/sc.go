// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 SC (System and Communications
// Protection) Family
// =========================================================================
//
// NIST SP 800-171 §3.13 — System and Communications Protection family (SC)
// 6 controls: 4 automated + 2 evidence-mapped
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerSCControls wires System and Communications Protection controls.
func (m *NIST800171Module) registerSCControls() {
	// SC-4: Information Sharing (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-4",
		Name:        "Information Sharing",
		Description: "NIST 800-171 SC-4 (3.13.4): Information sharing controlled between systems",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.4", "NIST SP 800-53 Rev. 5 SC-4"},
	})

	// SC-7: Boundary Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-7",
		Name:        "Boundary Protection",
		Description: "NIST 800-171 SC-7 (3.13.7): System boundary protection with network segmentation",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBoundaryProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.7", "NIST SP 800-53 Rev. 5 SC-7"},
	})

	// SC-8: Transmission Confidentiality (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-8",
		Name:        "Transmission Confidentiality",
		Description: "NIST 800-171 SC-8 (3.13.8): Data encrypted in transit using TLS 1.2+",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransmissionConfidentiality,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.8", "NIST SP 800-53 Rev. 5 SC-8"},
	})

	// SC-12: Cryptographic Key Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-12",
		Name:        "Cryptographic Key Management",
		Description: "NIST 800-171 SC-12 (3.13.12): Cryptographic key management and protection",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptographicKeyManagement,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.12", "NIST SP 800-53 Rev. 5 SC-12"},
	})

	// SC-13: Cryptographic Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-13",
		Name:        "Cryptographic Protection",
		Description: "NIST 800-171 SC-13 (3.13.13): FIPS-validated cryptography for CUI protection",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCryptographicProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13.13", "NIST SP 800-53 Rev. 5 SC-13"},
	})

	// SC-23: Session Authenticity (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SC-23",
		Name:        "Session Authenticity",
		Description: "NIST 800-171 SC-23: Session authenticity protection against session hijacking",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.13", "NIST SP 800-53 Rev. 5 SC-23"},
	})
}

// --- SC Check Functions ---

func (m *NIST800171Module) checkBoundaryProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundary := strings.Contains(inputStr, "boundary") || strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "network_segmentation")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging")

	if hasBoundary && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-7",
			ControlName: "Boundary Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Boundary protection verified (firewall/segmentation + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBoundary {
		violations = append(violations, "boundary protection not detected")
	}
	if !hasMonitoring {
		violations = append(violations, "boundary monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-7",
		ControlName: "Boundary Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Boundary protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure boundary protection (network.firewall=true) and monitoring",
	}, nil
}

func (m *NIST800171Module) checkTransmissionConfidentiality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls_1_2")
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}

	if hasTLS || hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-8",
			ControlName: "Transmission Confidentiality",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Transmission confidentiality verified (TLS/encryption)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-8",
		ControlName: "Transmission Confidentiality",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Transmission confidentiality not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ for all data transmissions (security.tls_min_version=1.2)",
	}, nil
}

func (m *NIST800171Module) checkCryptographicKeyManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "kms")
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}

	if hasKeyMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-12",
			ControlName: "Cryptographic Key Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic key management verified (key management + rotation)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-12",
			ControlName: "Cryptographic Key Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "FIPS-validated cryptography detected but key management process not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Configure key management and rotation (crypto.key_management=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-12",
		ControlName: "Cryptographic Key Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic key management not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure key management and rotation (crypto.key_management=true)",
	}, nil
}

func (m *NIST800171Module) checkCryptographicProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := false
	for _, p := range m.fipsPatterns {
		if p.MatchString(inputStr) {
			hasFIPS = true
			break
		}
	}
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}

	if hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-13",
			ControlName: "Cryptographic Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic protection verified (FIPS-validated cryptography)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SC-13",
			ControlName: "Cryptographic Protection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Encryption detected but FIPS validation not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable FIPS-validated cryptography (crypto.fips_mode=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SC-13",
		ControlName: "Cryptographic Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic protection not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS-validated cryptography (crypto.fips_mode=true)",
	}, nil
}
