// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 MP (Media Protection) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Media Protection family (MP)
// §3.8 — Controls for protecting CUI on media.
//
// In-scope MP controls (7 controls: 4 automated + 3 evidence-mapped):
//   MP-1  Media Protection Policy/Procedures      (evidence-mapped)
//   MP-2  Media Access                            (automated)
//   MP-3  Media Marking                           (evidence-mapped)
//   MP-4  Media Storage                           (automated)
//   MP-5  Media Transport                         (automated)
//   MP-6  Media Sanitization                      (automated)
//   MP-7  Media Disposal                          (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerMPControls wires the MP family controls into the module.
func (m *NIST800171Module) registerMPControls() {
	// MP-1: Media Protection Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-1",
		Name:        "Media Protection Policy and Procedures",
		Description: "NIST 800-171 MP-1 (3.8.1): Media protection policy and procedures documented, reviewed, and disseminated",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.1", "NIST SP 800-53 Rev. 5 MP-1"},
	})

	// MP-2: Media Access (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-2",
		Name:        "Media Access",
		Description: "NIST 800-171 MP-2 (3.8.2): Media access restricted to authorized individuals with audit logging",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMediaAccess,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.2", "NIST SP 800-53 Rev. 5 MP-2"},
	})

	// MP-3: Media Marking (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-3",
		Name:        "Media Marking",
		Description: "NIST 800-171 MP-3 (3.8.3): CUI media marked to indicate distribution and handling requirements",
		Category:    "Media Protection",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.3", "NIST SP 800-53 Rev. 5 MP-3"},
	})

	// MP-4: Media Storage (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-4",
		Name:        "Media Storage",
		Description: "NIST 800-171 MP-4 (3.8.4): Media storage physically and logically secured with encryption",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMediaStorage,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.4", "NIST SP 800-53 Rev. 5 MP-4"},
	})

	// MP-5: Media Transport (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-5",
		Name:        "Media Transport",
		Description: "NIST 800-171 MP-5 (3.8.5): Media transport protected with encryption and chain of custody",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMediaTransport,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.5", "NIST SP 800-53 Rev. 5 MP-5"},
	})

	// MP-6: Media Sanitization (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-6",
		Name:        "Media Sanitization",
		Description: "NIST 800-171 MP-6 (3.8.6): Media sanitized before disposal or reuse with verified sanitization methods",
		Category:    "Media Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaSanitization,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8.6", "NIST SP 800-53 Rev. 5 MP-6"},
	})

	// MP-7: Media Disposal (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MP-7",
		Name:        "Media Disposal",
		Description: "NIST 800-171 MP-7: Media disposal documented and verified with sanitization records",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.8", "NIST SP 800-53 Rev. 5 MP-7"},
	})
}

// checkMediaAccess verifies media access is restricted to authorized
// individuals. Maps to MP-2.
func (m *NIST800171Module) checkMediaAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "media_access") || strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging") || strings.Contains(inputStr, "monitoring")
	hasRestriction := strings.Contains(inputStr, "restricted") || strings.Contains(inputStr, "authorization") || strings.Contains(inputStr, "authorized")

	if hasAccessControl && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-2",
			ControlName: "Media Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Media access controls verified (access control + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasRestriction && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-2",
			ControlName: "Media Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Media access controls verified (authorization + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAccessControl && !hasRestriction {
		violations = append(violations, "media access controls not detected")
	}
	if !hasAudit {
		violations = append(violations, "media access audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-MP-2",
		ControlName: "Media Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Media access gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure media access controls and audit logging (media.access_control=true, media.audit=true)",
	}, nil
}

// checkMediaStorage verifies media is stored securely with encryption.
// Maps to MP-4.
func (m *NIST800171Module) checkMediaStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}
	hasStorageSecurity := strings.Contains(inputStr, "media_storage") || strings.Contains(inputStr, "encrypted_storage") || strings.Contains(inputStr, "secure_storage")
	hasAccessControl := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "restricted")

	if hasEncryption && (hasStorageSecurity || hasAccessControl) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-4",
			ControlName: "Media Storage",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Media storage controls verified (encryption + secure storage/access control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryption {
		violations = append(violations, "media encryption not configured")
	}
	if !hasStorageSecurity && !hasAccessControl {
		violations = append(violations, "secure media storage not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-MP-4",
		ControlName: "Media Storage",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Media storage gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable media encryption and secure storage (media.encrypted_storage=true, media.access_control=true)",
	}, nil
}

// checkMediaTransport verifies media is protected during transport.
// Maps to MP-5.
func (m *NIST800171Module) checkMediaTransport(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := strings.Contains(inputStr, "encryption") || strings.Contains(inputStr, "encrypted") || strings.Contains(inputStr, "tls")
	hasChainOfCustody := strings.Contains(inputStr, "chain_of_custody") || strings.Contains(inputStr, "custody") || strings.Contains(inputStr, "tracking")
	hasTransport := strings.Contains(inputStr, "media_transport") || strings.Contains(inputStr, "transport_encryption") || strings.Contains(inputStr, "secure_transport")

	if hasEncryption && (hasChainOfCustody || hasTransport) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-5",
			ControlName: "Media Transport",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Media transport controls verified (encryption + chain of custody/transport security)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryption {
		violations = append(violations, "transport encryption not configured")
	}
	if !hasChainOfCustody && !hasTransport {
		violations = append(violations, "chain of custody or secure transport not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-MP-5",
		ControlName: "Media Transport",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Media transport gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable transport encryption and chain of custody tracking (media.transport_encryption=true)",
	}, nil
}

// checkMediaSanitization verifies media sanitization before disposal.
// Maps to MP-6.
func (m *NIST800171Module) checkMediaSanitization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSanitization := strings.Contains(inputStr, "sanitization") || strings.Contains(inputStr, "sanitise") || strings.Contains(inputStr, "wipe") || strings.Contains(inputStr, "secure_erase")
	hasVerification := strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "verified") || strings.Contains(inputStr, "audit_log")
	hasPolicy := strings.Contains(inputStr, "disposal_policy") || strings.Contains(inputStr, "media_policy") || strings.Contains(inputStr, "policy")

	if hasSanitization && hasVerification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-6",
			ControlName: "Media Sanitization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media sanitization verified (sanitization + verification)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasSanitization && hasPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-MP-6",
			ControlName: "Media Sanitization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Media sanitization detected but verification not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable sanitization verification (media.sanitization_verification=true)",
		}, nil
	}

	violations := []string{}
	if !hasSanitization {
		violations = append(violations, "media sanitization not configured")
	}
	if !hasVerification {
		violations = append(violations, "sanitization verification not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-MP-6",
		ControlName: "Media Sanitization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Media sanitization gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure media sanitization with verification (media.sanitization=true, media.sanitization_verification=true)",
	}, nil
}
