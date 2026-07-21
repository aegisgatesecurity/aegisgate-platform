// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FIPS 140-2/140-3 Compliance Module
// =========================================================================
//
// FIPS 140 (Federal Information Processing Standard) is the US federal
// standard for cryptographic modules. AegisGate implements the FIPS 140-2
// and 140-3 compliance checks as a licensed add-on module. This is the
// 6th compliance framework shipped (HIPAA, PCI-DSS, EU AI Act, SOC 2,
// ISO 42001, FIPS 140; FedRAMP is the only Path B module remaining).
//
// Module metadata:
//   - Framework:   "fips"
//   - Version:     "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $299/mo (founder-locked 2026-06-04)
//
// This module is a thin compliance wrapper around the existing FIPS
// crypto engine in `upstream/aegisgate/pkg/crypto/fips/` (492 LOC,
// 6 compliance checks, approved algorithms/ciphers/key sizes, audit
// logging, self-test). The compliance module exposes those primitives
// as AegisGate ControlDefinitions so the Compliance Scan Engine can
// report on FIPS posture alongside SOC 2, HIPAA, etc.
//
// IMPORTANT — Self-attested posture:
//   AegisGate is not a NIST CMVP-accredited Cryptographic Module
//   Validation Program laboratory. The FIPS mode in this codebase is
//   "FIPS-compliant" in the sense that the Go standard library
//   crypto/cipher primitives used (AES-GCM, ECDSA P-256, SHA-256/384)
//   are FIPS-approved algorithms, but the Go runtime itself is not a
//   CMVP-validated module. Customers who require CMVP-validated
//   crypto (federal agencies, defense) must integrate a CMVP-validated
//   module (e.g., via PKCS#11) and run AegisGate in a CMVP-validated
//   execution environment. This is documented in the customer 1-pager
//   and the pricing page disclaimer.
//
// Coverage: 10 controls across 5 FIPS 140-2/-3 areas (Cryptographic
// Module Specification, Module Ports and Interfaces, Roles/Services/
// Authentication, Software/Firmware Security, Operational Environment).
// Of the 10 controls, 8 have automated CheckFunc implementations; the
// remaining 2 (CMVP validation certificate, HSM integration) are
// configuration checks (the customer must supply these).
//
// Reference: FIPS 140-2: https://csrc.nist.gov/publications/detail/fips/140/2/final
//            FIPS 140-3: https://csrc.nist.gov/publications/detail/fips/140/3/final
//            SP 800-57 (Key Management): https://csrc.nist.gov/publications/detail/sp/800/57/part/1/rev-5/final
//
// =========================================================================

package fips

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	fipscrypto "github.com/aegisgatesecurity/aegisgate/pkg/crypto/fips"
)

// FIPS140Module implements the FIPS 140-2/140-3 compliance framework
// as a licensed add-on. It embeds *compliance.BaseComplianceModule
// which provides RegisterControl, Controls(), Framework(), Version(),
// CheckAll(), and GenerateAssessment() out of the box.
type FIPS140Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	hashPatterns   []*regexp.Regexp
	cipherPatterns []*regexp.Regexp
	tlsVersionPats []*regexp.Regexp
}

// NewFIPS140Module creates a new FIPS 140 compliance module. It is
// safe to call multiple times; the module is stateless after
// construction aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleFIPS entry in
// moduleRequirements).
func NewFIPS140Module() *FIPS140Module {
	m := &FIPS140Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("fips", "1.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *FIPS140Module) initPatterns() {
	m.hashPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)sha-?256`),
		regexp.MustCompile(`(?i)sha-?384`),
		regexp.MustCompile(`(?i)sha-?512`),
		regexp.MustCompile(`(?i)sha3-?256`),
		regexp.MustCompile(`(?i)sha3-?384`),
		regexp.MustCompile(`(?i)sha3-?512`),
	}
	// Approved cipher pattern. Matches both "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	// (Go crypto/tls constant naming) and the human-friendly "ECDHE-RSA-AES256-GCM-SHA384".
	// The optional "(WITH|_|-)" between algorithm and key size handles both styles.
	m.cipherPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ecdhe[-_ ]?rsa[-_ ]?(with[-_ ]?)?aes[-_ ]?(128|256)[-_ ]?gcm[-_ ]?sha[-_]?(256|384)`),
		regexp.MustCompile(`(?i)ecdhe[-_ ]?ecdsa[-_ ]?(with[-_ ]?)?aes[-_ ]?(128|256)[-_ ]?gcm[-_ ]?sha[-_]?(256|384)`),
		regexp.MustCompile(`(?i)rsa[-_ ]?(with[-_ ]?)?aes[-_ ]?(128|256)[-_ ]?gcm[-_ ]?sha[-_]?(256|384)`),
	}
	m.tlsVersionPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)tls[-_ ]?1[._-]2`),
		regexp.MustCompile(`(?i)tls[-_ ]?1[._-]3`),
		// Allows "min_version: 1.2", "min_version:1.3", "min-version-1.2",
		// "minversion 1.3" — common yaml/json/cobra flag styles.
		regexp.MustCompile(`(?i)min[-_ ]?version[: _-]*1[._-][23]`),
	}
}

// registerControls wires all 10 FIPS 140-2/140-3 controls into the
// module. Called once from NewFIPS140Module.
func (m *FIPS140Module) registerControls() {
	// Cryptographic Module Specification (FIPS 140-2 §4.1, FIPS 140-3 §7.1)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-001",
		Name:        "FIPS Mode Enabled",
		Description: "FIPS 140 §7.1: FIPS mode is enabled in the platform configuration",
		Category:    "Cryptographic Module Specification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFIPSModeEnabled,
		References:  []string{"FIPS 140-2 §4.1", "FIPS 140-3 §7.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-002",
		Name:        "FIPS Compliance Level Configured",
		Description: "FIPS 140: Compliance level is explicitly set to 140-2 or 140-3",
		Category:    "Cryptographic Module Specification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFIPSLevel,
		References:  []string{"FIPS 140-2", "FIPS 140-3"},
	})

	// Module Ports and Interfaces (FIPS 140-2 §4.2, FIPS 140-3 §7.2)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-003",
		Name:        "Approved TLS Cipher Suites",
		Description: "FIPS 140 §7.2: All TLS cipher suites are FIPS-approved (ECDHE+AES-GCM, no RC4/3DES/MD5/SHA-1)",
		Category:    "Module Ports and Interfaces",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkApprovedCipherSuites,
		References:  []string{"FIPS 140-2 §4.2", "SP 800-52r2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-004",
		Name:        "Minimum TLS Version 1.2",
		Description: "FIPS 140 §7.2: Minimum TLS version is 1.2 (TLS 1.0/1.1 not allowed)",
		Category:    "Module Ports and Interfaces",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMinimumTLSVersion,
		References:  []string{"FIPS 140-2 §4.2", "SP 800-52r2"},
	})

	// Roles, Services, and Authentication (FIPS 140-2 §4.3, FIPS 140-3 §7.3)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-005",
		Name:        "Approved Hash Algorithms",
		Description: "FIPS 140 §7.3: Only FIPS-approved hash algorithms in use (SHA-256/384/512, SHA3-256/384/512). No MD5, no SHA-1 (except legacy signature verification)",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkApprovedHashes,
		References:  []string{"FIPS 140-2 §4.3", "FIPS 180-4 (SHS)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-006",
		Name:        "Minimum Cryptographic Key Sizes",
		Description: "FIPS 140 §7.3: Minimum key sizes meet FIPS requirements (RSA ≥ 2048, ECDSA ≥ 256, AES ≥ 128, SHA ≥ 224)",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMinimumKeySizes,
		References:  []string{"FIPS 140-2 §4.3", "SP 800-131A"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-007",
		Name:        "Cryptographic Self-Test",
		Description: "FIPS 140 §7.3: Cryptographic self-test (RNG + RSA key generation) passes",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSelfTest,
		References:  []string{"FIPS 140-2 §4.3.1", "FIPS 140-3 §7.3.1"},
	})

	// Software/Firmware Security (FIPS 140-2 §4.4, FIPS 140-3 §7.4)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-008",
		Name:        "Cryptographic Audit Logging",
		Description: "FIPS 140 §7.4: All cryptographic operations are logged for audit",
		Category:    "Software/Firmware Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogging,
		References:  []string{"FIPS 140-2 §4.4.4", "FIPS 140-3 §7.4.4"},
	})

	// Operational Environment (FIPS 140-2 §4.5, FIPS 140-3 §7.5)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-009",
		Name:        "CMVP Validation Status",
		Description: "FIPS 140: CMVP validation certificate is configured (optional; required for federal agencies and defense)",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Customer-supplied CMVP number
		References:  []string{"FIPS 140-2 §4.5", "FIPS 140-3 §7.5", "NIST CMVP"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-010",
		Name:        "HSM Integration",
		Description: "FIPS 140: HSM (Hardware Security Module) integration for key storage (optional; required for high-assurance environments)",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Customer-supplied HSM configuration
		References:  []string{"FIPS 140-2 §4.5", "PKCS#11"},
	})
}

// ============================================================================
// Check implementations
// ============================================================================

// checkFIPSModeEnabled verifies that FIPS mode is currently enabled
// in the fips.CurrentMode global.
func (m *FIPS140Module) checkFIPSModeEnabled(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if fipscrypto.IsEnabled() {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-001",
			ControlName: "FIPS Mode Enabled",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "FIPS mode is enabled (level: " + fipscrypto.GetLevel().String() + ")",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-001",
		ControlName: "FIPS Mode Enabled",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "FIPS mode is not enabled",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS mode in platformconfig.TLS.FIPS.Enabled (or AEGISGATE_FIPS_ENABLED=true) AND call fips.Configure(fips.Level140_2) at startup",
	}, nil
}

// checkFIPSLevel verifies the configured FIPS level is 140-2 or 140-3.
func (m *FIPS140Module) checkFIPSLevel(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	level := fipscrypto.GetLevel()
	if level == fipscrypto.Level140_2 || level == fipscrypto.Level140_3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-002",
			ControlName: "FIPS Compliance Level Configured",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FIPS compliance level is " + level.String(),
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-002",
		ControlName: "FIPS Compliance Level Configured",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FIPS compliance level not configured (LevelNone)",
		Timestamp:   time.Now(),
		Remediation: "Call fips.Configure(fips.Level140_2) or fips.Configure(fips.Level140_3) at startup",
	}, nil
}

// checkApprovedCipherSuites verifies the TLS configuration uses only
// FIPS-approved cipher suites. The input should be the platform's
// TLS configuration as a string (cipher suite names).
func (m *FIPS140Module) checkApprovedCipherSuites(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	// Disallowed cipher patterns (FIPS-banned)
	disallowed := []string{
		"RC4", "3DES", "DES", "MD5", "SHA-1", "SHA1", "EXPORT", "NULL", "anon",
	}
	disallowedFound := []string{}
	for _, bad := range disallowed {
		if strings.Contains(inputStr, bad) {
			disallowedFound = append(disallowedFound, bad)
		}
	}

	// At least one approved cipher must be present
	hasApproved := false
	for _, p := range m.cipherPatterns {
		if p.MatchString(inputStr) {
			hasApproved = true
			break
		}
	}

	if len(disallowedFound) == 0 && hasApproved {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-003",
			ControlName: "Approved TLS Cipher Suites",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "All TLS cipher suites are FIPS-approved (ECDHE+AES-GCM)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if len(disallowedFound) > 0 {
		violations = append(violations, "disallowed ciphers present: "+strings.Join(disallowedFound, ", "))
	}
	if !hasApproved {
		violations = append(violations, "no FIPS-approved ciphers detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-003",
		ControlName: "Approved TLS Cipher Suites",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "TLS cipher suite violations: " + strings.Join(violations, "; "),
		Timestamp:   time.Now(),
		Remediation: "Configure TLS with only FIPS-approved ciphers (ECDHE-RSA-AES128/256-GCM-SHA256/384, ECDHE-ECDSA-AES128/256-GCM-SHA256/384). Use pkg/tls.GetFIPSTLSConfig().",
	}, nil
}

// checkMinimumTLSVersion verifies the minimum TLS version is 1.2 or 1.3.
// patterns[0] = TLS 1.2, patterns[1] = TLS 1.3, patterns[2] = min_version 1.x.
func (m *FIPS140Module) checkMinimumTLSVersion(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS12 := false
	hasTLS13 := false
	for i, p := range m.tlsVersionPats {
		if p.MatchString(inputStr) {
			switch i {
			case 0: // TLS 1.2 pattern
				hasTLS12 = true
			case 1: // TLS 1.3 pattern
				hasTLS13 = true
			case 2: // min_version 1.x pattern (matches both 1.2 and 1.3)
				// Look for the actual version number in the input.
				if strings.Contains(inputStr, "1.3") {
					hasTLS13 = true
				} else if strings.Contains(inputStr, "1.2") {
					hasTLS12 = true
				}
			}
		}
	}

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-004",
			ControlName: "Minimum TLS Version 1.2",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Minimum TLS version is 1.3 (FIPS 140-3 compatible)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS12 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-004",
			ControlName: "Minimum TLS Version 1.2",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Minimum TLS version is 1.2 (FIPS 140-2 minimum)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-004",
		ControlName: "Minimum TLS Version 1.2",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No FIPS-compatible TLS version detected (need TLS 1.2 or 1.3)",
		Timestamp:   time.Now(),
		Remediation: "Set tls.min_version to 1.2 or 1.3 in configs/aegisgate-platform.yaml",
	}, nil
}

// checkApprovedHashes verifies only FIPS-approved hash algorithms are
// in use (SHA-256/384/512, SHA3 variants). The input should be the
// platform config or scan report as a string.
func (m *FIPS140Module) checkApprovedHashes(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	// Disallowed hash patterns
	disallowed := []string{"MD5", "MD-5", "SHA-1", "SHA1"}
	disallowedFound := []string{}
	for _, bad := range disallowed {
		if strings.Contains(inputStr, bad) {
			disallowedFound = append(disallowedFound, bad)
		}
	}

	hasApproved := false
	for _, p := range m.hashPatterns {
		if p.MatchString(inputStr) {
			hasApproved = true
			break
		}
	}

	if len(disallowedFound) == 0 && hasApproved {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-005",
			ControlName: "Approved Hash Algorithms",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Only FIPS-approved hash algorithms in use (SHA-256/384/512, SHA3 variants)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if len(disallowedFound) > 0 {
		violations = append(violations, "disallowed hashes: "+strings.Join(disallowedFound, ", "))
	}
	if !hasApproved {
		violations = append(violations, "no FIPS-approved hashes detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-005",
		ControlName: "Approved Hash Algorithms",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Hash algorithm violations: " + strings.Join(violations, "; "),
		Timestamp:   time.Now(),
		Remediation: "Migrate to SHA-256, SHA-384, SHA-512, or SHA3-256/384/512. Remove MD5 and SHA-1 usage.",
	}, nil
}

// checkMinimumKeySizes verifies the configured minimum key sizes
// meet FIPS requirements. Input should contain key size indicators.
func (m *FIPS140Module) checkMinimumKeySizes(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	mins := fipscrypto.MinimumKeySizes()

	// Check for weak key sizes
	violations := []string{}

	// RSA: must be >= 2048
	rsaSmall := regexp.MustCompile(`rsa[_ ]?(\d{3,4})`)
	for _, m := range rsaSmall.FindAllStringSubmatch(inputStr, -1) {
		if len(m) > 1 {
			var size int
			_, _ = fmt.Sscanf(m[1], "%d", &size)
			if size > 0 && size < mins["RSA"] {
				violations = append(violations, "RSA "+m[1]+" bits < FIPS minimum of 2048")
			}
		}
	}

	// ECDSA: must be >= 256
	ecdsaSmall := regexp.MustCompile(`ecdsa[_ ]?(p-?)?(\d{2,3})`)
	for _, m := range ecdsaSmall.FindAllStringSubmatch(inputStr, -1) {
		if len(m) > 2 {
			var size int
			_, _ = fmt.Sscanf(m[2], "%d", &size)
			if size > 0 && size < mins["ECDSA"] {
				violations = append(violations, "ECDSA P-"+m[2]+" < FIPS minimum of 256")
			}
		}
	}

	// AES: must be >= 128
	aesSmall := regexp.MustCompile(`aes[_ ]?(\d{2,3})`)
	for _, m := range aesSmall.FindAllStringSubmatch(inputStr, -1) {
		if len(m) > 1 {
			var size int
			_, _ = fmt.Sscanf(m[1], "%d", &size)
			if size > 0 && size < mins["AES"] {
				violations = append(violations, "AES "+m[1]+" < FIPS minimum of 128")
			}
		}
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-006",
			ControlName: "Minimum Cryptographic Key Sizes",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "All key sizes meet FIPS minimums (RSA >= 2048, ECDSA >= 256, AES >= 128)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-006",
		ControlName: "Minimum Cryptographic Key Sizes",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Key size violations: " + strings.Join(violations, "; "),
		Timestamp:   time.Now(),
		Remediation: "Use RSA >= 2048, ECDSA >= P-256, AES >= 128. See SP 800-131A for the complete key size requirements.",
	}, nil
}

// checkSelfTest runs the FIPS cryptographic self-test and reports
// the result. This is the same self-test required by FIPS 140-2 §4.3.1
// (Power-Up Self-Test) and FIPS 140-3 §7.3.1.
func (m *FIPS140Module) checkSelfTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if err := fipscrypto.SelfTest(); err != nil {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-007",
			ControlName: "Cryptographic Self-Test",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "FIPS self-test failed: " + err.Error(),
			Timestamp:   time.Now(),
			Remediation: "Investigate the cryptographic self-test failure. The self-test covers RNG and RSA key generation.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-007",
		ControlName: "Cryptographic Self-Test",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "FIPS cryptographic self-test passed (RNG + RSA key generation)",
		Timestamp:   time.Now(),
	}, nil
}

// checkAuditLogging verifies that FIPS audit logging is enabled
// (FIPS 140-2 §4.4.4 audit requirements).
func (m *FIPS140Module) checkAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	mode := fipscrypto.GetMode()
	if mode.AuditEnabled {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-008",
			ControlName: "Cryptographic Audit Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FIPS audit logging is enabled",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-008",
		ControlName: "Cryptographic Audit Logging",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "FIPS audit logging is not enabled (cryptographic operations are not being audited)",
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS audit logging with fips.Configure(level, fips.WithAudit(true)) at startup, or set platformconfig.TLS.FIPS.AuditLogging=true",
	}, nil
}

// Dependencies returns required modules. FIPS depends on the TLS
// configuration and the crypto module.
func (m *FIPS140Module) Dependencies() []string {
	return []string{"tls", "crypto"}
}
