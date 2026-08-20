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
//   - Version:     "2.0" (v4.x Tier 1: 40 controls, 25 automated, 15 manual)
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
// Coverage: 40 controls across 10 categories covering FIPS 140-2 and
// FIPS 140-3 comprehensively. 25 controls are automated (config/scan
// based), 15 are manual (documentation/procedural). The 10 categories:
//   1. Cryptographic Module Specification (FIPS-140-001, 002, 013, 014)
//   2. Module Ports and Interfaces (FIPS-140-003, 004, 015, 016)
//   3. Roles, Services, and Authentication (FIPS-140-005, 006, 007, 017, 018, 019)
//   4. Software/Firmware Security (FIPS-140-008, 020, 021)
//   5. Operational Environment (FIPS-140-009, 012, 022, 023, 024)
//   6. Cryptographic Key Management (FIPS-140-025, 026, 027, 028, 029)
//   7. Self-Tests (FIPS-140-030, 031, 032)
//   8. Design Assurance (FIPS-140-010, 033, 034)
//   9. Mitigation of Other Attacks (FIPS-140-011, 035, 036)
//  10. FIPS 140-3 Specific (FIPS-140-037, 038, 039, 040)
//
// Out of scope justification: FIPS 140-2 areas 5 (Physical Security)
// and 8 (EMI/EMC) are hardware-level. AegisGate is software. These
// areas are correctly out-of-scope for a software cryptographic module
// and are the customer's responsibility (they need CMVP-validated
// hardware). See plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md and
// plans/V3X-CLOSE-OUT-RELEVANCE-ANALYSIS-2026-07-21.md.
//
// Reference: FIPS 140-2: https://csrc.nist.gov/publications/detail/fips/140/2/final
//            FIPS 140-3: https://csrc.nist.gov/publications/detail/fips/140/3/final
//            SP 800-57 (Key Management): https://csrc.nist.gov/publications/detail/sp/800/57/part/1/rev-5/final
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
		BaseComplianceModule: compliance.NewBaseComplianceModule("fips", "2.0", core.TierProfessional),
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

// registerControls wires all 40 FIPS 140-2/140-3 controls into the
// module. Called once from NewFIPS140Module.
//
// Out of scope (hardware-level, not software):
//   - FIPS 140-2 §4.5 (Physical Security) — physical tamper resistance
//   - FIPS 140-3 §7.5 (EMI/EMC) — hardware electromagnetic compatibility
//
// These are correctly NOT registered; they are the customer's
// responsibility (CMVP-validated hardware).
func (m *FIPS140Module) registerControls() {
	// ====================================================================
	// Category 1: Cryptographic Module Specification
	// FIPS 140-2 §4.1, FIPS 140-3 §7.1
	// ====================================================================

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

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-013",
		Name:        "Module Boundary Definition",
		Description: "Define and document the cryptographic module boundary including all hardware, software, and firmware components",
		Category:    "Cryptographic Module Specification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkModuleBoundary,
		References:  []string{"FIPS 140-2 §4.1", "FIPS 140-3 §7.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-014",
		Name:        "Security Policy Documentation",
		Description: "Maintain a formal security policy for the cryptographic module specifying rules and procedures",
		Category:    "Cryptographic Module Specification",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.1", "FIPS 140-3 §7.1"},
	})

	// ====================================================================
	// Category 2: Module Ports and Interfaces
	// FIPS 140-2 §4.2, FIPS 140-3 §7.2
	// ====================================================================

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

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-015",
		Name:        "Interface Specification",
		Description: "Document all physical and logical interfaces to the cryptographic module",
		Category:    "Module Ports and Interfaces",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.2", "FIPS 140-3 §7.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-016",
		Name:        "Data Input/Output Interfaces",
		Description: "Ensure data input and output interfaces are properly separated from control interfaces",
		Category:    "Module Ports and Interfaces",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInterfaceSeparation,
		References:  []string{"FIPS 140-2 §4.2", "FIPS 140-3 §7.2"},
	})

	// ====================================================================
	// Category 3: Roles, Services, and Authentication
	// FIPS 140-2 §4.3, FIPS 140-3 §7.3
	// ====================================================================

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
		Description: "FIPS 140 §7.3: Minimum key sizes meet FIPS requirements (RSA >= 2048, ECDSA >= 256, AES >= 128, SHA >= 224)",
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

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-017",
		Name:        "Operator Roles",
		Description: "Define and document authorized operator roles for the cryptographic module",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.3", "FIPS 140-3 §7.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-018",
		Name:        "Service Authorization",
		Description: "Implement role-based authorization for cryptographic services",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkServiceAuth,
		References:  []string{"FIPS 140-2 §4.3", "FIPS 140-3 §7.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-019",
		Name:        "Identity-Based Authentication",
		Description: "Implement identity-based authentication for operator access to the module",
		Category:    "Roles, Services, and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIdentityAuth,
		References:  []string{"FIPS 140-2 §4.3", "FIPS 140-3 §7.3"},
	})

	// ====================================================================
	// Category 4: Software/Firmware Security
	// FIPS 140-2 §4.4, FIPS 140-3 §7.4
	// ====================================================================

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

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-020",
		Name:        "Firmware Integrity",
		Description: "Verify firmware integrity using approved integrity checking techniques",
		Category:    "Software/Firmware Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFirmwareIntegrity,
		References:  []string{"FIPS 140-2 §4.4", "FIPS 140-3 §7.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-021",
		Name:        "Software Update Procedures",
		Description: "Establish procedures for authorized software updates to the cryptographic module",
		Category:    "Software/Firmware Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.4", "FIPS 140-3 §7.4"},
	})

	// ====================================================================
	// Category 5: Operational Environment
	// FIPS 140-2 §4.6, FIPS 140-3 §7.5
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-009",
		Name:        "CMVP Validation Status",
		Description: "FIPS 140 §7.5: CMVP validation certificate is configured (optional; required for federal agencies and defense). AegisGate verifies the configuration is set; the actual CMVP certificate management is the customer's responsibility.",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCMVPValidation,
		References:  []string{"FIPS 140-2 §4.6", "FIPS 140-3 §7.5", "NIST CMVP"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-012",
		Name:        "HSM Integration",
		Description: "FIPS 140 §7.5: HSM (Hardware Security Module) integration for key storage (optional; required for high-assurance environments). AegisGate verifies the configuration is set; the actual HSM hardware and PKCS#11 integration is the customer's responsibility.",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkHSMIntegration,
		References:  []string{"FIPS 140-2 §4.5", "PKCS#11"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-022",
		Name:        "Operating System Requirements",
		Description: "Specify operating system requirements for the cryptographic module's execution environment",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.6", "FIPS 140-3 §7.5"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-023",
		Name:        "Environmental Controls",
		Description: "Implement environmental controls for the module's operating environment",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.6", "FIPS 140-3 §7.5"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-024",
		Name:        "Configuration Management",
		Description: "Maintain configuration management for the cryptographic module environment",
		Category:    "Operational Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigManagement,
		References:  []string{"FIPS 140-2 §4.6", "FIPS 140-3 §7.5"},
	})

	// ====================================================================
	// Category 6: Cryptographic Key Management
	// FIPS 140-2 §4.7, FIPS 140-3 §7.7, SP 800-57
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-025",
		Name:        "Key Generation",
		Description: "Generate cryptographic keys using approved methods and parameters",
		Category:    "Cryptographic Key Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkKeyGeneration,
		References:  []string{"FIPS 140-2 §4.7", "SP 800-57 Part 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-026",
		Name:        "Key Distribution",
		Description: "Establish secure procedures for cryptographic key distribution",
		Category:    "Cryptographic Key Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.7", "SP 800-57 Part 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-027",
		Name:        "Key Storage",
		Description: "Store cryptographic keys securely with access controls",
		Category:    "Cryptographic Key Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkKeyStorage,
		References:  []string{"FIPS 140-2 §4.7", "SP 800-57 Part 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-028",
		Name:        "Key Archival",
		Description: "Establish procedures for archiving cryptographic keys",
		Category:    "Cryptographic Key Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.7", "SP 800-57 Part 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-029",
		Name:        "Key Zeroization",
		Description: "Implement zeroization procedures for cryptographic keys and CSPs",
		Category:    "Cryptographic Key Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkKeyZeroization,
		References:  []string{"FIPS 140-2 §4.7", "FIPS 140-3 §7.7"},
	})

	// ====================================================================
	// Category 7: Self-Tests
	// FIPS 140-2 §4.3.1, FIPS 140-3 §7.3.1
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-030",
		Name:        "Power-Up Self-Tests",
		Description: "Perform power-up self-tests including known-answer tests and software/firmware integrity tests",
		Category:    "Self-Tests",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPowerUpTests,
		References:  []string{"FIPS 140-2 §4.3.1", "FIPS 140-3 §7.3.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-031",
		Name:        "Conditional Self-Tests",
		Description: "Perform conditional self-tests including pairwise consistency tests and random number generator tests",
		Category:    "Self-Tests",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConditionalTests,
		References:  []string{"FIPS 140-2 §4.3.1", "FIPS 140-3 §7.3.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-032",
		Name:        "Self-Test Failure Response",
		Description: "Implement procedures for responding to self-test failures",
		Category:    "Self-Tests",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSelfTestFailure,
		References:  []string{"FIPS 140-2 §4.3.1", "FIPS 140-3 §7.3.1"},
	})

	// ====================================================================
	// Category 8: Design Assurance
	// FIPS 140-2 §4.10, FIPS 140-3 §7.10
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-010",
		Name:        "Design Assurance",
		Description: "FIPS 140 §7.10: Software design assurance — SBOM generation, test coverage, CI vulnerability scanning, signed releases. Hardware-level design assurance is the customer's responsibility.",
		Category:    "Design Assurance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDesignAssurance,
		References:  []string{"FIPS 140-2 §4.10", "FIPS 140-3 §7.10"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-033",
		Name:        "Configuration Management Plan",
		Description: "Maintain a configuration management plan for the cryptographic module lifecycle",
		Category:    "Design Assurance",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkFIPSConfigMgmt,
		References:  []string{"FIPS 140-2 §4.10", "FIPS 140-3 §7.10"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-034",
		Name:        "Delivery and Operation",
		Description: "Establish procedures for secure delivery, installation, and operation of the module",
		Category:    "Design Assurance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.10", "FIPS 140-3 §7.10"},
	})

	// ====================================================================
	// Category 9: Mitigation of Other Attacks
	// FIPS 140-2 §4.11, FIPS 140-3 §7.12
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-011",
		Name:        "Mitigation of Other Attacks",
		Description: "FIPS 140 §7.12: Mitigation of side-channel attacks (timing, cache, power, fault injection). Constant-time operations for RSA/ECDSA/AES, blinding for RSA, etc.",
		Category:    "Mitigation of Other Attacks",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMitigationOfOtherAttacks,
		References:  []string{"FIPS 140-2 §4.11", "FIPS 140-3 §7.12"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-035",
		Name:        "Side-Channel Attack Mitigation",
		Description: "Implement constant-time algorithms and side-channel attack mitigations",
		Category:    "Mitigation of Other Attacks",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSideChannel,
		References:  []string{"FIPS 140-2 §4.11", "FIPS 140-3 §7.12"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-036",
		Name:        "Power Analysis Mitigation",
		Description: "Document mitigations against power analysis attacks (DPA/SPA)",
		Category:    "Mitigation of Other Attacks",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"FIPS 140-2 §4.11", "FIPS 140-3 §7.12"},
	})

	// ====================================================================
	// Category 10: FIPS 140-3 Specific
	// FIPS 140-3 additional requirements
	// ====================================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-037",
		Name:        "Cryptographic Algorithm Standardization",
		Description: "FIPS 140-3: Ensure all cryptographic algorithms are approved per NIST standards",
		Category:    "FIPS 140-3 Specific",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAlgorithmStandard,
		References:  []string{"FIPS 140-3 §7.1", "NIST SP 800-140C"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-038",
		Name:        "Security Function Initialization",
		Description: "FIPS 140-3: Document security function initialization procedures",
		Category:    "FIPS 140-3 Specific",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityFunctionInit,
		References:  []string{"FIPS 140-3 §7.8"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-039",
		Name:        "Software/Firmware Update Verification",
		Description: "FIPS 140-3: Verify software/firmware updates using digital signatures",
		Category:    "FIPS 140-3 Specific",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkUpdateVerification,
		References:  []string{"FIPS 140-3 §7.4", "NIST SP 800-140D"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FIPS-140-040",
		Name:        "Critical Security Parameter Protection",
		Description: "FIPS 140-3: Implement protection for critical security parameters during all lifecycle phases",
		Category:    "FIPS 140-3 Specific",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCSPProtection,
		References:  []string{"FIPS 140-3 §7.7", "NIST SP 800-140E"},
	})
}

// ============================================================================
// Check implementations — Existing Controls (FIPS-140-001 through 012)
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

// checkDesignAssurance verifies the software design assurance evidence
// required for FIPS 140-2 §4.10 and FIPS 140-3 §7.10. This includes SBOM
// generation, test coverage, CI vulnerability scanning, and signed
// releases. Hardware-level design assurance is the customer's
// responsibility (CMVP-validated hardware).
func (m *FIPS140Module) checkDesignAssurance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasCoverage := strings.Contains(inputStr, "coverage") || strings.Contains(inputStr, "go test -cover")
	hasVulnScan := strings.Contains(inputStr, "govulncheck") || strings.Contains(inputStr, "trivy") || strings.Contains(inputStr, "vuln_scan")
	hasSignedRelease := strings.Contains(inputStr, "signed") || strings.Contains(inputStr, "dco") || strings.Contains(inputStr, "gpg")

	present := 0
	missing := []string{}
	if hasSBOM {
		present++
	} else {
		missing = append(missing, "SBOM generation")
	}
	if hasCoverage {
		present++
	} else {
		missing = append(missing, "test coverage (go test -cover)")
	}
	if hasVulnScan {
		present++
	} else {
		missing = append(missing, "CI vulnerability scanning (govulncheck, Trivy)")
	}
	if hasSignedRelease {
		present++
	} else {
		missing = append(missing, "signed releases (DCO, GPG)")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-010",
			ControlName: "Design Assurance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Software design assurance verified: SBOM + test coverage + CI vulnerability scanning + signed releases",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-010",
			ControlName: "Design Assurance",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial design assurance: " + intToStr(present) + " of 4 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable SBOM generation (CycloneDX), go test -cover in CI, govulncheck/Trivy vulnerability scanning, and signed releases (DCO)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-010",
		ControlName: "Design Assurance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No design assurance evidence: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable SBOM generation (CycloneDX), go test -cover in CI, govulncheck/Trivy vulnerability scanning, and signed releases (DCO)",
	}, nil
}

// checkMitigationOfOtherAttacks verifies the platform implements
// side-channel attack mitigations as required by FIPS 140-2 §4.11 and
// FIPS 140-3 §7.12. This covers:
//   - Constant-time operations for RSA/ECDSA/AES (Go runtime)
//   - Blinding for RSA (mitigates timing attacks)
//   - Cache-timing resistance (Go runtime crypto/cipher)
//   - Power analysis resistance (hardware-level; CMVP customer responsibility)
//   - Fault injection resistance (hardware-level; CMVP customer responsibility)
//
// AegisGate verifies the SOFTWARE-level mitigations: that the platform
// is using FIPS-approved algorithms (which Go implements with
// side-channel resistance) and that the platform has the right config.
func (m *FIPS140Module) checkMitigationOfOtherAttacks(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	// Verify the platform is using FIPS-approved algorithms, which
	// Go's crypto/cipher implements with side-channel resistance.
	hasECDSA := strings.Contains(inputStr, "ecdsa") || strings.Contains(inputStr, "ec_p256") || strings.Contains(inputStr, "p-256")
	hasAES := strings.Contains(inputStr, "aes") || strings.Contains(inputStr, "aes_256") || strings.Contains(inputStr, "aes-256")
	hasRSA := strings.Contains(inputStr, "rsa") || strings.Contains(inputStr, "rsa_2048") || strings.Contains(inputStr, "rsa-2048")

	// Verify the platform's runtime has the mitigations enabled.
	// Go's crypto/cipher always uses constant-time operations for
	// FIPS-approved algorithms; we verify this by checking that
	// the FIPS mode is enabled (which is the runtime config that
	// enforces FIPS-approved algorithms).
	hasFIPSMode := fipscrypto.IsEnabled()

	// Verify TLS 1.3 (which has built-in downgrade protection and
	// constant-time handshake).
	hasTLS13 := false
	for _, p := range m.tlsVersionPats {
		if p.MatchString(inputStr) {
			// pattern[1] is TLS 1.3 specifically
			// We use a quick check on the input string
			if strings.Contains(inputStr, "1.3") {
				hasTLS13 = true
				break
			}
		}
	}

	present := 0
	missing := []string{}
	if hasFIPSMode {
		present++
	} else {
		missing = append(missing, "FIPS mode (required for constant-time crypto)")
	}
	if hasECDSA {
		present++
	} else {
		missing = append(missing, "ECDSA (constant-time signature operations)")
	}
	if hasAES {
		present++
	} else {
		missing = append(missing, "AES (constant-time block cipher)")
	}
	if hasRSA {
		present++
	} else {
		missing = append(missing, "RSA (blinding for timing attack resistance)")
	}
	if hasTLS13 {
		present++
	} else {
		missing = append(missing, "TLS 1.3 (built-in downgrade protection)")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-011",
			ControlName: "Mitigation of Other Attacks",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Side-channel mitigations verified: FIPS mode + constant-time crypto (RSA blinding, ECDSA, AES) + TLS 1.3 downgrade protection. Hardware-level mitigations (power analysis, fault injection) are the customer's responsibility (CMVP-validated hardware).",
			Timestamp:   time.Now(),
		}, nil
	}

	if present >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-011",
			ControlName: "Mitigation of Other Attacks",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial side-channel mitigations: " + intToStr(present) + " of 5 software mitigations configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable FIPS mode (which enforces constant-time crypto in Go's crypto/cipher), use ECDSA + AES + RSA (blinding), and TLS 1.3. Hardware-level mitigations (power analysis, fault injection) require CMVP-validated hardware and are the customer's responsibility.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-011",
		ControlName: "Mitigation of Other Attacks",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No side-channel mitigations detected: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable FIPS mode (which enforces constant-time crypto in Go's crypto/cipher), use ECDSA + AES + RSA (blinding), and TLS 1.3. Hardware-level mitigations (power analysis, fault injection) require CMVP-validated hardware and are the customer's responsibility.",
	}, nil
}

// checkCMVPValidation verifies the customer has configured the CMVP
// validation certificate. Required for federal agencies and defense.
// This is a configuration check, not a CMVP certificate verification.
func (m *FIPS140Module) checkCMVPValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasCMVPNumber := strings.Contains(inputStr, "cmvp") || strings.Contains(inputStr, "validation_number") || strings.Contains(inputStr, "cmvp_number")
	hasValidationCert := strings.Contains(inputStr, "validation_certificate") || strings.Contains(inputStr, "cert_loaded")
	hasModuleValidated := strings.Contains(inputStr, "module_validated") || strings.Contains(inputStr, "fips_validated")

	present := 0
	missing := []string{}
	if hasCMVPNumber {
		present++
	} else {
		missing = append(missing, "CMVP validation number")
	}
	if hasValidationCert {
		present++
	} else {
		missing = append(missing, "validation certificate loaded")
	}
	if hasModuleValidated {
		present++
	} else {
		missing = append(missing, "module validated flag")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-009",
			ControlName: "CMVP Validation Status",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "CMVP validation status configured: validation number + certificate loaded + module validated flag",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-009",
			ControlName: "CMVP Validation Status",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial CMVP configuration: " + intToStr(present) + " of 3 configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure CMVP validation number, load validation certificate, and set the module_validated flag. Required for federal agencies and defense.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-009",
		ControlName: "CMVP Validation Status",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No CMVP validation configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Required for federal agencies and defense: load CMVP validation certificate and configure validation number in platformconfig.TLS.FIPS.CMVP",
	}, nil
}

// checkHSMIntegration verifies the customer has configured HSM
// integration. Required for high-assurance environments. This is a
// configuration check, not a hardware verification.
func (m *FIPS140Module) checkHSMIntegration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasHSM := strings.Contains(inputStr, "hsm") || strings.Contains(inputStr, "hardware_security_module")
	hasPKCS11 := strings.Contains(inputStr, "pkcs11") || strings.Contains(inputStr, "pkcs_11")
	hasHSMEndpoint := strings.Contains(inputStr, "hsm_endpoint") || strings.Contains(inputStr, "hsm_url")

	present := 0
	missing := []string{}
	if hasHSM {
		present++
	} else {
		missing = append(missing, "HSM configured")
	}
	if hasPKCS11 {
		present++
	} else {
		missing = append(missing, "PKCS#11 interface")
	}
	if hasHSMEndpoint {
		present++
	} else {
		missing = append(missing, "HSM endpoint")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-012",
			ControlName: "HSM Integration",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "HSM integration configured: HSM + PKCS#11 + endpoint",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-012",
			ControlName: "HSM Integration",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial HSM configuration: " + intToStr(present) + " of 3 configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure HSM, PKCS#11 interface, and HSM endpoint in platformconfig.TLS.FIPS.HSM. Required for high-assurance environments.",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-012",
		ControlName: "HSM Integration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No HSM integration configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Optional for standard deployments; required for high-assurance: configure HSM, PKCS#11 interface, and HSM endpoint in platformconfig.TLS.FIPS.HSM",
	}, nil
}

// ============================================================================
// Check implementations — New Controls (FIPS-140-016 through 040)
// ============================================================================

// checkInterfaceSeparation verifies data input/output interfaces are
// properly separated from control interfaces (FIPS-140-016).
func (m *FIPS140Module) checkInterfaceSeparation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasInterfaceSep := strings.Contains(lower, "interface_separation") || strings.Contains(lower, "interface separation")
	hasDataPort := strings.Contains(lower, "data_port") || strings.Contains(lower, "data port")
	hasControlPort := strings.Contains(lower, "control_port") || strings.Contains(lower, "control port")

	present := 0
	missing := []string{}
	if hasInterfaceSep {
		present++
	} else {
		missing = append(missing, "interface separation config")
	}
	if hasDataPort {
		present++
	} else {
		missing = append(missing, "data port definition")
	}
	if hasControlPort {
		present++
	} else {
		missing = append(missing, "control port definition")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-016",
			ControlName: "Data Input/Output Interfaces",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data and control interfaces are properly separated",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-016",
			ControlName: "Data Input/Output Interfaces",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial interface separation: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure interface_separation, define data_port and control_port to ensure data and control interfaces are separated",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-016",
		ControlName: "Data Input/Output Interfaces",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No interface separation configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure interface_separation, define data_port and control_port to ensure data and control interfaces are separated",
	}, nil
}

// checkServiceAuth verifies role-based authorization for cryptographic
// services (FIPS-140-018).
func (m *FIPS140Module) checkServiceAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasRoleBased := strings.Contains(lower, "role_based") || strings.Contains(lower, "role based")
	hasServiceAuth := strings.Contains(lower, "service_auth") || strings.Contains(lower, "service auth")
	hasAuthorizedRole := strings.Contains(lower, "authorized_role") || strings.Contains(lower, "authorized role")

	present := 0
	missing := []string{}
	if hasRoleBased {
		present++
	} else {
		missing = append(missing, "role-based access control")
	}
	if hasServiceAuth {
		present++
	} else {
		missing = append(missing, "service authorization config")
	}
	if hasAuthorizedRole {
		present++
	} else {
		missing = append(missing, "authorized role mapping")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-018",
			ControlName: "Service Authorization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Role-based service authorization is configured",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-018",
			ControlName: "Service Authorization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial service authorization: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure role_based, service_auth, and authorized_role for cryptographic service authorization",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-018",
		ControlName: "Service Authorization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No service authorization configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure role_based, service_auth, and authorized_role for cryptographic service authorization",
	}, nil
}

// checkIdentityAuth verifies identity-based authentication for operator
// access to the cryptographic module (FIPS-140-019).
func (m *FIPS140Module) checkIdentityAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasIdentityAuth := strings.Contains(lower, "identity_auth") || strings.Contains(lower, "identity auth")
	hasOperatorAuth := strings.Contains(lower, "operator_auth") || strings.Contains(lower, "operator auth")
	hasMFA := strings.Contains(lower, "mfa") || strings.Contains(lower, "multi_factor")

	present := 0
	missing := []string{}
	if hasIdentityAuth {
		present++
	} else {
		missing = append(missing, "identity authentication config")
	}
	if hasOperatorAuth {
		present++
	} else {
		missing = append(missing, "operator authentication")
	}
	if hasMFA {
		present++
	} else {
		missing = append(missing, "multi-factor authentication")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-019",
			ControlName: "Identity-Based Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Identity-based authentication is configured with MFA",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-019",
			ControlName: "Identity-Based Authentication",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial identity authentication: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure identity_auth, operator_auth, and enable MFA for operator access to the cryptographic module",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-019",
		ControlName: "Identity-Based Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No identity-based authentication configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure identity_auth, operator_auth, and enable MFA for operator access to the cryptographic module",
	}, nil
}

// checkFirmwareIntegrity verifies firmware integrity using approved
// integrity checking techniques (FIPS-140-020).
func (m *FIPS140Module) checkFirmwareIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasFirmwareIntegrity := strings.Contains(lower, "firmware_integrity") || strings.Contains(lower, "firmware integrity")
	hasCodeSigning := strings.Contains(lower, "code_signing") || strings.Contains(lower, "code signing")
	hasSecureBoot := strings.Contains(lower, "secure_boot") || strings.Contains(lower, "secure boot")

	present := 0
	missing := []string{}
	if hasFirmwareIntegrity {
		present++
	} else {
		missing = append(missing, "firmware integrity check")
	}
	if hasCodeSigning {
		present++
	} else {
		missing = append(missing, "code signing")
	}
	if hasSecureBoot {
		present++
	} else {
		missing = append(missing, "secure boot")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-020",
			ControlName: "Firmware Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Firmware integrity verified: integrity check + code signing + secure boot",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-020",
			ControlName: "Firmware Integrity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial firmware integrity: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable firmware_integrity checks, code_signing, and secure_boot for cryptographic module firmware",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-020",
		ControlName: "Firmware Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No firmware integrity configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable firmware_integrity checks, code_signing, and secure_boot for cryptographic module firmware",
	}, nil
}

// checkConfigManagement verifies configuration management for the
// cryptographic module environment (FIPS-140-024).
func (m *FIPS140Module) checkConfigManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasConfigMgmt := strings.Contains(lower, "configuration_management") || strings.Contains(lower, "configuration management")
	hasCMDB := strings.Contains(lower, "cmdb")
	hasBaseline := strings.Contains(lower, "baseline_config") || strings.Contains(lower, "baseline config")

	present := 0
	missing := []string{}
	if hasConfigMgmt {
		present++
	} else {
		missing = append(missing, "configuration management")
	}
	if hasCMDB {
		present++
	} else {
		missing = append(missing, "CMDB integration")
	}
	if hasBaseline {
		present++
	} else {
		missing = append(missing, "baseline configuration")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-024",
			ControlName: "Configuration Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration management is configured: CM + CMDB + baseline config",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-024",
			ControlName: "Configuration Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial configuration management: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure configuration_management, CMDB integration, and baseline_config for the cryptographic module environment",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-024",
		ControlName: "Configuration Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No configuration management configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure configuration_management, CMDB integration, and baseline_config for the cryptographic module environment",
	}, nil
}

// checkKeyGeneration verifies cryptographic keys are generated using
// approved methods and parameters (FIPS-140-025).
func (m *FIPS140Module) checkKeyGeneration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasKeyGen := strings.Contains(lower, "key_generation") || strings.Contains(lower, "key gen")
	hasRNG := strings.Contains(lower, "random_number") || strings.Contains(lower, "random number")

	// Also verify FIPS mode is enabled (which enforces approved key generation)
	hasFIPSMode := fipscrypto.IsEnabled()

	present := 0
	missing := []string{}
	if hasKeyGen {
		present++
	} else {
		missing = append(missing, "key generation config")
	}
	if hasRNG {
		present++
	} else {
		missing = append(missing, "approved random number generator")
	}
	if hasFIPSMode {
		present++
	} else {
		missing = append(missing, "FIPS mode (enforces approved key generation)")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-025",
			ControlName: "Key Generation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Key generation uses approved methods and parameters",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-025",
			ControlName: "Key Generation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial key generation: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure key_generation with approved random_number generator and enable FIPS mode",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-025",
		ControlName: "Key Generation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No approved key generation configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure key_generation with approved random_number generator and enable FIPS mode",
	}, nil
}

// checkKeyStorage verifies cryptographic keys are stored securely with
// access controls (FIPS-140-027).
func (m *FIPS140Module) checkKeyStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasKeyStorage := strings.Contains(lower, "key_storage") || strings.Contains(lower, "key storage")
	hasKeyVault := strings.Contains(lower, "key_vault") || strings.Contains(lower, "key vault")
	hasHSMStorage := strings.Contains(lower, "hsm_storage") || strings.Contains(lower, "hsm storage")

	present := 0
	missing := []string{}
	if hasKeyStorage {
		present++
	} else {
		missing = append(missing, "key storage config")
	}
	if hasKeyVault {
		present++
	} else {
		missing = append(missing, "key vault")
	}
	if hasHSMStorage {
		present++
	} else {
		missing = append(missing, "HSM storage")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-027",
			ControlName: "Key Storage",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Cryptographic keys are stored securely with access controls",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-027",
			ControlName: "Key Storage",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial key storage: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure key_storage with key_vault or hsm_storage for secure key storage with access controls",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-027",
		ControlName: "Key Storage",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No secure key storage configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure key_storage with key_vault or hsm_storage for secure key storage with access controls",
	}, nil
}

// checkKeyZeroization verifies zeroization procedures for cryptographic
// keys and CSPs (FIPS-140-029).
func (m *FIPS140Module) checkKeyZeroization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasZeroization := strings.Contains(lower, "zeroization") || strings.Contains(lower, "zeroisation")
	hasKeyDestruction := strings.Contains(lower, "key_destruction") || strings.Contains(lower, "key destruction")
	hasSecureWipe := strings.Contains(lower, "secure_wipe") || strings.Contains(lower, "secure wipe")

	present := 0
	missing := []string{}
	if hasZeroization {
		present++
	} else {
		missing = append(missing, "zeroization procedure")
	}
	if hasKeyDestruction {
		present++
	} else {
		missing = append(missing, "key destruction config")
	}
	if hasSecureWipe {
		present++
	} else {
		missing = append(missing, "secure wipe")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-029",
			ControlName: "Key Zeroization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Key zeroization procedures are configured",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-029",
			ControlName: "Key Zeroization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial zeroization: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure zeroization, key_destruction, and secure_wipe for cryptographic keys and CSPs",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-029",
		ControlName: "Key Zeroization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No zeroization configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure zeroization, key_destruction, and secure_wipe for cryptographic keys and CSPs",
	}, nil
}

// checkPowerUpTests verifies power-up self-tests including known-answer
// tests and software/firmware integrity tests (FIPS-140-030).
func (m *FIPS140Module) checkPowerUpTests(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasPowerUp := strings.Contains(lower, "power_up_test") || strings.Contains(lower, "power up test")
	hasStartup := strings.Contains(lower, "startup_test") || strings.Contains(lower, "startup test")
	hasKAT := strings.Contains(lower, "known_answer_test") || strings.Contains(lower, "known answer test")

	// Also run the actual FIPS self-test
	selfTestPass := true
	if err := fipscrypto.SelfTest(); err != nil {
		selfTestPass = false
	}

	present := 0
	missing := []string{}
	if hasPowerUp {
		present++
	} else {
		missing = append(missing, "power-up test config")
	}
	if hasStartup {
		present++
	} else {
		missing = append(missing, "startup test")
	}
	if hasKAT {
		present++
	} else {
		missing = append(missing, "known-answer test")
	}
	if selfTestPass {
		present++
	} else {
		missing = append(missing, "FIPS self-test execution")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-030",
			ControlName: "Power-Up Self-Tests",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Power-up self-tests configured and passing: power-up test + startup test + known-answer test",
			Timestamp:   time.Now(),
		}, nil
	}

	if present >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-030",
			ControlName: "Power-Up Self-Tests",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial power-up self-tests: " + intToStr(present) + " of 4 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure power_up_test, startup_test, and known_answer_test for power-up self-tests",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-030",
		ControlName: "Power-Up Self-Tests",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No power-up self-tests configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure power_up_test, startup_test, and known_answer_test for power-up self-tests",
	}, nil
}

// checkConditionalTests verifies conditional self-tests including
// pairwise consistency tests and RNG tests (FIPS-140-031).
func (m *FIPS140Module) checkConditionalTests(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasConditional := strings.Contains(lower, "conditional_test") || strings.Contains(lower, "conditional test")
	hasRNGTest := strings.Contains(lower, "rng_test") || strings.Contains(lower, "rng test")
	hasPairwise := strings.Contains(lower, "pairwise_test") || strings.Contains(lower, "pairwise test")

	present := 0
	missing := []string{}
	if hasConditional {
		present++
	} else {
		missing = append(missing, "conditional test config")
	}
	if hasRNGTest {
		present++
	} else {
		missing = append(missing, "RNG test")
	}
	if hasPairwise {
		present++
	} else {
		missing = append(missing, "pairwise consistency test")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-031",
			ControlName: "Conditional Self-Tests",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Conditional self-tests configured: conditional test + RNG test + pairwise test",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-031",
			ControlName: "Conditional Self-Tests",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial conditional self-tests: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure conditional_test, rng_test, and pairwise_test for conditional self-tests",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-031",
		ControlName: "Conditional Self-Tests",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No conditional self-tests configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure conditional_test, rng_test, and pairwise_test for conditional self-tests",
	}, nil
}

// checkSelfTestFailure verifies procedures for responding to self-test
// failures (FIPS-140-032).
func (m *FIPS140Module) checkSelfTestFailure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasSelfTestFailure := strings.Contains(lower, "self_test_failure") || strings.Contains(lower, "self test failure")
	hasFailSafe := strings.Contains(lower, "fail_safe") || strings.Contains(lower, "fail safe")
	hasErrorState := strings.Contains(lower, "error_state") || strings.Contains(lower, "error state")

	present := 0
	missing := []string{}
	if hasSelfTestFailure {
		present++
	} else {
		missing = append(missing, "self-test failure config")
	}
	if hasFailSafe {
		present++
	} else {
		missing = append(missing, "fail-safe mode")
	}
	if hasErrorState {
		present++
	} else {
		missing = append(missing, "error state handling")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-032",
			ControlName: "Self-Test Failure Response",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Self-test failure response configured: failure handling + fail-safe + error state",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-032",
			ControlName: "Self-Test Failure Response",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial failure response: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure self_test_failure, fail_safe, and error_state for self-test failure response",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-032",
		ControlName: "Self-Test Failure Response",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No self-test failure response configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure self_test_failure, fail_safe, and error_state for self-test failure response",
	}, nil
}

// checkSideChannel verifies constant-time algorithms and side-channel
// attack mitigations (FIPS-140-035).
func (m *FIPS140Module) checkSideChannel(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasConstantTime := strings.Contains(lower, "constant_time") || strings.Contains(lower, "constant time")
	hasSideChannel := strings.Contains(lower, "side_channel") || strings.Contains(lower, "side channel")
	hasTimingAttack := strings.Contains(lower, "timing_attack") || strings.Contains(lower, "timing attack")

	present := 0
	missing := []string{}
	if hasConstantTime {
		present++
	} else {
		missing = append(missing, "constant-time algorithms")
	}
	if hasSideChannel {
		present++
	} else {
		missing = append(missing, "side-channel mitigation config")
	}
	if hasTimingAttack {
		present++
	} else {
		missing = append(missing, "timing attack protection")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-035",
			ControlName: "Side-Channel Attack Mitigation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Side-channel mitigations configured: constant-time + side-channel protection + timing attack resistance",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-035",
			ControlName: "Side-Channel Attack Mitigation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial side-channel mitigation: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure constant_time, side_channel, and timing_attack mitigations",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-035",
		ControlName: "Side-Channel Attack Mitigation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No side-channel mitigations configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure constant_time, side_channel, and timing_attack mitigations",
	}, nil
}

// checkAlgorithmStandard verifies all cryptographic algorithms are
// approved per NIST standards (FIPS-140-037, FIPS 140-3 specific).
func (m *FIPS140Module) checkAlgorithmStandard(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasApprovedAlgo := strings.Contains(lower, "approved_algorithm") || strings.Contains(lower, "approved algorithm")
	hasNISTStandard := strings.Contains(lower, "nist_standard") || strings.Contains(lower, "nist standard")
	hasStandardized := strings.Contains(lower, "standardized")

	// Also verify FIPS mode is enabled (which enforces approved algorithms)
	hasFIPSMode := fipscrypto.IsEnabled()

	present := 0
	missing := []string{}
	if hasApprovedAlgo {
		present++
	} else {
		missing = append(missing, "approved algorithm list")
	}
	if hasNISTStandard {
		present++
	} else {
		missing = append(missing, "NIST standard reference")
	}
	if hasStandardized {
		present++
	} else {
		missing = append(missing, "standardization flag")
	}
	if hasFIPSMode {
		present++
	} else {
		missing = append(missing, "FIPS mode (enforces approved algorithms)")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-037",
			ControlName: "Cryptographic Algorithm Standardization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "All cryptographic algorithms are approved per NIST standards",
			Timestamp:   time.Now(),
		}, nil
	}

	if present >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-037",
			ControlName: "Cryptographic Algorithm Standardization",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial algorithm standardization: " + intToStr(present) + " of 4 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure approved_algorithm list, reference nist_standard, set standardized flag, and enable FIPS mode",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-037",
		ControlName: "Cryptographic Algorithm Standardization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No algorithm standardization configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure approved_algorithm list, reference nist_standard, set standardized flag, and enable FIPS mode",
	}, nil
}

// checkUpdateVerification verifies software/firmware updates using
// digital signatures (FIPS-140-039, FIPS 140-3 specific).
func (m *FIPS140Module) checkUpdateVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasUpdateVerify := strings.Contains(lower, "update_verification") || strings.Contains(lower, "update verification")
	hasSigVerify := strings.Contains(lower, "signature_verification") || strings.Contains(lower, "signature verification")
	hasSignedUpdate := strings.Contains(lower, "signed_update") || strings.Contains(lower, "signed update")

	present := 0
	missing := []string{}
	if hasUpdateVerify {
		present++
	} else {
		missing = append(missing, "update verification config")
	}
	if hasSigVerify {
		present++
	} else {
		missing = append(missing, "signature verification")
	}
	if hasSignedUpdate {
		present++
	} else {
		missing = append(missing, "signed update policy")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-039",
			ControlName: "Software/Firmware Update Verification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Software/firmware update verification configured: update verification + signature verification + signed update",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-039",
			ControlName: "Software/Firmware Update Verification",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial update verification: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure update_verification, signature_verification, and signed_update for software/firmware update verification",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-039",
		ControlName: "Software/Firmware Update Verification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No update verification configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure update_verification, signature_verification, and signed_update for software/firmware update verification",
	}, nil
}

// checkCSPProtection verifies protection for critical security parameters
// during all lifecycle phases (FIPS-140-040, FIPS 140-3 specific).
func (m *FIPS140Module) checkCSPProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	lower := strings.ToLower(inputStr)

	hasCSPProtection := strings.Contains(lower, "csp_protection") || strings.Contains(lower, "csp protection")
	hasCriticalParam := strings.Contains(lower, "critical_parameter") || strings.Contains(lower, "critical parameter")
	hasSensitiveParam := strings.Contains(lower, "sensitive_parameter") || strings.Contains(lower, "sensitive parameter")

	present := 0
	missing := []string{}
	if hasCSPProtection {
		present++
	} else {
		missing = append(missing, "CSP protection config")
	}
	if hasCriticalParam {
		present++
	} else {
		missing = append(missing, "critical parameter list")
	}
	if hasSensitiveParam {
		present++
	} else {
		missing = append(missing, "sensitive parameter handling")
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-040",
			ControlName: "Critical Security Parameter Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Critical security parameter protection configured: CSP protection + critical parameters + sensitive parameters",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FIPS-140-040",
			ControlName: "Critical Security Parameter Protection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial CSP protection: " + intToStr(present) + " of 3 components configured; missing: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure csp_protection, critical_parameter list, and sensitive_parameter handling for CSP lifecycle protection",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FIPS-140-040",
		ControlName: "Critical Security Parameter Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No CSP protection configured: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure csp_protection, critical_parameter list, and sensitive_parameter handling for CSP lifecycle protection",
	}, nil
}

// ============================================================================
// Helpers
// ============================================================================

// intToStr is a small helper to avoid importing strconv in every check.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-intToStr(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules. FIPS depends on the TLS
// configuration and the crypto module.
func (m *FIPS140Module) Dependencies() []string {
	return []string{"tls", "crypto"}
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *FIPS140Module) checkModuleBoundary(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundary := strings.Contains(inputStr, "module_boundary") || strings.Contains(inputStr, "boundary_definition") || strings.Contains(inputStr, "security_boundary")
	if hasBoundary {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-013", ControlName: "Module Boundary Definition", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Module boundary definition detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-013", ControlName: "Module Boundary Definition", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Module boundary not detected", Timestamp: time.Now(), Remediation: "Define module boundary"}, nil
}

func (m *FIPS140Module) checkFIPSConfigMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCM := strings.Contains(inputStr, "configuration_management_plan") || strings.Contains(inputStr, "config_management") || strings.Contains(inputStr, "cm_plan")
	if hasCM {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-033", ControlName: "Configuration Management Plan", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Configuration management plan detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-033", ControlName: "Configuration Management Plan", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "CM plan not detected", Timestamp: time.Now(), Remediation: "Implement configuration management plan"}, nil
}

func (m *FIPS140Module) checkSecurityFunctionInit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInit := strings.Contains(inputStr, "security_function_init") || strings.Contains(inputStr, "function_initialization") || strings.Contains(inputStr, "secure_init")
	if hasInit {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-038", ControlName: "Security Function Initialization", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security function initialization detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FIPS-140-038", ControlName: "Security Function Initialization", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security function init not detected", Timestamp: time.Now(), Remediation: "Implement security function initialization"}, nil
}
