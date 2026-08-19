// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX Compliance Module
// =========================================================================
//
// TISAX (Trusted Information Security Assessment Exchange) AL2 is the
// European automotive industry's information security assessment standard,
// based on ISO 27001 but tailored for the automotive supply chain.
//
// AegisGate implements TISAX as a licensed add-on module. This is the
// 12th compliance framework in the AegisGate roadmap (HIPAA, PCI-DSS,
// EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP, ISO 27001, NIST CSF,
// OWASP, CSA STAR, TISAX).
//
// Module metadata:
//   - Framework:   "tisax"
//   - Version:     "1.0"
//   - Required tier: Enterprise (gated via pkg/compliance/gating.go)
//   - Monthly price: $599/mo (founder-locked 2026-07-22)
//   - Baseline:    TISAX AL2 (ISO 27001-based, automotive supply chain)
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT an accredited TISAX audit provider. The TISAX module
//   generates the technical evidence (audit logs, IOC store, trust framework
//   attestations, compliance scan results) that a customer uses in their
//   TISAX assessment package. The TISAX assessment and label issuance is
//   the customer's responsibility through an accredited TISAX audit provider
//   (e.g., TÜV, DEKRA).
//
// Architecture (family-based file structure):
//   - tisax.go:      module wiring, registerControls, Dependencies, pattern caches
//   - is_or.go:      Information Security + Organization & Risk families
//   - dsc_pp_dp.go:  Data & System Controls + Privacy & Personnel + Development & Prototyping
//   - tisax_test.go: unit tests
//   - doc.go:        package documentation
//
// Design: TISAX controls are mapped to existing AegisGate modules
// (ISO 27001, SOC 2, FIPS 140, IOC store, Trust Framework) to avoid
// duplicating the implementation. Each TISAX control either:
//   1. Is AUTOMATED and reuses an existing AegisGate scanner output
//      (e.g., TISAX IS-01 Information Security Policy maps to ISO 27001 A.5.1)
//   2. Is EVIDENCE-MAPPED and AegisGate generates the evidence
//      artifact (audit log, IOC, attestation) the customer attaches
//      to their TISAX assessment package
//
// Reference: TISAX v6 AL2 ISA Catalogue
//            https://enx.com/tisax
//            ISO 27001:2022
//
// =========================================================================

package tisax

import (
	"regexp"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// TISAXModule implements the TISAX AL2 compliance framework as a licensed
// add-on. It embeds *compliance.BaseComplianceModule which provides
// RegisterControl, Controls, Framework, Version, CheckAll, and
// GenerateAssessment out of the box.
type TISAXModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	encryptionPatterns []*regexp.Regexp
	auditPatterns      []*regexp.Regexp
	accessPatterns     []*regexp.Regexp
}

// NewTISAXModule creates a new TISAX compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Enterprise tier via
// pkg/compliance/gating.go (license.ModuleTISAX entry).
func NewTISAXModule() *TISAXModule {
	m := &TISAXModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("tisax", "1.0", core.TierEnterprise),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *TISAXModule) initPatterns() {
	m.encryptionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)encryption[_ ]?at[_ ]?rest`),
		regexp.MustCompile(`(?i)data[_ ]?encrypted`),
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
		regexp.MustCompile(`(?i)aes[_ ]?256`),
		regexp.MustCompile(`(?i)fips[_ ]?140`),
	}
	m.auditPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)hash[_ ]?chain`),
	}
	m.accessPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)rbac`),
		regexp.MustCompile(`(?i)roles`),
		regexp.MustCompile(`(?i)abac`),
		regexp.MustCompile(`(?i)least[_ ]?privilege`),
	}
}

// registerControls wires all TISAX AL2 controls into the module.
// Called once from NewTISAXModule.
//
// Controls are organized by TISAX ISA family:
//
//	IS  = Information Security
//	OR  = Organization & Risk
//	DSC = Data & System Controls
//	PP  = Privacy & Personnel
//	DP  = Development & Prototyping
func (m *TISAXModule) registerControls() {
	// IS: Information Security (14 controls)
	m.registerISControls()

	// OR: Organization & Risk (12 controls)
	m.registerORControls()

	// DSC: Data & System Controls (14 controls)
	m.registerDSCControls()

	// PP: Privacy & Personnel (13 controls)
	m.registerPPControls()

	// DP: Development & Prototyping (12 controls)
	m.registerDPControls()
}

// Dependencies returns required modules. TISAX depends on the
// ISO 27001 / SOC 2 / FIPS 140 modules (for evidence reuse) and the
// IOC store + Trust Framework (for monitoring and attestation).
func (m *TISAXModule) Dependencies() []string {
	return []string{"iso27001", "soc2", "fips", "ioc", "trust"}
}

// hasEncryption checks if the input matches any encryption pattern.
func (m *TISAXModule) hasEncryption(input string) bool {
	for _, p := range m.encryptionPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasAudit checks if the input matches any audit/logging pattern.
func (m *TISAXModule) hasAudit(input string) bool {
	for _, p := range m.auditPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasAccessControl checks if the input matches any access control pattern.
func (m *TISAXModule) hasAccessControl(input string) bool {
	for _, p := range m.accessPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}
