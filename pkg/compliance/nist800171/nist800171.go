// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 Compliance Module
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Protecting Controlled Unclassified Information
// in Nonfederal Systems and Organizations.
//
// AegisGate implements NIST 800-171 as a licensed add-on module. This is
// the 8th compliance framework in the AegisGate roadmap (HIPAA, PCI-DSS,
// EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP, NIST 800-171).
//
// Module metadata:
//   - Framework:   "nist800171"
//   - Version:     "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $399/mo
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a CMMC Assessor or C3PAO. The NIST 800-171 module
//   generates the technical evidence (audit logs, IOC store, trust
//   framework attestations, compliance scan results) that a customer
//   uses in their CMMC assessment or self-attestation (SPRS). The
//   CMMC assessment and certification are the customer's responsibility.
//
// Architecture (family-based file structure):
//   - nist800171.go: module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:          Access Control family (AC-1 – AC-17)
//   - au.go:          Audit and Accountability family (AU-1 – AU-9)
//   - cm_si.go:       Configuration Management + System Integrity (CM-2 – SI-3)
//   - ia.go:          Identification and Authentication family (IA-1 – IA-8)
//   - ir_ra.go:       Incident Response + Risk Assessment (IR-1 – RA-3)
//   - sc.go:          System and Communications Protection (SC-4 – SC-23)
//   - cp_ma_sa.go:    Contingency Planning + Maintenance + System Acquisition (CP-1 – SA-5)
//   - nist800171_test.go: unit tests
//
// Design: NIST 800-171 controls are mapped to existing AegisGate modules
// (SOC 2, ISO 27001, HIPAA, FIPS 140, Trust Framework, IOC store) to
// avoid duplicating the implementation. Each NIST 800-171 control either:
//   1. Is AUTOMATED and reuses an existing AegisGate scanner output
//   2. Is EVIDENCE-MAPPED and AegisGate generates the evidence artifact
//   3. Is MANUAL and the customer produces the documentation/process
//      evidence (represented as evidence-mapped controls without CheckFunc)
//
// Reference: NIST SP 800-171 Rev. 2
//            https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final
//
// =========================================================================

package nist800171

import (
	"regexp"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NIST800171Module implements the NIST 800-171 Rev. 2 compliance
// framework as a licensed add-on. It embeds *compliance.BaseComplianceModule
// which provides RegisterControl, Controls, Framework, Version,
// CheckAll, and GenerateAssessment out of the box.
type NIST800171Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	mfaPatterns        []*regexp.Regexp
	fipsPatterns       []*regexp.Regexp
	auditLogPatterns   []*regexp.Regexp
	encryptionPatterns []*regexp.Regexp
}

// NewNIST800171Module creates a new NIST 800-171 compliance module. It
// is safe to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleNIST800171 entry).
func NewNIST800171Module() *NIST800171Module {
	m := &NIST800171Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nist800171", "1.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *NIST800171Module) initPatterns() {
	m.mfaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mfa`),
		regexp.MustCompile(`(?i)multi[_ ]?factor`),
		regexp.MustCompile(`(?i)2fa`),
		regexp.MustCompile(`(?i)two[_ ]?factor`),
	}
	m.fipsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)fips[_ ]?140`),
		regexp.MustCompile(`(?i)fips[_ ]?mode`),
		regexp.MustCompile(`(?i)cmvp`),
	}
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)hash[_ ]?chain`),
	}
	m.encryptionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)encryption[_ ]?at[_ ]?rest`),
		regexp.MustCompile(`(?i)data[_ ]?encrypted`),
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
	}
}

// registerControls wires all NIST 800-171 controls into the module.
// Called once from NewNIST800171Module.
//
// Controls are organized by NIST SP 800-171 Rev. 2 family:
//
//	AC = Access Control
//	AU = Audit and Accountability
//	CM = Configuration Management
//	IA = Identification and Authentication
//	IR = Incident Response
//	RA = Risk Assessment
//	SA = System and Services Acquisition
//	SC = System and Communications Protection
//	SI = System and Information Integrity
//	CP = Contingency Planning
//	MA = Maintenance
func (m *NIST800171Module) registerControls() {
	// AC: Access Control (8 controls)
	m.registerACControls()

	// AU: Audit and Accountability (5 controls)
	m.registerAUControls()

	// CM + SI: Configuration Management + System Integrity (6 controls)
	m.registerCMSIControls()

	// IA: Identification and Authentication (5 controls)
	m.registerIAControls()

	// IR + RA: Incident Response + Risk Assessment (5 controls)
	m.registerIRRAControls()

	// SC: System and Communications Protection (6 controls)
	m.registerSCControls()

	// CP + MA + SA: Contingency Planning + Maintenance + System Acquisition (6 controls)
	m.registerCPMASAControls()
}

// Dependencies returns required modules. NIST 800-171 depends on the
// SOC 2 / ISO 27001 / HIPAA / FIPS modules (for evidence reuse) and
// the IOC store + Trust Framework (for monitoring and attestation).
func (m *NIST800171Module) Dependencies() []string {
	return []string{"soc2", "iso27001", "hipaa", "fips", "ioc", "trust"}
}
