// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Compliance Module
// =========================================================================
//
// FedRAMP (Federal Risk and Authorization Management Program) is the
// US federal government's standardized approach to security assessment,
// authorization, and continuous monitoring of cloud products and
// services. FedRAMP is based on NIST SP 800-53 Rev. 5 controls.
//
// AegisGate implements FedRAMP as a licensed add-on module. This is
// the 7th compliance framework in the AegisGate roadmap (HIPAA, PCI-DSS,
// EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP).
//
// Module metadata:
//   - Framework:   "fedramp"
//   - Version:     "2.0"  (Path C: full in-scope control coverage)
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $499/mo (founder-locked 2026-06-04)
//   - Baseline:    FedRAMP Moderate (NIST SP 800-53 Rev. 5)
//
// IMPORTANT — Self-attested posture (same as EU AI Act + FIPS):
//   AegisGate is NOT a FedRAMP-accredited 3PAO (Third Party Assessment
//   Organization). The FedRAMP module generates the technical evidence
//   (audit logs, IOC store, trust framework attestations, compliance
//   scan results) that a customer uses in their FedRAMP A&A package
//   (SAP, SAR, POA&M). The 3PAO assessment and ATO (Authority to
//   Operate) issuance is the customer's responsibility, just as
//   HIPAA audit and Notified Body certification are the customer's
//   responsibility for HIPAA and EU AI Act respectively.
//
// Architecture (Path C — family-based file structure):
//   - fedramp.go:   module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:        Access Control family (AC-2, AC-3, AC-6, AC-14, AC-17, AC-24)
//   - au.go:        Audit and Accountability family (AU-2, AU-3, AU-6, AU-9, AU-10, AU-12, AU-16)
//   - ia.go:        Identification and Authentication family (IA-2, IA-3, IA-5, IA-6, IA-7, IA-8)
//   - sc.go:        System and Communications Protection family (SC-4, SC-7, SC-8, SC-12, SC-13, SC-23, SC-28)
//   - cm_si.go:     Configuration Management + System & Information Integrity (CM-2, CM-3, CM-5, CM-6, CM-8, SI-2, SI-3, SI-4, SI-7, SI-8, SI-10, SI-16)
//   - ir_sa_sr.go:  Incident Response, System & Services Acquisition, Supply Chain Risk Management (IR-4–IR-8, SA-4–SA-22, SR-3–SR-12)
//   - ra_ca.go:     Risk Assessment, Assessment & Authorization (RA-3–RA-7, CA-2, CA-7, CA-8, CA-9)
//   - fedramp_test.go: unit tests
//   - doc.go:        package documentation
//
// Design: FedRAMP controls are mapped to existing AegisGate modules
// (SOC 2, HIPAA, ISO 42001, FIPS 140, Trust Framework, IOC store) to
// avoid duplicating the implementation. Each FedRAMP control either:
//   1. Is AUTOMATED and reuses an existing AegisGate scanner output
//      (e.g., FedRAMP AC-2 Account Management maps to SOC 2 CC6.1)
//   2. Is EVIDENCE-MAPPED and AegisGate generates the evidence
//      artifact (audit log, IOC, attestation) the customer attaches
//      to their FedRAMP A&A package
//   3. Is MANUAL and the customer produces the documentation/process
//      evidence (e.g., FedRAMP AT-2 Security Awareness Training)
//
// Reference: NIST SP 800-53 Rev. 5
//            https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
//            FedRAMP Moderate baseline: ~323 controls
//            FedRAMP High baseline: ~421 controls
//
// =========================================================================

package fedramp

import (
	"regexp"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// FedRAMPModule implements the FedRAMP (Moderate baseline) compliance
// framework as a licensed add-on. It embeds *compliance.BaseComplianceModule
// which provides RegisterControl, Controls, Framework, Version,
// CheckAll, and GenerateAssessment out of the box.
type FedRAMPModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	mfaPatterns        []*regexp.Regexp
	fipsPatterns       []*regexp.Regexp
	auditLogPatterns   []*regexp.Regexp
	encryptionPatterns []*regexp.Regexp
}

// NewFedRAMPModule creates a new FedRAMP compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleFedRAMP entry).
func NewFedRAMPModule() *FedRAMPModule {
	m := &FedRAMPModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("fedramp", "2.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *FedRAMPModule) initPatterns() {
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

// registerControls wires all FedRAMP (Moderate baseline) controls
// into the module. Called once from NewFedRAMPModule.
//
// Controls are organized by NIST SP 800-53 Rev. 5 family:
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
//	SR = Supply Chain Risk Management
//	CA = Assessment, Authorization, and Monitoring
func (m *FedRAMPModule) registerControls() {
	// AC: Access Control (6 controls)
	m.registerACControls()

	// AU: Audit and Accountability (7 controls)
	m.registerAUControls()

	// IA: Identification and Authentication (6 controls)
	m.registerIAControls()

	// SC: System and Communications Protection (7 controls)
	m.registerSCControls()

	// CM: Configuration Management (5 controls)
	m.registerCMControls()

	// SI: System and Information Integrity (6 controls)
	m.registerSIControls()

	// IR: Incident Response (5 controls)
	m.registerIRControls()

	// SA: System and Services Acquisition (5 controls)
	m.registerSAControls()

	// SR: Supply Chain Risk Management (5 controls)
	m.registerSRControls()

	// RA: Risk Assessment (4 controls)
	m.registerRAControls()

	// CA: Assessment, Authorization, and Monitoring (4 controls)
	m.registerCAControls()
}

// Dependencies returns required modules. FedRAMP depends on the
// SOC 2 / ISO 42001 / FIPS 140 modules (for evidence reuse) and the
// IOC store + Trust Framework (for monitoring and attestation).
func (m *FedRAMPModule) Dependencies() []string {
	return []string{"soc2", "iso42001", "fips", "ioc", "trust"}
}
