// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC Level 2 Compliance Module
// =========================================================================
//
// CMMC Level 2 (Cybersecurity Maturity Model Certification, Level 2)
// is the DoD's framework for Defense Industrial Base (DIB) contractors
// handling Controlled Unclassified Information (CUI). CMMC L2 is based
// on NIST SP 800-171 Rev. 2 practices with 14 domains.
//
// AegisGate implements CMMC L2 as a licensed add-on module. This is
// the 8th compliance framework in the AegisGate roadmap (HIPAA, PCI-DSS,
// EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP, CMMC L2).
//
// Module metadata:
//   - Framework:   "cmmcl2"
//   - Version:     "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $499/mo (founder-locked 2026-06-04)
//   - Baseline:    CMMC Level 2 (NIST SP 800-171 Rev. 2)
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a C3PAO (CMMC Third-Party Assessment Organization).
//   The CMMC L2 module generates the technical evidence (audit logs,
//   IOC store, trust framework attestations, compliance scan results)
//   that a customer uses in their CMMC assessment. The C3PAO assessment
//   and CMMC certification issuance is the customer's responsibility,
//   just as HIPAA audit and Notified Body certification are the customer's
//   responsibility for HIPAA and EU AI Act respectively.
//
// Architecture (domain-based file structure):
//   - cmmcl2.go:       module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:            Access Control domain (AC.1.001, AC.2.001–AC.2.007)
//   - am.go:            Asset Management domain (AM.1.001–AM.2.002)
//   - au.go:            Audit and Accountability domain (AU.1.001–AU.2.004)
//   - ca_cm.go:         Assessment & Authorization + Configuration Management
//   - ia_ir.go:         Identification & Authentication + Incident Response
//   - ma_mp_pe.go:      Maintenance + Media Protection + Physical Protection
//   - ra_sa_sc_si.go:   Risk Assessment + Situational Awareness +
//                       System & Communications Protection + System & Information Integrity
//   - cmmcl2_test.go:   unit tests
//   - doc.go:           package documentation
//
// Design: CMMC L2 controls are mapped to existing AegisGate modules
// (SOC 2, ISO 27001, FedRAMP, IOC store, Trust Framework) to avoid
// duplicating the implementation. Each CMMC L2 control either:
//   1. Is AUTOMATED and reuses an existing AegisGate scanner output
//      (e.g., CMMC L2 AC.1.001 maps to SOC 2 CC6.1)
//   2. Is EVIDENCE-MAPPED and AegisGate generates the evidence
//      artifact (audit log, IOC, attestation) the customer attaches
//      to their CMMC assessment package
//   3. Is MANUAL and the customer produces the documentation/process
//      evidence (e.g., CMMC L2 AC.2.007 Policy Documentation)
//
// Reference: CMMC Level 2 (NIST SP 800-171 Rev. 2)
//            https://cmmc.osd.mil/
//            14 domains, 110 practices
//            AegisGate covers 52 scanner-checkable practices
//
// =========================================================================

package cmmcl2

import (
	"regexp"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CMMCL2Module implements the CMMC Level 2 compliance framework as a
// licensed add-on. It embeds *compliance.BaseComplianceModule which
// provides RegisterControl, Controls, Framework, Version, CheckAll,
// and GenerateAssessment out of the box.
type CMMCL2Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	mfaPatterns        []*regexp.Regexp
	auditPatterns      []*regexp.Regexp
	encryptionPatterns []*regexp.Regexp
	accessPatterns     []*regexp.Regexp
	incidentPatterns   []*regexp.Regexp
}

// NewCMMCL2Module creates a new CMMC Level 2 compliance module. It is
// safe to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleCMMCL2 entry).
func NewCMMCL2Module() *CMMCL2Module {
	m := &CMMCL2Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("cmmcl2", "1.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *CMMCL2Module) initPatterns() {
	m.mfaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mfa`),
		regexp.MustCompile(`(?i)multi[_ ]?factor`),
		regexp.MustCompile(`(?i)2fa`),
		regexp.MustCompile(`(?i)two[_ ]?factor`),
	}
	m.auditPatterns = []*regexp.Regexp{
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
	m.accessPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)access[_ ]?control`),
		regexp.MustCompile(`(?i)rbac`),
		regexp.MustCompile(`(?i)abac`),
		regexp.MustCompile(`(?i)policy[_ ]?enforcement`),
	}
	m.incidentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)incident[_ ]?response`),
		regexp.MustCompile(`(?i)ioc`),
		regexp.MustCompile(`(?i)siem`),
		regexp.MustCompile(`(?i)alert`),
	}
}

// registerControls wires all CMMC Level 2 controls into the module.
// Called once from NewCMMCL2Module.
//
// Controls are organized by CMMC L2 domain:
//
//	AC = Access Control
//	AM = Asset Management
//	AU = Audit and Accountability
//	CA = Assessment and Authorization
//	CM = Configuration Management
//	IA = Identification and Authentication
//	IR = Incident Response
//	MA = Maintenance
//	MP = Media Protection
//	PE = Physical Protection
//	RA = Risk Assessment
//	SA = Situational Awareness
//	SC = System and Communications Protection
//	SI = System and Information Integrity
func (m *CMMCL2Module) registerControls() {
	// AC: Access Control (8 controls)
	m.registerACControls()

	// AM: Asset Management (3 controls)
	m.registerAMControls()

	// AU: Audit and Accountability (4 controls)
	m.registerAUControls()

	// CA + CM: Assessment & Authorization + Configuration Management (8 controls)
	m.registerCAControls()
	m.registerCMControls()

	// IA + IR: Identification & Authentication + Incident Response (8 controls)
	m.registerIAControls()
	m.registerIRControls()

	// MA + MP + PE: Maintenance + Media Protection + Physical Protection (7 controls)
	m.registerMAControls()
	m.registerMPControls()
	m.registerPEControls()

	// RA + SA + SC + SI: Risk Assessment + Situational Awareness +
	//                    System & Communications Protection + System & Information Integrity (14 controls)
	m.registerRAControls()
	m.registerSAControls()
	m.registerSCControls()
	m.registerSIControls()
}

// Dependencies returns required modules. CMMC L2 depends on the
// SOC 2 / ISO 27001 / FedRAMP modules (for evidence reuse) and the
// IOC store + Trust Framework (for monitoring and attestation).
func (m *CMMCL2Module) Dependencies() []string {
	return []string{"soc2", "iso27001", "fedramp", "ioc", "trust"}
}
