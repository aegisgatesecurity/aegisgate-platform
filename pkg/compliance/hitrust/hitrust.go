// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF Compliance Module
// =========================================================================
//
// HITRUST CSF (Common Security Framework) v11.2 is a certifiable
// framework that inherits from HIPAA, NIST SP 800-53, ISO 27001,
// PCI-DSS, and other standards. It provides a single framework for
// managing information risk across multiple regulatory requirements.
//
// AegisGate implements HITRUST CSF as a licensed add-on module. This is
// the 11th compliance framework in the AegisGate roadmap (HIPAA, PCI-DSS,
// EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP, CIS, NIST CSF,
// ISO 27001, HITRUST CSF).
//
// Module metadata:
//   - Framework:   "hitrust"
//   - Version:     "1.0"
//   - Required tier: Enterprise+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $799/mo (founder-locked 2026-07-22)
//   - Baseline:    HITRUST CSF v11.2
//   - Controls:    200 (80 automated + 120 manual)
//
// IMPORTANT — Self-attested posture (same as EU AI Act + FIPS + FedRAMP):
//   AegisGate is NOT a HITRUST-authorized External Assessor (EA). The
//   HITRUST CSF module generates the technical evidence (audit logs,
//   IOC store, trust framework attestations, compliance scan results)
//   that a customer uses in their HITRUST CSF Assessment and MyCSF
//   portal. The HITRUST CSF certification and External Assessment are
//   the customer's responsibility, just as HIPAA audit and Notified
//   Body certification are the customer's responsibility for HIPAA
//   and EU AI Act respectively.
//
// Architecture (family-based file structure):
//   - hitrust.go:   module wiring, registerControls, Dependencies, pattern caches
//   - am.go:        Access Management family (AM-01 through AM-25)
//   - id_ip_pe.go:  Identity (ID-01..10), Info Protection (IP-01..25),
//                   Privacy & Endpoint (PE-01..25) families
//   - op_or_pr.go:  Operations (OP-01..20), Organizational Risk (OR-01..10),
//                   Program (PR-01..15) families
//   - bc_ra_ca.go:  Business Continuity (BC-01..10), Regulatory Assessment
//                   (RA-01..10), Change Management (CA-01..10) families
//   - ir_sd.go:     Incident Response (IR-01..15), Supplier/Development
//                   (SD-01..15), AI Controls (AI-01..10) families
//
// Control families (13 families, 200 controls):
//   AM = Access Management          (25 controls: 14 automated + 11 manual)
//   ID = Identity Management        (10 controls:  7 automated +  3 manual)
//   IP = Information Protection     (25 controls: 15 automated + 10 manual)
//   PE = Privacy and Endpoint       (25 controls:  5 automated + 20 manual)
//   OP = Operations                 (20 controls:  8 automated + 12 manual)
//   OR = Organizational Risk        (10 controls:  5 automated +  5 manual)
//   PR = Program                    (15 controls:  2 automated + 13 manual)
//   BC = Business Continuity        (10 controls:  5 automated +  5 manual)
//   RA = Regulatory Assessment      (10 controls:  2 automated +  8 manual)
//   CA = Change Management          (10 controls:  5 automated +  5 manual)
//   IR = Incident Response          (15 controls: 6 automated + 9 manual)
//   SD = Supplier/Development       (15 controls:  1 automated + 14 manual)
//   AI = AI Controls                (10 controls:  2 automated +  8 manual)
//   Total: 200 controls (80 automated + 120 manual)
//
// Reference: HITRUST CSF v11.2
//            https://hitrustalliance.net/csf-license-agreement/
//            HITRUST CSF Assessment: e1, i1, r2 certification levels
//
// =========================================================================

package hitrust

import (
	"regexp"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// HITRUSTModule implements the HITRUST CSF v11.2 compliance framework
// as a licensed add-on. It embeds *compliance.BaseComplianceModule
// which provides RegisterControl, Controls, Framework, Version,
// CheckAll, and GenerateAssessment out of the box.
type HITRUSTModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	mfaPatterns        []*regexp.Regexp
	rbacPatterns       []*regexp.Regexp
	encryptionPatterns []*regexp.Regexp
	auditPatterns      []*regexp.Regexp
	vulnPatterns       []*regexp.Regexp
	firewallPatterns   []*regexp.Regexp
}

// NewHITRUSTModule creates a new HITRUST CSF compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is gated to Enterprise+ tier via
// pkg/compliance/gating.go (license.ModuleHITRUST entry).
func NewHITRUSTModule() *HITRUSTModule {
	m := &HITRUSTModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("hitrust", "1.0", core.TierEnterprise),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *HITRUSTModule) initPatterns() {
	m.mfaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mfa`),
		regexp.MustCompile(`(?i)multi[_ ]?factor`),
		regexp.MustCompile(`(?i)2fa`),
		regexp.MustCompile(`(?i)two[_ ]?factor`),
		regexp.MustCompile(`(?i)otp`),
		regexp.MustCompile(`(?i)totp`),
	}
	m.rbacPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)rbac`),
		regexp.MustCompile(`(?i)role[_ ]?based`),
		regexp.MustCompile(`(?i)abac`),
		regexp.MustCompile(`(?i)attribute[_ ]?based`),
		regexp.MustCompile(`(?i)roles`),
	}
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
		regexp.MustCompile(`(?i)siem`),
	}
	m.vulnPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)vulnerability[_ ]?scan`),
		regexp.MustCompile(`(?i)scanner`),
		regexp.MustCompile(`(?i)patch[_ ]?management`),
		regexp.MustCompile(`(?i)cve`),
		regexp.MustCompile(`(?i)cvss`),
	}
	m.firewallPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)firewall`),
		regexp.MustCompile(`(?i)waf`),
		regexp.MustCompile(`(?i)egress[_ ]?filter`),
		regexp.MustCompile(`(?i)network[_ ]?policy`),
		regexp.MustCompile(`(?i)proxy`),
	}
}

// registerControls wires all HITRUST CSF v11.2 controls into the module.
// Called once from NewHITRUSTModule.
//
// Controls are organized by HITRUST CSF v11.2 family across multiple files:
//
//	AM = Access Management            (am.go)
//	ID = Identity Management          (id_ip_pe.go)
//	IP = Information Protection       (id_ip_pe.go)
//	PE = Privacy and Endpoint         (id_ip_pe.go)
//	OP = Operations                   (op_or_pr.go)
//	OR = Organizational Risk          (op_or_pr.go)
//	PR = Program                      (op_or_pr.go)
//	BC = Business Continuity          (bc_ra_ca.go)
//	RA = Regulatory Assessment        (bc_ra_ca.go)
//	CA = Change Management            (bc_ra_ca.go)
//	IR = Incident Response            (ir_sd.go)
//	SD = Supplier/Development         (ir_sd.go)
//	AI = AI Controls                  (ir_sd.go)
func (m *HITRUSTModule) registerControls() {
	// AM: Access Management (25 controls)
	m.registerAMControls()

	// ID/IP/PE: Identity, Info Protection, Privacy & Endpoint (60 controls)
	m.registerIDIPPEControls()

	// OP/OR/PR: Operations, Organizational Risk, Program (45 controls)
	m.registerOPOrPRControls()

	// BC/RA/CA: Business Continuity, Regulatory Assessment, Change Mgmt (30 controls)
	m.registerBCRACAControls()

	// IR/SD/AI: Incident Response, Supplier/Development, AI Controls (40 controls)
	m.registerIRSDControls()
}

// Dependencies returns required modules. HITRUST CSF depends on the
// HIPAA, ISO 27001, FIPS 140, SOC 2 modules (for evidence reuse) and
// the IOC store + Trust Framework (for monitoring and attestation).
func (m *HITRUSTModule) Dependencies() []string {
	return []string{"hipaa", "iso27001", "fips", "soc2", "ioc", "trust"}
}

// hasMFA checks if the input contains MFA-related patterns.
func (m *HITRUSTModule) hasMFA(input string) bool {
	for _, p := range m.mfaPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasRBAC checks if the input contains RBAC-related patterns.
func (m *HITRUSTModule) hasRBAC(input string) bool {
	for _, p := range m.rbacPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasEncryption checks if the input contains encryption-related patterns.
func (m *HITRUSTModule) hasEncryption(input string) bool {
	for _, p := range m.encryptionPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasAudit checks if the input contains audit-related patterns.
func (m *HITRUSTModule) hasAudit(input string) bool {
	for _, p := range m.auditPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasVulnScan checks if the input contains vulnerability scanning patterns.
func (m *HITRUSTModule) hasVulnScan(input string) bool {
	for _, p := range m.vulnPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}

// hasFirewall checks if the input contains firewall/network patterns.
func (m *HITRUSTModule) hasFirewall(input string) bool {
	for _, p := range m.firewallPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	return false
}
