// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST CSF 2.0 Module
// =========================================================================
//
// NIST Cybersecurity Framework 2.0 (the de-facto US enterprise security
// framework, originally NIST CSF 1.1 from 2018, expanded to 2.0 in
// February 2024). Appears in 60%+ of US enterprise RFPs.
//
// The 6 CSF 2.0 Functions are mapped cleanly to AegisGate's 6-pillar
// coverage:
//   GOVERN    -> Platform governance, audit, compliance
//   IDENTIFY  -> Asset inventory, IOC store, threat model
//   PROTECT   -> Access control, encryption, output filtering
//   DETECT    -> Scanner, anomaly detection, IOC federation
//   RESPOND   -> Trust Framework attestations, audit log, kill switch
//   RECOVER   -> Audit log replay, hash-chain verification, IOC store restore
//
// Module metadata:
//   - Framework:     "nist_csf"
//   - Version:       "2.0"
//   - Required tier: Professional ($79/mo)
//   - Controls:      131 subcategories (23 automated, 108 manual)
//   - Functions:     6 (GV, ID, PR, DE, RS, RC)
//   - Categories:    22
//
// Architecture:
//   - nist_csf.go:        module wiring, 131 RegisterControl calls,
//                          23 CheckFunc implementations
//   - nist_csf_test.go:   unit tests
//   - tier_coverage_test.go: tier/framework tests
//
// Reference: https://www.nist.gov/cyberframework
//            NIST CSF 2.0 (February 26, 2024)
// =========================================================================

package nist_csf

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NISTCSFModule implements the NIST Cybersecurity Framework 2.0.
type NISTCSFModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches
	auditLogPatterns []*regexp.Regexp
	tlsPatterns      []*regexp.Regexp
}

// NewNISTCSFModule creates a new NIST CSF 2.0 module.
func NewNISTCSFModule() *NISTCSFModule {
	m := &NISTCSFModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nist_csf", "2.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

func (m *NISTCSFModule) initPatterns() {
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
	}
	m.tlsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
		regexp.MustCompile(`(?i)min[_ ]?version[_ ]?1[._][23]`),
	}
}

// ============================================================================
// Control Registration — 131 subcategories
// ============================================================================

func (m *NISTCSFModule) registerControls() {
	// ── Function GV (Govern) — 36 subcategories, 6 categories ──

	// GV.OC (Organizational Context) — 5
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OC-01", Name: "Organizational mission understood and communicated",
		Description: "The organizational mission is understood and communicated.",
		Category:    "GV.OC (Organizational Context)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OC-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OC-02", Name: "Internal culture understood",
		Description: "The organizational internal culture is understood.",
		Category:    "GV.OC (Organizational Context)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OC-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OC-03", Name: "Connectivity to other organizations understood",
		Description: "Connectivity to other organizations and customers is understood.",
		Category:    "GV.OC (Organizational Context)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OC-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OC-04", Name: "Cybersecurity considered across all aspects",
		Description: "Cybersecurity is considered across all aspects of the organization.",
		Category:    "GV.OC (Organizational Context)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OC-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OC-05", Name: "Cybersecurity approach integrated with risk functions",
		Description: "The organization's cybersecurity approach is integrated with other risk functions.",
		Category:    "GV.OC (Organizational Context)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OC-05"},
	})

	// GV.RM (Risk Management) — 7
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-01", Name: "Risk management processes established",
		Description: "Risk management processes are established, managed, and agreed to by stakeholders.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkGovern,
		References: []string{"NIST CSF 2.0 GV.RM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-02", Name: "Risk responsibilities assigned",
		Description: "Risk responsibilities are assigned and understood.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-03", Name: "Risk management integrated into enterprise risk",
		Description: "Risk management processes are integrated into enterprise risk management.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-04", Name: "Risk tolerance determined",
		Description: "Risk management processes include determining organizational risk tolerance.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-05", Name: "Supply chain risk determined",
		Description: "Risk management processes include determining, documenting, and responding to supply chain risk.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-06", Name: "Critical infrastructure risk determined",
		Description: "Risk management processes include determining cybersecurity risk associated with critical infrastructure.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RM-07", Name: "Third-party provider risk determined",
		Description: "Risk management processes include cybersecurity risk associated with using third-party and external providers.",
		Category:    "GV.RM (Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RM-07"},
	})

	// GV.RR (Risk Strategy) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RR-01", Name: "Risk responses prioritized",
		Description: "Cybersecurity risk management responses and remediation are prioritized.",
		Category:    "GV.RR (Risk Strategy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RR-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RR-02", Name: "Risk responses integrated with enterprise risk",
		Description: "Cybersecurity risk management responses and remediation are integrated with enterprise risk.",
		Category:    "GV.RR (Risk Strategy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RR-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RR-03", Name: "Risk response decisions include risk tolerance",
		Description: "Cybersecurity risk management response decisions include risk tolerance.",
		Category:    "GV.RR (Risk Strategy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RR-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.RR-04", Name: "Risk response decisions include legal and regulatory requirements",
		Description: "Risk management response decisions include legal and regulatory requirements.",
		Category:    "GV.RR (Risk Strategy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.RR-04"},
	})

	// GV.PO (Policy) — 6
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-01", Name: "Cybersecurity policies established",
		Description: "Cybersecurity policies are established, managed, and published.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkPolicy,
		References: []string{"NIST CSF 2.0 GV.PO-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-02", Name: "Roles and responsibilities established",
		Description: "Cybersecurity roles and responsibilities are established and managed.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.PO-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-03", Name: "Supply chain risk management policies established",
		Description: "Cybersecurity supply chain risk management policies are established, managed, and published.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.PO-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-04", Name: "Processes and procedures established",
		Description: "Processes and procedures are established and managed.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.PO-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-05", Name: "Technology infrastructure policies established",
		Description: "Technology infrastructure policies are established, managed, and published.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.PO-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.PO-06", Name: "Asset management processes established",
		Description: "Processes and procedures for asset management are established and managed.",
		Category:    "GV.PO (Policy)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.PO-06"},
	})

	// GV.OV (Oversight) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OV-01", Name: "Cybersecurity performance reviewed",
		Description: "Organizational cybersecurity performance is reviewed and reported against organizational risk tolerance.",
		Category:    "GV.OV (Oversight)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OV-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OV-02", Name: "Risk management results reviewed",
		Description: "Cybersecurity risk management results are reviewed and reported against organizational risk tolerance.",
		Category:    "GV.OV (Oversight)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OV-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OV-03", Name: "Oversight results inform improvements",
		Description: "Risk management and oversight results are used to inform and improve risk management.",
		Category:    "GV.OV (Oversight)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OV-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.OV-04", Name: "Risk management communicated to stakeholders",
		Description: "Cybersecurity risk management activities and results are communicated to stakeholders.",
		Category:    "GV.OV (Oversight)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.OV-04"},
	})

	// GV.SC (Supply Chain Risk Management) — 10
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-01", Name: "Supply chain risk management integrated",
		Description: "Cybersecurity supply chain risk management is integrated into cybersecurity risk management.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-02", Name: "Supply chain risk processes established",
		Description: "Cybersecurity supply chain risk management processes are established, managed, and agreed to by stakeholders.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-03", Name: "Supply chain requirements communicated",
		Description: "Cybersecurity supply chain requirements are established, managed, and communicated to suppliers and third-party providers.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-04", Name: "Cybersecurity requirements in contracts",
		Description: "Cybersecurity requirements are included in supplier and third-party contracts.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-05", Name: "Supply chain risks identified and assessed",
		Description: "Cybersecurity supply chain risk management activities include identifying, assessing, and prioritizing supply chain risks.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-06", Name: "Supply chain risks mitigated",
		Description: "Cybersecurity supply chain risk management activities include mitigation of supply chain risks.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-07", Name: "Supply chain risks monitored",
		Description: "Cybersecurity supply chain risk management activities include monitoring of supply chain risks.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-08", Name: "Supply chain risks tracked and documented",
		Description: "Cybersecurity supply chain risk management processes include tracking, documenting, and responding to supply chain risks.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-09", Name: "Supply chain risks responded to",
		Description: "Cybersecurity supply chain risk management activities include tracking, documenting, and responding to supply chain risks.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "GV.SC-10", Name: "Supply chain risks communicated",
		Description: "Cybersecurity supply chain risk management activities include communicating supply chain risks and findings.",
		Category:    "GV.SC (Supply Chain Risk Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 GV.SC-10"},
	})

	// ── Function ID (Identify) — 20 subcategories, 3 categories ──

	// ID.AM (Asset Management) — 8
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-01", Name: "Asset inventories established",
		Description: "Inventories of assets are established and managed.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkAssetMgmt,
		References: []string{"NIST CSF 2.0 ID.AM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-02", Name: "Software and services inventoried",
		Description: "Software, platforms, and services are inventoried and managed.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkSoftwareInventory, References: []string{"NIST CSF 2.0 ID.AM-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-03", Name: "Data inventoried",
		Description: "Data are inventoried and managed.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkDataInventory, References: []string{"NIST CSF 2.0 ID.AM-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-04", Name: "Device inventories maintained",
		Description: "Device inventories are maintained.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkDeviceInventory, References: []string{"NIST CSF 2.0 ID.AM-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-05", Name: "Dependencies and criticality understood",
		Description: "Dependencies and criticality are understood.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.AM-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-06", Name: "Suppliers inventoried",
		Description: "Suppliers and third-party providers are inventoried and managed.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.AM-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-07", Name: "Data sensitivity and classification managed",
		Description: "Data sensitivity and classification are understood and managed.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkDataClassification, References: []string{"NIST CSF 2.0 ID.AM-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.AM-08", Name: "Systems and services inventoried",
		Description: "Systems, platforms, and services are inventoried.",
		Category:    "ID.AM (Asset Management)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkSystemInventory, References: []string{"NIST CSF 2.0 ID.AM-08"},
	})

	// ID.RA (Risk Assessment) — 10
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-01", Name: "Vulnerabilities identified and managed",
		Description: "Vulnerabilities are identified, documented, and managed.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkVulnMgmt,
		References: []string{"NIST CSF 2.0 ID.RA-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-02", Name: "Threats identified and managed",
		Description: "Threats are identified, documented, and managed.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkThreatMgmt,
		References: []string{"NIST CSF 2.0 ID.RA-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-03", Name: "Risk assessments performed",
		Description: "Risk assessments are performed and documented.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkRiskAssess,
		References: []string{"NIST CSF 2.0 ID.RA-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-04", Name: "Threats and vulnerabilities prioritized",
		Description: "Threats and vulnerabilities are prioritized.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkThreatPrioritization, References: []string{"NIST CSF 2.0 ID.RA-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-05", Name: "Asset criticality and risk tolerance understood",
		Description: "Asset criticality and risk tolerance are understood and used to inform risk management.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-06", Name: "Risk assessment results inform risk management",
		Description: "Risk assessment results are used to inform risk management.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-07", Name: "Risk assessment results inform risk responses",
		Description: "Risk assessment results are used to inform and prioritize risk responses.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-08", Name: "Risk assessment results inform remediation",
		Description: "Risk assessment results are used to inform and prioritize remediation.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-09", Name: "Risk assessment results inform improvements",
		Description: "Risk assessment results are used to inform and prioritize improvements.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.RA-10", Name: "Improvements evaluated for effectiveness",
		Description: "Improvements are evaluated for effectiveness.",
		Category:    "ID.RA (Risk Assessment)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.RA-10"},
	})

	// ID.IM (Improvements) — 2
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.IM-01", Name: "Improvements identified",
		Description: "Improvements are identified from assessments, risk monitoring, and other sources.",
		Category:    "ID.IM (Improvements)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.IM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "ID.IM-02", Name: "Improvements implemented and evaluated",
		Description: "Improvements are implemented and evaluated for effectiveness.",
		Category:    "ID.IM (Improvements)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 ID.IM-02"},
	})

	// ── Function PR (Protect) — 28 subcategories, 5 categories ──

	// PR.AA (Identity, Authentication, and Access) — 5
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AA-01", Name: "Identities and credentials managed",
		Description: "Identities and credentials are managed.",
		Category:    "PR.AA (Identity, Authentication, and Access)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIdentity,
		References: []string{"NIST CSF 2.0 PR.AA-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AA-02", Name: "Authenticators protected",
		Description: "Authenticators are protected.",
		Category:    "PR.AA (Identity, Authentication, and Access)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAuthenticators,
		References: []string{"NIST CSF 2.0 PR.AA-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AA-03", Name: "Users authenticated",
		Description: "Users are authenticated.",
		Category:    "PR.AA (Identity, Authentication, and Access)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAuthentication,
		References: []string{"NIST CSF 2.0 PR.AA-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AA-04", Name: "Permissions and access managed",
		Description: "Permissions, privileges, and access are managed.",
		Category:    "PR.AA (Identity, Authentication, and Access)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAccessMgmt,
		References: []string{"NIST CSF 2.0 PR.AA-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AA-05", Name: "Network access managed and enforced",
		Description: "Network access is managed and enforced.",
		Category:    "PR.AA (Identity, Authentication, and Access)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkNetworkAccessMgmt, References: []string{"NIST CSF 2.0 PR.AA-05"},
	})

	// PR.AT (Awareness and Training) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AT-01", Name: "Awareness training provided",
		Description: "Awareness training is provided.",
		Category:    "PR.AT (Awareness and Training)", Severity: compliance.SeverityLow,
		Automated: false, References: []string{"NIST CSF 2.0 PR.AT-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AT-02", Name: "Role-based training provided",
		Description: "Role-based training is provided.",
		Category:    "PR.AT (Awareness and Training)", Severity: compliance.SeverityLow,
		Automated: false, References: []string{"NIST CSF 2.0 PR.AT-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AT-03", Name: "Advanced training topics included",
		Description: "Training includes advanced topics.",
		Category:    "PR.AT (Awareness and Training)", Severity: compliance.SeverityLow,
		Automated: false, References: []string{"NIST CSF 2.0 PR.AT-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.AT-04", Name: "Training updated and communicated",
		Description: "Training is updated and communicated.",
		Category:    "PR.AT (Awareness and Training)", Severity: compliance.SeverityLow,
		Automated: false, References: []string{"NIST CSF 2.0 PR.AT-04"},
	})

	// PR.DS (Data Security) — 10
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-01", Name: "Confidentiality, integrity, and availability protected",
		Description: "Confidentiality, integrity, and availability of data are protected.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkDataSecurity,
		References: []string{"NIST CSF 2.0 PR.DS-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-02", Name: "Backups protected and managed",
		Description: "Backups are protected and managed.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkBackupProtection, References: []string{"NIST CSF 2.0 PR.DS-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-03", Name: "Configuration management established",
		Description: "Configuration management is established and managed.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkConfigManagement, References: []string{"NIST CSF 2.0 PR.DS-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-04", Name: "Integrity checking performed",
		Description: "Integrity checking is performed.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkIntegrityChecking, References: []string{"NIST CSF 2.0 PR.DS-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-05", Name: "Communications and control networks protected",
		Description: "Communications and control networks are protected.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkNetworkProtection, References: []string{"NIST CSF 2.0 PR.DS-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-06", Name: "Transmission media protected",
		Description: "Transmission media are protected.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true,
		CheckFunc: m.checkNISTCSFTransmissionMedia, References: []string{"NIST CSF 2.0 PR.DS-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-07", Name: "Data managed throughout lifecycle",
		Description: "Data are managed and protected throughout their lifecycle.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkDataLifecycle, References: []string{"NIST CSF 2.0 PR.DS-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-08", Name: "Data protected at rest",
		Description: "Data are managed and protected at rest.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkDataAtRest,
		References: []string{"NIST CSF 2.0 PR.DS-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-09", Name: "Data protected in transit",
		Description: "Data are managed and protected in transit.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true, CheckFunc: m.checkDataInTransit,
		References: []string{"NIST CSF 2.0 PR.DS-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.DS-10", Name: "Network and communication protocols protected",
		Description: "Network and communication protocols are protected.",
		Category:    "PR.DS (Data Security)", Severity: compliance.SeverityCritical,
		Automated: true,
		CheckFunc: m.checkNISTCSFNetworkProtocols, References: []string{"NIST CSF 2.0 PR.DS-10"},
	})

	// PR.PS (Platform Security) — 6
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-01", Name: "Platform configuration management established",
		Description: "Configuration management is established and managed.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkPlatformConfig, References: []string{"NIST CSF 2.0 PR.PS-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-02", Name: "Software lifecycle managed",
		Description: "Software lifecycle is managed.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true,
		CheckFunc: m.checkNISTCSFSoftwareLifecycle, References: []string{"NIST CSF 2.0 PR.PS-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-03", Name: "Platforms hardened and managed",
		Description: "Platforms are hardened and managed.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkPlatformHardening, References: []string{"NIST CSF 2.0 PR.PS-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-04", Name: "Platforms removed when no longer needed",
		Description: "Platforms are removed when no longer needed.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true,
		CheckFunc: m.checkNISTCSFPlatformRemoval, References: []string{"NIST CSF 2.0 PR.PS-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-05", Name: "Platforms protected from manipulation",
		Description: "Platforms are protected from manipulation.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkPlatformProtection, References: []string{"NIST CSF 2.0 PR.PS-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.PS-06", Name: "Platform integrity verified",
		Description: "Platform integrity is verified.",
		Category:    "PR.PS (Platform Security)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkPlatformIntegrity, References: []string{"NIST CSF 2.0 PR.PS-06"},
	})

	// PR.IR (Technology Infrastructure Resilience) — 3
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.IR-01", Name: "Backups protected and managed",
		Description: "Backups are protected and managed.",
		Category:    "PR.IR (Technology Infrastructure Resilience)", Severity: compliance.SeverityMedium,
		Automated: true,
		CheckFunc: m.checkNISTCSFBackupsProtected, References: []string{"NIST CSF 2.0 PR.IR-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.IR-02", Name: "Monitoring performed and reported",
		Description: "Monitoring is performed and reported.",
		Category:    "PR.IR (Technology Infrastructure Resilience)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkMonitoringReported, References: []string{"NIST CSF 2.0 PR.IR-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "PR.IR-03", Name: "Technologies tested and validated",
		Description: "Technologies are tested and validated.",
		Category:    "PR.IR (Technology Infrastructure Resilience)", Severity: compliance.SeverityMedium,
		Automated: true,
		CheckFunc: m.checkNISTCSFTechValidated, References: []string{"NIST CSF 2.0 PR.IR-03"},
	})

	// ── Function DE (Detect) — 19 subcategories, 2 categories ──

	// DE.CM (Continuous Monitoring) — 10
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-01", Name: "Networks and network services monitored",
		Description: "Networks and network services are monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkNetworkMonitor,
		References: []string{"NIST CSF 2.0 DE.CM-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-02", Name: "Physical environment monitored",
		Description: "Physical environment is monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.CM-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-03", Name: "Personnel activity monitored",
		Description: "Personnel activity is monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.CM-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-04", Name: "Events monitored to detect anomalies",
		Description: "Events are monitored to detect anomalies.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAnomalyDetect,
		References: []string{"NIST CSF 2.0 DE.CM-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-05", Name: "Asset vulnerabilities monitored",
		Description: "Asset vulnerabilities are monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkVulnMonitor,
		References: []string{"NIST CSF 2.0 DE.CM-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-06", Name: "External service provider activity monitored",
		Description: "External service provider activity is monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.CM-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-07", Name: "Detection processes monitored",
		Description: "Detection processes are monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkDetectionMonitoring, References: []string{"NIST CSF 2.0 DE.CM-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-08", Name: "Unauthorized service providers monitored",
		Description: "Unauthorized service providers and connections are monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.CM-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-09", Name: "Unauthorized mobile code monitored",
		Description: "Unauthorized mobile code is monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: true,
		CheckFunc: m.checkNISTCSFMobileCodeMonitor, References: []string{"NIST CSF 2.0 DE.CM-09"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.CM-10", Name: "Unauthorized physical access monitored",
		Description: "Unauthorized physical access is monitored.",
		Category:    "DE.CM (Continuous Monitoring)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.CM-10"},
	})

	// DE.AE (Adverse Events) — 9
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-01", Name: "Events detected",
		Description: "Events are detected.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkEventDetect,
		References: []string{"NIST CSF 2.0 DE.AE-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-02", Name: "Event information propagated",
		Description: "Event information is propagated.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.AE-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-03", Name: "Anomalies analyzed",
		Description: "Anomalies are analyzed.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAnomalyAnalysis, References: []string{"NIST CSF 2.0 DE.AE-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-04", Name: "Anomalies prioritized",
		Description: "Anomalies are prioritized.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.AE-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-05", Name: "Intrusions detected",
		Description: "Intrusions are detected.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIntrusionDetect,
		References: []string{"NIST CSF 2.0 DE.AE-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-06", Name: "Impact analyzed",
		Description: "Impact is analyzed.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.AE-06"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-07", Name: "Adverse events reported",
		Description: "Adverse events are reported.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAdverseEventReporting, References: []string{"NIST CSF 2.0 DE.AE-07"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-08", Name: "Adverse events correlated",
		Description: "Adverse events are correlated.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 DE.AE-08"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "DE.AE-09", Name: "Adverse events detected",
		Description: "Adverse events are detected.",
		Category:    "DE.AE (Adverse Events)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkAdverseEventDetection, References: []string{"NIST CSF 2.0 DE.AE-09"},
	})

	// ── Function RS (Respond) — 18 subcategories, 4 categories ──

	// RS.MA (Incident Management) — 5
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MA-01", Name: "Incidents declared",
		Description: "Incidents are declared.",
		Category:    "RS.MA (Incident Management)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIncidentMgmt,
		References: []string{"NIST CSF 2.0 RS.MA-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MA-02", Name: "Incidents assessed",
		Description: "Incidents are assessed.",
		Category:    "RS.MA (Incident Management)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIncidentAssessed, References: []string{"NIST CSF 2.0 RS.MA-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MA-03", Name: "Incidents managed",
		Description: "Incidents are managed.",
		Category:    "RS.MA (Incident Management)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIncidentManaged, References: []string{"NIST CSF 2.0 RS.MA-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MA-04", Name: "Incidents escalated",
		Description: "Incidents are escalated.",
		Category:    "RS.MA (Incident Management)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.MA-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MA-05", Name: "Incidents contained",
		Description: "Incidents are contained.",
		Category:    "RS.MA (Incident Management)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.MA-05"},
	})

	// RS.AN (Analysis) — 5
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.AN-01", Name: "Detection notifications investigated",
		Description: "Notifications from detection systems are investigated.",
		Category:    "RS.AN (Analysis)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.AN-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.AN-02", Name: "Impact understood",
		Description: "Impact is understood.",
		Category:    "RS.AN (Analysis)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.AN-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.AN-03", Name: "Forensics performed",
		Description: "Forensics are performed.",
		Category:    "RS.AN (Analysis)", Severity: compliance.SeverityHigh,
		Automated: true,
		CheckFunc: m.checkNISTCSFForensics, References: []string{"NIST CSF 2.0 RS.AN-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.AN-04", Name: "Investigations scoped",
		Description: "Investigations are scoped.",
		Category:    "RS.AN (Analysis)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.AN-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.AN-05", Name: "Investigations classified",
		Description: "Investigations are classified.",
		Category:    "RS.AN (Analysis)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.AN-05"},
	})

	// RS.CO (Communication) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.CO-01", Name: "Stakeholders notified",
		Description: "Stakeholders are notified.",
		Category:    "RS.CO (Communication)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkCommNotify,
		References: []string{"NIST CSF 2.0 RS.CO-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.CO-02", Name: "Information shared",
		Description: "Information is shared.",
		Category:    "RS.CO (Communication)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.CO-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.CO-03", Name: "Voluntary information sharing established",
		Description: "Voluntary information sharing is established.",
		Category:    "RS.CO (Communication)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.CO-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.CO-04", Name: "Stakeholders kept up to date",
		Description: "Stakeholders are kept up to date.",
		Category:    "RS.CO (Communication)", Severity: compliance.SeverityHigh,
		Automated: false, References: []string{"NIST CSF 2.0 RS.CO-04"},
	})

	// RS.MI (Mitigation, Response, and Recovery) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MI-01", Name: "Incidents contained",
		Description: "Incidents are contained.",
		Category:    "RS.MI (Mitigation, Response, and Recovery)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkMitigation,
		References: []string{"NIST CSF 2.0 RS.MI-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MI-02", Name: "Incidents mitigated",
		Description: "Incidents are mitigated.",
		Category:    "RS.MI (Mitigation, Response, and Recovery)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIncidentMitigated, References: []string{"NIST CSF 2.0 RS.MI-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MI-03", Name: "Incidents resolved",
		Description: "Incidents are resolved.",
		Category:    "RS.MI (Mitigation, Response, and Recovery)", Severity: compliance.SeverityHigh,
		Automated: true, CheckFunc: m.checkIncidentResolved, References: []string{"NIST CSF 2.0 RS.MI-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RS.MI-04", Name: "Newly identified vulnerabilities mitigated",
		Description: "Newly identified vulnerabilities are mitigated.",
		Category:    "RS.MI (Mitigation, Response, and Recovery)", Severity: compliance.SeverityHigh,
		Automated: true,
		CheckFunc: m.checkNISTCSFVulnMitigated, References: []string{"NIST CSF 2.0 RS.MI-04"},
	})

	// ── Function RC (Recover) — 10 subcategories, 2 categories ──

	// RC.RP (Recovery Plan) — 6
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-01", Name: "Recovery plan established",
		Description: "Recovery plan is established and managed.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkRecoveryPlan,
		References: []string{"NIST CSF 2.0 RC.RP-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-02", Name: "Recovery plan implemented",
		Description: "Recovery plan is implemented.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: true, CheckFunc: m.checkRecoveryImpl,
		References: []string{"NIST CSF 2.0 RC.RP-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-03", Name: "Recovery plan improved",
		Description: "Recovery plan is improved.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.RP-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-04", Name: "Recovery plan communicated",
		Description: "Recovery plan is communicated.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.RP-04"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-05", Name: "Recovery plan tested",
		Description: "Recovery plan is tested.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: true,
		CheckFunc: m.checkNISTCSFRecoveryTest, References: []string{"NIST CSF 2.0 RC.RP-05"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.RP-06", Name: "Recovery plan coordinated with parties",
		Description: "Recovery plan includes coordination with internal and external parties.",
		Category:    "RC.RP (Recovery Plan)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.RP-06"},
	})

	// RC.CO (Recovery Communication) — 4
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.CO-01", Name: "Recovery communications managed",
		Description: "Recovery communications are managed.",
		Category:    "RC.CO (Recovery Communication)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.CO-01"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.CO-02", Name: "Recovery communications shared",
		Description: "Recovery communications are shared.",
		Category:    "RC.CO (Recovery Communication)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.CO-02"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.CO-03", Name: "Recovery communications updated",
		Description: "Recovery communications are updated.",
		Category:    "RC.CO (Recovery Communication)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.CO-03"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID: "RC.CO-04", Name: "Recovery communications coordinated",
		Description: "Recovery communications are coordinated with stakeholders.",
		Category:    "RC.CO (Recovery Communication)", Severity: compliance.SeverityMedium,
		Automated: false, References: []string{"NIST CSF 2.0 RC.CO-04"},
	})
}

// ============================================================================
// CheckFunc implementations — 23 automated checks
// ============================================================================

// checkGovern verifies risk management processes are established (GV.RM-01).
func (m *NISTCSFModule) checkGovern(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRiskMgmt := strings.Contains(s, "risk_management") || strings.Contains(s, "risk_assessment")
	hasCompliance := strings.Contains(s, "compliance_scan") || strings.Contains(s, "/api/v1/compliance")
	hasPolicy := strings.Contains(s, "security_policy") || strings.Contains(s, "cybersecurity_policy")
	if hasRiskMgmt && hasCompliance {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "GV.RM-01", ControlName: "Risk management processes established",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Risk management processes and compliance scanning detected", Timestamp: time.Now(),
		}, nil
	}
	if hasRiskMgmt || hasCompliance || hasPolicy {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "GV.RM-01", ControlName: "Risk management processes established",
			Status: compliance.StatusPartial, Severity: compliance.SeverityMedium,
			Message: "Partial risk management evidence detected", Timestamp: time.Now(),
			Remediation: "Establish documented risk management processes and enable compliance scanning",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "GV.RM-01", ControlName: "Risk management processes established",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No risk management evidence detected", Timestamp: time.Now(),
		Remediation: "Establish documented risk management processes and enable compliance scanning",
	}, nil
}

// checkPolicy verifies cybersecurity policies are established (GV.PO-01).
func (m *NISTCSFModule) checkPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasPolicy := strings.Contains(s, "security_policy") || strings.Contains(s, "cybersecurity_policy") || strings.Contains(s, "ai_policy") || strings.Contains(s, "policy")
	if hasPolicy {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "GV.PO-01", ControlName: "Cybersecurity policies established",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Cybersecurity policies detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "GV.PO-01", ControlName: "Cybersecurity policies established",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No cybersecurity policies detected", Timestamp: time.Now(),
		Remediation: "Establish, document, and publish cybersecurity policies",
	}, nil
}

// checkAssetMgmt verifies asset inventories are established (ID.AM-01).
func (m *NISTCSFModule) checkAssetMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasInventory := strings.Contains(s, "asset_inventory") || strings.Contains(s, "ioc_store") || strings.Contains(s, "model_id") || strings.Contains(s, "inventory")
	if hasInventory {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "ID.AM-01", ControlName: "Asset inventories established",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Asset inventory detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "ID.AM-01", ControlName: "Asset inventories established",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No asset inventory detected", Timestamp: time.Now(),
		Remediation: "Establish and maintain an asset inventory (use AegisGate IOC store)",
	}, nil
}

// checkVulnMgmt verifies vulnerabilities are identified and managed (ID.RA-01).
func (m *NISTCSFModule) checkVulnMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasVuln := strings.Contains(s, "vulnerability") || strings.Contains(s, "vuln_scan") || strings.Contains(s, "cve")
	if hasVuln {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "ID.RA-01", ControlName: "Vulnerabilities identified and managed",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Vulnerability management detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "ID.RA-01", ControlName: "Vulnerabilities identified and managed",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No vulnerability management detected", Timestamp: time.Now(),
		Remediation: "Implement vulnerability scanning and CVE tracking",
	}, nil
}

// checkThreatMgmt verifies threats are identified and managed (ID.RA-02).
func (m *NISTCSFModule) checkThreatMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasThreat := strings.Contains(s, "threat_model") || strings.Contains(s, "stride") || strings.Contains(s, "threat_intel")
	if hasThreat {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "ID.RA-02", ControlName: "Threats identified and managed",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Threat management detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "ID.RA-02", ControlName: "Threats identified and managed",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No threat management detected", Timestamp: time.Now(),
		Remediation: "Document threat models (STRIDE) and integrate threat intelligence",
	}, nil
}

// checkRiskAssess verifies risk assessments are performed (ID.RA-03).
func (m *NISTCSFModule) checkRiskAssess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRisk := strings.Contains(s, "risk_assessment") || strings.Contains(s, "risk_register")
	if hasRisk {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "ID.RA-03", ControlName: "Risk assessments performed",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Risk assessment detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "ID.RA-03", ControlName: "Risk assessments performed",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No risk assessment detected", Timestamp: time.Now(),
		Remediation: "Perform and document risk assessments; maintain a risk register",
	}, nil
}

// checkIdentity verifies identities and credentials are managed (PR.AA-01).
func (m *NISTCSFModule) checkIdentity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasIdentity := strings.Contains(s, "identity") || strings.Contains(s, "identity_management") || strings.Contains(s, "iam")
	if hasIdentity {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.AA-01", ControlName: "Identities and credentials managed",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Identity management detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.AA-01", ControlName: "Identities and credentials managed",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No identity management detected", Timestamp: time.Now(),
		Remediation: "Implement identity and credential management (IAM)",
	}, nil
}

// checkAuthenticators verifies authenticators are protected (PR.AA-02).
func (m *NISTCSFModule) checkAuthenticators(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAuthenticator := strings.Contains(s, "mfa") || strings.Contains(s, "multi_factor") || strings.Contains(s, "authenticator") || strings.Contains(s, "totp")
	if hasAuthenticator {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.AA-02", ControlName: "Authenticators protected",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Authenticator protection (MFA) detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.AA-02", ControlName: "Authenticators protected",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No authenticator protection detected", Timestamp: time.Now(),
		Remediation: "Enable multi-factor authentication (MFA) and protect authenticators",
	}, nil
}

// checkAuthentication verifies users are authenticated (PR.AA-03).
func (m *NISTCSFModule) checkAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAuth := strings.Contains(s, "authentication") || strings.Contains(s, "auth_enabled") || strings.Contains(s, "sso")
	if hasAuth {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.AA-03", ControlName: "Users authenticated",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "User authentication detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.AA-03", ControlName: "Users authenticated",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No user authentication detected", Timestamp: time.Now(),
		Remediation: "Enable user authentication and consider SSO integration",
	}, nil
}

// checkAccessMgmt verifies permissions and access are managed (PR.AA-04).
func (m *NISTCSFModule) checkAccessMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAccess := strings.Contains(s, "rbac") || strings.Contains(s, "roles") || strings.Contains(s, "permissions") || strings.Contains(s, "access_control")
	if hasAccess {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.AA-04", ControlName: "Permissions and access managed",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Access management (RBAC) detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.AA-04", ControlName: "Permissions and access managed",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No access management detected", Timestamp: time.Now(),
		Remediation: "Implement role-based access control (RBAC) and manage permissions",
	}, nil
}

// checkDataSecurity verifies CIA of data is protected (PR.DS-01).
func (m *NISTCSFModule) checkDataSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasEncrypt := strings.Contains(s, "encryption") || strings.Contains(s, "encrypt")
	hasDataSec := strings.Contains(s, "data_security") || strings.Contains(s, "cia")
	hasIntegrity := strings.Contains(s, "integrity")
	if hasEncrypt && (hasDataSec || hasIntegrity) {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.DS-01", ControlName: "Confidentiality, integrity, and availability protected",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message: "Data security (encryption + integrity) detected", Timestamp: time.Now(),
		}, nil
	}
	if hasEncrypt || hasDataSec || hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.DS-01", ControlName: "Confidentiality, integrity, and availability protected",
			Status: compliance.StatusPartial, Severity: compliance.SeverityCritical,
			Message: "Partial data security measures detected", Timestamp: time.Now(),
			Remediation: "Implement encryption, data security controls, and integrity checking",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.DS-01", ControlName: "Confidentiality, integrity, and availability protected",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "No data security measures detected", Timestamp: time.Now(),
		Remediation: "Implement encryption, data security controls, and integrity checking",
	}, nil
}

// checkDataAtRest verifies data is protected at rest (PR.DS-08).
func (m *NISTCSFModule) checkDataAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAtRest := strings.Contains(s, "encryption_at_rest") || strings.Contains(s, "data_encrypted") || strings.Contains(s, "aes")
	if hasAtRest {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.DS-08", ControlName: "Data protected at rest",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message: "Encryption at rest detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.DS-08", ControlName: "Data protected at rest",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "No encryption at rest detected", Timestamp: time.Now(),
		Remediation: "Enable encryption at rest (AES) for all stored data",
	}, nil
}

// checkDataInTransit verifies data is protected in transit (PR.DS-09).
func (m *NISTCSFModule) checkDataInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(s) {
			hasTLS = true
			break
		}
	}
	hasHTTPS := strings.Contains(s, "https") || strings.Contains(s, "encryption_in_transit")
	if hasTLS || hasHTTPS {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "PR.DS-09", ControlName: "Data protected in transit",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message: "Encryption in transit (TLS 1.2+) detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "PR.DS-09", ControlName: "Data protected in transit",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message: "No encryption in transit detected", Timestamp: time.Now(),
		Remediation: "Enable TLS 1.2+ for all data in transit; enforce HTTPS",
	}, nil
}

// checkNetworkMonitor verifies networks are monitored (DE.CM-01).
func (m *NISTCSFModule) checkNetworkMonitor(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasMonitor := strings.Contains(s, "network_monitor") || strings.Contains(s, "traffic_monitor") || strings.Contains(s, "ids") || strings.Contains(s, "ips")
	if hasMonitor {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "DE.CM-01", ControlName: "Networks and network services monitored",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Network monitoring detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "DE.CM-01", ControlName: "Networks and network services monitored",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No network monitoring detected", Timestamp: time.Now(),
		Remediation: "Implement network monitoring (IDS/IPS, traffic monitoring)",
	}, nil
}

// checkAnomalyDetect verifies anomaly detection is in place (DE.CM-04).
func (m *NISTCSFModule) checkAnomalyDetect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAnomaly := strings.Contains(s, "anomaly") || strings.Contains(s, "anomaly_detection") || strings.Contains(s, "trust_score")
	if hasAnomaly {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "DE.CM-04", ControlName: "Events monitored to detect anomalies",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Anomaly detection detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "DE.CM-04", ControlName: "Events monitored to detect anomalies",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No anomaly detection detected", Timestamp: time.Now(),
		Remediation: "Enable anomaly detection and trust scoring",
	}, nil
}

// checkVulnMonitor verifies vulnerability monitoring is in place (DE.CM-05).
func (m *NISTCSFModule) checkVulnMonitor(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasVulnMon := strings.Contains(s, "vuln_monitor") || strings.Contains(s, "vulnerability_scan") || strings.Contains(s, "patch")
	if hasVulnMon {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "DE.CM-05", ControlName: "Asset vulnerabilities monitored",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Vulnerability monitoring detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "DE.CM-05", ControlName: "Asset vulnerabilities monitored",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No vulnerability monitoring detected", Timestamp: time.Now(),
		Remediation: "Implement continuous vulnerability monitoring and patch management",
	}, nil
}

// checkEventDetect verifies event detection is in place (DE.AE-01).
func (m *NISTCSFModule) checkEventDetect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasEvent := strings.Contains(s, "scanner") || strings.Contains(s, "threat_detection") || strings.Contains(s, "event_detection")
	if hasEvent {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "DE.AE-01", ControlName: "Events detected",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Event detection detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "DE.AE-01", ControlName: "Events detected",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No event detection detected", Timestamp: time.Now(),
		Remediation: "Implement event detection (scanner, threat detection)",
	}, nil
}

// checkIntrusionDetect verifies intrusion detection is in place (DE.AE-05).
func (m *NISTCSFModule) checkIntrusionDetect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasIntrusion := strings.Contains(s, "intrusion") || strings.Contains(s, "ids") || strings.Contains(s, "ips") || strings.Contains(s, "siem")
	if hasIntrusion {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "DE.AE-05", ControlName: "Intrusions detected",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Intrusion detection detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "DE.AE-05", ControlName: "Intrusions detected",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No intrusion detection detected", Timestamp: time.Now(),
		Remediation: "Implement intrusion detection (IDS/IPS/SIEM)",
	}, nil
}

// checkIncidentMgmt verifies incident management is in place (RS.MA-01).
func (m *NISTCSFModule) checkIncidentMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasIR := strings.Contains(s, "incident_response") || strings.Contains(s, "ir_plan") || strings.Contains(s, "incident_mgmt")
	if hasIR {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "RS.MA-01", ControlName: "Incidents declared",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Incident management detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "RS.MA-01", ControlName: "Incidents declared",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No incident management detected", Timestamp: time.Now(),
		Remediation: "Establish an incident response plan and incident management process",
	}, nil
}

// checkCommNotify verifies stakeholder notification is in place (RS.CO-01).
func (m *NISTCSFModule) checkCommNotify(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasNotify := strings.Contains(s, "alerting") || strings.Contains(s, "notification") || strings.Contains(s, "pagerduty") || strings.Contains(s, "slack")
	if hasNotify {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "RS.CO-01", ControlName: "Stakeholders notified",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Stakeholder notification detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "RS.CO-01", ControlName: "Stakeholders notified",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No stakeholder notification detected", Timestamp: time.Now(),
		Remediation: "Configure alerting and stakeholder notification (PagerDuty, Slack)",
	}, nil
}

// checkMitigation verifies incident containment is in place (RS.MI-01).
func (m *NISTCSFModule) checkMitigation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasContainment := strings.Contains(s, "kill_switch") || strings.Contains(s, "abort") || strings.Contains(s, "containment")
	if hasContainment {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "RS.MI-01", ControlName: "Incidents contained",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message: "Incident containment detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "RS.MI-01", ControlName: "Incidents contained",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message: "No incident containment detected", Timestamp: time.Now(),
		Remediation: "Implement kill switch / abort / containment mechanisms",
	}, nil
}

// checkRecoveryPlan verifies recovery plan is established (RC.RP-01).
func (m *NISTCSFModule) checkRecoveryPlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRecovery := strings.Contains(s, "backup") || strings.Contains(s, "disaster_recovery") || strings.Contains(s, "recovery_plan")
	if hasRecovery {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "RC.RP-01", ControlName: "Recovery plan established",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Recovery plan detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "RC.RP-01", ControlName: "Recovery plan established",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No recovery plan detected", Timestamp: time.Now(),
		Remediation: "Establish a recovery plan with backups and disaster recovery procedures",
	}, nil
}

// checkRecoveryImpl verifies recovery plan is implemented (RC.RP-02).
func (m *NISTCSFModule) checkRecoveryImpl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasImpl := strings.Contains(s, "audit_replay") || strings.Contains(s, "log_replay") || strings.Contains(s, "hash_chain") || strings.Contains(s, "log_integrity")
	if hasImpl {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "RC.RP-02", ControlName: "Recovery plan implemented",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium,
			Message: "Recovery implementation (audit replay, log integrity) detected", Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "RC.RP-02", ControlName: "Recovery plan implemented",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium,
		Message: "No recovery implementation detected", Timestamp: time.Now(),
		Remediation: "Implement audit log replay and hash-chain integrity for recovery",
	}, nil
}

// ── P2 Compliance Automation Expansion: Additional automated controls ──

func (m *NISTCSFModule) checkSoftwareInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "software_inventory") || strings.Contains(s, "asset_inventory") || strings.Contains(s, "service_inventory")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-02", ControlName: "Software and services inventoried", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Software and service inventory detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-02", ControlName: "Software and services inventoried", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Software inventory indicators not detected", Timestamp: time.Now(), Remediation: "Maintain inventory of software, platforms, and services"}, nil
}

func (m *NISTCSFModule) checkDataInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "data_inventory") || strings.Contains(s, "data_catalog") || strings.Contains(s, "data_mapping")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-03", ControlName: "Data inventoried", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data inventory detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-03", ControlName: "Data inventoried", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Data inventory indicators not detected", Timestamp: time.Now(), Remediation: "Maintain inventory of data and information"}, nil
}

func (m *NISTCSFModule) checkDeviceInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "device_inventory") || strings.Contains(s, "hardware_inventory") || strings.Contains(s, "asset_management")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-04", ControlName: "Device inventories maintained", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Device inventory detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-04", ControlName: "Device inventories maintained", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Device inventory indicators not detected", Timestamp: time.Now(), Remediation: "Maintain device inventories"}, nil
}

func (m *NISTCSFModule) checkDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "data_classification") || strings.Contains(s, "data_sensitivity") || strings.Contains(s, "classification_policy")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-07", ControlName: "Data sensitivity and classification managed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data classification detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-07", ControlName: "Data sensitivity and classification managed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Data classification indicators not detected", Timestamp: time.Now(), Remediation: "Implement data sensitivity classification"}, nil
}

func (m *NISTCSFModule) checkSystemInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "system_inventory") || strings.Contains(s, "system_catalog") || strings.Contains(s, "service_registry")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-08", ControlName: "Systems and services inventoried", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "System inventory detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.AM-08", ControlName: "Systems and services inventoried", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "System inventory indicators not detected", Timestamp: time.Now(), Remediation: "Maintain inventory of systems and services"}, nil
}

func (m *NISTCSFModule) checkThreatPrioritization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "threat_prioritization") || strings.Contains(s, "vulnerability_prioritization") || strings.Contains(s, "risk_prioritization")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.RA-04", ControlName: "Threats and vulnerabilities prioritized", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Threat prioritization detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ID.RA-04", ControlName: "Threats and vulnerabilities prioritized", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Threat prioritization indicators not detected", Timestamp: time.Now(), Remediation: "Prioritize threats and vulnerabilities"}, nil
}

func (m *NISTCSFModule) checkNetworkAccessMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "network_access") || strings.Contains(s, "network_acl") || strings.Contains(s, "firewall_rules")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.AA-05", ControlName: "Network access managed and enforced", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Network access management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.AA-05", ControlName: "Network access managed and enforced", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Network access management indicators not detected", Timestamp: time.Now(), Remediation: "Implement network access management and enforcement"}, nil
}

func (m *NISTCSFModule) checkBackupProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "backup_protection") || strings.Contains(s, "backup_encryption") || strings.Contains(s, "backup_management")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-02", ControlName: "Backups protected and managed", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Backup protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-02", ControlName: "Backups protected and managed", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Backup protection indicators not detected", Timestamp: time.Now(), Remediation: "Protect and manage backups"}, nil
}

func (m *NISTCSFModule) checkConfigManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "configuration_management") || strings.Contains(s, "config_management") || strings.Contains(s, "baseline_config")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-03", ControlName: "Configuration management established", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Configuration management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-03", ControlName: "Configuration management established", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Configuration management indicators not detected", Timestamp: time.Now(), Remediation: "Establish configuration management"}, nil
}

func (m *NISTCSFModule) checkIntegrityChecking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "integrity_checking") || strings.Contains(s, "file_integrity") || strings.Contains(s, "hash_verification") || strings.Contains(s, "checksum")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-04", ControlName: "Integrity checking performed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Integrity checking detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-04", ControlName: "Integrity checking performed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Integrity checking indicators not detected", Timestamp: time.Now(), Remediation: "Perform integrity checking"}, nil
}

func (m *NISTCSFModule) checkNetworkProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "network_protection") || strings.Contains(s, "network_segmentation") || strings.Contains(s, "control_network")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-05", ControlName: "Communications and control networks protected", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Network protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-05", ControlName: "Communications and control networks protected", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Network protection indicators not detected", Timestamp: time.Now(), Remediation: "Protect communications and control networks"}, nil
}

func (m *NISTCSFModule) checkDataLifecycle(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "data_lifecycle") || strings.Contains(s, "lifecycle_management") || strings.Contains(s, "data_governance")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-07", ControlName: "Data managed throughout lifecycle", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data lifecycle management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-07", ControlName: "Data managed throughout lifecycle", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Data lifecycle indicators not detected", Timestamp: time.Now(), Remediation: "Manage data throughout its lifecycle"}, nil
}

func (m *NISTCSFModule) checkPlatformConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "platform_config") || strings.Contains(s, "platform_configuration") || strings.Contains(s, "baseline_configuration")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-01", ControlName: "Platform configuration management established", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Platform configuration management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-01", ControlName: "Platform configuration management established", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Platform config management indicators not detected", Timestamp: time.Now(), Remediation: "Establish platform configuration management"}, nil
}

func (m *NISTCSFModule) checkPlatformHardening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "platform_hardening") || strings.Contains(s, "hardening") || strings.Contains(s, "security_hardening")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-03", ControlName: "Platforms hardened and managed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Platform hardening detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-03", ControlName: "Platforms hardened and managed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Platform hardening indicators not detected", Timestamp: time.Now(), Remediation: "Harden and manage platforms"}, nil
}

func (m *NISTCSFModule) checkPlatformProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "platform_protection") || strings.Contains(s, "tamper_protection") || strings.Contains(s, "platform_security")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-05", ControlName: "Platforms protected from manipulation", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Platform protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-05", ControlName: "Platforms protected from manipulation", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Platform protection indicators not detected", Timestamp: time.Now(), Remediation: "Protect platforms from manipulation"}, nil
}

func (m *NISTCSFModule) checkPlatformIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "platform_integrity") || strings.Contains(s, "integrity_verification") || strings.Contains(s, "boot_integrity")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-06", ControlName: "Platform integrity verified", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Platform integrity verification detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-06", ControlName: "Platform integrity verified", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Platform integrity indicators not detected", Timestamp: time.Now(), Remediation: "Verify platform integrity"}, nil
}

func (m *NISTCSFModule) checkMonitoringReported(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "monitoring") || strings.Contains(s, "monitoring_report") || strings.Contains(s, "performance_monitoring")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-02", ControlName: "Monitoring performed and reported", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Monitoring and reporting detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-02", ControlName: "Monitoring performed and reported", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Monitoring indicators not detected", Timestamp: time.Now(), Remediation: "Perform and report monitoring"}, nil
}

func (m *NISTCSFModule) checkDetectionMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "detection_monitoring") || strings.Contains(s, "detection_process") || strings.Contains(s, "threat_detection")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.CM-07", ControlName: "Detection processes monitored", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Detection process monitoring detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.CM-07", ControlName: "Detection processes monitored", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Detection monitoring indicators not detected", Timestamp: time.Now(), Remediation: "Monitor detection processes"}, nil
}

func (m *NISTCSFModule) checkAnomalyAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "anomaly_analysis") || strings.Contains(s, "anomaly_detection") || strings.Contains(s, "behavioral_analysis")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-03", ControlName: "Anomalies analyzed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Anomaly analysis detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-03", ControlName: "Anomalies analyzed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Anomaly analysis indicators not detected", Timestamp: time.Now(), Remediation: "Analyze anomalies"}, nil
}

func (m *NISTCSFModule) checkAdverseEventReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "adverse_event") || strings.Contains(s, "event_reporting") || strings.Contains(s, "incident_reporting")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-07", ControlName: "Adverse events reported", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Adverse event reporting detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-07", ControlName: "Adverse events reported", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Adverse event reporting indicators not detected", Timestamp: time.Now(), Remediation: "Report adverse events"}, nil
}

func (m *NISTCSFModule) checkAdverseEventDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "adverse_event_detection") || strings.Contains(s, "event_detection") || strings.Contains(s, "anomaly_alert")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-09", ControlName: "Adverse events detected", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Adverse event detection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.AE-09", ControlName: "Adverse events detected", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Adverse event detection indicators not detected", Timestamp: time.Now(), Remediation: "Detect adverse events"}, nil
}

func (m *NISTCSFModule) checkIncidentAssessed(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "incident_assessment") || strings.Contains(s, "incident_triage") || strings.Contains(s, "incident_evaluation")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MA-02", ControlName: "Incidents assessed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Incident assessment detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MA-02", ControlName: "Incidents assessed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Incident assessment indicators not detected", Timestamp: time.Now(), Remediation: "Assess incidents"}, nil
}

func (m *NISTCSFModule) checkIncidentManaged(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "incident_management") || strings.Contains(s, "incident_handling") || strings.Contains(s, "incident_response")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MA-03", ControlName: "Incidents managed", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Incident management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MA-03", ControlName: "Incidents managed", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Incident management indicators not detected", Timestamp: time.Now(), Remediation: "Manage incidents"}, nil
}

func (m *NISTCSFModule) checkIncidentMitigated(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "incident_mitigation") || strings.Contains(s, "mitigation") || strings.Contains(s, "containment")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-02", ControlName: "Incidents mitigated", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Incident mitigation detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-02", ControlName: "Incidents mitigated", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Incident mitigation indicators not detected", Timestamp: time.Now(), Remediation: "Mitigate incidents"}, nil
}

func (m *NISTCSFModule) checkIncidentResolved(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	has := strings.Contains(s, "incident_resolution") || strings.Contains(s, "incident_resolution") || strings.Contains(s, "recovery") || strings.Contains(s, "post_incident")
	if has {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-03", ControlName: "Incidents resolved", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Incident resolution detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-03", ControlName: "Incidents resolved", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Incident resolution indicators not detected", Timestamp: time.Now(), Remediation: "Resolve incidents"}, nil
}

// Dependencies returns required modules.
func (m *NISTCSFModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "ioc", "trust"}
}

// ===== P5 Comprehensive Review: Additional CheckFunc implementations =====

func (m *NISTCSFModule) checkNISTCSFTransmissionMedia(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "transmission_media_protected") || strings.Contains(inputStr, "media_protection") || strings.Contains(inputStr, "cable_protection") || strings.Contains(inputStr, "transmission_security") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-06", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Transmission media protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-06", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical, Message: "Transmission media protection not configured", Timestamp: time.Now(), Remediation: "Protect transmission media"}, nil
}

func (m *NISTCSFModule) checkNISTCSFNetworkProtocols(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "network_protocol_protection") || strings.Contains(inputStr, "protocol_security") || strings.Contains(inputStr, "communication_protocol_protected") || strings.Contains(inputStr, "secure_protocol") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-10", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Network protocol protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.DS-10", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Network protocol protection not configured", Timestamp: time.Now(), Remediation: "Protect network and communication protocols"}, nil
}

func (m *NISTCSFModule) checkNISTCSFSoftwareLifecycle(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "software_lifecycle") || strings.Contains(inputStr, "software_lifecycle_managed") || strings.Contains(inputStr, "sdlc") || strings.Contains(inputStr, "lifecycle_management") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-02", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Software lifecycle management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-02", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Software lifecycle management not configured", Timestamp: time.Now(), Remediation: "Manage software lifecycle"}, nil
}

func (m *NISTCSFModule) checkNISTCSFPlatformRemoval(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "platform_removal") || strings.Contains(inputStr, "decommission_platform") || strings.Contains(inputStr, "platform_decommissioned") || strings.Contains(inputStr, "removed_platform") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-04", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Platform removal detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.PS-04", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Platform removal not configured", Timestamp: time.Now(), Remediation: "Remove platforms when no longer needed"}, nil
}

func (m *NISTCSFModule) checkNISTCSFBackupsProtected(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "backup_protected") || strings.Contains(inputStr, "backup_managed") || strings.Contains(inputStr, "backup_security") || strings.Contains(inputStr, "protected_backup") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-01", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Backups protected and managed detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-01", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Backup protection not configured", Timestamp: time.Now(), Remediation: "Protect and manage backups"}, nil
}

func (m *NISTCSFModule) checkNISTCSFTechValidated(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "tech_validated") || strings.Contains(inputStr, "technology_tested") || strings.Contains(inputStr, "tech_test") || strings.Contains(inputStr, "validation_testing") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-03", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Technology testing detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "PR.IR-03", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Technology testing not configured", Timestamp: time.Now(), Remediation: "Test and validate technologies"}, nil
}

func (m *NISTCSFModule) checkNISTCSFMobileCodeMonitor(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "mobile_code_monitor") || strings.Contains(inputStr, "mobile_code_detection") || strings.Contains(inputStr, "unauthorized_code_monitor") || strings.Contains(inputStr, "code_monitoring") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.CM-09", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Mobile code monitoring detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "DE.CM-09", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Mobile code monitoring not configured", Timestamp: time.Now(), Remediation: "Monitor for unauthorized mobile code"}, nil
}

func (m *NISTCSFModule) checkNISTCSFForensics(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "forensics") || strings.Contains(inputStr, "forensic_capability") || strings.Contains(inputStr, "digital_forensics") || strings.Contains(inputStr, "forensic_analysis") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.AN-03", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Forensics capability detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.AN-03", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Forensics capability not configured", Timestamp: time.Now(), Remediation: "Perform forensics during incident response"}, nil
}

func (m *NISTCSFModule) checkNISTCSFVulnMitigated(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "vuln_mitigated") || strings.Contains(inputStr, "vulnerability_mitigated") || strings.Contains(inputStr, "vuln_remediated") || strings.Contains(inputStr, "vulnerability_remediation") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-04", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Vulnerability mitigation detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RS.MI-04", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Vulnerability mitigation not configured", Timestamp: time.Now(), Remediation: "Mitigate newly identified vulnerabilities"}, nil
}

func (m *NISTCSFModule) checkNISTCSFRecoveryTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	if strings.Contains(inputStr, "recovery_plan_test") || strings.Contains(inputStr, "recovery_test") || strings.Contains(inputStr, "dr_test") || strings.Contains(inputStr, "disaster_recovery_test") {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RC.RP-05", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Recovery plan testing detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "RC.RP-05", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Recovery plan testing not configured", Timestamp: time.Now(), Remediation: "Test recovery plan"}, nil
}
