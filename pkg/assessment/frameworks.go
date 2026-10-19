// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 3: Compliance Frameworks — 31 frameworks mapped to OWASP LLM Top 10
//
// frameworks.go extends the Phase 1 compliance mapping (5 frameworks) to
// 31 frameworks covering cybersecurity, AI governance, privacy, and
// industry-specific standards. Each framework maps OWASP LLM Top 10
// categories to its control IDs.
//
// Frameworks are organized into tiers:
//   - Tier 1 (Core Cybersecurity): NIST 800-171, SOC 2, ISO 27001, HIPAA, GDPR
//   - Tier 2 (US Government): NIST 800-53, NIST CSF 2.0, FedRAMP, CMMC 2.0, SSDF
//   - Tier 3 (Industry): PCI DSS 4.0, CIS Controls v8, COBIT 2019, ITIL 4, CSA STAR
//   - Tier 4 (AI Governance): NIST AI RMF, ISO 42001, EU AI Act, ENISA AI, CSA AI
//   - Tier 5 (Privacy): CCPA/CPRA, LGPD, PIPL, Singapore PDPA, Canada PIPEDA
//   - Tier 6 (Application Security): OWASP ASVS, OWASP Top 10, CWE Top 25, MITRE ATT&CK

package assessment

import "sort"

// =========================================================================
// Framework Metadata
// =========================================================================

// FrameworkTier classifies a compliance framework by scope.
type FrameworkTier string

const (
	Tier1CoreCyber    FrameworkTier = "Core Cybersecurity"
	Tier2USGov        FrameworkTier = "US Government"
	Tier3Industry     FrameworkTier = "Industry Standards"
	Tier4AIGovernance FrameworkTier = "AI Governance"
	Tier5Privacy      FrameworkTier = "Privacy Regulations"
	Tier6AppSecurity  FrameworkTier = "Application Security"
)

// FrameworkInfo describes a compliance framework.
type FrameworkInfo struct {
	ID          ComplianceFramework `json:"id"`
	Name        string              `json:"name"`
	Tier        FrameworkTier       `json:"tier"`
	Description string              `json:"description"`
}

// =========================================================================
// Framework Constants (31 total)
// =========================================================================

// Tier 1: Core Cybersecurity (Phase 1 — already defined in compliance_map.go)
// FrameworkNIST800171, FrameworkSOC2, FrameworkISO27001, FrameworkHIPAA, FrameworkGDPR

// Tier 2: US Government
const (
	FrameworkNIST80053 ComplianceFramework = "NIST800-53"
	FrameworkNISTCSF   ComplianceFramework = "NIST-CSF-2.0"
	FrameworkFedRAMP   ComplianceFramework = "FedRAMP"
	FrameworkCMMC      ComplianceFramework = "CMMC-2.0"
	FrameworkSSDF      ComplianceFramework = "NIST-SSDF-800-218A"
)

// Tier 3: Industry Standards
const (
	FrameworkPCIDSS  ComplianceFramework = "PCI-DSS-4.0"
	FrameworkCIS     ComplianceFramework = "CIS-Controls-v8"
	FrameworkCOBIT   ComplianceFramework = "COBIT-2019"
	FrameworkITIL    ComplianceFramework = "ITIL-4"
	FrameworkCSASTAR ComplianceFramework = "CSA-STAR"
)

// Tier 4: AI Governance
const (
	FrameworkAIRMF    ComplianceFramework = "NIST-AI-RMF-1.0"
	FrameworkISO42001 ComplianceFramework = "ISO-42001"
	FrameworkEUAIAct  ComplianceFramework = "EU-AI-Act"
	FrameworkENISAAI  ComplianceFramework = "ENISA-AI-Threat"
	FrameworkCSAAI    ComplianceFramework = "CSA-AI-Controls"
	FrameworkISO23894 ComplianceFramework = "ISO-23894"
	FrameworkNIST1270 ComplianceFramework = "NIST-SP-1270"
)

// Tier 5: Privacy Regulations
const (
	FrameworkCCPA   ComplianceFramework = "CCPA-CPRA"
	FrameworkLGPD   ComplianceFramework = "LGPD"
	FrameworkPIPL   ComplianceFramework = "PIPL"
	FrameworkPDPA   ComplianceFramework = "SG-PDPA"
	FrameworkPIPEDA ComplianceFramework = "PIPEDA"
)

// Tier 6: Application Security
const (
	FrameworkASVS    ComplianceFramework = "OWASP-ASVS"
	FrameworkOWASP10 ComplianceFramework = "OWASP-Top-10"
	FrameworkCWE25   ComplianceFramework = "CWE-Top-25"
	FrameworkATTCK   ComplianceFramework = "MITRE-ATTACK"
)

// =========================================================================
// Framework Registry
// =========================================================================

// frameworkRegistry holds metadata for all 31 supported frameworks.
var frameworkRegistry = []FrameworkInfo{
	// Tier 1: Core Cybersecurity
	{FrameworkNIST800171, "NIST SP 800-171", Tier1CoreCyber, "Protecting CUI in Nonfederal Systems"},
	{FrameworkSOC2, "SOC 2 Type II", Tier1CoreCyber, "Trust Services Criteria for security, availability, confidentiality"},
	{FrameworkISO27001, "ISO/IEC 27001:2022", Tier1CoreCyber, "Information Security Management Systems"},
	{FrameworkHIPAA, "HIPAA Security Rule", Tier1CoreCyber, "Healthcare data protection (45 CFR 164)"},
	{FrameworkGDPR, "GDPR", Tier1CoreCyber, "EU General Data Protection Regulation"},

	// Tier 2: US Government
	{FrameworkNIST80053, "NIST SP 800-53 Rev 5", Tier2USGov, "Security and Privacy Controls for Information Systems"},
	{FrameworkNISTCSF, "NIST Cybersecurity Framework 2.0", Tier2USGov, "Protect, Detect, Respond, Recover, Govern"},
	{FrameworkFedRAMP, "FedRAMP", Tier2USGov, "Federal Risk and Authorization Management Program"},
	{FrameworkCMMC, "CMMC 2.0", Tier2USGov, "Cybersecurity Maturity Model Certification"},
	{FrameworkSSDF, "NIST SP 800-218A (SSDF)", Tier2USGov, "Secure Software Development Framework"},

	// Tier 3: Industry Standards
	{FrameworkPCIDSS, "PCI DSS 4.0", Tier3Industry, "Payment Card Industry Data Security Standard"},
	{FrameworkCIS, "CIS Controls v8", Tier3Industry, "Center for Internet Security Critical Security Controls"},
	{FrameworkCOBIT, "COBIT 2019", Tier3Industry, "Governance and Management of Enterprise IT"},
	{FrameworkITIL, "ITIL 4", Tier3Industry, "Information Technology Infrastructure Library"},
	{FrameworkCSASTAR, "CSA STAR", Tier3Industry, "Cloud Security Alliance Security Trust Assurance Registry"},

	// Tier 4: AI Governance
	{FrameworkAIRMF, "NIST AI RMF 1.0", Tier4AIGovernance, "AI Risk Management Framework (Govern, Map, Measure, Manage)"},
	{FrameworkISO42001, "ISO/IEC 42001:2023", Tier4AIGovernance, "AI Management System Standard"},
	{FrameworkEUAIAct, "EU AI Act", Tier4AIGovernance, "European Union Artificial Intelligence Act"},
	{FrameworkENISAAI, "ENISA AI Threat Landscape", Tier4AIGovernance, "EU Agency for Cybersecurity AI threat taxonomy"},
	{FrameworkCSAAI, "CSA AI Controls", Tier4AIGovernance, "Cloud Security Alliance AI Security Controls"},
	{FrameworkISO23894, "ISO/IEC 23894:2024", Tier4AIGovernance, "AI Risk Management Guidance"},
	{FrameworkNIST1270, "NIST SP 1270", Tier4AIGovernance, "AI Safety Framework"},

	// Tier 5: Privacy Regulations
	{FrameworkCCPA, "CCPA/CPRA", Tier5Privacy, "California Consumer Privacy Act / Privacy Rights Act"},
	{FrameworkLGPD, "LGPD", Tier5Privacy, "Brazilian General Data Protection Law"},
	{FrameworkPIPL, "PIPL", Tier5Privacy, "China Personal Information Protection Law"},
	{FrameworkPDPA, "Singapore PDPA", Tier5Privacy, "Personal Data Protection Act"},
	{FrameworkPIPEDA, "PIPEDA", Tier5Privacy, "Canada Personal Information Protection and Electronic Documents Act"},

	// Tier 6: Application Security
	{FrameworkASVS, "OWASP ASVS 4.0", Tier6AppSecurity, "Application Security Verification Standard"},
	{FrameworkOWASP10, "OWASP Top 10:2021", Tier6AppSecurity, "Web Application Security Risks"},
	{FrameworkCWE25, "CWE Top 25", Tier6AppSecurity, "Most Dangerous Software Weaknesses"},
	{FrameworkATTCK, "MITRE ATT&CK", Tier6AppSecurity, "Adversarial Tactics, Techniques, and Procedures"},
}

// SupportedFrameworksV2 returns all 31 supported compliance frameworks.
// This supersedes SupportedFrameworks() (which returns only the 5 Phase 1 frameworks).
func SupportedFrameworksV2() []ComplianceFramework {
	fws := make([]ComplianceFramework, 0, len(frameworkRegistry))
	for _, fi := range frameworkRegistry {
		fws = append(fws, fi.ID)
	}
	return fws
}

// AllFrameworkInfo returns metadata for all supported frameworks, sorted by tier then name.
func AllFrameworkInfo() []FrameworkInfo {
	result := make([]FrameworkInfo, len(frameworkRegistry))
	copy(result, frameworkRegistry)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Tier != result[j].Tier {
			return tierOrder(result[i].Tier) < tierOrder(result[j].Tier)
		}
		return result[i].Name < result[j].Name
	})
	return result
}

// FrameworkInfoByID returns metadata for a specific framework, or nil if not found.
func FrameworkInfoByID(id ComplianceFramework) *FrameworkInfo {
	for i := range frameworkRegistry {
		if frameworkRegistry[i].ID == id {
			return &frameworkRegistry[i]
		}
	}
	return nil
}

// FrameworksByTier returns all frameworks in a given tier.
func FrameworksByTier(tier FrameworkTier) []FrameworkInfo {
	var result []FrameworkInfo
	for _, fi := range frameworkRegistry {
		if fi.Tier == tier {
			result = append(result, fi)
		}
	}
	return result
}

// tierOrder returns a numeric sort order for tiers.
func tierOrder(t FrameworkTier) int {
	switch t {
	case Tier1CoreCyber:
		return 1
	case Tier2USGov:
		return 2
	case Tier3Industry:
		return 3
	case Tier4AIGovernance:
		return 4
	case Tier5Privacy:
		return 5
	case Tier6AppSecurity:
		return 6
	default:
		return 99
	}
}

// =========================================================================
// Extended OWASP → Control Mapping (26 new frameworks)
// =========================================================================

// owaspControlMapV2 extends the Phase 1 owaspControlMap with 26 additional
// frameworks. The Phase 1 map (5 frameworks) is preserved for backward
// compatibility; this map adds the new frameworks.
//
// Each OWASP category maps to the most relevant control IDs per framework.
// Empty slices mean the framework doesn't have a direct control for that
// category (the gap is noted in the compliance posture report).
var owaspControlMapV2 = map[string]map[ComplianceFramework][]string{
	"LLM01": {
		FrameworkNIST80053: {"SI-10", "SI-3", "SC-18"},
		FrameworkNISTCSF:   {"PR.PT-1", "DE.CM-8"},
		FrameworkFedRAMP:   {"SI-10", "SI-3"},
		FrameworkCMMC:      {"SC.3.184", "SI.3.217"},
		FrameworkSSDF:      {"PW.1.1", "PW.7.1"},
		FrameworkPCIDSS:    {"6.2.4", "6.3.3"},
		FrameworkCIS:       {"CIS-16", "CIS-17"},
		FrameworkCOBIT:     {"APO13.1", "DSS05.1"},
		FrameworkITIL:      {"SVS-7", "ITIL-SV-3"},
		FrameworkCSASTAR:   {"IAM-01", "DSP-01"},
		FrameworkAIRMF:     {"MS-1.1", "ME-4.1", "MG-1.2"},
		FrameworkISO42001:  {"A.8.3", "A.9.2"},
		FrameworkEUAIAct:   {"Art.14", "Art.15", "Art.27"},
		FrameworkENISAAI:   {"AI-01", "AI-03"},
		FrameworkCSAAI:     {"AIS-01", "AIS-05"},
		FrameworkISO23894:  {"6.2.3", "6.3.2"},
		FrameworkNIST1270:  {"3.2", "4.1"},
		FrameworkCCPA:      {"1798.150"},
		FrameworkLGPD:      {"Art.46"},
		FrameworkPIPL:      {"Art.24", "Art.55"},
		FrameworkPDPA:      {"Sec.12"},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V13.2", "V1.14"},
		FrameworkOWASP10:   {"A03"},
		FrameworkCWE25:     {"CWE-94", "CWE-74"},
		FrameworkATTCK:     {"T1059", "T1566"},
	},
	"LLM02": {
		FrameworkNIST80053: {"SC-28", "MP-5", "SI-12"},
		FrameworkNISTCSF:   {"PR.DS-1", "PR.DS-5"},
		FrameworkFedRAMP:   {"SC-28", "SI-12"},
		FrameworkCMMC:      {"SC.3.187", "MP.3.122"},
		FrameworkSSDF:      {"PW.6.1", "PW.6.2"},
		FrameworkPCIDSS:    {"3.3", "3.5"},
		FrameworkCIS:       {"CIS-3", "CIS-6"},
		FrameworkCOBIT:     {"APO01.3", "DSS06.2"},
		FrameworkITIL:      {"SVS-5"},
		FrameworkCSASTAR:   {"DSP-01", "DSP-03"},
		FrameworkAIRMF:     {"ME-2.3", "MS-2.2"},
		FrameworkISO42001:  {"A.7.3", "A.8.5"},
		FrameworkEUAIAct:   {"Art.10", "Art.13"},
		FrameworkENISAAI:   {"AI-04", "AI-07"},
		FrameworkCSAAI:     {"AIS-02", "AIS-08"},
		FrameworkISO23894:  {"6.2.4", "6.4.1"},
		FrameworkNIST1270:  {"3.3"},
		FrameworkCCPA:      {"1798.150", "1798.105"},
		FrameworkLGPD:      {"Art.46", "Art.48"},
		FrameworkPIPL:      {"Art.24", "Art.28"},
		FrameworkPDPA:      {"Sec.11", "Sec.12"},
		FrameworkPIPEDA:    {"Sec.4.7", "Sec.4.3.3"},
		FrameworkASVS:      {"V8.3", "V14.3"},
		FrameworkOWASP10:   {"A02", "A04"},
		FrameworkCWE25:     {"CWE-200", "CWE-359"},
		FrameworkATTCK:     {"T1552", "T1530"},
	},
	"LLM03": {
		FrameworkNIST80053: {"SA-11", "SR-11", "SR-3"},
		FrameworkNISTCSF:   {"PR.IP-2", "ID.SC-1"},
		FrameworkFedRAMP:   {"SA-11", "SR-11"},
		FrameworkCMMC:      {"SA.4.169"},
		FrameworkSSDF:      {"PO.1.1", "PS.1.1", "PS.2.1"},
		FrameworkPCIDSS:    {"6.2.4", "6.3.2"},
		FrameworkCIS:       {"CIS-16", "CIS-2"},
		FrameworkCOBIT:     {"APO10.1", "APO12.1"},
		FrameworkITIL:      {"SVS-4"},
		FrameworkCSASTAR:   {"STA-01", "TVM-01"},
		FrameworkAIRMF:     {"MAP-1.2", "MG-2.3"},
		FrameworkISO42001:  {"A.6.2", "A.8.4"},
		FrameworkEUAIAct:   {"Art.9", "Art.16"},
		FrameworkENISAAI:   {"AI-02", "AI-09"},
		FrameworkCSAAI:     {"AIS-03", "AIS-10"},
		FrameworkISO23894:  {"6.1.2", "6.2.5"},
		FrameworkNIST1270:  {"2.3"},
		FrameworkCCPA:      {},
		FrameworkLGPD:      {},
		FrameworkPIPL:      {"Art.55"},
		FrameworkPDPA:      {},
		FrameworkPIPEDA:    {},
		FrameworkASVS:      {"V14.5", "V5.2"},
		FrameworkOWASP10:   {"A06", "A08"},
		FrameworkCWE25:     {"CWE-1104", "CWE-829"},
		FrameworkATTCK:     {"T1195", "T1087"},
	},
	"LLM04": {
		FrameworkNIST80053: {"SI-7", "SI-3", "SC-44"},
		FrameworkNISTCSF:   {"PR.DS-6", "DE.CM-6"},
		FrameworkFedRAMP:   {"SI-7", "SC-44"},
		FrameworkCMMC:      {"SI.3.217"},
		FrameworkSSDF:      {"PW.5.1", "PW.7.1"},
		FrameworkPCIDSS:    {"6.2.4"},
		FrameworkCIS:       {"CIS-7", "CIS-16"},
		FrameworkCOBIT:     {"APO13.1"},
		FrameworkITIL:      {"SVS-7"},
		FrameworkCSASTAR:   {"TVM-01", "DSP-04"},
		FrameworkAIRMF:     {"MS-3.3", "ME-4.2"},
		FrameworkISO42001:  {"A.8.6", "A.9.3"},
		FrameworkEUAIAct:   {"Art.10", "Art.15"},
		FrameworkENISAAI:   {"AI-05", "AI-10"},
		FrameworkCSAAI:     {"AIS-04", "AIS-11"},
		FrameworkISO23894:  {"6.3.3", "6.4.2"},
		FrameworkNIST1270:  {"3.4"},
		FrameworkCCPA:      {"1798.150"},
		FrameworkLGPD:      {"Art.20"},
		FrameworkPIPL:      {"Art.24"},
		FrameworkPDPA:      {},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V14.4"},
		FrameworkOWASP10:   {"A08"},
		FrameworkCWE25:     {"CWE-94", "CWE-506"},
		FrameworkATTCK:     {"T1190", "T1068"},
	},
	"LLM05": {
		FrameworkNIST80053: {"SI-10", "SC-18", "SI-12"},
		FrameworkNISTCSF:   {"PR.PT-1", "PR.DS-1"},
		FrameworkFedRAMP:   {"SI-10", "SI-12"},
		FrameworkCMMC:      {"SI.3.217"},
		FrameworkSSDF:      {"PW.6.1", "PW.7.2"},
		FrameworkPCIDSS:    {"6.2.4", "3.3"},
		FrameworkCIS:       {"CIS-16"},
		FrameworkCOBIT:     {"DSS05.1"},
		FrameworkITIL:      {"SVS-3"},
		FrameworkCSASTAR:   {"DSP-01", "DSP-05"},
		FrameworkAIRMF:     {"ME-2.3", "MS-2.3"},
		FrameworkISO42001:  {"A.8.5", "A.9.2"},
		FrameworkEUAIAct:   {"Art.13", "Art.14"},
		FrameworkENISAAI:   {"AI-06", "AI-11"},
		FrameworkCSAAI:     {"AIS-05", "AIS-12"},
		FrameworkISO23894:  {"6.2.4", "6.4.3"},
		FrameworkNIST1270:  {"3.5"},
		FrameworkCCPA:      {"1798.150"},
		FrameworkLGPD:      {"Art.46"},
		FrameworkPIPL:      {"Art.24"},
		FrameworkPDPA:      {"Sec.12"},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V14.3", "V12.4"},
		FrameworkOWASP10:   {"A03", "A05"},
		FrameworkCWE25:     {"CWE-79", "CWE-116"},
		FrameworkATTCK:     {"T1059", "T1485"},
	},
	"LLM06": {
		FrameworkNIST80053: {"AC-3", "AC-6", "SI-4"},
		FrameworkNISTCSF:   {"PR.AC-1", "PR.AC-4"},
		FrameworkFedRAMP:   {"AC-3", "AC-6"},
		FrameworkCMMC:      {"AC.2.16", "AC.3.18"},
		FrameworkSSDF:      {"PW.4.1", "PW.4.2"},
		FrameworkPCIDSS:    {"7.2", "6.2.4"},
		FrameworkCIS:       {"CIS-6", "CIS-12"},
		FrameworkCOBIT:     {"DSS05.3", "APO01.1"},
		FrameworkITIL:      {"SVS-5"},
		FrameworkCSASTAR:   {"IAM-01", "IAM-05"},
		FrameworkAIRMF:     {"MG-3.1", "MS-3.4"},
		FrameworkISO42001:  {"A.5.3", "A.8.2"},
		FrameworkEUAIAct:   {"Art.14", "Art.16", "Art.27"},
		FrameworkENISAAI:   {"AI-08", "AI-12"},
		FrameworkCSAAI:     {"AIS-06", "AIS-13"},
		FrameworkISO23894:  {"6.3.4", "6.4.4"},
		FrameworkNIST1270:  {"4.2"},
		FrameworkCCPA:      {"1798.135"},
		FrameworkLGPD:      {"Art.46"},
		FrameworkPIPL:      {"Art.24", "Art.55"},
		FrameworkPDPA:      {"Sec.12"},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V4.1", "V1.4"},
		FrameworkOWASP10:   {"A01"},
		FrameworkCWE25:     {"CWE-862", "CWE-269"},
		FrameworkATTCK:     {"T1078", "T1548"},
	},
	"LLM07": {
		FrameworkNIST80053: {"SC-28", "SI-12", "MP-5"},
		FrameworkNISTCSF:   {"PR.DS-1", "PR.DS-5"},
		FrameworkFedRAMP:   {"SC-28", "SI-12"},
		FrameworkCMMC:      {"SC.3.187"},
		FrameworkSSDF:      {"PW.6.2"},
		FrameworkPCIDSS:    {"3.5"},
		FrameworkCIS:       {"CIS-3", "CIS-16"},
		FrameworkCOBIT:     {"APO01.3"},
		FrameworkITIL:      {"SVS-5"},
		FrameworkCSASTAR:   {"DSP-01", "IAM-02"},
		FrameworkAIRMF:     {"ME-2.3", "MS-2.4"},
		FrameworkISO42001:  {"A.7.3", "A.8.5"},
		FrameworkEUAIAct:   {"Art.10", "Art.13"},
		FrameworkENISAAI:   {"AI-04", "AI-13"},
		FrameworkCSAAI:     {"AIS-07", "AIS-14"},
		FrameworkISO23894:  {"6.2.4", "6.4.5"},
		FrameworkNIST1270:  {"3.6"},
		FrameworkCCPA:      {"1798.150"},
		FrameworkLGPD:      {"Art.46"},
		FrameworkPIPL:      {"Art.24"},
		FrameworkPDPA:      {"Sec.11"},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V14.3", "V8.3"},
		FrameworkOWASP10:   {"A05"},
		FrameworkCWE25:     {"CWE-200", "CWE-522"},
		FrameworkATTCK:     {"T1552", "T1087"},
	},
	"LLM08": {
		FrameworkNIST80053: {"SI-7", "SC-44", "SI-3"},
		FrameworkNISTCSF:   {"PR.DS-6", "DE.CM-6"},
		FrameworkFedRAMP:   {"SI-7", "SC-44"},
		FrameworkCMMC:      {"SI.3.217"},
		FrameworkSSDF:      {"PW.5.1"},
		FrameworkPCIDSS:    {"6.2.4"},
		FrameworkCIS:       {"CIS-7", "CIS-16"},
		FrameworkCOBIT:     {"APO13.1"},
		FrameworkITIL:      {"SVS-7"},
		FrameworkCSASTAR:   {"TVM-01", "DSP-04"},
		FrameworkAIRMF:     {"MS-3.3", "ME-4.3"},
		FrameworkISO42001:  {"A.8.6", "A.9.4"},
		FrameworkEUAIAct:   {"Art.10", "Art.15"},
		FrameworkENISAAI:   {"AI-05", "AI-14"},
		FrameworkCSAAI:     {"AIS-08", "AIS-15"},
		FrameworkISO23894:  {"6.3.3", "6.4.6"},
		FrameworkNIST1270:  {"3.4"},
		FrameworkCCPA:      {"1798.150"},
		FrameworkLGPD:      {"Art.20"},
		FrameworkPIPL:      {"Art.24"},
		FrameworkPDPA:      {},
		FrameworkPIPEDA:    {"Sec.4.7"},
		FrameworkASVS:      {"V14.4"},
		FrameworkOWASP10:   {"A08"},
		FrameworkCWE25:     {"CWE-94", "CWE-506"},
		FrameworkATTCK:     {"T1190", "T1068"},
	},
	"LLM09": {
		FrameworkNIST80053: {"SI-12", "SI-4"},
		FrameworkNISTCSF:   {"DE.CM-1", "RS.AN-1"},
		FrameworkFedRAMP:   {"SI-12"},
		FrameworkCMMC:      {},
		FrameworkSSDF:      {"PW.7.2"},
		FrameworkPCIDSS:    {},
		FrameworkCIS:       {"CIS-17"},
		FrameworkCOBIT:     {"APO12.1"},
		FrameworkITIL:      {},
		FrameworkCSASTAR:   {"DSP-05"},
		FrameworkAIRMF:     {"MS-4.1", "ME-4.4"},
		FrameworkISO42001:  {"A.9.5", "A.10.1"},
		FrameworkEUAIAct:   {"Art.13", "Art.14", "Art.55"},
		FrameworkENISAAI:   {"AI-15", "AI-16"},
		FrameworkCSAAI:     {"AIS-09", "AIS-16"},
		FrameworkISO23894:  {"6.4.7", "6.5.1"},
		FrameworkNIST1270:  {"3.7", "4.3"},
		FrameworkCCPA:      {"1798.185"},
		FrameworkLGPD:      {"Art.20"},
		FrameworkPIPL:      {"Art.24"},
		FrameworkPDPA:      {},
		FrameworkPIPEDA:    {},
		FrameworkASVS:      {"V14.1"},
		FrameworkOWASP10:   {},
		FrameworkCWE25:     {"CWE-609", "CWE-451"},
		FrameworkATTCK:     {"T1566", "T1498"},
	},
	"LLM10": {
		FrameworkNIST80053: {"SC-5", "SI-10", "AU-4"},
		FrameworkNISTCSF:   {"PR.PT-4", "DE.AE-3"},
		FrameworkFedRAMP:   {"SC-5"},
		FrameworkCMMC:      {"SC.5.199"},
		FrameworkSSDF:      {"PW.7.1"},
		FrameworkPCIDSS:    {"6.2.4", "10.3"},
		FrameworkCIS:       {"CIS-12", "CIS-13"},
		FrameworkCOBIT:     {"DSS05.2", "APO13.1"},
		FrameworkITIL:      {"SVS-3"},
		FrameworkCSASTAR:   {"DSP-02", "BCD-01"},
		FrameworkAIRMF:     {"MS-4.2", "ME-4.5"},
		FrameworkISO42001:  {"A.9.6", "A.10.2"},
		FrameworkEUAIAct:   {"Art.15", "Art.27"},
		FrameworkENISAAI:   {"AI-17", "AI-18"},
		FrameworkCSAAI:     {"AIS-10", "AIS-17"},
		FrameworkISO23894:  {"6.4.8", "6.5.2"},
		FrameworkNIST1270:  {"3.8"},
		FrameworkCCPA:      {},
		FrameworkLGPD:      {},
		FrameworkPIPL:      {"Art.55"},
		FrameworkPDPA:      {},
		FrameworkPIPEDA:    {},
		FrameworkASVS:      {"V14.2"},
		FrameworkOWASP10:   {},
		FrameworkCWE25:     {"CWE-400", "CWE-770"},
		FrameworkATTCK:     {"T1499", "T1565"},
	},
}

// ControlsForOWASPV2 returns compliance control IDs for a given OWASP category
// and framework, across all 31 frameworks. It checks the V2 map first, then
// falls back to the Phase 1 map for backward compatibility.
func ControlsForOWASPV2(owasp string, framework ComplianceFramework) []string {
	if frameworkMap, ok := owaspControlMapV2[owasp]; ok {
		if controls, ok := frameworkMap[framework]; ok {
			return controls
		}
	}
	// Fall back to Phase 1 map.
	return ControlsForOWASP(owasp, framework)
}

// ComputeCompliancePostureV2 maps assessment results to compliance posture
// across all 31 frameworks.
func ComputeCompliancePostureV2(results []ScenarioResult) map[string]FrameworkPosture {
	posture := make(map[string]FrameworkPosture)

	// Initialize posture for each framework.
	for _, fw := range SupportedFrameworksV2() {
		posture[string(fw)] = FrameworkPosture{
			Framework:     string(fw),
			TotalControls: 0,
			Verified:      0,
			AtRisk:        0,
		}
	}

	// Track which controls are verified vs at-risk.
	verifiedControls := make(map[ComplianceFramework]map[string]bool)
	atRiskControls := make(map[ComplianceFramework]map[string]bool)

	for _, fw := range SupportedFrameworksV2() {
		verifiedControls[fw] = make(map[string]bool)
		atRiskControls[fw] = make(map[string]bool)
	}

	// For each scenario result, map to controls.
	for _, sr := range results {
		for _, fw := range SupportedFrameworksV2() {
			controls := ControlsForOWASPV2(sr.OWASP, fw)
			for _, ctrl := range controls {
				if sr.Blocked {
					verifiedControls[fw][ctrl] = true
				} else {
					atRiskControls[fw][ctrl] = true
				}
			}
		}
	}

	// Compute posture per framework.
	for _, fw := range SupportedFrameworksV2() {
		verified := len(verifiedControls[fw])
		atRisk := len(atRiskControls[fw])
		total := verified + atRisk
		p := posture[string(fw)]
		p.TotalControls = total
		p.Verified = verified
		p.AtRisk = atRisk
		if total > 0 {
			p.Coverage = float64(verified) / float64(total)
		}
		posture[string(fw)] = p
	}

	return posture
}

// FrameworkCount returns the total number of supported frameworks.
func FrameworkCount() int {
	return len(frameworkRegistry)
}
