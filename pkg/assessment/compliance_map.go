// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 1: Compliance Mapping — Scenario → OWASP → Framework Controls

package assessment

// ComplianceFramework is a supported compliance framework.
type ComplianceFramework string

const (
	FrameworkNIST800171 ComplianceFramework = "NIST800-171"
	FrameworkSOC2       ComplianceFramework = "SOC2"
	FrameworkISO27001   ComplianceFramework = "ISO27001"
	FrameworkHIPAA      ComplianceFramework = "HIPAA"
	FrameworkGDPR       ComplianceFramework = "GDPR"
)

// SupportedFrameworks returns the Phase 1 compliance frameworks.
func SupportedFrameworks() []ComplianceFramework {
	return []ComplianceFramework{
		FrameworkNIST800171,
		FrameworkSOC2,
		FrameworkISO27001,
		FrameworkHIPAA,
		FrameworkGDPR,
	}
}

// owaspControlMap maps OWASP LLM Top 10 categories to compliance framework controls.
var owaspControlMap = map[string]map[ComplianceFramework][]string{
	"LLM01": {
		FrameworkNIST800171: {"3.14.1", "3.14.6"},
		FrameworkSOC2:       {"CC7.1", "CC7.2"},
		FrameworkISO27001:   {"A.12.6.1"},
		FrameworkHIPAA:      {"164.312(b)"},
		FrameworkGDPR:       {"Art. 32"},
	},
	"LLM02": {
		FrameworkNIST800171: {"3.13.16", "3.13.8"},
		FrameworkSOC2:       {"CC6.1"},
		FrameworkISO27001:   {"A.8.2.1", "A.10.1.1"},
		FrameworkHIPAA:      {"164.312(a)", "164.312(b)"},
		FrameworkGDPR:       {"Art. 5", "Art. 32"},
	},
	"LLM03": {
		FrameworkNIST800171: {"3.11.2"},
		FrameworkSOC2:       {"CC7.2"},
		FrameworkISO27001:   {"A.12.6.1"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {"Art. 32"},
	},
	"LLM04": {
		FrameworkNIST800171: {"3.14.1"},
		FrameworkSOC2:       {"CC7.1"},
		FrameworkISO27001:   {"A.12.2.1"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {"Art. 5"},
	},
	"LLM05": {
		FrameworkNIST800171: {"3.14.1"},
		FrameworkSOC2:       {"CC7.1"},
		FrameworkISO27001:   {"A.12.6.1"},
		FrameworkHIPAA:      {"164.312(b)"},
		FrameworkGDPR:       {"Art. 32"},
	},
	"LLM06": {
		FrameworkNIST800171: {"3.4.5"},
		FrameworkSOC2:       {"CC6.3"},
		FrameworkISO27001:   {"A.9.4.4"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {"Art. 32"},
	},
	"LLM07": {
		FrameworkNIST800171: {"3.13.16"},
		FrameworkSOC2:       {"CC6.1"},
		FrameworkISO27001:   {"A.8.2.1"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {"Art. 32"},
	},
	"LLM08": {
		FrameworkNIST800171: {"3.14.1"},
		FrameworkSOC2:       {"CC7.1"},
		FrameworkISO27001:   {"A.12.2.1"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {"Art. 5"},
	},
	"LLM09": {
		FrameworkNIST800171: {},
		FrameworkSOC2:       {},
		FrameworkISO27001:   {},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {},
	},
	"LLM10": {
		FrameworkNIST800171: {"3.14.6"},
		FrameworkSOC2:       {"CC7.2"},
		FrameworkISO27001:   {"A.12.1.3"},
		FrameworkHIPAA:      {},
		FrameworkGDPR:       {},
	},
}

// ControlsForOWASP returns the compliance control IDs for a given OWASP category and framework.
func ControlsForOWASP(owasp string, framework ComplianceFramework) []string {
	if frameworkMap, ok := owaspControlMap[owasp]; ok {
		if controls, ok := frameworkMap[framework]; ok {
			return controls
		}
	}
	return nil
}

// ComputeCompliancePosture maps assessment results to compliance framework posture.
func ComputeCompliancePosture(results []ScenarioResult) map[string]FrameworkPosture {
	posture := make(map[string]FrameworkPosture)

	// Initialize posture for each framework
	for _, fw := range SupportedFrameworks() {
		posture[string(fw)] = FrameworkPosture{
			Framework:     string(fw),
			TotalControls: 0,
			Verified:      0,
			AtRisk:        0,
		}
	}

	// Track which controls are verified vs at-risk
	verifiedControls := make(map[ComplianceFramework]map[string]bool)
	atRiskControls := make(map[ComplianceFramework]map[string]bool)

	for _, fw := range SupportedFrameworks() {
		verifiedControls[fw] = make(map[string]bool)
		atRiskControls[fw] = make(map[string]bool)
	}

	// For each scenario result, map to controls
	for _, sr := range results {
		for _, fw := range SupportedFrameworks() {
			controls := ControlsForOWASP(sr.OWASP, fw)
			for _, ctrl := range controls {
				if sr.Blocked {
					verifiedControls[fw][ctrl] = true
				} else {
					atRiskControls[fw][ctrl] = true
				}
			}
		}
	}

	// Compute posture per framework
	for _, fw := range SupportedFrameworks() {
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
