//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"encoding/json"
	"fmt"
	"time"
)

// MappingRelationship represents the relationship between controls from different frameworks
type MappingRelationship struct {
	SourceFramework string   `json:"source_framework"`
	SourceControl   string   `json:"source_control"`
	TargetFramework string   `json:"target_framework"`
	TargetControls  []string `json:"target_controls"`
	Relationship    string   `json:"relationship"`
	Confidence      float32  `json:"confidence"`
	Description     string   `json:"description"`
}

// FrameworkMapping provides bidirectional mapping between compliance frameworks
type FrameworkMapping struct {
	Name               string                `json:"name"`
	Description        string                `json:"description"`
	CreatedAt          time.Time             `json:"created_at"`
	UpdatedAt          time.Time             `json:"updated_at"`
	ControlToTechnique map[string][]string   `json:"control_to_technique"`
	TechniqueToControl map[string][]string   `json:"technique_to_control"`
	Mappings           []MappingRelationship `json:"mappings"`
}

// ConsolidatedFinding represents a security/compliance finding unified across frameworks
type ConsolidatedFinding struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	Severity           string   `json:"severity"`
	Frameworks         []string `json:"frameworks"`
	Controls           []string `json:"controls"`
	Techniques         []string `json:"techniques"`
	Remediation        string   `json:"remediation"`
	Evidence           []string `json:"evidence"`
	RiskScore          float32  `json:"risk_score"`
	AffectedComponents []string `json:"affected_components"`
	DiscoveryDate      string   `json:"discovery_date"`
}

// UnifiedComplianceReport provides a consolidated view across multiple frameworks
type UnifiedComplianceReport struct {
	GeneratedAt       time.Time             `json:"generated_at"`
	Frameworks        []string              `json:"frameworks"`
	TotalFindings     int                   `json:"total_findings"`
	CriticalFindings  int                   `json:"critical_findings"`
	HighFindings      int                   `json:"high_findings"`
	MediumFindings    int                   `json:"medium_findings"`
	LowFindings       int                   `json:"low_findings"`
	Findings          []ConsolidatedFinding `json:"findings"`
	FrameworkCoverage map[string]int        `json:"framework_coverage"`
	TechniqueCoverage map[string][]string   `json:"technique_coverage"`
	ComplianceScore   float32               `json:"compliance_score"`
	Gaps              []ComplianceGap       `json:"gaps"`
}

// ComplianceGap represents a gap in coverage across frameworks
type ComplianceGap struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	MissingControls []string `json:"missing_controls"`
	RiskLevel       string   `json:"risk_level"`
	Recommendations []string `json:"recommendations"`
}

// NewFrameworkMapping creates a new NIST AI RMF <-> MITRE ATLAS mapping
func NewFrameworkMapping() *FrameworkMapping {
	mapping := &FrameworkMapping{
		Name:               "NIST AI RMF <-> MITRE ATLAS Mapping",
		Description:        "Bidirectional mapping between NIST AI Risk Management Framework and MITRE ATLAS adversarial AI techniques",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	mapping.buildMappings()
	return mapping
}

func (m *FrameworkMapping) buildMappings() {
	// GOVERN (GV) Function
	m.AddMapping("GV1", []string{"T1535", "T1484", "T1632", "T1589"}, "supports", 0.9, "Establishing organizational context helps identify potential adversarial threats to AI systems")
	m.AddMapping("GV2", []string{"T1484", "T1658"}, "supports", 0.8, "Stakeholder interests alignment supports against jailbreak and adversarial attacks")
	m.AddMapping("GV3", []string{"T1535", "T1484", "T1632", "T1589", "T1658"}, "mitigates", 0.95, "Comprehensive AI risk management addresses all major adversarial techniques")
	m.AddMapping("GV4", []string{"T1535", "T1484", "T1584", "T1658"}, "addresses", 0.85, "Risk portfolio management includes technical controls for prompt injection and adversarial examples")

	// MAP (MP) Function
	m.AddMapping("MP1", []string{"T1632", "T1589"}, "detects", 0.9, "System context helps identify potential training data exposure and prompt extraction vectors")
	m.AddMapping("MP2", []string{"T1589", "T1584"}, "supports", 0.85, "Component identification reveals potential data exposure and injection points")
	m.AddMapping("MP3", []string{"T1484", "T1658"}, "detects", 0.8, "Capability identification helps recognize jailbreak and adversarial example susceptibility")
	m.AddMapping("MP4", []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658"}, "detects", 0.95, "Adversarial profiling directly addresses all ATLAS techniques")

	// MEASURE (ME) Function
	m.AddMapping("ME1", []string{"T1535", "T1484", "T1584"}, "detects", 0.85, "Measuring system effectiveness helps detect prompt injection and jailbreak attempts")
	m.AddMapping("ME2", []string{"T1535", "T1484", "T1632", "T1658"}, "detects", 0.9, "Analyzing misuse patterns identifies injection, extraction, and adversarial example attempts")
	m.AddMapping("ME3", []string{"T1535", "T1484", "T1584", "T1658"}, "detects", 0.95, "Measuring safeguards directly validates defenses against all relevant ATLAS techniques")
	m.AddMapping("ME4", []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658"}, "detects", 0.9, "Root cause analysis covers all adversarial technique categories")

	// MANAGE (RG) Function
	m.AddMapping("RG1", []string{"T1535", "T1484", "T1584", "T1658"}, "mitigates", 0.9, "Risk response planning includes mitigations for injection and adversarial techniques")
	m.AddMapping("RG2", []string{"T1535", "T1484", "T1584", "T1658"}, "mitigates", 0.95, "Implementation of risk responses directly addresses adversarial threats")
	m.AddMapping("RG3", []string{"T1535", "T1484", "T1632"}, "supports", 0.75, "Stakeholder communication supports awareness of adversarial risks")
	m.AddMapping("RG4", []string{"T1535", "T1484", "T1589", "T1584", "T1658"}, "mitigates", 0.85, "Risk management within tolerance addresses all technical adversarial vectors")

	// Extended NIST AI RMF mappings with all 18 MITRE ATLAS techniques
	// Covers: T1535, T1484, T1632, T1589, T1584, T1658, T1648, T1590, T1592, T1556, T1552, T1566, T1486, T1611, T1621, T1599, T1110, T1041

	// GV1-EXT - Organizational Context (all 18 techniques)
	m.AddMapping("GV1-EXT", []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658", "T1648", "T1590", "T1592", "T1556", "T1552", "T1566", "T1486", "T1611", "T1621", "T1599", "T1110", "T1041"}, "supports", 0.95, "Organizational context covers all adversarial AI techniques")

	// MP4-EXT - Adversarial Profiling (all 18 techniques)
	m.AddMapping("MP4-EXT", []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658", "T1648", "T1590", "T1592", "T1556", "T1552", "T1566", "T1486", "T1611", "T1621", "T1599", "T1110", "T1041"}, "detects", 0.95, "Adversarial profiling detects all 18 ATLAS techniques")

	// ME4-EXT - Root Cause Analysis (all 18 techniques)
	m.AddMapping("ME4-EXT", []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658", "T1648", "T1590", "T1592", "T1556", "T1552", "T1566", "T1486", "T1611", "T1621", "T1599", "T1110", "T1041"}, "detects", 0.95, "Root cause analysis covers all adversarial technique categories")
}

func (m *FrameworkMapping) AddMapping(controlID string, techniques []string, relationship string, confidence float32, description string) {
	m.ControlToTechnique[controlID] = techniques
	for _, technique := range techniques {
		if existing, ok := m.TechniqueToControl[technique]; ok {
			alreadyMapped := false
			for _, c := range existing {
				if c == controlID {
					alreadyMapped = true
					break
				}
			}
			if !alreadyMapped {
				m.TechniqueToControl[technique] = append(existing, controlID)
			}
		} else {
			m.TechniqueToControl[technique] = []string{controlID}
		}
	}
	mapping := MappingRelationship{
		SourceFramework: "NIST AI RMF",
		SourceControl:   controlID,
		TargetFramework: "MITRE ATLAS",
		TargetControls:  techniques,
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, mapping)
	m.UpdatedAt = time.Now()
}

func (m *FrameworkMapping) GetTechniquesForControl(controlID string) []string {
	return m.ControlToTechnique[controlID]
}

func (m *FrameworkMapping) GetControlsForTechnique(techniqueID string) []string {
	return m.TechniqueToControl[techniqueID]
}

func (m *FrameworkMapping) GetMappingsForControl(controlID string) []MappingRelationship {
	var result []MappingRelationship
	for _, mapping := range m.Mappings {
		if mapping.SourceControl == controlID {
			result = append(result, mapping)
		}
	}
	return result
}

func NewConsolidatedFinding(title, description, severity, remediation string) *ConsolidatedFinding {
	return &ConsolidatedFinding{
		ID:                 generateID(),
		Title:              title,
		Description:        description,
		Severity:           severity,
		Remediation:        remediation,
		Frameworks:         []string{},
		Controls:           []string{},
		Techniques:         []string{},
		Evidence:           []string{},
		RiskScore:          calculateRiskScore(severity),
		AffectedComponents: []string{},
		DiscoveryDate:      time.Now().Format("2006-01-02"),
	}
}

func (f *ConsolidatedFinding) AddFramework(framework string) {
	for _, existing := range f.Frameworks {
		if existing == framework {
			return
		}
	}
	f.Frameworks = append(f.Frameworks, framework)
}

func (f *ConsolidatedFinding) AddControl(controlID string) {
	for _, existing := range f.Controls {
		if existing == controlID {
			return
		}
	}
	f.Controls = append(f.Controls, controlID)
}

func (f *ConsolidatedFinding) AddTechnique(techniqueID string) {
	for _, existing := range f.Techniques {
		if existing == techniqueID {
			return
		}
	}
	f.Techniques = append(f.Techniques, techniqueID)
}

func (f *ConsolidatedFinding) AddEvidence(evidence string) {
	f.Evidence = append(f.Evidence, evidence)
}

func (m *FrameworkMapping) GenerateUnifiedReport(findings []Finding) *UnifiedComplianceReport {
	report := &UnifiedComplianceReport{
		GeneratedAt:       time.Now(),
		Frameworks:        []string{"NIST AI RMF", "MITRE ATLAS"},
		Findings:          []ConsolidatedFinding{},
		FrameworkCoverage: make(map[string]int),
		TechniqueCoverage: make(map[string][]string),
		Gaps:              []ComplianceGap{},
	}
	consolidatedMap := make(map[string]*ConsolidatedFinding)
	for _, finding := range findings {
		associatedTechniques := []string{}
		// Derive controls from the pattern description (using requirement ID from pattern if available)
		controls := []string{}
		if finding.Description != "" {
			// Use pattern description as a proxy for control ID
			controls = []string{finding.Description}
		}
		for _, control := range controls {
			if techniques, ok := m.ControlToTechnique[control]; ok {
				associatedTechniques = append(associatedTechniques, techniques...)
			}
		}
		// Use Severity.String() since Severity is a type, not a string
		key := fmt.Sprintf("%s-%s", finding.Description, finding.Severity.String())
		if existing, ok := consolidatedMap[key]; ok {
			// Add framework if we can determine it from context
			for _, fw := range report.Frameworks {
				existing.AddFramework(fw)
			}
			for _, control := range controls {
				existing.AddControl(control)
			}
			for _, technique := range associatedTechniques {
				existing.AddTechnique(technique)
			}
			// Use Match as evidence
			if len(finding.Match) > 0 {
				existing.AddEvidence(finding.Match)
			}
		} else {
			// Derive title from pattern description, description from pattern, remediation from recommendation
			title := finding.Description
			if title == "" {
				title = "Compliance Finding"
			}
			description := finding.Description
			remediation := "See compliance framework guidelines"
			if remediation == "" {
				remediation = "Review and address the compliance finding"
			}
			severityStr := finding.Severity.String()
			consolidated := NewConsolidatedFinding(title, description, severityStr, remediation)
			for _, fw := range report.Frameworks {
				consolidated.AddFramework(fw)
			}
			for _, control := range controls {
				consolidated.AddControl(control)
			}
			for _, technique := range associatedTechniques {
				consolidated.AddTechnique(technique)
			}
			// Use Match and Context as evidence
			if len(finding.Match) > 0 {
				consolidated.AddEvidence(finding.Match)
			}
			if len(finding.Context) > 0 {
				consolidated.AddEvidence(finding.Context)
			}
			consolidatedMap[key] = consolidated
		}
	}
	for _, consolidated := range consolidatedMap {
		report.Findings = append(report.Findings, *consolidated)
		switch consolidated.Severity {
		case "critical":
			report.CriticalFindings++
		case "high":
			report.HighFindings++
		case "medium":
			report.MediumFindings++
		case "low":
			report.LowFindings++
		default:
			report.LowFindings++
		}
	}
	report.TotalFindings = len(report.Findings)
	for _, finding := range report.Findings {
		for _, framework := range finding.Frameworks {
			report.FrameworkCoverage[framework]++
		}
		for _, technique := range finding.Techniques {
			for _, control := range finding.Controls {
				covered := false
				for _, existingControl := range report.TechniqueCoverage[technique] {
					if existingControl == control {
						covered = true
						break
					}
				}
				if !covered {
					report.TechniqueCoverage[technique] = append(report.TechniqueCoverage[technique], control)
				}
			}
		}
	}
	if report.TotalFindings > 0 {
		weightedSum := float32(report.CriticalFindings)*4.0 + float32(report.HighFindings)*3.0 + float32(report.MediumFindings)*2.0 + float32(report.LowFindings)*1.0
		maxScore := float32(report.TotalFindings) * 4.0
		report.ComplianceScore = 100.0 * (1.0 - (weightedSum / maxScore))
		if report.ComplianceScore < 0 {
			report.ComplianceScore = 0
		}
	}
	report.Gaps = m.identifyGaps(report)
	return report
}

func (m *FrameworkMapping) identifyGaps(report *UnifiedComplianceReport) []ComplianceGap {
	gaps := []ComplianceGap{}
	allTechniques := []string{"T1535", "T1484", "T1632", "T1589", "T1584", "T1658"}
	for _, technique := range allTechniques {
		controls, ok := report.TechniqueCoverage[technique]
		if !ok || len(controls) == 0 {
			gap := ComplianceGap{
				ID:              generateID(),
				Title:           fmt.Sprintf("Uncovered Technique: %s", technique),
				Description:     fmt.Sprintf("No findings are associated with %s - potential blind spot", technique),
				MissingControls: m.getControlsForTechnique(technique),
				RiskLevel:       "high",
				Recommendations: []string{fmt.Sprintf("Implement detection controls for %s", technique), "Add monitoring for this adversarial technique"},
			}
			gaps = append(gaps, gap)
		} else if len(controls) < 2 {
			gap := ComplianceGap{
				ID:              generateID(),
				Title:           fmt.Sprintf("Undercovered Technique: %s", technique),
				Description:     fmt.Sprintf("Only %d control(s) cover %s - consider additional controls", len(controls), technique),
				MissingControls: []string{},
				RiskLevel:       "medium",
				Recommendations: []string{fmt.Sprintf("Add redundant controls for %s", technique), "Implement defense-in-depth approach"},
			}
			gaps = append(gaps, gap)
		}
	}
	return gaps
}

func (m *FrameworkMapping) getControlsForTechnique(techniqueID string) []string {
	switch techniqueID {
	case "T1535":
		return []string{"GV3", "GV4", "ME3", "RG1", "RG2"}
	case "T1484":
		return []string{"GV2", "GV3", "MP3", "ME3", "RG1", "RG2"}
	case "T1632":
		return []string{"GV1", "MP1", "ME2", "RG3"}
	case "T1589":
		return []string{"GV1", "MP1", "MP2", "RG4"}
	case "T1584":
		return []string{"GV4", "MP2", "ME1", "ME3", "ME4", "RG1", "RG2", "RG4"}
	case "T1658":
		return []string{"GV2", "GV3", "MP3", "ME2", "ME3", "ME4", "RG1", "RG2", "RG4"}
	default:
		return []string{}
	}
}

func (m *FrameworkMapping) ToJSON() (string, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *UnifiedComplianceReport) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func generateID() string {
	return fmt.Sprintf("MAP-%d", time.Now().UnixNano())
}

func calculateRiskScore(severity string) float32 {
	switch severity {
	case "critical":
		return 0.9
	case "high":
		return 0.7
	case "medium":
		return 0.5
	case "low":
		return 0.3
	default:
		return 0.1
	}
}

func AvailableMappings() []string {
	return []string{"NIST AI RMF <-> MITRE ATLAS", "OWASP AI Top 10 <-> MITRE ATLAS"}
}

func GetMapping(name string) *FrameworkMapping {
	switch name {
	case "NIST AI RMF <-> MITRE ATLAS":
		return NewFrameworkMapping()
	case "OWASP AI Top 10 <-> MITRE ATLAS":
		return NewOWASPMapping()
	default:
		return nil
	}
}

// NewOWASPMapping creates a mapping between OWASP AI Top 10 and MITRE ATLAS
func NewOWASPMapping() *FrameworkMapping {
	mapping := &FrameworkMapping{
		Name:               "OWASP AI Top 10 <-> MITRE ATLAS",
		Description:        "Bidirectional mapping between OWASP AI Top 10 vulnerabilities and MITRE ATLAS adversarial AI techniques",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	mapping.buildOWASPMappings()
	return mapping
}

func (m *FrameworkMapping) buildOWASPMappings() {
	// OWASP AI Top 10 to MITRE ATLAS mappings
	// Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/

	// AI01: Prompt Injection -> Maps to prompt injection related techniques
	m.AddOWASPMapping("OWASP-AI01", []string{"T1535", "T1484"}, "equivalent", 0.95,
		"Prompt Injection directly maps to ATLAS prompt injection and LLM jailbreak techniques")

	// AI02: Insecure Output Handling -> Maps to output manipulation techniques
	m.AddOWASPMapping("OWASP-AI02", []string{"T1632", "T1589"}, "relates", 0.85,
		"Insecure Output Handling relates to training data extraction and output leaking techniques")

	// AI03: Training Data Poisoning -> Maps to data poisoning techniques
	m.AddOWASPMapping("OWASP-AI03", []string{"T1590", "T1592"}, "equivalent", 0.9,
		"Training Data Poisoning maps to ML model poisoning and data manipulation techniques")

	// AI04: Model Denial of Service -> Maps to DoS and resource exhaustion techniques
	m.AddOWASPMapping("OWASP-AI04", []string{"T1486", "T1611"}, "relates", 0.8,
		"Model DoS relates to resource consumption and denial of service techniques")

	// AI05: Supply Chain Vulnerabilities -> Maps to supply chain and compromise techniques
	m.AddOWASPMapping("OWASP-AI05", []string{"T1556", "T1552", "T1566"}, "equivalent", 0.9,
		"Supply Chain Vulnerabilities map to model theft, data compromise, and supply chain techniques")

	// AI06: Sensitive Information Disclosure -> Maps to data exfiltration techniques
	m.AddOWASPMapping("OWASP-AI06", []string{"T1589", "T1584", "T1599"}, "equivalent", 0.9,
		"Sensitive Information Disclosure maps to data extraction and membership inference techniques")

	// AI07: Insecure Plugin Design -> Maps to code execution and plugin attack techniques
	m.AddOWASPMapping("OWASP-AI07", []string{"T1648", "T1110", "T1041"}, "relates", 0.85,
		"Insecure Plugin Design relates to code injection, authentication bypass, and command execution techniques")

	// AI08: Excessive Agency -> Maps to privilege escalation and misuse techniques
	m.AddOWASPMapping("OWASP-AI08", []string{"T1484", "T1621"}, "relates", 0.8,
		"Excessive Agency relates to LLM jailbreak and service abuse techniques")

	// AI09: Overreliance -> Maps to social engineering and manipulation techniques
	m.AddOWASPMapping("OWASP-AI09", []string{"T1535", "T1484", "T1658"}, "relates", 0.75,
		"Overreliance relates to prompt injection and LLM jailbreak via social engineering")

	// AI10: Model Theft -> Maps to model extraction and theft techniques
	m.AddOWASPMapping("OWASP-AI10", []string{"T1648", "T1599", "T1611"}, "equivalent", 0.95,
		"Model Theft maps directly to model extraction, membership inference, and service theft techniques")
}

// AddOWASPMapping adds a mapping from OWASP control to ATLAS techniques
func (m *FrameworkMapping) AddOWASPMapping(controlID string, techniques []string, relationship string, confidence float32, description string) {
	m.ControlToTechnique[controlID] = techniques
	for _, technique := range techniques {
		if existing, ok := m.TechniqueToControl[technique]; ok {
			alreadyMapped := false
			for _, c := range existing {
				if c == controlID {
					alreadyMapped = true
					break
				}
			}
			if !alreadyMapped {
				m.TechniqueToControl[technique] = append(existing, controlID)
			}
		} else {
			m.TechniqueToControl[technique] = []string{controlID}
		}
	}
	mapping := MappingRelationship{
		SourceFramework: "OWASP AI Top 10",
		SourceControl:   controlID,
		TargetFramework: "MITRE ATLAS",
		TargetControls:  techniques,
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, mapping)
	m.UpdatedAt = time.Now()
}

// NewNIST1500Mapping creates a new NIST 1500 <-> Multi-Framework mapping
func NewNIST1500Mapping() *FrameworkMapping {
	mapping := &FrameworkMapping{
		Name:               "NIST 1500 <-> Multi-Framework Mapping",
		Description:        "Bidirectional mapping between NIST 1500 AI Controls and MITRE ATLAS, OWASP AI Top 10, NIST AI RMF",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	mapping.buildNIST1500Mappings()
	return mapping
}

// buildNIST1500Mappings creates mappings for all 10 NIST 1500 control families
func (m *FrameworkMapping) buildNIST1500Mappings() {
	// === GOV: AI Governance Controls ===
	m.AddNIST1500Mapping("NIST1500-GOV-1", []string{"ATLAS-T1535"}, []string{"OWASP-AI09"}, []string{"NIST-AI-RMF-GV1"}, "equivalent", 0.95,
		"AI Policy and Governance maps to NIST AI RMF Governance function and Overreliance controls")
	m.AddNIST1500Mapping("NIST1500-GOV-2", []string{"ATLAS-T0043"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-GV2"}, "equivalent", 0.9,
		"AI Roles and Responsibilities maps to supply chain accountability controls")
	m.AddNIST1500Mapping("NIST1500-GOV-3", []string{"ATLAS-T0010"}, []string{"OWASP-AI01"}, []string{"NIST-AI-RMF-GV3"}, "equivalent", 0.9,
		"AI Risk Classification maps to prompt injection and adversarial risk controls")
	m.AddNIST1500Mapping("NIST1500-GOV-4", []string{"ATLAS-T0044"}, []string{"OWASP-AI07"}, []string{"NIST-AI-RMF-GV4"}, "relates", 0.85,
		"AI Impact Assessment relates to plugin security and system integration risks")
	m.AddNIST1500Mapping("NIST1500-GOV-5", []string{"ATLAS-T0029"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-GV5"}, "relates", 0.85,
		"AI System Inventory relates to excessive agency and system misuse controls")

	// === RISK: AI Risk Assessment Controls ===
	m.AddNIST1500Mapping("NIST1500-RISK-1", []string{"ATLAS-T0007", "ATLAS-T0009"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-ME1"}, "equivalent", 0.95,
		"AI Threat Modeling maps to data poisoning and model manipulation techniques")
	m.AddNIST1500Mapping("NIST1500-RISK-2", []string{"ATLAS-T0048"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-ME2"}, "equivalent", 0.9,
		"AI Vulnerability Assessment maps to sensitive information disclosure controls")
	m.AddNIST1500Mapping("NIST1500-RISK-3", []string{"ATLAS-T0040"}, []string{"OWASP-AI04"}, []string{"NIST-AI-RMF-ME3"}, "relates", 0.85,
		"AI Risk Quantification relates to model DoS and service availability")
	m.AddNIST1500Mapping("NIST1500-RISK-4", []string{"ATLAS-T0049"}, []string{"OWASP-AI10"}, []string{"NIST-AI-RMF-ME4"}, "equivalent", 0.9,
		"AI Risk Monitoring maps to model theft and intellectual property controls")
	m.AddNIST1500Mapping("NIST1500-RISK-5", []string{"ATLAS-T0005"}, []string{"OWASP-AI02"}, []string{"NIST-AI-RMF-ME5"}, "relates", 0.85,
		"AI Risk Reporting relates to insecure output handling and disclosure controls")

	// === DATA: AI Data Management Controls ===
	m.AddNIST1500Mapping("NIST1500-DATA-1", []string{"ATLAS-T0010"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-DA1"}, "equivalent", 0.95,
		"AI Data Governance maps to training data poisoning controls")
	m.AddNIST1500Mapping("NIST1500-DATA-2", []string{"ATLAS-T0011"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-DA2"}, "equivalent", 0.9,
		"AI Data Quality maps to sensitive information disclosure controls")
	m.AddNIST1500Mapping("NIST1500-DATA-3", []string{"ATLAS-T0012"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-DA3"}, "equivalent", 0.9,
		"AI Data Provenance maps to data poisoning and supply chain controls")
	m.AddNIST1500Mapping("NIST1500-DATA-4", []string{"ATLAS-T0013"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-DA4"}, "relates", 0.85,
		"AI Data Privacy relates to supply chain and third-party data risks")
	m.AddNIST1500Mapping("NIST1500-DATA-5", []string{"ATLAS-T0014"}, []string{"OWASP-AI02"}, []string{"NIST-AI-RMF-DA5"}, "relates", 0.85,
		"AI Data Retention relates to insecure output handling and data leakage")
	m.AddNIST1500Mapping("NIST1500-DATA-6", []string{"ATLAS-T0015"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-DA6"}, "equivalent", 0.9,
		"AI Data Disposal maps to sensitive information disclosure and exfiltration controls")

	// === MODEL: AI Model Lifecycle Controls ===
	m.AddNIST1500Mapping("NIST1500-MODEL-1", []string{"ATLAS-T0020"}, []string{"OWASP-AI10"}, []string{"NIST-AI-RMF-ML1"}, "equivalent", 0.95,
		"AI Model Development maps to model theft and intellectual property controls")
	m.AddNIST1500Mapping("NIST1500-MODEL-2", []string{"ATLAS-T0021"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-ML2"}, "equivalent", 0.9,
		"AI Model Training maps to training data poisoning controls")
	m.AddNIST1500Mapping("NIST1500-MODEL-3", []string{"ATLAS-T0022"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-ML3"}, "equivalent", 0.9,
		"AI Model Validation maps to supply chain vulnerability controls")
	m.AddNIST1500Mapping("NIST1500-MODEL-4", []string{"ATLAS-T0023"}, []string{"OWASP-AI04"}, []string{"NIST-AI-RMF-ML4"}, "relates", 0.85,
		"AI Model Deployment relates to model DoS and service availability")
	m.AddNIST1500Mapping("NIST1500-MODEL-5", []string{"ATLAS-T0024"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-ML5"}, "relates", 0.85,
		"AI Model Retirement relates to excessive agency and system misuse controls")

	// === SEC: AI Security Controls ===
	m.AddNIST1500Mapping("NIST1500-SEC-1", []string{"ATLAS-T0001"}, []string{"OWASP-AI01"}, []string{"NIST-AI-RMF-SE1"}, "equivalent", 0.95,
		"AI Access Control maps to prompt injection and authentication bypass controls")
	m.AddNIST1500Mapping("NIST1500-SEC-2", []string{"ATLAS-T0002"}, []string{"OWASP-AI01"}, []string{"NIST-AI-RMF-SE2"}, "equivalent", 0.9,
		"AI Authentication maps to prompt injection and identity spoofing controls")
	m.AddNIST1500Mapping("NIST1500-SEC-3", []string{"ATLAS-T0003"}, []string{"OWASP-AI07"}, []string{"NIST-AI-RMF-SE3"}, "equivalent", 0.9,
		"AI Encryption maps to insecure plugin design and data exposure controls")
	m.AddNIST1500Mapping("NIST1500-SEC-4", []string{"ATLAS-T0004"}, []string{"OWASP-AI04"}, []string{"NIST-AI-RMF-SE4"}, "relates", 0.85,
		"AI Audit Logging relates to model DoS and activity monitoring controls")
	m.AddNIST1500Mapping("NIST1500-SEC-5", []string{"ATLAS-T0005"}, []string{"OWASP-AI02"}, []string{"NIST-AI-RMF-SE5"}, "relates", 0.85,
		"AI Intrusion Detection relates to insecure output handling attacks")
	m.AddNIST1500Mapping("NIST1500-SEC-6", []string{"ATLAS-T0006"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-SE6"}, "equivalent", 0.9,
		"AI Security Testing maps to excessive agency and privilege escalation controls")

	// === PRIV: AI Privacy Controls ===
	m.AddNIST1500Mapping("NIST1500-PRIV-1", []string{"ATLAS-T0030"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-PR1"}, "equivalent", 0.95,
		"AI Privacy by Design maps to sensitive information disclosure controls")
	m.AddNIST1500Mapping("NIST1500-PRIV-2", []string{"ATLAS-T0031"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-PR2"}, "equivalent", 0.9,
		"AI Data Minimization maps to information extraction and inference attacks")
	m.AddNIST1500Mapping("NIST1500-PRIV-3", []string{"ATLAS-T0032"}, []string{"OWASP-AI02"}, []string{"NIST-AI-RMF-PR3"}, "relates", 0.85,
		"AI Consent Management relates to output leakage and data exposure")
	m.AddNIST1500Mapping("NIST1500-PRIV-4", []string{"ATLAS-T0033"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-PR4"}, "equivalent", 0.9,
		"AI Privacy Impact Assessment maps to membership inference attacks")
	m.AddNIST1500Mapping("NIST1500-PRIV-5", []string{"ATLAS-T0034"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-PR5"}, "relates", 0.85,
		"AI Privacy Monitoring relates to sensitive data exfiltration controls")

	// === TRANS: AI Transparency Controls ===
	m.AddNIST1500Mapping("NIST1500-TRANS-1", []string{"ATLAS-T0040"}, []string{"OWASP-AI09"}, []string{"NIST-AI-RMF-TR1"}, "equivalent", 0.9,
		"AI Documentation maps to overreliance and accountability controls")
	m.AddNIST1500Mapping("NIST1500-TRANS-2", []string{"ATLAS-T0041"}, []string{"OWASP-AI02"}, []string{"NIST-AI-RMF-TR2"}, "relates", 0.85,
		"AI Explainability relates to output handling and interpretation risks")
	m.AddNIST1500Mapping("NIST1500-TRANS-3", []string{"ATLAS-T0042"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-TR3"}, "relates", 0.85,
		"AI Disclosure relates to excessive agency and system behavior controls")
	m.AddNIST1500Mapping("NIST1500-TRANS-4", []string{"ATLAS-T0043"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-TR4"}, "relates", 0.85,
		"AI Reporting relates to supply chain transparency accountability")

	// === FAIR: AI Fairness Controls ===
	m.AddNIST1500Mapping("NIST1500-FAIR-1", []string{"ATLAS-T0035"}, []string{"OWASP-AI09"}, []string{"NIST-AI-RMF-FA1"}, "relates", 0.85,
		"AI Bias Detection relates to overreliance and model behavior manipulation")
	m.AddNIST1500Mapping("NIST1500-FAIR-2", []string{"ATLAS-T0036"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-FA2"}, "equivalent", 0.9,
		"AI Fairness Testing maps to data poisoning and bias injection attacks")
	m.AddNIST1500Mapping("NIST1500-FAIR-3", []string{"ATLAS-T0037"}, []string{"OWASP-AI06"}, []string{"NIST-AI-RMF-FA3"}, "relates", 0.85,
		"AI Disparate Impact relates to sensitive information and demographic inference")
	m.AddNIST1500Mapping("NIST1500-FAIR-4", []string{"ATLAS-T0038"}, []string{"OWASP-AI09"}, []string{"NIST-AI-RMF-FA4"}, "relates", 0.85,
		"AI Mitigation Strategies relates to overreliance on biased predictions")
	m.AddNIST1500Mapping("NIST1500-FAIR-5", []string{"ATLAS-T0039"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-FA5"}, "relates", 0.85,
		"AI Fairness Monitoring relates to excessive agency in automated decisions")

	// === SC: AI Supply Chain Controls ===
	m.AddNIST1500Mapping("NIST1500-SC-1", []string{"ATLAS-T0045"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-SC1"}, "equivalent", 0.95,
		"AI Third-Party Risk maps directly to supply chain vulnerability controls")
	m.AddNIST1500Mapping("NIST1500-SC-2", []string{"ATLAS-T0046"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-SC2"}, "equivalent", 0.9,
		"AI Vendor Assessment maps to model theft and supply chain compromise")
	m.AddNIST1500Mapping("NIST1500-SC-3", []string{"ATLAS-T0047"}, []string{"OWASP-AI10"}, []string{"NIST-AI-RMF-SC3"}, "equivalent", 0.9,
		"AI Component Verification maps to model theft and intellectual property controls")
	m.AddNIST1500Mapping("NIST1500-SC-4", []string{"ATLAS-T0048"}, []string{"OWASP-AI03"}, []string{"NIST-AI-RMF-SC4"}, "relates", 0.85,
		"AI Supply Chain Monitoring relates to training data poisoning risks")
	m.AddNIST1500Mapping("NIST1500-SC-5", []string{"ATLAS-T0049"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-SC5"}, "relates", 0.85,
		"AI Supply Chain Incident Response relates to supply chain attack remediation")

	// === IR: AI Incident Response Controls ===
	m.AddNIST1500Mapping("NIST1500-IR-1", []string{"ATLAS-T0050"}, []string{"OWASP-AI01", "OWASP-AI02"}, []string{"NIST-AI-RMF-IR1"}, "equivalent", 0.9,
		"AI Incident Preparation maps to prompt injection and output handling response")
	m.AddNIST1500Mapping("NIST1500-IR-2", []string{"ATLAS-T0051"}, []string{"OWASP-AI04"}, []string{"NIST-AI-RMF-IR2"}, "equivalent", 0.9,
		"AI Incident Detection maps to model DoS and service disruption detection")
	m.AddNIST1500Mapping("NIST1500-IR-3", []string{"ATLAS-T0052"}, []string{"OWASP-AI08"}, []string{"NIST-AI-RMF-IR3"}, "relates", 0.85,
		"AI Incident Containment relates to excessive agency mitigation controls")
	m.AddNIST1500Mapping("NIST1500-IR-4", []string{"ATLAS-T0053"}, []string{"OWASP-AI10"}, []string{"NIST-AI-RMF-IR4"}, "equivalent", 0.9,
		"AI Incident Eradication maps to model theft recovery controls")
	m.AddNIST1500Mapping("NIST1500-IR-5", []string{"ATLAS-T0054"}, []string{"OWASP-AI05"}, []string{"NIST-AI-RMF-IR5"}, "relates", 0.85,
		"AI Incident Recovery relates to supply chain incident remediation")
}

// NIST1500ControlMapping represents a multi-framework mapping for a NIST 1500 control
type NIST1500ControlMapping struct {
	ControlID       string   `json:"control_id"`
	ATLASTechniques []string `json:"atlas_techniques"`
	OWASPControls   []string `json:"owasp_controls"`
	NISTAIRMF       []string `json:"nist_ai_rmf"`
	Relationship    string   `json:"relationship"`
	Confidence      float32  `json:"confidence"`
	Description     string   `json:"description"`
}

// AddNIST1500Mapping adds a multi-framework mapping for a NIST 1500 control
func (m *FrameworkMapping) AddNIST1500Mapping(controlID string, atlasTechniques []string, owaspControls []string, nistAIRMF []string, relationship string, confidence float32, description string) {
	// Map to ATLAS techniques
	m.ControlToTechnique[controlID] = atlasTechniques
	for _, technique := range atlasTechniques {
		if existing, ok := m.TechniqueToControl[technique]; ok {
			alreadyMapped := false
			for _, c := range existing {
				if c == controlID {
					alreadyMapped = true
					break
				}
			}
			if !alreadyMapped {
				m.TechniqueToControl[technique] = append(existing, controlID)
			}
		} else {
			m.TechniqueToControl[technique] = []string{controlID}
		}
	}

	// Add ATLAS mapping relationship
	mapping := MappingRelationship{
		SourceFramework: "NIST 1500",
		SourceControl:   controlID,
		TargetFramework: "MITRE ATLAS",
		TargetControls:  atlasTechniques,
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, mapping)

	// Add OWASP mapping relationship
	owaspMapping := MappingRelationship{
		SourceFramework: "NIST 1500",
		SourceControl:   controlID,
		TargetFramework: "OWASP AI Top 10",
		TargetControls:  owaspControls,
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, owaspMapping)

	// Add NIST AI RMF mapping relationship
	rmfMapping := MappingRelationship{
		SourceFramework: "NIST 1500",
		SourceControl:   controlID,
		TargetFramework: "NIST AI RMF",
		TargetControls:  nistAIRMF,
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, rmfMapping)
	m.UpdatedAt = time.Now()
}

// GetNIST1500MappingsForControl returns all mappings for a specific NIST 1500 control
func GetNIST1500MappingsForControl(controlID string) []MappingRelationship {
	mapping := NewNIST1500Mapping()
	var result []MappingRelationship
	for _, m := range mapping.Mappings {
		if m.SourceControl == controlID {
			result = append(result, m)
		}
	}
	return result
}

// GetAllNIST1500ControlMappings returns all NIST 1500 control mappings grouped by control
func GetAllNIST1500ControlMappings() map[string]NIST1500ControlMapping {
	mapping := NewNIST1500Mapping()
	result := make(map[string]NIST1500ControlMapping)

	for _, m := range mapping.Mappings {
		if m.SourceFramework == "NIST 1500" {
			if existing, ok := result[m.SourceControl]; ok {
				switch m.TargetFramework {
				case "MITRE ATLAS":
					existing.ATLASTechniques = m.TargetControls
				case "OWASP AI Top 10":
					existing.OWASPControls = m.TargetControls
				case "NIST AI RMF":
					existing.NISTAIRMF = m.TargetControls
				}
				result[m.SourceControl] = existing
			} else {
				ctrl := NIST1500ControlMapping{
					ControlID:    m.SourceControl,
					Relationship: m.Relationship,
					Confidence:   m.Confidence,
					Description:  m.Description,
				}
				switch m.TargetFramework {
				case "MITRE ATLAS":
					ctrl.ATLASTechniques = m.TargetControls
				case "OWASP AI Top 10":
					ctrl.OWASPControls = m.TargetControls
				case "NIST AI RMF":
					ctrl.NISTAIRMF = m.TargetControls
				}
				result[m.SourceControl] = ctrl
			}
		}
	}
	return result
}
