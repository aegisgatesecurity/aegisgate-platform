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
	return []string{"NIST AI RMF <-> MITRE ATLAS", "OWASP AI Top 10 <-> MITRE ATLAS", "FedRAMP <-> MITRE ATLAS"}
}

func GetMapping(name string) *FrameworkMapping {
	switch name {
	case "NIST AI RMF <-> MITRE ATLAS":
		return NewFrameworkMapping()
	case "OWASP AI Top 10 <-> MITRE ATLAS":
		return NewOWASPMapping()
	case "FedRAMP <-> MITRE ATLAS":
		return NewFedRAMPMapping()
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
// NewFedRAMPMapping creates a bidirectional mapping between FedRAMP Moderate
// (NIST 800-53 Rev. 5) controls and MITRE ATLAS adversarial AI techniques.
// This is the technique-level traceability web that complements the
// control-level mapping in pkg/compliance/mapping/mapping.go.
//
// When a FedRAMP AC-2 alarm fires, the operator sees not just the SOC 2
// and ISO 27001 equivalents (from mapping.go), but also which adversarial
// AI techniques this control detects or mitigates (from this mapping).
func NewFedRAMPMapping() *FrameworkMapping {
	mapping := &FrameworkMapping{
		Name:               "FedRAMP Moderate <-> MITRE ATLAS Mapping",
		Description:        "Bidirectional mapping between FedRAMP Moderate (NIST 800-53 Rev. 5) controls and MITRE ATLAS adversarial AI techniques",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ControlToTechnique: make(map[string][]string),
		TechniqueToControl: make(map[string][]string),
		Mappings:           []MappingRelationship{},
	}
	mapping.buildFedRAMPMappings()
	return mapping
}

// buildFedRAMPMappings maps each FedRAMP control family to its relevant
// ATLAS techniques, OWASP LLM controls, and NIST AI RMF categories.
func (m *FrameworkMapping) buildFedRAMPMappings() {
	// === AC: Access Control ===
	m.AddFedRAMPMapping("FedRAMP-AC-2", "Account Management",
		[]string{"T1535", "T1556", "T1110"}, "mitigates", 0.9,
		"RBAC with MFA prevents unauthorized account access, credential theft, and brute force")
	m.AddFedRAMPMapping("FedRAMP-AC-3", "Access Enforcement",
		[]string{"T1548", "T1078"}, "mitigates", 0.9,
		"Access enforcement prevents privilege escalation and abuse of elevation")
	m.AddFedRAMPMapping("FedRAMP-AC-6", "Least Privilege",
		[]string{"T1548", "T1078", "T1621"}, "mitigates", 0.85,
		"Least privilege limits lateral movement and privilege escalation")
	m.AddFedRAMPMapping("FedRAMP-AC-17", "Remote Access",
		[]string{"T1078", "T1133", "T1090"}, "mitigates", 0.85,
		"Remote access controls prevent unauthorized remote sessions and C2 channels")
	m.AddFedRAMPMapping("FedRAMP-AC-24", "Access Control Policy Support",
		[]string{"T1078", "T1548"}, "supports", 0.75,
		"Policy-driven access control supports detection of policy violations")

	// === AU: Audit and Accountability ===
	m.AddFedRAMPMapping("FedRAMP-AU-2", "Audit Events",
		[]string{"T1070", "T1070.002", "T1562"}, "mitigates", 0.95,
		"Comprehensive audit logging detects log tampering, deletion, and defense impairment")
	m.AddFedRAMPMapping("FedRAMP-AU-3", "Content of Audit Records",
		[]string{"T1070", "T1070.004"}, "mitigates", 0.9,
		"Rich audit records enable forensic analysis of indicator removal")
	m.AddFedRAMPMapping("FedRAMP-AU-6", "Audit Review and Analysis",
		[]string{"T1070", "T1562.001"}, "detects", 0.85,
		"Audit review detects anomalous patterns indicating compromise")
	m.AddFedRAMPMapping("FedRAMP-AU-9", "Protection of Audit Information",
		[]string{"T1070", "T1070.002"}, "mitigates", 0.95,
		"Tamper-evident audit logging prevents post-hoc log modification")
	m.AddFedRAMPMapping("FedRAMP-AU-10", "Audit Record Retention",
		[]string{"T1070.002", "T1562"}, "mitigates", 0.85,
		"Long-term retention enables historical forensic analysis")
	m.AddFedRAMPMapping("FedRAMP-AU-12", "Audit Generation",
		[]string{"T1070", "T1562"}, "mitigates", 0.9,
		"Automated audit generation ensures no gaps in security event records")
	m.AddFedRAMPMapping("FedRAMP-AU-16", "Cross-Organization Audit Logging",
		[]string{"T1070", "T1590"}, "mitigates", 0.85,
		"Cross-org audit logging enables detection of distributed attack patterns")

	// === IA: Identification and Authentication ===
	m.AddFedRAMPMapping("FedRAMP-IA-2", "Identification and Authentication",
		[]string{"T1078", "T1110", "T1535"}, "mitigates", 0.95,
		"MFA and strong authentication prevents credential reuse, brute force, and unsecured credentials")
	m.AddFedRAMPMapping("FedRAMP-IA-5", "Authenticator Management",
		[]string{"T1535", "T1552", "T1078"}, "mitigates", 0.9,
		"Authenticator lifecycle management prevents credential leakage and token theft")
	m.AddFedRAMPMapping("FedRAMP-IA-7", "Cryptographic Module Authentication",
		[]string{"T1557", "T1573"}, "mitigates", 0.85,
		"FIPS-validated crypto modules prevent AiTM and encryption downgrade attacks")

	// === SC: System and Communications Protection ===
	m.AddFedRAMPMapping("FedRAMP-SC-8", "Transmission Confidentiality and Integrity",
		[]string{"T1557", "T1573", "T1041"}, "mitigates", 0.95,
		"TLS 1.2+ with FIPS ciphers prevents AiTM interception and data exfiltration")
	m.AddFedRAMPMapping("FedRAMP-SC-7", "Boundary Protection",
		[]string{"T1136", "T1190", "T1090"}, "mitigates", 0.85,
		"Network boundary protection limits C2 channels and external exploitation")
	m.AddFedRAMPMapping("FedRAMP-SC-12", "Cryptographic Key Management",
		[]string{"T1552", "T1573"}, "mitigates", 0.85,
		"Key management prevents credential extraction and crypto downgrade")
	m.AddFedRAMPMapping("FedRAMP-SC-28", "Protection of Information at Rest",
		[]string{"T1486", "T1552"}, "mitigates", 0.9,
		"Encryption at rest prevents data exfiltration and credential harvesting from storage")

	// === CM: Configuration Management ===
	m.AddFedRAMPMapping("FedRAMP-CM-2", "Baseline Configuration",
		[]string{"T1529", "T1070.004"}, "mitigates", 0.85,
		"Baseline configs detect unauthorized system changes and config drift")
	m.AddFedRAMPMapping("FedRAMP-CM-6", "Configuration Settings",
		[]string{"T1070.004", "T1529"}, "mitigates", 0.85,
		"Hardened configuration settings reduce attack surface")

	// === SI: System and Information Integrity ===
	m.AddFedRAMPMapping("FedRAMP-SI-2", "Flaw Remediation",
		[]string{"T1190", "T1648", "T1611"}, "mitigates", 0.9,
		"Timely patching prevents exploitation of known vulnerabilities")
	m.AddFedRAMPMapping("FedRAMP-SI-3", "Malicious Code Protection",
		[]string{"T1059", "T1566", "T1648"}, "mitigates", 0.85,
		"Anti-malware detects command interpreters, phishing payloads, and serverless exploits")
	m.AddFedRAMPMapping("FedRAMP-SI-4", "System Monitoring",
		[]string{"T1562", "T1070", "T1590", "T1595"}, "detects", 0.9,
		"Continuous monitoring detects defense evasion, log tampering, and reconnaissance")
	m.AddFedRAMPMapping("FedRAMP-SI-7", "Software and Information Integrity",
		[]string{"T1190", "T1552"}, "mitigates", 0.85,
		"Integrity monitoring detects unauthorized software changes and credential files")

	// === IR: Incident Response ===
	m.AddFedRAMPMapping("FedRAMP-IR-4", "Incident Handling",
		[]string{"T1070", "T1562.001"}, "detects", 0.85,
		"Automated incident response detects and responds to security events")
	m.AddFedRAMPMapping("FedRAMP-IR-6", "Incident Reporting",
		[]string{"T1070", "T1562"}, "supports", 0.8,
		"Structured incident reporting supports regulatory notification requirements")

	// === RA: Risk Assessment ===
	m.AddFedRAMPMapping("FedRAMP-RA-5", "Vulnerability Monitoring and Scanning",
		[]string{"T1190", "T1595", "T1648"}, "detects", 0.9,
		"Continuous vulnerability scanning detects exploitable attack surface")
	m.AddFedRAMPMapping("FedRAMP-RA-3", "Risk Assessment",
		[]string{"T1590", "T1592"}, "supports", 0.8,
		"Risk assessment identifies reconnaissance threats to cloud-hosted AI systems")

	// === CA: Security Assessment ===
	m.AddFedRAMPMapping("FedRAMP-CA-7", "Continuous Monitoring",
		[]string{"T1595", "T1562", "T1070"}, "detects", 0.85,
		"Continuous monitoring detects active scanning, defense impairment, and log tampering")
	m.AddFedRAMPMapping("FedRAMP-CA-8", "Penetration Testing",
		[]string{"T1595.001", "T1190"}, "detects", 0.85,
		"Regular penetration testing validates defense against active scanning and public-facing exploits")

	// === SA: System and Services Acquisition ===
	m.AddFedRAMPMapping("FedRAMP-SA-22", "Unsupported System Components",
		[]string{"T1190", "T1648", "T1611"}, "mitigates", 0.85,
		"Removing unsupported components eliminates known-vulnerable attack surface")
	m.AddFedRAMPMapping("FedRAMP-SA-11", "Developer Security Testing",
		[]string{"T1190", "T1059", "T1648"}, "mitigates", 0.85,
		"Developer security testing catches vulnerabilities before deployment")

	// === SR: Supply Chain Risk Management ===
	m.AddFedRAMPMapping("FedRAMP-SR-3", "Supply Chain Controls and Processes",
		[]string{"T0043", "T0044", "T1590"}, "mitigates", 0.8,
		"Supply chain controls prevent compromised AI model provenance and data")
	m.AddFedRAMPMapping("FedRAMP-SR-4", "Provenance",
		[]string{"T0043", "T1590"}, "mitigates", 0.85,
		"Software provenance tracking prevents supply chain compromise")
	m.AddFedRAMPMapping("FedRAMP-SR-12", "Supply Chain Software and Firmware Integrity Verification",
		[]string{"T0043", "T1552"}, "mitigates", 0.85,
		"Integrity verification prevents compromised supply chain components")

	// === AC: Additional Access Control ===
	m.AddFedRAMPMapping("FedRAMP-AC-1", "Access Control Policy and Procedures",
		[]string{"T1078"}, "supports", 0.7,
		"Access control policy establishes baseline security requirements that support detection of unauthorized access")
	m.AddFedRAMPMapping("FedRAMP-AC-4", "Information Flow Enforcement",
		[]string{"T1041", "T1090", "T1562"}, "mitigates", 0.85,
		"Information flow enforcement prevents unauthorized data exfiltration and C2 channels")
	m.AddFedRAMPMapping("FedRAMP-AC-5", "Separation of Duties",
		[]string{"T1548", "T1078"}, "mitigates", 0.8,
		"Separation of duties prevents privilege escalation and insider threat collusion")
	m.AddFedRAMPMapping("FedRAMP-AC-7", "Unsuccessful Login Attempts",
		[]string{"T1110", "T1078"}, "mitigates", 0.85,
		"Account lockout thresholds mitigate brute force and credential stuffing attacks")
	m.AddFedRAMPMapping("FedRAMP-AC-8", "System Use Notification",
		[]string{"T1078"}, "supports", 0.6,
		"System use notification supports legal deterrence of unauthorized access attempts")
	m.AddFedRAMPMapping("FedRAMP-AC-10", "Concurrent Session Control",
		[]string{"T1078", "T1556"}, "mitigates", 0.75,
		"Session limits detect and prevent concurrent session abuse and credential sharing")
	m.AddFedRAMPMapping("FedRAMP-AC-11", "Session Lock",
		[]string{"T1078"}, "mitigates", 0.7,
		"Session lock prevents unauthorized access to unattended sessions")
	m.AddFedRAMPMapping("FedRAMP-AC-12", "Session Termination",
		[]string{"T1078", "T1556"}, "mitigates", 0.8,
		"Automatic session termination limits window of opportunity for session hijacking")
	m.AddFedRAMPMapping("FedRAMP-AC-14", "Permitted Actions Without Identification",
		[]string{"T1078"}, "supports", 0.65,
		"Explicitly defining public access boundaries supports monitoring of unauthorized privilege escalation")
	m.AddFedRAMPMapping("FedRAMP-AC-20", "Use of External Systems",
		[]string{"T1133", "T1078", "T1562"}, "mitigates", 0.75,
		"External system usage controls mitigate risks from remote access and third-party compromise")
	m.AddFedRAMPMapping("FedRAMP-AC-21", "Information Sharing",
		[]string{"T1567", "T1041"}, "mitigates", 0.7,
		"Information sharing controls prevent unauthorized data exfiltration through approved channels")
	m.AddFedRAMPMapping("FedRAMP-AC-22", "Publicly Accessible Content",
		[]string{"T1595", "T1590"}, "supports", 0.65,
		"Public content controls support preventing information disclosure through public-facing services")
	m.AddFedRAMPMapping("FedRAMP-AC-23", "Data Mining Protection",
		[]string{"T1590", "T1592"}, "mitigates", 0.75,
		"Anti-data-mining controls prevent automated reconnaissance and information harvesting")

	// === AT: Awareness and Training ===
	m.AddFedRAMPMapping("FedRAMP-AT-1", "Awareness and Training Policy",
		[]string{"T1566", "T1598"}, "supports", 0.7,
		"Security awareness policy supports phishing and social engineering resistance")
	m.AddFedRAMPMapping("FedRAMP-AT-2", "Security Awareness Training",
		[]string{"T1566", "T1598"}, "mitigates", 0.8,
		"Awareness training mitigates phishing, social engineering, and pretexting attacks")
	m.AddFedRAMPMapping("FedRAMP-AT-3", "Role-Based Training",
		[]string{"T1566", "T1078", "T1548"}, "mitigates", 0.8,
		"Role-based security training reduces insider threat and privilege abuse risks")

	// === AU: Additional Audit ===
	m.AddFedRAMPMapping("FedRAMP-AU-1", "Audit and Accountability Policy",
		[]string{"T1070"}, "supports", 0.7,
		"Audit policy establishes accountability frameworks that support investigation of indicator removal")
	m.AddFedRAMPMapping("FedRAMP-AU-4", "Audit Storage Capacity",
		[]string{"T1070", "T1562"}, "mitigates", 0.8,
		"Adequate audit storage prevents log loss from defense evasion and impairment attacks")
	m.AddFedRAMPMapping("FedRAMP-AU-5", "Response to Audit Processing Failures",
		[]string{"T1562", "T1070.002"}, "mitigates", 0.85,
		"Alerting on audit failures detects deliberate log impairment and tampering attempts")
	m.AddFedRAMPMapping("FedRAMP-AU-7", "Audit Reduction and Report Generation",
		[]string{"T1070"}, "detects", 0.8,
		"Audit reduction enables efficient detection of security events among high-volume logs")
	m.AddFedRAMPMapping("FedRAMP-AU-11", "Audit Record Retention",
		[]string{"T1070.002", "T1562"}, "mitigates", 0.8,
		"Audit retention policy prevents destruction of forensic evidence during incident investigation")
	m.AddFedRAMPMapping("FedRAMP-AU-13", "Monitoring for Information Disclosure",
		[]string{"T1567", "T1041"}, "detects", 0.8,
		"Information disclosure monitoring detects data exfiltration and leakage events")
	m.AddFedRAMPMapping("FedRAMP-AU-14", "Session Audit",
		[]string{"T1078", "T1556"}, "detects", 0.8,
		"Session auditing detects unauthorized session activity and credential misuse")

	// === CA: Additional Assessment ===
	m.AddFedRAMPMapping("FedRAMP-CA-1", "Security Assessment and Authorization Policy",
		[]string{"T1595", "T1040"}, "supports", 0.7,
		"Assessment policy establishes vulnerability scanning and penetration testing requirements")
	m.AddFedRAMPMapping("FedRAMP-CA-2", "Security Assessments",
		[]string{"T1595", "T1040"}, "detects", 0.85,
		"Regular security assessments detect vulnerabilities and configuration weaknesses")
	m.AddFedRAMPMapping("FedRAMP-CA-3", "System Interconnections",
		[]string{"T1133", "T1090"}, "mitigates", 0.8,
		"System interconnection controls prevent unauthorized lateral movement across network boundaries")
	m.AddFedRAMPMapping("FedRAMP-CA-5", "Plan of Action and Milestones",
		[]string{"T1190", "T1595"}, "supports", 0.65,
		"POA&M tracking supports timely remediation of discovered vulnerabilities and attack surface")
	m.AddFedRAMPMapping("FedRAMP-CA-9", "Internal Connections",
		[]string{"T1090", "T1078"}, "mitigates", 0.8,
		"Internal connection controls prevent unauthorized network traversal and lateral movement")

	// === CM: Additional Configuration Management ===
	m.AddFedRAMPMapping("FedRAMP-CM-1", "Configuration Management Policy",
		[]string{"T1529", "T1070.004"}, "supports", 0.65,
		"Configuration management policy supports detection of unauthorized system changes")
	m.AddFedRAMPMapping("FedRAMP-CM-3", "Configuration Change Control",
		[]string{"T1529", "T1070.004"}, "mitigates", 0.85,
		"Change control prevents unauthorized configuration modifications and detects config drift")
	m.AddFedRAMPMapping("FedRAMP-CM-4", "Security Impact Analysis",
		[]string{"T1190", "T1529"}, "mitigates", 0.8,
		"Security impact analysis catches vulnerabilities introduced by configuration changes")
	m.AddFedRAMPMapping("FedRAMP-CM-5", "Access Restrictions for Change",
		[]string{"T1548", "T1078"}, "mitigates", 0.85,
		"Change access restrictions prevent unauthorized privilege escalation through configuration modification")
	m.AddFedRAMPMapping("FedRAMP-CM-7", "Least Functionality",
		[]string{"T1190", "T1059", "T1562"}, "mitigates", 0.85,
		"Least functionality eliminates unnecessary attack surface and reduces exploitation vectors")
	m.AddFedRAMPMapping("FedRAMP-CM-8", "System Component Inventory",
		[]string{"T1595", "T1040"}, "detects", 0.75,
		"Component inventory detects unauthorized components and shadow IT through asset tracking")
	m.AddFedRAMPMapping("FedRAMP-CM-9", "Configuration Settings",
		[]string{"T1070.004", "T1529"}, "mitigates", 0.8,
		"Documented configuration settings enable detection of unauthorized changes")
	m.AddFedRAMPMapping("FedRAMP-CM-10", "Software Usage Restrictions",
		[]string{"T1190", "T1059"}, "mitigates", 0.75,
		"Software restrictions prevent execution of unauthorized tools and interpreters")
	m.AddFedRAMPMapping("FedRAMP-CM-11", "User-Installed Software",
		[]string{"T1059", "T1566"}, "mitigates", 0.75,
		"User-installed software controls prevent malware delivery through unauthorized applications")
	m.AddFedRAMPMapping("FedRAMP-CM-12", "Information Location",
		[]string{"T1041", "T1567"}, "mitigates", 0.7,
		"Information location controls support data loss prevention and exfiltration detection")

	// === CP: Contingency Planning ===
	m.AddFedRAMPMapping("FedRAMP-CP-1", "Contingency Planning Policy",
		[]string{"T1562", "T1070"}, "supports", 0.65,
		"Contingency planning policy supports service continuity during defense evasion attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-2", "Contingency Plan",
		[]string{"T1562", "T1070", "T1489"}, "mitigates", 0.8,
		"Contingency planning mitigates impact of denial-of-service and defense evasion attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-3", "Contingency Training",
		[]string{"T1566", "T1489"}, "supports", 0.65,
		"Contingency training supports organizational resilience against service disruption attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-4", "Contingency Plan Testing",
		[]string{"T1489", "T1562"}, "mitigates", 0.75,
		"Regular contingency testing validates response effectiveness against disruption attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-6", "Alternate Storage Site",
		[]string{"T1486", "T1562"}, "mitigates", 0.7,
		"Alternate storage prevents data loss from ransomware and destructive attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-7", "Alternate Processing Site",
		[]string{"T1489", "T1562"}, "mitigates", 0.75,
		"Alternate processing ensures service continuity during denial-of-service attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-8", "Telecommunications Services",
		[]string{"T1489", "T1090"}, "mitigates", 0.7,
		"Telecommunications redundancy mitigates network disruption and DoS attacks")
	m.AddFedRAMPMapping("FedRAMP-CP-9", "System Backup",
		[]string{"T1486", "T1562", "T1070.002"}, "mitigates", 0.85,
		"System backups enable recovery from ransomware, data destruction, and log tampering")
	m.AddFedRAMPMapping("FedRAMP-CP-10", "System Recovery and Reconstitution",
		[]string{"T1486", "T1489"}, "mitigates", 0.8,
		"System recovery provides resilience against ransomware and destructive attacks")

	// === IA: Additional Identification ===
	m.AddFedRAMPMapping("FedRAMP-IA-1", "Identification and Authentication Policy",
		[]string{"T1078"}, "supports", 0.65,
		"Authentication policy establishes baseline requirements for identity verification")
	m.AddFedRAMPMapping("FedRAMP-IA-3", "Device Identification and Authentication",
		[]string{"T1078", "T1556"}, "mitigates", 0.8,
		"Device authentication prevents unauthorized device access and credential bypass")
	m.AddFedRAMPMapping("FedRAMP-IA-4", "Identifier Management",
		[]string{"T1535", "T1078"}, "mitigates", 0.8,
		"Identifier lifecycle management prevents stale account abuse and credential reuse")
	m.AddFedRAMPMapping("FedRAMP-IA-6", "Authenticator Feedback",
		[]string{"T1110", "T1078"}, "mitigates", 0.75,
		"Authentication feedback controls prevent information disclosure during login attempts")
	m.AddFedRAMPMapping("FedRAMP-IA-8", "Non-Organizational Users",
		[]string{"T1078", "T1133"}, "mitigates", 0.8,
		"Non-organizational user authentication prevents unauthorized external access and account misuse")
	m.AddFedRAMPMapping("FedRAMP-IA-9", "Service Identification and Authentication",
		[]string{"T1556", "T1078"}, "mitigates", 0.8,
		"Service authentication prevents impersonation and unauthorized service-to-service communication")
	m.AddFedRAMPMapping("FedRAMP-IA-10", "Adaptive Identification and Authentication",
		[]string{"T1110", "T1078", "T1621"}, "mitigates", 0.85,
		"Adaptive authentication responds to risk signals and prevents credential-based attacks")
	m.AddFedRAMPMapping("FedRAMP-IA-11", "Re-Authentication",
		[]string{"T1078", "T1556"}, "mitigates", 0.85,
		"Re-authentication for sensitive actions prevents session hijacking and credential replay")

	// === IR: Additional Incident Response ===
	m.AddFedRAMPMapping("FedRAMP-IR-1", "Incident Response Policy",
		[]string{"T1070", "T1562"}, "supports", 0.65,
		"IR policy establishes response requirements that support investigation of defense evasion")
	m.AddFedRAMPMapping("FedRAMP-IR-2", "Incident Response Training",
		[]string{"T1566", "T1078"}, "supports", 0.7,
		"IR training supports detection of social engineering and credential compromise indicators")
	m.AddFedRAMPMapping("FedRAMP-IR-3", "Incident Response Testing",
		[]string{"T1595", "T1190"}, "mitigates", 0.75,
		"IR testing validates detection and response effectiveness against adversarial techniques")
	m.AddFedRAMPMapping("FedRAMP-IR-5", "Incident Monitoring",
		[]string{"T1070", "T1562", "T1595"}, "detects", 0.85,
		"Incident monitoring detects active threats including defense evasion and reconnaissance")
	m.AddFedRAMPMapping("FedRAMP-IR-7", "Incident Response Assistance",
		[]string{"T1595", "T1070"}, "supports", 0.75,
		"IR assistance provides specialized expertise for analyzing sophisticated attack patterns")
	m.AddFedRAMPMapping("FedRAMP-IR-8", "Incident Response Plan",
		[]string{"T1489", "T1070"}, "mitigates", 0.8,
		"IR plan ensures coordinated response to ransomware, DDoS, and data breach incidents")
	m.AddFedRAMPMapping("FedRAMP-IR-9", "Lessons Learned",
		[]string{"T1595", "T1070"}, "supports", 0.7,
		"Lessons learned improves detection of recurring attack patterns and techniques")
	m.AddFedRAMPMapping("FedRAMP-IR-10", "Real-Time Incident Response",
		[]string{"T1070", "T1562", "T1595"}, "detects", 0.85,
		"Real-time IR enables immediate detection and response to active security incidents")

	// === MA: Maintenance ===
	m.AddFedRAMPMapping("FedRAMP-MA-1", "System Maintenance Policy",
		[]string{"T1078", "T1070"}, "supports", 0.65,
		"Maintenance policy establishes requirements for controlled system access during maintenance")
	m.AddFedRAMPMapping("FedRAMP-MA-4", "Maintenance Tools",
		[]string{"T1059", "T1078", "T1562"}, "mitigates", 0.75,
		"Controlled maintenance tools prevent abuse of command interpreters and privilege escalation")

	// === MP: Media Protection ===
	m.AddFedRAMPMapping("FedRAMP-MP-5", "Media Transport",
		[]string{"T1041", "T1567"}, "mitigates", 0.75,
		"Media transport controls prevent data exfiltration during physical media movement")
	m.AddFedRAMPMapping("FedRAMP-MP-6", "Media Sanitization",
		[]string{"T1552", "T1041"}, "mitigates", 0.85,
		"Media sanitization prevents credential harvesting and data recovery from discarded media")

	// === PE: Physical ===
	m.AddFedRAMPMapping("FedRAMP-PE-3", "Physical Access Control",
		[]string{"T1552", "T1078"}, "mitigates", 0.7,
		"Physical access controls prevent unauthorized physical access to systems and credentials")
	m.AddFedRAMPMapping("FedRAMP-PE-20", "Asset Monitoring and Tracking",
		[]string{"T1590", "T1552"}, "detects", 0.7,
		"Asset monitoring detects physical asset theft and unauthorized movement")

	// === PL: Planning ===
	m.AddFedRAMPMapping("FedRAMP-PL-1", "Security Planning Policy",
		[]string{"T1595"}, "supports", 0.6,
		"Security planning policy establishes risk assessment requirements that support threat detection")
	m.AddFedRAMPMapping("FedRAMP-PL-2", "System Security Plan",
		[]string{"T1595", "T1040"}, "supports", 0.65,
		"System security plan documents attack surface and defense posture for vulnerability management")

	// === PM: Program Management ===
	m.AddFedRAMPMapping("FedRAMP-PM-1", "Information Security Program",
		[]string{"T1595"}, "supports", 0.6,
		"Security program management supports organization-wide threat awareness and vulnerability response")
	m.AddFedRAMPMapping("FedRAMP-PM-14", "Security and Privacy Training",
		[]string{"T1566", "T1598"}, "supports", 0.65,
		"Organization-wide training supports phishing resistance and social engineering awareness")

	// === PS: Personnel ===
	m.AddFedRAMPMapping("FedRAMP-PS-1", "Personnel Security Policy",
		[]string{"T1078", "T1535"}, "supports", 0.6,
		"Personnel security policy supports insider threat detection and credential management")
	m.AddFedRAMPMapping("FedRAMP-PS-2", "Position Risk Designation",
		[]string{"T1548", "T1078"}, "supports", 0.6,
		"Position risk designation supports appropriate access control and privilege limitation")
	m.AddFedRAMPMapping("FedRAMP-PS-3", "Personnel Screening",
		[]string{"T1078", "T1535"}, "supports", 0.6,
		"Personnel screening supports insider threat prevention and unauthorized access mitigation")

	// === RA: Additional Risk Assessment ===
	m.AddFedRAMPMapping("FedRAMP-RA-1", "Risk Assessment Policy",
		[]string{"T1595"}, "supports", 0.6,
		"Risk assessment policy establishes vulnerability scanning and threat modeling requirements")
	m.AddFedRAMPMapping("FedRAMP-RA-4", "Vulnerability Scanning",
		[]string{"T1595", "T1190", "T1040"}, "detects", 0.85,
		"Vulnerability scanning detects exploitable attack surface and known vulnerability patterns")
	m.AddFedRAMPMapping("FedRAMP-RA-6", "Technical Surveillance Countermeasures",
		[]string{"T1590", "T1592"}, "detects", 0.75,
		"Technical surveillance countermeasures detect reconnaissance and information gathering")
	m.AddFedRAMPMapping("FedRAMP-RA-7", "Risk Response",
		[]string{"T1190", "T1595"}, "mitigates", 0.75,
		"Risk response processes drive timely remediation of discovered vulnerabilities")
	m.AddFedRAMPMapping("FedRAMP-RA-9", "Criticality Analysis",
		[]string{"T1590", "T1595"}, "supports", 0.7,
		"Criticality analysis prioritizes protection of highest-value assets against targeted attacks")

	// === SA: Additional System Acquisition ===
	m.AddFedRAMPMapping("FedRAMP-SA-1", "System Acquisition Policy",
		[]string{"T0043", "T1590"}, "supports", 0.65,
		"Acquisition policy establishes supply chain security requirements and vendor assessment")
	m.AddFedRAMPMapping("FedRAMP-SA-4", "Acquisition Process",
		[]string{"T0043", "T1590"}, "mitigates", 0.75,
		"Acquisition process ensures security requirements in procurement and supply chain validation")
	m.AddFedRAMPMapping("FedRAMP-SA-5", "System Documentation",
		[]string{"T1595", "T1040"}, "supports", 0.7,
		"System documentation supports security testing and vulnerability identification")
	m.AddFedRAMPMapping("FedRAMP-SA-8", "Security Engineering Principles",
		[]string{"T1190", "T1648"}, "mitigates", 0.8,
		"Security engineering principles prevent common vulnerability patterns in system design")
	m.AddFedRAMPMapping("FedRAMP-SA-9", "External System Services",
		[]string{"T1133", "T1078"}, "mitigates", 0.75,
		"External system services controls prevent supply chain compromise through third-party access")
	m.AddFedRAMPMapping("FedRAMP-SA-10", "Developer Configuration Management",
		[]string{"T1529", "T1190"}, "mitigates", 0.75,
		"Developer CM prevents unauthorized changes in build and deployment pipelines")
	m.AddFedRAMPMapping("FedRAMP-SC-1", "System Protection Policy",
		[]string{"T1190", "T1562"}, "supports", 0.65,
		"System protection policy establishes baseline security requirements for all systems")
	m.AddFedRAMPMapping("FedRAMP-SC-2", "Public Access Protections",
		[]string{"T1595", "T1190"}, "mitigates", 0.8,
		"Public access protections prevent unauthorized access through external-facing services")

	// === SC: Additional System Protection ===
	m.AddFedRAMPMapping("FedRAMP-SC-3", "Security Function Isolation",
		[]string{"T1548", "T1078"}, "mitigates", 0.85,
		"Security function isolation prevents privilege escalation and security mechanism bypass")
	m.AddFedRAMPMapping("FedRAMP-SC-4", "Information in Shared Resources",
		[]string{"T1041", "T1562"}, "mitigates", 0.8,
		"Shared resource controls prevent information leakage between tenants and co-resident attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-5", "Denial of Service Protection",
		[]string{"T1489", "T1562"}, "mitigates", 0.85,
		"DoS protections mitigate volumetric and application-layer denial of service attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-6", "Resource Priority",
		[]string{"T1489"}, "mitigates", 0.75,
		"Resource priority controls ensure critical services remain available during DoS attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-13", "Cryptographic Protection",
		[]string{"T1557", "T1573", "T1041"}, "mitigates", 0.9,
		"Cryptographic protection prevents AiTM interception, data exfiltration, and crypto downgrade attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-15", "Collaborative Computing",
		[]string{"T1078", "T1556"}, "mitigates", 0.8,
		"Collaborative computing controls prevent unauthorized remote access and session hijacking")
	m.AddFedRAMPMapping("FedRAMP-SC-21", "Secure Name Resolution",
		[]string{"T1090", "T1078"}, "mitigates", 0.8,
		"Secure DNS prevents DNS spoofing, hijacking, and command-and-control via DNS")
	m.AddFedRAMPMapping("FedRAMP-SC-22", "Architecture and Provisioning",
		[]string{"T1190", "T1090"}, "mitigates", 0.75,
		"Secure architecture provisioning prevents unauthorized network access and lateral movement")
	m.AddFedRAMPMapping("FedRAMP-SC-23", "Session Authenticity",
		[]string{"T1078", "T1556", "T1557"}, "mitigates", 0.85,
		"Session authenticity protections prevent session hijacking, replay, and AiTM attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-24", "Fail in Known State",
		[]string{"T1489", "T1562"}, "mitigates", 0.75,
		"Fail-safe defaults prevent information disclosure during system failures and attacks")
	m.AddFedRAMPMapping("FedRAMP-SC-25", "Thin Nodes",
		[]string{"T1190", "T1059"}, "mitigates", 0.7,
		"Minimal attack surface on compute nodes reduces exploitation vectors and lateral movement")
	m.AddFedRAMPMapping("FedRAMP-SC-26", "Honeypots",
		[]string{"T1595", "T1590"}, "detects", 0.8,
		"Honeypots detect reconnaissance, scanning, and active exploitation attempts")
	m.AddFedRAMPMapping("FedRAMP-SC-34", "Least Functionality",
		[]string{"T1059", "T1190"}, "mitigates", 0.85,
		"Least functionality eliminates unnecessary ports, services, and functions to reduce attack surface")
	m.AddFedRAMPMapping("FedRAMP-SC-39", "Process Isolation",
		[]string{"T1548", "T1059"}, "mitigates", 0.85,
		"Process isolation prevents privilege escalation and cross-tenant data access")
	m.AddFedRAMPMapping("FedRAMP-SC-40", "Wireless Link Protection",
		[]string{"T1090", "T1557"}, "mitigates", 0.75,
		"Wireless link protection prevents interception and AiTM attacks on wireless networks")
	m.AddFedRAMPMapping("FedRAMP-SC-44", "Detonatable Software",
		[]string{"T1566", "T1059", "T1648"}, "mitigates", 0.8,
		"Detonatable sandboxing prevents malware and exploit execution from reaching production systems")

	// === SI: Additional System Integrity ===
	m.AddFedRAMPMapping("FedRAMP-SI-1", "System Integrity Policy",
		[]string{"T1562", "T1070"}, "supports", 0.65,
		"System integrity policy establishes requirements for detecting and responding to system compromise")
	m.AddFedRAMPMapping("FedRAMP-SI-8", "Spam Protection",
		[]string{"T1566", "T1598"}, "mitigates", 0.75,
		"Spam protection prevents phishing and social engineering delivery vectors")
	m.AddFedRAMPMapping("FedRAMP-SI-10", "Information Input Validation",
		[]string{"T1190", "T1059"}, "mitigates", 0.85,
		"Input validation prevents injection attacks, XSS, and command execution exploits")
	m.AddFedRAMPMapping("FedRAMP-SI-11", "Error Handling",
		[]string{"T1590", "T1562"}, "mitigates", 0.75,
		"Secure error handling prevents information disclosure and defense impairment through error channels")
	m.AddFedRAMPMapping("FedRAMP-SI-12", "Information Management",
		[]string{"T1041", "T1567"}, "mitigates", 0.75,
		"Information management controls prevent unauthorized data retention and exfiltration")
	m.AddFedRAMPMapping("FedRAMP-SI-14", "Non-Repudiation",
		[]string{"T1070", "T1070.002"}, "mitigates", 0.85,
		"Non-repudiation prevents denial of actions and supports forensic investigation of log tampering")
	m.AddFedRAMPMapping("FedRAMP-SI-16", "Memory Protection",
		[]string{"T1059", "T1648", "T1190"}, "mitigates", 0.85,
		"Memory protection prevents buffer overflow, ROP, and memory corruption exploitation")

	// === SR: Additional Supply Chain ===
	m.AddFedRAMPMapping("FedRAMP-SR-6", "Supplier Assessments and Reviews",
		[]string{"T0043", "T1590"}, "mitigates", 0.75,
		"Supplier assessments prevent supply chain compromise through vendor security evaluation")
	m.AddFedRAMPMapping("FedRAMP-SR-8", "Notification Agreements",
		[]string{"T0043", "T1590"}, "supports", 0.7,
		"Supplier notification agreements support early warning of supply chain compromise incidents")

	// === MP: Media Protection ===
	m.AddFedRAMPMapping("FedRAMP-MP-1", "Media Protection Policy",
		[]string{"T1552", "T1041"}, "supports", 0.65,
		"Media protection policy establishes requirements for preventing data exfiltration via physical media")

	// === PE: Physical Security ===
	m.AddFedRAMPMapping("FedRAMP-PE-1", "Physical and Environmental Protection Policy",
		[]string{"T1552", "T1078"}, "supports", 0.6,
		"Physical protection policy establishes baseline requirements for preventing unauthorized physical access")

	// === SR: Supply Chain Policy ===
	m.AddFedRAMPMapping("FedRAMP-SR-1", "Supply Chain Risk Management Policy",
		[]string{"T0043", "T1590"}, "supports", 0.65,
		"Supply chain risk management policy establishes requirements for vendor assessment and provenance tracking")
}

// AddFedRAMPMapping adds a FedRAMP control mapping to the framework mapping.
func (m *FrameworkMapping) AddFedRAMPMapping(controlID, title string, techniques []string, relationship string, confidence float32, description string) {
	mapping := MappingRelationship{
		SourceControl:   controlID,
		SourceFramework: "FedRAMP Moderate",
		TargetControls:  techniques,
		TargetFramework: "MITRE ATLAS",
		Relationship:    relationship,
		Confidence:      confidence,
		Description:     description,
	}
	m.Mappings = append(m.Mappings, mapping)
	m.ControlToTechnique[controlID] = techniques
	for _, technique := range techniques {
		m.TechniqueToControl[technique] = append(m.TechniqueToControl[technique], controlID)
	}
}

// GetFedRAMPMappingsForControl returns all ATLAS technique mappings for a FedRAMP control.
func GetFedRAMPMappingsForControl(controlID string) []MappingRelationship {
	mapping := NewFedRAMPMapping()
	var results []MappingRelationship
	for _, m := range mapping.Mappings {
		if m.SourceControl == controlID {
			results = append(results, m)
		}
	}
	return results
}

// GetFedRAMPControlsForTechnique returns all FedRAMP controls that address an ATLAS technique.
func GetFedRAMPControlsForTechnique(techniqueID string) []string {
	mapping := NewFedRAMPMapping()
	controls, ok := mapping.TechniqueToControl[techniqueID]
	if !ok {
		return nil
	}
	return controls
}

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
