// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package compliance

import (
	"fmt"
	"time"
)

// SOC2TrustServiceCriteria represents SOC 2 Trust Service Criteria
type SOC2TrustServiceCriteria struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Controls    []string `json:"controls"`
}

// SOC2Control represents a single SOC 2 control
type SOC2Control struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Criteria     string   `json:"criteria"`
	Description  string   `json:"description"`
	Requirements []string `json:"requirements"`
	Evidence     []string `json:"evidence"`
}

// SOC2Framework represents the SOC 2 compliance framework
type SOC2Framework struct {
	Name          string                     `json:"name"`
	Description   string                     `json:"description"`
	TrustCriteria []SOC2TrustServiceCriteria `json:"trust_criteria"`
	Controls      []SOC2Control              `json:"controls"`
	ControlMap    map[string]SOC2Control     `json:"control_map"`
	AIControls    []string                   `json:"ai_controls"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

// NewSOC2Framework creates a new SOC 2 compliance framework
func NewSOC2Framework() *SOC2Framework {
	framework := &SOC2Framework{
		Name:        "SOC 2 Type II",
		Description: "Service Organization Control 2 - Trust Service Criteria for AI/ML systems",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ControlMap:  make(map[string]SOC2Control),
	}
	framework.initTrustCriteria()
	framework.initControls()
	return framework
}

func (s *SOC2Framework) initTrustCriteria() {
	s.TrustCriteria = []SOC2TrustServiceCriteria{
		{
			ID:          "CC",
			Name:        "Security (Common Criteria)",
			Category:    "Security",
			Description: "The system is protected against unauthorized access",
			Controls:    []string{"CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"},
		},
		{
			ID:          "A",
			Name:        "Availability",
			Category:    "Availability",
			Description: "The system meets availability commitments",
			Controls:    []string{"A1"},
		},
		{
			ID:          "PI",
			Name:        "Processing Integrity",
			Category:    "Integrity",
			Description: "System processing is complete, valid, accurate",
			Controls:    []string{"PI1"},
		},
		{
			ID:          "C",
			Name:        "Confidentiality",
			Category:    "Confidentiality",
			Description: "Information designated as confidential is protected",
			Controls:    []string{"C1", "C2"},
		},
		{
			ID:          "P",
			Name:        "Privacy",
			Category:    "Privacy",
			Description: "Personal information is handled properly",
			Controls:    []string{"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"},
		},
	}
}

func (s *SOC2Framework) initControls() {
	s.Controls = []SOC2Control{
		{ID: "CC1.1", Name: "Control Environment", Criteria: "CC1", Description: "The entity demonstrates commitment to integrity", Requirements: []string{"Code of conduct", "Security training", "Background checks"}},
		{ID: "CC3.2", Name: "AI-Specific Risk Assessment", Criteria: "CC3", Description: "Risks specific to AI/ML systems identified", Requirements: []string{"Model bias assessment", "Adversarial testing", "Data quality", "Model drift"}},
		{ID: "CC5.4", Name: "AI Model Change Control", Criteria: "CC5", Description: "AI/ML model changes approved and documented", Requirements: []string{"Model registry", "Lineage tracking", "Retraining approval"}},
		{ID: "CC6.2", Name: "ML Environment Security", Criteria: "CC6", Description: "ML training and inference secured", Requirements: []string{"Isolated environments", "Sandboxed inference", "Container security"}},
		{ID: "CC6.3", Name: "Data Protection", Criteria: "CC6", Description: "Data protected from unauthorized access", Requirements: []string{"Encryption", "Masking", "Privacy-preserving ML"}},
		{ID: "CC6.4", Name: "Adversarial Defense", Criteria: "CC6", Description: "Protected against adversarial AI attacks", Requirements: []string{"Input validation", "Adversarial training", "Anomaly detection", "Model hardening"}},
		{ID: "CC6.5", Name: "Vulnerability Management", Criteria: "CC6", Description: "Vulnerabilities identified and addressed", Requirements: []string{"Vulnerability scanning", "Penetration testing", "Patch management"}},
		{ID: "CC6.6", Name: "System Operations", Criteria: "CC6", Description: "Security operations monitored", Requirements: []string{"SIEM", "Security monitoring", "Model behavior monitoring"}},
		{ID: "PI1.2", Name: "ML Processing Integrity", Criteria: "PI1", Description: "ML processing produces accurate results", Requirements: []string{"Model validation", "Benchmarking", "Bias detection", "Quality monitoring"}},
	}

	for _, control := range s.Controls {
		s.ControlMap[control.ID] = control
	}

	s.AIControls = []string{"CC3.2", "CC5.4", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "PI1.2"}
}

func (s *SOC2Framework) GetControl(controlID string) (*SOC2Control, error) {
	control, exists := s.ControlMap[controlID]
	if !exists {
		return nil, fmt.Errorf("control %s not found", controlID)
	}
	return &control, nil
}

func (s *SOC2Framework) GetControlsByCriteria(criteria string) []SOC2Control {
	var controls []SOC2Control
	for _, control := range s.Controls {
		if control.Criteria == criteria {
			controls = append(controls, control)
		}
	}
	return controls
}

func (s *SOC2Framework) GetAIControls() []SOC2Control {
	var controls []SOC2Control
	for _, controlID := range s.AIControls {
		if control, exists := s.ControlMap[controlID]; exists {
			controls = append(controls, control)
		}
	}
	return controls
}

type SOC2Assessment struct {
	Framework       *SOC2Framework
	AssessmentDate  time.Time
	Auditor         string
	Scope           []string
	ControlFindings []SOC2ControlFinding
	OverallRating   string
	ComplianceScore float32
}

type SOC2ControlFinding struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Status        string   `json:"status"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	Evidence      []string `json:"evidence"`
	Remediation   string   `json:"remediation"`
	RelatedAICtls []string `json:"related_ai_controls"`
}

func (s *SOC2Framework) NewSOC2Assessment(auditor string, scope []string) *SOC2Assessment {
	return &SOC2Assessment{
		Framework:       s,
		AssessmentDate:  time.Now(),
		Auditor:         auditor,
		Scope:           scope,
		ControlFindings: []SOC2ControlFinding{},
		OverallRating:   "In Progress",
	}
}

func (a *SOC2Assessment) AddControlFinding(finding SOC2ControlFinding) {
	a.ControlFindings = append(a.ControlFindings, finding)
	a.calculateScore()
}

func (a *SOC2Assessment) calculateScore() {
	if len(a.ControlFindings) == 0 {
		a.ComplianceScore = 0
		return
	}

	passCount := 0
	for _, finding := range a.ControlFindings {
		if finding.Status == "Pass" {
			passCount++
		}
	}
	a.ComplianceScore = float32(passCount) / float32(len(a.ControlFindings)) * 100

	if a.ComplianceScore >= 90 {
		a.OverallRating = "Effective"
	} else if a.ComplianceScore >= 70 {
		a.OverallRating = "Needs Improvement"
	} else {
		a.OverallRating = "Ineffective"
	}
}

func (a *SOC2Assessment) GenerateReport() string {
	report := "=== SOC 2 Compliance Assessment Report ===\n"
	report += "Assessment Date: " + a.AssessmentDate.Format("2006-01-02") + "\n"
	report += "Auditor: " + a.Auditor + "\n"
	report += "Overall Rating: " + a.OverallRating + "\n"
	report += fmt.Sprintf("Compliance Score: %.2f%%\n", a.ComplianceScore)
	report += "\nControl Findings:\n"

	for _, finding := range a.ControlFindings {
		report += fmt.Sprintf("\n[%s] %s - %s\n", finding.Status, finding.ControlID, finding.ControlName)
		report += fmt.Sprintf("Severity: %s\n", finding.Severity)
		report += fmt.Sprintf("Description: %s\n", finding.Description)
		if finding.Remediation != "" {
			report += fmt.Sprintf("Remediation: %s\n", finding.Remediation)
		}
	}

	return report
}
