// Package iso21434 provides ISO 21434 automotive cybersecurity compliance controls
// as a licensed add-on module. ISO 21434 defines cybersecurity engineering requirements
// for road vehicle electrical and electronic (E/E) systems throughout their lifecycle.
package iso21434

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ISO21434Module implements ISO 21434 automotive cybersecurity compliance controls.
type ISO21434Module struct {
	*compliance.BaseComplianceModule
	automotivePatterns []*regexp.Regexp
	taraPatterns       []*regexp.Regexp
	csmsPatterns       []*regexp.Regexp
}

// NewISO21434Module creates a new ISO 21434 compliance module.
func NewISO21434Module() *ISO21434Module {
	m := &ISO21434Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("iso21434", "ISO-21434-2021", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *ISO21434Module) initPatterns() {
	m.automotivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)iso\s*21434`),
		regexp.MustCompile(`(?i)automotive\s*cybersecurity`),
		regexp.MustCompile(`(?i)\bvehicle\b`),
		regexp.MustCompile(`(?i)\becu\b|electronic\s*control\s*unit`),
		regexp.MustCompile(`(?i)\boem\b|original\s*equipment\s*manufacturer`),
		regexp.MustCompile(`(?i)tier[- ]?1\s*supplier`),
	}
	m.taraPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)threat\s*analysis`),
		regexp.MustCompile(`(?i)risk\s*assessment`),
		regexp.MustCompile(`(?i)\btara\b`),
		regexp.MustCompile(`(?i)attack\s*surface`),
	}
	m.csmsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)cybersecurity\s*management`),
		regexp.MustCompile(`(?i)\bcsms\b`),
		regexp.MustCompile(`(?i)security\s*culture`),
	}
}

func (m *ISO21434Module) registerControls() {
	// Cybersecurity Management (CM)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-001",
		Name:        "Cybersecurity Management System (CSMS)",
		Description: "Organization must establish, implement, and maintain a cybersecurity management system",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCSMS,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-002",
		Name:        "Cybersecurity Culture and Competence",
		Description: "Organization must foster cybersecurity culture and ensure personnel competence",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCultureCompetence,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-003",
		Name:        "Cybersecurity Audit and Management Review",
		Description: "Organization must conduct cybersecurity audits and management reviews at planned intervals",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditManagementReview,
	})

	// Risk Assessment (RA)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-001",
		Name:        "Threat Analysis and Risk Assessment (TARA)",
		Description: "TARA must be performed to identify and assess cybersecurity risks to assets",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTARA,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-002",
		Name:        "Asset-based Risk Identification",
		Description: "Assets must be identified and their cybersecurity risks assessed based on damage scenarios",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAssetRiskIdentification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-003",
		Name:        "Risk Treatment Decision",
		Description: "Risk treatment decisions must be made and documented for each identified risk",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskTreatmentDecision,
	})

	// Product Development (PD)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-001",
		Name:        "Cybersecurity Goals and Claims",
		Description: "Cybersecurity goals and claims must be defined based on risk assessment outcomes",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityGoals,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-002",
		Name:        "Cybersecurity Requirements",
		Description: "Cybersecurity requirements must be derived from goals and allocated to system components",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityRequirements,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-003",
		Name:        "Architectural Design Security",
		Description: "System architecture must incorporate security design principles and mitigate identified threats",
		Category:    "Product Development",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkArchitecturalDesignSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-004",
		Name:        "Integration and Verification",
		Description: "Cybersecurity verification must be performed during integration and testing phases",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntegrationVerification,
	})

	// Production and Operations (PO)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-001",
		Name:        "Production Cybersecurity Controls",
		Description: "Cybersecurity controls must be validated during production and manufacturing processes",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProductionControls,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-002",
		Name:        "Incident Response and Monitoring",
		Description: "Organization must monitor for cybersecurity incidents and maintain an incident response plan",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-003",
		Name:        "Vulnerability Management and OTA Updates",
		Description: "Vulnerabilities must be managed and remediated, including via over-the-air (OTA) updates",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
	})
}

// CheckFunc implementations — each returns *compliance.ControlCheckResult.

func (m *ISO21434Module) checkCSMS(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.csmsPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "ISO21434-CM-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Cybersecurity management system content detected",
				Details:   "ISO 21434 requires establishing, implementing, and maintaining a CSMS",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No CSMS patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCultureCompetence(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security culture") || strings.Contains(content, "competence") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-CM-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity culture or competence reference detected",
			Details:   "ISO 21434 requires fostering cybersecurity culture and ensuring personnel competence",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity culture or competence references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkAuditManagementReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "audit") && (strings.Contains(content, "management review") || strings.Contains(content, "cybersecurity")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-CM-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity audit or management review content detected",
			Details:   "ISO 21434 requires cybersecurity audits and management reviews at planned intervals",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity audit or management review patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkTARA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.taraPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "ISO21434-RA-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Threat Analysis and Risk Assessment (TARA) content detected",
				Details:   "ISO 21434 requires TARA to identify and assess cybersecurity risks to assets",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No TARA patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkAssetRiskIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "asset") && (strings.Contains(content, "risk") || strings.Contains(content, "damage scenario")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-RA-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Asset-based risk identification content detected",
			Details:   "ISO 21434 requires identifying assets and assessing cybersecurity risks based on damage scenarios",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No asset-based risk identification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkRiskTreatmentDecision(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "risk treatment") || (strings.Contains(content, "risk") && strings.Contains(content, "decision")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-RA-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Risk treatment decision content detected",
			Details:   "ISO 21434 requires risk treatment decisions to be made and documented for each identified risk",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No risk treatment decision references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCybersecurityGoals(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "cybersecurity goal") || strings.Contains(content, "cybersecurity claim") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity goals or claims reference detected",
			Details:   "ISO 21434 requires cybersecurity goals and claims to be defined based on risk assessment outcomes",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity goals or claims references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCybersecurityRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "cybersecurity requirement") || strings.Contains(content, "security requirement") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity requirements content detected",
			Details:   "ISO 21434 requires cybersecurity requirements to be derived from goals and allocated to components",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity requirements patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkArchitecturalDesignSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "architecture") && (strings.Contains(content, "security") || strings.Contains(content, "threat")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Architectural design security content detected",
			Details:   "ISO 21434 requires the system architecture to incorporate security design principles and mitigate threats",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No architectural design security patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkIntegrationVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "integration") || strings.Contains(content, "verification")) && strings.Contains(content, "cybersecurity") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-004",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Integration and verification content detected",
			Details:   "ISO 21434 requires cybersecurity verification during integration and testing phases",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-004",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No integration and verification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkProductionControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "production") && (strings.Contains(content, "cybersecurity") || strings.Contains(content, "security control")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Production cybersecurity controls content detected",
			Details:   "ISO 21434 requires cybersecurity controls to be validated during production and manufacturing",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No production cybersecurity control patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "incident response") || (strings.Contains(content, "monitoring") && strings.Contains(content, "cybersecurity")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Incident response or monitoring content detected",
			Details:   "ISO 21434 requires monitoring for cybersecurity incidents and maintaining an incident response plan",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No incident response or monitoring patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "vulnerability") || strings.Contains(content, "ota") || strings.Contains(content, "over-the-air") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vulnerability management or OTA update content detected",
			Details:   "ISO 21434 requires vulnerabilities to be managed and remediated, including via OTA updates",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No vulnerability management or OTA update patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// GetPatterns returns the detection patterns for this module.
func (m *ISO21434Module) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.automotivePatterns...)
	all = append(all, m.taraPatterns...)
	all = append(all, m.csmsPatterns...)
	return all
}

// Framework returns the framework identifier.
func (m *ISO21434Module) Framework() string {
	return "ISO-21434"
}

// Version returns the framework version.
func (m *ISO21434Module) Version() string {
	return "2021"
}

// LastUpdated returns the last update time.
func (m *ISO21434Module) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *ISO21434Module) String() string {
	return fmt.Sprintf("ISO 21434 Module (v%s, %d controls)", m.Version(), len(m.automotivePatterns)+len(m.taraPatterns)+len(m.csmsPatterns))
}