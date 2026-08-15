// Package tsa_sd provides TSA Security Directive compliance controls as a licensed add-on module.
// TSA Security Directive (TSA-SD-2023) covers pipeline and transportation security, including
// cybersecurity assessments, incident response planning, access control, detection and monitoring,
// and coordination with CISA for critical pipeline infrastructure.
package tsa_sd

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// TSASDModule implements TSA Security Directive compliance controls.
type TSASDModule struct {
	*compliance.BaseComplianceModule
	pipelinePatterns  []*regexp.Regexp
	cisaPatterns      []*regexp.Regexp
	incidentPatterns  []*regexp.Regexp
}

// NewTSASDModule creates a new TSA Security Directive compliance module.
func NewTSASDModule() *TSASDModule {
	m := &TSASDModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("tsa_sd", "TSA-SD-2023", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *TSASDModule) initPatterns() {
	m.pipelinePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)pipeline`),
		regexp.MustCompile(`(?i)TSA\s*security\s*directive`),
		regexp.MustCompile(`(?i)critical\s*pipeline`),
		regexp.MustCompile(`(?i)hazardous\s*liquid`),
		regexp.MustCompile(`(?i)natural\s*gas`),
	}
	m.cisaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)CISA`),
		regexp.MustCompile(`(?i)cybersecurity\s*and\s*infrastructure`),
		regexp.MustCompile(`(?i)reporting\s*requirement`),
	}
	m.incidentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)incident\s*response\s*plan|IRP`),
		regexp.MustCompile(`(?i)containment`),
		regexp.MustCompile(`(?i)eradication`),
	}
}

func (m *TSASDModule) registerControls() {
	// Pipeline Security (PS)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-001",
		Name:        "Pipeline Cybersecurity Assessment",
		Description: "Pipeline operators must conduct cybersecurity assessments to identify vulnerabilities and risks",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPipelineCybersecurityAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-002",
		Name:        "Incident Response Plan",
		Description: "Pipeline operators must maintain an incident response plan for cybersecurity incidents",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-003",
		Name:        "Critical Infrastructure Identification",
		Description: "Operators must identify and document critical pipeline infrastructure assets",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCriticalInfrastructureIdentification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-004",
		Name:        "Cybersecurity Performance Measures",
		Description: "Pipeline operators must implement and track cybersecurity performance measures",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityPerformanceMeasures,
	})

	// Access Control (AC)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-001",
		Name:        "Multi-Factor Authentication for Critical Systems",
		Description: "Multi-factor authentication must be required for access to critical pipeline systems",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFACriticalSystems,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-002",
		Name:        "Remote Access Security",
		Description: "Remote access to pipeline systems must use secure authentication and monitoring",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccessSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-003",
		Name:        "Privileged Account Management",
		Description: "Privileged accounts must be managed with strict controls and monitoring",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccountManagement,
	})

	// Detection and Monitoring (DM)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-001",
		Name:        "Continuous Monitoring",
		Description: "Pipeline operators must implement continuous monitoring of critical systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-002",
		Name:        "Threat Detection Capability",
		Description: "Operators must maintain threat detection capabilities for pipeline systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatDetectionCapability,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-003",
		Name:        "Security Event Logging",
		Description: "Security events must be logged and retained for pipeline systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityEventLogging,
	})

	// Coordination and Reporting (CR)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-001",
		Name:        "CISA Notification Requirements",
		Description: "Pipeline operators must notify CISA of cybersecurity incidents within required timeframes",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCISANotificationRequirements,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-002",
		Name:        "Industry Information Sharing",
		Description: "Operators must participate in industry information sharing programs for threat intelligence",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIndustryInformationSharing,
	})
}

// CheckFunc implementations — each returns *compliance.ControlCheckResult.

func (m *TSASDModule) checkPipelineCybersecurityAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.pipelinePatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-PS-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Pipeline cybersecurity assessment content detected — verify assessment is current",
				Details:   "Pipeline operators must conduct regular cybersecurity assessments to identify vulnerabilities and risks",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No pipeline cybersecurity assessment patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkIncidentResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.incidentPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-PS-002",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Incident response plan content detected — verify plan is tested and current",
				Details:   "Pipeline operators must maintain and test an incident response plan for cybersecurity incidents",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No incident response plan patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkCriticalInfrastructureIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "critical") && (strings.Contains(content, "pipeline") || strings.Contains(content, "infrastructure")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-PS-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Critical infrastructure identification content detected — verify asset inventory is current",
			Details:   "Operators must identify and document critical pipeline infrastructure assets",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No critical infrastructure identification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkCybersecurityPerformanceMeasures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "performance measure") && (strings.Contains(content, "cybersecurity") || strings.Contains(content, "metric")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-PS-004",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Cybersecurity performance measures content detected — verify metrics are tracked",
			Details:   "Pipeline operators must implement and track cybersecurity performance measures",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-004",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No cybersecurity performance measure patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkMFACriticalSystems(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "multi-factor") || strings.Contains(content, "mfa") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Multi-factor authentication reference detected — verify MFA is enforced on critical systems",
			Details:   "Multi-factor authentication must be required for access to critical pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No MFA references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkRemoteAccessSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "remote access") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Remote access reference detected — verify secure authentication and monitoring",
			Details:   "Remote access to pipeline systems must use secure authentication and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No remote access references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkPrivilegedAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "privileged") || strings.Contains(content, "admin account") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Privileged account reference detected — verify strict controls and monitoring",
			Details:   "Privileged accounts must be managed with strict controls and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No privileged account references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "continuous monitoring") || (strings.Contains(content, "monitoring") && strings.Contains(content, "pipeline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Continuous monitoring content detected — verify monitoring covers critical systems",
			Details:   "Pipeline operators must implement continuous monitoring of critical systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No continuous monitoring patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkThreatDetectionCapability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "threat detection") || (strings.Contains(content, "detection") && (strings.Contains(content, "ids") || strings.Contains(content, "ips") || strings.Contains(content, "edr"))) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Threat detection capability content detected — verify detection covers pipeline systems",
			Details:   "Operators must maintain threat detection capabilities for pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No threat detection capability patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkSecurityEventLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security event") || (strings.Contains(content, "event log") && strings.Contains(content, "security")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Security event logging content detected — verify logs are retained per policy",
			Details:   "Security events must be logged and retained for pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No security event logging patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkCISANotificationRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.cisaPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-CR-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "CISA notification content detected — verify notification procedures are established",
				Details:   "Pipeline operators must notify CISA of cybersecurity incidents within required timeframes",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No CISA notification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkIndustryInformationSharing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "information sharing") || (strings.Contains(content, "threat intelligence") && strings.Contains(content, "industry")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CR-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Industry information sharing content detected — verify participation in threat intelligence programs",
			Details:   "Operators must participate in industry information sharing programs for threat intelligence",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No industry information sharing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// GetPatterns returns the detection patterns for this module.
func (m *TSASDModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.pipelinePatterns...)
	all = append(all, m.cisaPatterns...)
	all = append(all, m.incidentPatterns...)
	return all
}

// Framework returns the framework identifier.
func (m *TSASDModule) Framework() string {
	return "TSA-SD"
}

// Version returns the framework version.
func (m *TSASDModule) Version() string {
	return "2023"
}

// LastUpdated returns the last update time.
func (m *TSASDModule) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *TSASDModule) String() string {
	return fmt.Sprintf("TSA SD Module (v%s, %d controls)", m.Version(), len(m.pipelinePatterns)+len(m.cisaPatterns)+len(m.incidentPatterns))
}