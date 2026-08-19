// Package tsa_sd provides TSA Security Directive compliance controls as a licensed add-on module.
// TSA Security Directive (TSA-SD-2023) covers pipeline and transportation security, including
// cybersecurity assessments, incident response planning, access control, detection and monitoring,
// configuration and vulnerability management, data protection, AI controls, and coordination with
// CISA for critical pipeline infrastructure.
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
	pipelinePatterns       []*regexp.Regexp
	cisaPatterns           []*regexp.Regexp
	incidentPatterns       []*regexp.Regexp
	accessControlPatterns  []*regexp.Regexp
	vulnPatterns           []*regexp.Regexp
	dataProtectionPatterns []*regexp.Regexp
	aiPatterns             []*regexp.Regexp
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
	m.accessControlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)multi.?factor|MFA`),
		regexp.MustCompile(`(?i)remote\s*access`),
		regexp.MustCompile(`(?i)privileged\s*account`),
		regexp.MustCompile(`(?i)access\s*control\s*list|ACL`),
	}
	m.vulnPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)vulnerability\s*scan`),
		regexp.MustCompile(`(?i)patch\s*management`),
		regexp.MustCompile(`(?i)baseline\s*configuration`),
		regexp.MustCompile(`(?i)end.?of.?life|EOL`),
	}
	m.dataProtectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)encryption|encrypt`),
		regexp.MustCompile(`(?i)data\s*classification`),
		regexp.MustCompile(`(?i)secure\s*disposal|data\s*destruction`),
	}
	m.aiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AI\s*model`),
		regexp.MustCompile(`(?i)anomaly\s*detection`),
		regexp.MustCompile(`(?i)explainab|XAI`),
		regexp.MustCompile(`(?i)machine\s*learning|ML`),
	}
}

func (m *TSASDModule) registerControls() {
	// ── Pipeline Security (PS) — 7 controls (5 auto, 2 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-01",
		Name:        "Pipeline Cybersecurity Assessment",
		Description: "Pipeline operators must conduct cybersecurity assessments to identify vulnerabilities and risks",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPipelineCybersecurityAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-02",
		Name:        "Incident Response Plan",
		Description: "Pipeline operators must maintain an incident response plan for cybersecurity incidents",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-03",
		Name:        "Critical Infrastructure Identification",
		Description: "Operators must identify and document critical pipeline infrastructure assets",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCriticalInfrastructureIdentification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-04",
		Name:        "Cybersecurity Performance Measures",
		Description: "Pipeline operators must implement and track cybersecurity performance measures",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityPerformanceMeasures,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-05",
		Name:        "Pipeline Security Coordinator",
		Description: "Operators must designate a Pipeline Security Coordinator responsible for cybersecurity oversight",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPipelineSecurityCoordinator,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-06",
		Name:        "Annual Security Review",
		Description: "Pipeline operators must conduct an annual security review of all cybersecurity measures and controls",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkAnnualSecurityReview,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-PS-07",
		Name:        "Pipeline-Risk Assessment Update",
		Description: "Operators must update pipeline-risk assessments at least annually or after significant changes",
		Category:    "Pipeline Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkPipelineRiskAssessmentUpdate,
	})

	// ── Access Control (AC) — 6 controls (4 auto, 2 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-01",
		Name:        "Multi-Factor Authentication for Critical Systems",
		Description: "Multi-factor authentication must be required for access to critical pipeline systems",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFACriticalSystems,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-02",
		Name:        "Remote Access Security",
		Description: "Remote access to pipeline systems must use secure authentication and monitoring",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccessSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-03",
		Name:        "Privileged Account Management",
		Description: "Privileged accounts must be managed with strict controls and monitoring",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccountManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-04",
		Name:        "Access Control List Management",
		Description: "Access control lists must be documented, reviewed, and maintained for all pipeline systems",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessControlListManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-05",
		Name:        "Account Lifecycle Management",
		Description: "User accounts must be managed through a formal lifecycle process including provisioning, modification, and deactivation",
		Category:    "Access Control",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkAccountLifecycleManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AC-06",
		Name:        "Personnel Security Clearances",
		Description: "Personnel with access to critical pipeline systems must undergo appropriate security clearance and background checks",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkPersonnelSecurityClearances,
	})

	// ── Detection and Monitoring (DM) — 6 controls (4 auto, 2 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-01",
		Name:        "Continuous Monitoring",
		Description: "Pipeline operators must implement continuous monitoring of critical systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-02",
		Name:        "Threat Detection Capability",
		Description: "Operators must maintain threat detection capabilities for pipeline systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatDetectionCapability,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-03",
		Name:        "Security Event Logging",
		Description: "Security events must be logged and retained for pipeline systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityEventLogging,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-04",
		Name:        "Log Retention and Analysis",
		Description: "Security logs must be retained per policy and analyzed for threats and anomalies",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLogRetentionAndAnalysis,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-05",
		Name:        "Security Operations Center",
		Description: "Operators must establish or contract a Security Operations Center for 24/7 monitoring of pipeline systems",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		CheckFunc:   m.checkSecurityOperationsCenter,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DM-06",
		Name:        "Threat Hunting Program",
		Description: "Operators must establish a threat hunting program to proactively identify threats in pipeline environments",
		Category:    "Detection and Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkThreatHuntingProgram,
	})

	// ── Coordination and Reporting (CR) — 5 controls (3 auto, 2 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-01",
		Name:        "CISA Notification Requirements",
		Description: "Pipeline operators must notify CISA of cybersecurity incidents within required timeframes",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCISANotificationRequirements,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-02",
		Name:        "Industry Information Sharing",
		Description: "Operators must participate in industry information sharing programs for threat intelligence",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIndustryInformationSharing,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-03",
		Name:        "TSA Compliance Reporting",
		Description: "Operators must submit regular compliance reports to TSA demonstrating adherence to security directives",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTSAComplianceReporting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-04",
		Name:        "Joint Cybersecurity Assessments",
		Description: "Operators must participate in joint cybersecurity assessments with government and industry partners",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkJointCybersecurityAssessments,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CR-05",
		Name:        "Government Coordination Plan",
		Description: "Operators must maintain a government coordination plan for cybersecurity incident response and recovery",
		Category:    "Coordination and Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkGovernmentCoordinationPlan,
	})

	// ── Configuration and Vulnerability Management (CV) — 5 controls (3 auto, 2 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CV-01",
		Name:        "Baseline Configuration Management",
		Description: "Operators must maintain baseline configurations for all pipeline systems and detect deviations",
		Category:    "Configuration and Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBaselineConfigurationManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CV-02",
		Name:        "Vulnerability Scanning",
		Description: "Operators must conduct regular vulnerability scans of pipeline systems and remediate findings",
		Category:    "Configuration and Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityScanning,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CV-03",
		Name:        "Patch Management for Pipeline Systems",
		Description: "Operators must implement a patch management program for pipeline systems with defined SLAs",
		Category:    "Configuration and Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPatchManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CV-04",
		Name:        "Change Control Board",
		Description: "Operators must establish a Change Control Board to review and approve all changes to pipeline systems",
		Category:    "Configuration and Vulnerability Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkChangeControlBoard,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-CV-05",
		Name:        "End-of-Life System Remediation",
		Description: "Operators must identify and remediate end-of-life systems in the pipeline environment",
		Category:    "Configuration and Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkEndOfLifeSystemRemediation,
	})

	// ── Data Protection (DP) — 3 controls (2 auto, 1 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DP-01",
		Name:        "Encryption of Operational Data",
		Description: "Operational data in transit and at rest must be encrypted using approved cryptographic standards",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionOperationalData,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DP-02",
		Name:        "Data Classification for Pipeline Information",
		Description: "Pipeline information must be classified according to sensitivity and handled per classification requirements",
		Category:    "Data Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataClassificationPipelineInfo,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-DP-03",
		Name:        "Secure Data Disposal",
		Description: "Data and media must be securely disposed of using approved methods to prevent recovery of sensitive information",
		Category:    "Data Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkSecureDataDisposal,
	})

	// ── AI Controls (AI) — 3 controls (2 auto, 1 manual) ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AI-01",
		Name:        "AI Model Pipeline Data Protection",
		Description: "AI models processing pipeline data must implement data protection controls to prevent unauthorized access or leakage",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelPipelineDataProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AI-02",
		Name:        "AI Anomaly Detection for Pipeline Operations",
		Description: "AI-based anomaly detection systems must be deployed to identify operational anomalies in pipeline systems",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAnomalyDetectionPipelineOps,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TSA-SD-AI-03",
		Name:        "AI Decision Explainability for Critical Operations",
		Description: "AI systems making critical pipeline operation decisions must provide explainability and auditability of decisions",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkAIDecisionExplainability,
	})
}

// ─── CheckFunc implementations ────────────────────────────────────────────
// Each returns *compliance.ControlCheckResult.

// ── Pipeline Security ──

func (m *TSASDModule) checkPipelineCybersecurityAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.pipelinePatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-PS-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Pipeline cybersecurity assessment content detected — verify assessment is current",
				Details:   "Pipeline operators must conduct regular cybersecurity assessments to identify vulnerabilities and risks",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-01",
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
				ControlID: "TSA-SD-PS-02",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Incident response plan content detected — verify plan is tested and current",
				Details:   "Pipeline operators must maintain and test an incident response plan for cybersecurity incidents",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-02",
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
			ControlID: "TSA-SD-PS-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Critical infrastructure identification content detected — verify asset inventory is current",
			Details:   "Operators must identify and document critical pipeline infrastructure assets",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-03",
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
			ControlID: "TSA-SD-PS-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Cybersecurity performance measures content detected — verify metrics are tracked",
			Details:   "Pipeline operators must implement and track cybersecurity performance measures",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No cybersecurity performance measure patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkPipelineSecurityCoordinator(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security coordinator") || (strings.Contains(content, "coordinator") && strings.Contains(content, "pipeline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-PS-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Pipeline security coordinator reference detected — verify coordinator is designated and active",
			Details:   "Operators must designate a Pipeline Security Coordinator responsible for cybersecurity oversight",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No pipeline security coordinator patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkAnnualSecurityReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "annual security review") || (strings.Contains(content, "annual") && strings.Contains(content, "security") && strings.Contains(content, "review")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-PS-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Annual security review content detected — verify review is conducted and documented",
			Details:   "Pipeline operators must conduct an annual security review of all cybersecurity measures and controls",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No annual security review patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkPipelineRiskAssessmentUpdate(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "risk assessment") && (strings.Contains(content, "pipeline") || strings.Contains(content, "update")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-PS-07",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Pipeline-risk assessment update content detected — verify assessment is current",
			Details:   "Operators must update pipeline-risk assessments at least annually or after significant changes",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-PS-07",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No pipeline-risk assessment update patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── Access Control ──

func (m *TSASDModule) checkMFACriticalSystems(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "multi-factor") || strings.Contains(content, "mfa") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Multi-factor authentication reference detected — verify MFA is enforced on critical systems",
			Details:   "Multi-factor authentication must be required for access to critical pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-01",
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
			ControlID: "TSA-SD-AC-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Remote access reference detected — verify secure authentication and monitoring",
			Details:   "Remote access to pipeline systems must use secure authentication and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-02",
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
			ControlID: "TSA-SD-AC-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Privileged account reference detected — verify strict controls and monitoring",
			Details:   "Privileged accounts must be managed with strict controls and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No privileged account references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkAccessControlListManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "access control list") || strings.Contains(content, "acl") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Access control list reference detected — verify ACLs are documented and reviewed",
			Details:   "Access control lists must be documented, reviewed, and maintained for all pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No access control list patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkAccountLifecycleManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "account lifecycle") || (strings.Contains(content, "provisioning") && strings.Contains(content, "deactivation")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Account lifecycle management content detected — verify lifecycle process is formalized",
			Details:   "User accounts must be managed through a formal lifecycle process including provisioning, modification, and deactivation",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No account lifecycle management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkPersonnelSecurityClearances(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security clearance") || (strings.Contains(content, "background") && strings.Contains(content, "check")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AC-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Personnel security clearance content detected — verify clearances are current and documented",
			Details:   "Personnel with access to critical pipeline systems must undergo appropriate security clearance and background checks",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AC-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No personnel security clearance patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── Detection and Monitoring ──

func (m *TSASDModule) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "continuous monitoring") || (strings.Contains(content, "monitoring") && strings.Contains(content, "pipeline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Continuous monitoring content detected — verify monitoring covers critical systems",
			Details:   "Pipeline operators must implement continuous monitoring of critical systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-01",
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
			ControlID: "TSA-SD-DM-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Threat detection capability content detected — verify detection covers pipeline systems",
			Details:   "Operators must maintain threat detection capabilities for pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-02",
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
			ControlID: "TSA-SD-DM-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Security event logging content detected — verify logs are retained per policy",
			Details:   "Security events must be logged and retained for pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No security event logging patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkLogRetentionAndAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "log retention") || (strings.Contains(content, "retention") && strings.Contains(content, "log")) || (strings.Contains(content, "log") && strings.Contains(content, "analysis")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Log retention and analysis content detected — verify retention policies and analysis are in place",
			Details:   "Security logs must be retained per policy and analyzed for threats and anomalies",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No log retention and analysis patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkSecurityOperationsCenter(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security operations center") || strings.Contains(content, "soc") || strings.Contains(content, "24/7") || strings.Contains(content, "24x7") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Security operations center content detected — verify SOC is established and operational",
			Details:   "Operators must establish or contract a Security Operations Center for 24/7 monitoring of pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No security operations center patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkThreatHuntingProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "threat hunting") || (strings.Contains(content, "hunting") && strings.Contains(content, "threat")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DM-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Threat hunting program content detected — verify program is established and active",
			Details:   "Operators must establish a threat hunting program to proactively identify threats in pipeline environments",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DM-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No threat hunting program patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── Coordination and Reporting ──

func (m *TSASDModule) checkCISANotificationRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.cisaPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-CR-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "CISA notification content detected — verify notification procedures are established",
				Details:   "Pipeline operators must notify CISA of cybersecurity incidents within required timeframes",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-01",
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
			ControlID: "TSA-SD-CR-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Industry information sharing content detected — verify participation in threat intelligence programs",
			Details:   "Operators must participate in industry information sharing programs for threat intelligence",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No industry information sharing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkTSAComplianceReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "compliance report") || (strings.Contains(content, "tsa") && strings.Contains(content, "report")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CR-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "TSA compliance reporting content detected — verify reports are submitted on schedule",
			Details:   "Operators must submit regular compliance reports to TSA demonstrating adherence to security directives",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No TSA compliance reporting patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkJointCybersecurityAssessments(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "joint assessment") || (strings.Contains(content, "joint") && strings.Contains(content, "cybersecurity") && strings.Contains(content, "assessment")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CR-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Joint cybersecurity assessment content detected — verify participation is documented",
			Details:   "Operators must participate in joint cybersecurity assessments with government and industry partners",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No joint cybersecurity assessment patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkGovernmentCoordinationPlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "government coordination") || (strings.Contains(content, "coordination plan") && strings.Contains(content, "government")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CR-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Government coordination plan content detected — verify plan is maintained and tested",
			Details:   "Operators must maintain a government coordination plan for cybersecurity incident response and recovery",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CR-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No government coordination plan patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── Configuration and Vulnerability Management ──

func (m *TSASDModule) checkBaselineConfigurationManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "baseline configuration") || (strings.Contains(content, "configuration") && strings.Contains(content, "baseline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CV-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Baseline configuration management content detected — verify baselines are documented and deviations detected",
			Details:   "Operators must maintain baseline configurations for all pipeline systems and detect deviations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CV-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No baseline configuration management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkVulnerabilityScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "vulnerability scan") || strings.Contains(content, "vulnerability scanning") || (strings.Contains(content, "vulnerability") && strings.Contains(content, "scan")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CV-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Vulnerability scanning content detected — verify scans are conducted regularly and findings remediated",
			Details:   "Operators must conduct regular vulnerability scans of pipeline systems and remediate findings",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CV-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No vulnerability scanning patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkPatchManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "patch management") || (strings.Contains(content, "patch") && strings.Contains(content, "pipeline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CV-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Patch management content detected — verify patch SLAs are defined and met for pipeline systems",
			Details:   "Operators must implement a patch management program for pipeline systems with defined SLAs",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CV-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No patch management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkChangeControlBoard(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "change control board") || (strings.Contains(content, "change control") && strings.Contains(content, "board")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CV-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Change control board content detected — verify board is established and reviewing changes",
			Details:   "Operators must establish a Change Control Board to review and approve all changes to pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CV-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No change control board patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkEndOfLifeSystemRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "end-of-life") || strings.Contains(content, "end of life") || strings.Contains(content, "eol") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-CV-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "End-of-life system content detected — verify EOL systems are identified and remediation planned",
			Details:   "Operators must identify and remediate end-of-life systems in the pipeline environment",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-CV-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No end-of-life system patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── Data Protection ──

func (m *TSASDModule) checkEncryptionOperationalData(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "encryption") || strings.Contains(content, "encrypt") {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DP-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Encryption reference detected — verify operational data is encrypted in transit and at rest",
			Details:   "Operational data in transit and at rest must be encrypted using approved cryptographic standards",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DP-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No encryption patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkDataClassificationPipelineInfo(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "data classification") || (strings.Contains(content, "classification") && strings.Contains(content, "pipeline")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DP-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Data classification content detected — verify pipeline information is classified per sensitivity",
			Details:   "Pipeline information must be classified according to sensitivity and handled per classification requirements",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DP-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No data classification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkSecureDataDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "secure disposal") || strings.Contains(content, "data destruction") || (strings.Contains(content, "disposal") && strings.Contains(content, "data")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-DP-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Secure data disposal content detected — verify approved disposal methods are used",
			Details:   "Data and media must be securely disposed of using approved methods to prevent recovery of sensitive information",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-DP-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No secure data disposal patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── AI Controls ──

func (m *TSASDModule) checkAIModelPipelineDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.aiPatterns {
		if p.MatchString(content) && (strings.Contains(strings.ToLower(content), "pipeline") || strings.Contains(strings.ToLower(content), "data")) {
			return &compliance.ControlCheckResult{
				ControlID: "TSA-SD-AI-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "AI model pipeline data protection content detected — verify data protection controls are in place",
				Details:   "AI models processing pipeline data must implement data protection controls to prevent unauthorized access or leakage",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AI-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No AI model pipeline data protection patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkAIAnomalyDetectionPipelineOps(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "anomaly detection") || (strings.Contains(content, "ai") && strings.Contains(content, "anomaly")) || (strings.Contains(content, "machine learning") && strings.Contains(content, "anomaly")) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AI-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI anomaly detection content detected — verify detection systems are deployed for pipeline operations",
			Details:   "AI-based anomaly detection systems must be deployed to identify operational anomalies in pipeline systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AI-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI anomaly detection patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *TSASDModule) checkAIDecisionExplainability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "explainab") || strings.Contains(content, "xai") || (strings.Contains(content, "ai") && strings.Contains(content, "decision") && (strings.Contains(content, "explain") || strings.Contains(content, "audit"))) {
		return &compliance.ControlCheckResult{
			ControlID: "TSA-SD-AI-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI decision explainability content detected — verify critical operation decisions are explainable and auditable",
			Details:   "AI systems making critical pipeline operation decisions must provide explainability and auditability of decisions",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "TSA-SD-AI-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI decision explainability patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ─── Module metadata methods ──────────────────────────────────────────────

// GetPatterns returns the detection patterns for this module.
func (m *TSASDModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.pipelinePatterns...)
	all = append(all, m.cisaPatterns...)
	all = append(all, m.incidentPatterns...)
	all = append(all, m.accessControlPatterns...)
	all = append(all, m.vulnPatterns...)
	all = append(all, m.dataProtectionPatterns...)
	all = append(all, m.aiPatterns...)
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
	return fmt.Sprintf("TSA SD Module (v%s, %d controls)", m.Version(), 35)
}
