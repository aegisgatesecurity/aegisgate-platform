// Package hitech provides HITECH Act compliance controls as a licensed add-on module.
// HITECH (Health Information Technology for Economic and Clinical Health Act) extends
// HIPAA with breach notification requirements, enhanced penalties, and audit log
// requirements for electronic health records (EHR).
package hitech

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// HITECHModule implements HITECH Act compliance controls.
type HITECHModule struct {
	*compliance.BaseComplianceModule
	breachPatterns []*regexp.Regexp
	auditPatterns  []*regexp.Regexp
	ehrPatterns    []*regexp.Regexp
}

// NewHITECHModule creates a new HITECH compliance module.
func NewHITECHModule() *HITECHModule {
	m := &HITECHModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("hitech", "HITECH-2009", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *HITECHModule) initPatterns() {
	m.breachPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)breach\s*(?:notification|report|incident)`),
		regexp.MustCompile(`(?i)unsecured\s*(?:phi|protected\s*health)`),
		regexp.MustCompile(`(?i)breach\s*affecting\s*(?:more\s*than|over)\s*\d+`),
	}
	m.auditPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit\s*(?:log|trail|record)\s*(?:access|entry|modification)`),
		regexp.MustCompile(`(?i)ehr\s*(?:access|log|audit)`),
		regexp.MustCompile(`(?i)meaningful\s*use`),
		regexp.MustCompile(`(?i)certified\s*(?:ehr|health\s*it)`),
	}
	m.ehrPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)electronic\s*health\s*record|ehr`),
		regexp.MustCompile(`(?i)health\s*information\s*exchange|hie`),
		regexp.MustCompile(`(?i)clinical\s*decision\s*support`),
		regexp.MustCompile(`(?i)e?\s*prescribing|eprescribe`),
	}
}

func (m *HITECHModule) registerControls() {
	// Breach Notification (BN)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-001",
		Name:        "Breach Notification Requirement",
		Description: "Covered entities must notify affected individuals of a breach of unsecured PHI within 60 days",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachNotification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-002",
		Name:        "HHS Breach Reporting",
		Description: "Breaches affecting 500+ individuals must be reported to HHS within 60 days",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkHHSReporting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-003",
		Name:        "Media Notification",
		Description: "Breaches affecting 500+ residents of a state must be reported to local media",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaNotification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-004",
		Name:        "Annual Breach Log",
		Description: "Breaches affecting fewer than 500 individuals must be logged and reported annually to HHS",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAnnualBreachLog,
	})

	// Enhanced Penalties (EP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-001",
		Name:        "Tiered Penalty Structure",
		Description: "HITECH establishes tiered civil monetary penalties based on culpability",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPenaltyStructure,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-002",
		Name:        "Annual Penalty Cap",
		Description: "Annual cap on penalties per violation tier (adjusted for inflation)",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPenaltyCap,
	})

	// EHR Audit Requirements (EA)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-001",
		Name:        "EHR Access Audit Logging",
		Description: "EHR systems must maintain audit logs of all access to electronic PHI",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEHRAuditLogging,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-002",
		Name:        "Audit Log Tamper Protection",
		Description: "Audit logs must be protected from alteration or deletion",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogTamperProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-003",
		Name:        "Meaningful Use Attestation",
		Description: "Providers must attest to meaningful use of certified EHR technology",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMeaningfulUse,
	})

	// Business Associate Accountability (BA)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-001",
		Name:        "Business Associate Direct Liability",
		Description: "HITECH makes business associates directly liable for HIPAA violations",
		Category:    "Business Associate",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBALiability,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-002",
		Name:        "Subcontractor Flow-Down",
		Description: "Business associates must flow down HIPAA obligations to subcontractors",
		Category:    "Business Associate",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSubcontractorFlowDown,
	})
}

// CheckFunc implementations — each returns *compliance.ControlCheckResult.

func (m *HITECHModule) checkBreachNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.breachPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-BN-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Potential breach notification content detected",
				Details:   "HITECH requires individual notification within 60 days of breach discovery",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No breach notification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkHHSReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "500+") || strings.Contains(content, "more than 500") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Large-scale breach detected — HHS reporting required within 60 days",
			Details:   "Breaches affecting 500+ individuals require immediate HHS notification",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No large-scale breach indicators detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkMediaNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	for _, p := range m.breachPatterns {
		if p.MatchString(content) && strings.Contains(content, "media") {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-BN-003",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Media notification may be required for this breach",
				Details:   "Breaches affecting 500+ state residents require media notification",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No media notification triggers detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAnnualBreachLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "breach") && strings.Contains(content, "annual") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-004",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Annual breach log entry detected — verify HHS annual report is filed",
			Details:   "Breaches under 500 individuals must be logged and reported annually to HHS",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-004",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No annual breach log entries detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkPenaltyStructure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "penalty") && strings.Contains(content, "tier") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Penalty tier reference detected — verify correct tier classification",
			Details:   "HITECH tiered penalties: (1) no knowledge, (2) reasonable cause, (3) willful neglect-corrected, (4) willful neglect-not corrected",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No penalty tier references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkPenaltyCap(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "annual cap") || strings.Contains(content, "penalty cap") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Annual penalty cap reference detected — verify inflation-adjusted amount",
			Details:   "Annual cap per violation tier is adjusted for inflation per HHS rulemaking",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No penalty cap references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkEHRAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.auditPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-EA-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "EHR audit log content detected — verify access logging is enabled",
				Details:   "EHR systems must log all access to electronic PHI",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No EHR audit log patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAuditLogTamperProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "audit log") && (strings.Contains(content, "delete") || strings.Contains(content, "modify") || strings.Contains(content, "alter")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Audit log modification detected — tamper protection may be violated",
			Details:   "Audit logs must be protected from alteration or deletion",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No audit log tamper indicators detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkMeaningfulUse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "meaningful use") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Meaningful use attestation reference detected — verify EHR certification",
			Details:   "Providers must attest to meaningful use of certified EHR technology",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No meaningful use references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBALiability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business associate") && strings.Contains(content, "liable") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Business associate liability reference detected — verify direct liability compliance",
			Details:   "HITECH makes business associates directly liable for HIPAA violations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No BA liability references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkSubcontractorFlowDown(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "subcontractor") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Subcontractor reference detected — verify HIPAA obligations are flowed down",
			Details:   "Business associates must flow down HIPAA obligations to subcontractors",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No subcontractor references detected",
		Timestamp: time.Now(),
	}, nil
}

// GetPatterns returns the detection patterns for this module.
func (m *HITECHModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.breachPatterns...)
	all = append(all, m.auditPatterns...)
	all = append(all, m.ehrPatterns...)
	return all
}

// Framework returns the framework identifier.
func (m *HITECHModule) Framework() string {
	return "HITECH"
}

// Version returns the framework version.
func (m *HITECHModule) Version() string {
	return "2009"
}

// LastUpdated returns the last update time.
func (m *HITECHModule) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *HITECHModule) String() string {
	return fmt.Sprintf("HITECH Module (v%s, %d controls)", m.Version(), len(m.breachPatterns)+len(m.auditPatterns)+len(m.ehrPatterns))
}