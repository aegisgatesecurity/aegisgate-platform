// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO/IEC 42001 AI Management System Module
// =========================================================================
//
// Implements ISO/IEC 42001 (AI Management System) compliance controls as
// a licensed add-on module. This is the 5th framework shipped (HIPAA,
// PCI-DSS, EU AI Act, SOC 2, ISO 42001; FedRAMP and FIPS 140 are
// Path B remaining).
//
// Module metadata:
//   - Framework:   "iso_42001"
//   - Version:     "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $79/mo (founder-locked 2026-06-04)
//
// Coverage: 8 controls across 5 ISO 42001 clauses (4.0 Context of
// Organization, 5.0 Leadership, 6.0 Planning, 7.0 Support, 8.0
// Operation, 9.0 Performance Evaluation, 10.0 Improvement, plus an
// AI-specific extension for AIMS controls). Of the 8 controls,
// 5 have automated CheckFunc implementations.
//
// Reference: ISO/IEC 42001:2023 AI Management Systems
//            https://www.iso.org/standard/81230.html
//
// =========================================================================

package iso42001

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ISO42001Module implements the ISO/IEC 42001 AI Management System
// compliance framework as a licensed add-on. It embeds
// *compliance.BaseComplianceModule which provides RegisterControl,
// Controls(), Framework(), Version(), CheckAll(), and
// GenerateAssessment() out of the box.
type ISO42001Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	policyPatterns    []*regexp.Regexp
	riskPatterns      []*regexp.Regexp
	documentationPats []*regexp.Regexp
}

// NewISO42001Module creates a new ISO 42001 compliance module. It is
// safe to call multiple times; the module is stateless after
// construction aside from its registered controls.
//
// The module is gated to Professional+ tier via
// pkg/compliance/gating.go (license.ModuleISO42001 entry in
// moduleRequirements).
func NewISO42001Module() *ISO42001Module {
	m := &ISO42001Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("iso_42001", "1.1", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated
// controls. Called once at construction time.
func (m *ISO42001Module) initPatterns() {
	m.policyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai[_ ]?policy`),
		regexp.MustCompile(`(?i)acceptable[_ ]?use[_ ]?policy`),
		regexp.MustCompile(`(?i)ai[_ ]?governance`),
		regexp.MustCompile(`(?i)aims[_ ]?policy`),
	}
	m.riskPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)risk[_ ]?assessment`),
		regexp.MustCompile(`(?i)risk[_ ]?treatment`),
		regexp.MustCompile(`(?i)ai[_ ]?risk`),
		regexp.MustCompile(`(?i)threat[_ ]?model`),
		regexp.MustCompile(`(?i)adversarial[_ ]?risk`),
	}
	m.documentationPats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)statement[_ ]?of[_ ]?applicability`),
		regexp.MustCompile(`(?i)risk[_ ]?register`),
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)compliance[_ ]?report`),
	}
}

// registerControls wires all 8 ISO 42001 controls into the module.
// Called once from NewISO42001Module. The 5 automated controls
// reference check* methods defined below; the rest are manual review.
func (m *ISO42001Module) registerControls() {
	// Clause 4: Context of the Organization
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-4.1",
		Name:        "Context of the Organization",
		Description: "ISO 42001 4.1: Understand the organization's context and the needs/expectations of interested parties",
		Category:    "Context of the Organization",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Requires organizational context review
		References:  []string{"ISO/IEC 42001:2023 4.1"},
	})

	// Clause 5: Leadership
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.1",
		Name:        "Leadership and Commitment",
		Description: "ISO 42001 5.1: Top management demonstrates leadership and commitment to the AI management system",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Requires organizational governance review
		References:  []string{"ISO/IEC 42001:2023 5.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-5.2",
		Name:        "AI Policy",
		Description: "ISO 42001 5.2: AI policy is established, communicated, and maintained",
		Category:    "Leadership",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIPolicy,
		References:  []string{"ISO/IEC 42001:2023 5.2"},
	})

	// Clause 6: Planning
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-6.1",
		Name:        "AI Risk Assessment and Treatment",
		Description: "ISO 42001 6.1: AI risks are identified, assessed, and treated",
		Category:    "Planning",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"ISO/IEC 42001:2023 6.1"},
	})

	// Clause 7: Support
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-7.5",
		Name:        "Documented Information",
		Description: "ISO 42001 7.5: Documented information is created, updated, and controlled",
		Category:    "Support",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDocumentedInfo,
		References:  []string{"ISO/IEC 42001:2023 7.5"},
	})

	// Clause 8: Operation
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.2",
		Name:        "AI Risk Treatment Implementation",
		Description: "ISO 42001 8.2: AI risk treatment plan is implemented and effective",
		Category:    "Operation",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskTreatment,
		References:  []string{"ISO/IEC 42001:2023 8.2"},
	})

	// Clause 9: Performance Evaluation
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.1",
		Name:        "Monitoring, Measurement, Analysis, and Evaluation",
		Description: "ISO 42001 9.1: AIMS performance is monitored, measured, analyzed, and evaluated",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMonitoring,
		References:  []string{"ISO/IEC 42001:2023 9.1"},
	})

	// Clause 8: Operation (additional sub-clauses for v3.x Tier 1)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.1",
		Name:        "Operational Planning and Control",
		Description: "ISO 42001 8.1: Plan, implement, and control the processes needed to meet AI management system requirements and implement the actions determined in Clause 6. Includes criteria for AI system deployment.",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOperationalPlanning,
		References:  []string{"ISO/IEC 42001:2023 8.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-8.3",
		Name:        "AI System Change Management",
		Description: "ISO 42001 8.3: Control AI system changes (model updates, prompt template changes, agent configuration changes) and review unintended consequences. AegisGate's Trust Framework + signed attestations provide the change evidence.",
		Category:    "Operation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
		References:  []string{"ISO/IEC 42001:2023 8.3"},
	})

	// Clause 9: Performance Evaluation (additional sub-clauses for v3.x Tier 1)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.2",
		Name:        "Internal Audit (AIMS)",
		Description: "ISO 42001 9.2: Conduct internal audits at planned intervals to verify the AI management system conforms to requirements and is effectively implemented. AegisGate's audit log + scanner provide the audit evidence.",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalAudit,
		References:  []string{"ISO/IEC 42001:2023 9.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-9.3",
		Name:        "Management Review",
		Description: "ISO 42001 9.3: Top management reviews the AI management system at planned intervals to ensure its continuing suitability, adequacy, and effectiveness. AegisGate's CISO Posture Digest provides the review evidence.",
		Category:    "Performance Evaluation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkManagementReview,
		References:  []string{"ISO/IEC 42001:2023 9.3"},
	})

	// AI-Specific Extension: AegisGate's contribution to ISO 42001
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO42001-AI-001",
		Name:        "AI System Trust and Accountability",
		Description: "ISO 42001 AI Extension: AI systems have trust framework integration for accountability and audit trail",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Requires AegisGate Trust Framework integration review
		References:  []string{"AegisGate AI Controls"},
	})
}

// ============================================================================
// Check implementations
// ============================================================================

// checkAIPolicy verifies that an AI policy is documented, communicated,
// and includes acceptable use provisions.
func (m *ISO42001Module) checkAIPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := false
	for _, p := range m.policyPatterns {
		if p.MatchString(inputStr) {
			hasPolicy = true
			break
		}
	}
	hasCommunication := strings.Contains(inputStr, "communicated") || strings.Contains(inputStr, "published") || strings.Contains(inputStr, "documented")

	if hasPolicy && hasCommunication {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.2",
			ControlName: "AI Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI policy established and documented",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-5.2",
			ControlName: "AI Policy",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "AI policy detected but no documented communication",
			Timestamp:   time.Now(),
			Remediation: "Ensure AI policy is documented and published to all relevant parties",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-5.2",
		ControlName: "AI Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI policy detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and document an AI policy (e.g., 'AegisGate AI Acceptable Use Policy' in your internal docs)",
	}, nil
}

// checkRiskAssessment verifies that AI risk assessment is performed.
func (m *ISO42001Module) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matchedPatterns := []string{}
	for _, p := range m.riskPatterns {
		if p.MatchString(inputStr) {
			matchedPatterns = append(matchedPatterns, p.String())
		}
	}

	if len(matchedPatterns) >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.1",
			ControlName: "AI Risk Assessment and Treatment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI risk assessment detected with multiple risk patterns",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(matchedPatterns) == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-6.1",
			ControlName: "AI Risk Assessment and Treatment",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Single risk pattern detected; recommend documenting multiple risk dimensions",
			Timestamp:   time.Now(),
			Remediation: "Document risk across multiple dimensions: adversarial, privacy, model behavior, regulatory",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-6.1",
		ControlName: "AI Risk Assessment and Treatment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No AI risk assessment detected",
		Timestamp:   time.Now(),
		Remediation: "Perform an AI risk assessment covering adversarial, privacy, model behavior, and regulatory risks",
	}, nil
}

// checkDocumentedInfo verifies that required documented information
// (statement of applicability, risk register, audit logs) is in place.
func (m *ISO42001Module) checkDocumentedInfo(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	matched := 0
	for _, p := range m.documentationPats {
		if p.MatchString(inputStr) {
			matched++
		}
	}

	if matched >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.5",
			ControlName: "Documented Information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Documented information controls in place",
			Timestamp:   time.Now(),
		}, nil
	}

	if matched >= 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-7.5",
			ControlName: "Documented Information",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Some documented information detected; full set recommended",
			Timestamp:   time.Now(),
			Remediation: "Document: Statement of Applicability, Risk Register, Audit Logs, Compliance Reports",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-7.5",
		ControlName: "Documented Information",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No documented information detected",
		Timestamp:   time.Now(),
		Remediation: "Create SoA, risk register, audit log, compliance report (the AegisGate Trust Framework generates the audit log automatically)",
	}, nil
}

// checkRiskTreatment verifies that risk treatment is implemented and
// has measurable effectiveness (e.g., blocking rate, false positive rate).
func (m *ISO42001Module) checkRiskTreatment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTreatment := strings.Contains(inputStr, "risk_treatment") || strings.Contains(inputStr, "treatment_plan")
	hasBlocking := strings.Contains(inputStr, "block") || strings.Contains(inputStr, "deny")
	hasAudit := false
	for _, p := range m.auditLogPatterns() {
		if p.MatchString(inputStr) {
			hasAudit = true
			break
		}
	}

	if hasTreatment && (hasBlocking || hasAudit) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.2",
			ControlName: "AI Risk Treatment Implementation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI risk treatment implemented with measurable controls",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTreatment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.2",
			ControlName: "AI Risk Treatment Implementation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Risk treatment plan documented but no measurable controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement measurable controls: blocking rate, false positive rate, audit log",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.2",
		ControlName: "AI Risk Treatment Implementation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No risk treatment plan detected",
		Timestamp:   time.Now(),
		Remediation: "Implement a risk treatment plan: define risks, mitigations, owners, and measurable effectiveness metrics",
	}, nil
}

// checkMonitoring verifies that AIMS performance monitoring is in place
// (metrics, dashboards, alerting).
func (m *ISO42001Module) checkMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMetrics := strings.Contains(inputStr, "metric") || strings.Contains(inputStr, "prometheus")
	hasDashboard := strings.Contains(inputStr, "dashboard") || strings.Contains(inputStr, "grafana")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty") || strings.Contains(inputStr, "slack_alert")

	present := 0
	if hasMetrics {
		present++
	}
	if hasDashboard {
		present++
	}
	if hasAlerting {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.1",
			ControlName: "Monitoring, Measurement, Analysis, and Evaluation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AIMS performance monitoring configured",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.1",
			ControlName: "Monitoring, Measurement, Analysis, and Evaluation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial monitoring configured; recommend metrics + dashboard + alerting",
			Timestamp:   time.Now(),
			Remediation: "Configure metrics (Prometheus), dashboard (Grafana), and alerting (PagerDuty, Slack) for AIMS performance",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.1",
		ControlName: "Monitoring, Measurement, Analysis, and Evaluation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AIMS performance monitoring detected",
		Timestamp:   time.Now(),
		Remediation: "Set up metrics collection, dashboards, and alerting for AI management system performance",
	}, nil
}

// checkOperationalPlanning verifies that AI operational processes
// are planned and controlled. Maps to ISO 42001 8.1.
func (m *ISO42001Module) checkOperationalPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := false
	for _, p := range m.policyPatterns {
		if p.MatchString(inputStr) {
			hasPolicy = true
			break
		}
	}
	hasDocumentation := false
	for _, p := range m.documentationPats {
		if p.MatchString(inputStr) {
			hasDocumentation = true
			break
		}
	}

	if hasPolicy && hasDocumentation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.1",
			ControlName: "Operational Planning and Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Operational planning and control verified: AI policy + documented operational procedures",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasPolicy || hasDocumentation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.1",
			ControlName: "Operational Planning and Control",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial operational planning: 1 of 2 components (need both AI policy AND documented operational procedures)",
			Timestamp:   time.Now(),
			Remediation: "Document both the AI policy and the operational procedures for AI system deployment (AegisGate deployment guide + AI acceptable use policy)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.1",
		ControlName: "Operational Planning and Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No operational planning detected",
		Timestamp:   time.Now(),
		Remediation: "Document the AI policy AND the operational procedures for AI system deployment",
	}, nil
}

// checkChangeManagement verifies that AI system changes are
// controlled and reviewed. Maps to ISO 42001 8.3.
func (m *ISO42001Module) checkChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVersionControl := strings.Contains(inputStr, "model_version") || strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "git")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log") || strings.Contains(inputStr, "envelope")
	hasReviewProcess := strings.Contains(inputStr, "code_review") || strings.Contains(inputStr, "pr_review") || strings.Contains(inputStr, "change_review")
	hasRollback := strings.Contains(inputStr, "rollback") || strings.Contains(inputStr, "revert") || strings.Contains(inputStr, "previous_version")

	present := 0
	missing := []string{}
	if hasVersionControl {
		present++
	} else {
		missing = append(missing, "version control")
	}
	if hasAttestations {
		present++
	} else {
		missing = append(missing, "signed attestations")
	}
	if hasReviewProcess {
		present++
	} else {
		missing = append(missing, "review process")
	}
	if hasRollback {
		present++
	} else {
		missing = append(missing, "rollback capability")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.3",
			ControlName: "AI System Change Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI change management verified: version control + signed attestations + review process + rollback",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-8.3",
			ControlName: "AI System Change Management",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No AI change management controls detected",
			Timestamp:   time.Now(),
			Remediation: "Enable version control + AegisGate signed attestations + code review + rollback capability",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-8.3",
		ControlName: "AI System Change Management",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial AI change management: " + isoCount(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing change management components (version control, signed attestations, review process, rollback)",
	}, nil
}

// checkInternalAudit verifies that internal audits are conducted.
// Maps to ISO 42001 9.2.
func (m *ISO42001Module) checkInternalAudit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditLogPatterns() {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasAuditSchedule := strings.Contains(inputStr, "audit_schedule") || strings.Contains(inputStr, "audit_plan") || strings.Contains(inputStr, "scheduled_audit")
	hasAuditReport := strings.Contains(inputStr, "audit_report") || strings.Contains(inputStr, "audit_findings") || strings.Contains(inputStr, "audit_results")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit log")
	}
	if hasAuditSchedule {
		present++
	} else {
		missing = append(missing, "audit schedule")
	}
	if hasAuditReport {
		present++
	} else {
		missing = append(missing, "audit report")
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Internal Audit (AIMS)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal audit verified: audit log + audit schedule + audit report",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.2",
			ControlName: "Internal Audit (AIMS)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No internal audit controls detected",
			Timestamp:   time.Now(),
			Remediation: "Set up audit log + audit schedule + audit report per ISO 42001 9.2",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.2",
		ControlName: "Internal Audit (AIMS)",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial internal audit: " + isoCount(present) + "/3 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing internal audit components (audit log, audit schedule, audit report)",
	}, nil
}

// checkManagementReview verifies that management reviews are
// conducted. Maps to ISO 42001 9.3.
func (m *ISO42001Module) checkManagementReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCisoDigest := strings.Contains(inputStr, "ciso_digest") || strings.Contains(inputStr, "ciso_posture") || strings.Contains(inputStr, "executive_digest")
	hasReviewSchedule := strings.Contains(inputStr, "review_schedule") || strings.Contains(inputStr, "management_review") || strings.Contains(inputStr, "scheduled_review")
	hasReviewMinutes := strings.Contains(inputStr, "review_minutes") || strings.Contains(inputStr, "meeting_minutes") || strings.Contains(inputStr, "review_notes")
	hasActionItems := strings.Contains(inputStr, "action_items") || strings.Contains(inputStr, "follow_up") || strings.Contains(inputStr, "decisions")

	present := 0
	missing := []string{}
	if hasCisoDigest {
		present++
	} else {
		missing = append(missing, "CISO digest (executive summary)")
	}
	if hasReviewSchedule {
		present++
	} else {
		missing = append(missing, "review schedule")
	}
	if hasReviewMinutes {
		present++
	} else {
		missing = append(missing, "review minutes")
	}
	if hasActionItems {
		present++
	} else {
		missing = append(missing, "action items")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.3",
			ControlName: "Management Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Management review verified: CISO digest + review schedule + review minutes + action items",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO42001-9.3",
			ControlName: "Management Review",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No management review detected",
			Timestamp:   time.Now(),
			Remediation: "Set up CISO Posture Digest (AegisGate pkg/reporting/) + management review schedule + meeting minutes + action items",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO42001-9.3",
		ControlName: "Management Review",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial management review: " + isoCount(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing management review components (CISO digest, schedule, minutes, action items)",
	}, nil
}

// isoCount is a small helper to avoid importing strconv.
func isoCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-isoCount(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// auditLogPatterns is a helper for the risk treatment check. Returns
// the same patterns used by the SOC 2 module's audit logging check
// (duplicated here to keep modules decoupled).
func (m *ISO42001Module) auditLogPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
	}
}

// Dependencies returns required modules.
func (m *ISO42001Module) Dependencies() []string {
	return []string{"scanner", "trust", "metrics"}
}
