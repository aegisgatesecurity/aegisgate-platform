// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 AU (Audit and Accountability) Domain
// =========================================================================
//
// CMMC Level 2 — Audit and Accountability domain (AU)
// NIST SP 800-171 Rev. 2 §3.3 practices
//
// In-scope AU controls (8 of ~9 AU practices are scanner-checkable):
//   AU.1.001  Audit events                            (automated)
//   AU.2.001  Audit record content                   (automated)
//   AU.2.002  Audit review                           (automated)
//   AU.2.003  Audit protection                       (automated)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAUControls wires the AU domain controls into the module.
func (m *CMMCL2Module) registerAUControls() {
	// AU.1.001: Audit events (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-01",
		Name:        "Audit Events",
		Description: "CMMC L2 AU.1.001: Create, protect, and retain audit logs — logging enabled with integrity protection",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditEvents,
		References:  []string{"CMMC L2 AU.1.001", "NIST SP 800-171 §3.3.1"},
	})

	// AU.2.001: Audit record content (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-02",
		Name:        "Audit Record Content",
		Description: "CMMC L2 AU.2.001: Ensure audit records contain sufficient information — event type, timestamp, source, user, result",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditRecordContent,
		References:  []string{"CMMC L2 AU.2.001", "NIST SP 800-171 §3.3.2"},
	})

	// AU.2.002: Audit review (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-03",
		Name:        "Audit Review",
		Description: "CMMC L2 AU.2.002: Review and analyze audit records. AegisGate generates the audit review evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditReview,
		References:  []string{"CMMC L2 AU.2.002", "NIST SP 800-171 §3.3.3"},
	})

	// AU.2.003: Audit protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-04",
		Name:        "Audit Protection",
		Description: "CMMC L2 AU.2.003: Protect audit information and audit tools from unauthorized access, modification, and deletion. AegisGate generates the audit protection evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditProtection,
		References:  []string{"CMMC L2 AU.2.003", "NIST SP 800-171 §3.3.7"},
	})

	// AU.2.004: Audit log retention (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-05",
		Name:        "Audit Log Retention",
		Description: "CMMC L2 AU.2.004: Retain audit logs for the required period with tamper-evident storage",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogRetention,
		References:  []string{"CMMC L2 AU.2.004", "NIST SP 800-171 §3.3.4"},
	})

	// AU.2.005: Audit review and analysis (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-06",
		Name:        "Audit Review And Analysis",
		Description: "CMMC L2 AU.2.005: Review and analyze audit records for anomalies and security events",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditReviewAnalysis,
		References:  []string{"CMMC L2 AU.2.005", "NIST SP 800-171 §3.3.5"},
	})

	// AU.2.006: Time stamps (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-07",
		Name:        "Time Stamps",
		Description: "CMMC L2 AU.2.006: Use time stamps in audit records with synchronized time sources",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTimeStamps,
		References:  []string{"CMMC L2 AU.2.006", "NIST SP 800-171 §3.3.8"},
	})

	// AU.2.007: Audit reduction (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-08",
		Name:        "Audit Reduction",
		Description: "CMMC L2 AU.2.007: Audit reduction and report generation tools. AegisGate generates the audit reduction evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAuditReduction,
		References:  []string{"CMMC L2 AU.2.007", "NIST SP 800-171 §3.3.9"},
	})

	// AU.2.008: Session audit (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-09",
		Name:        "Session Audit",
		Description: "CMMC L2 AU.2.008: Audit session establishment and termination for CUI system access. AegisGate generates the session audit evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCMMCSessionAudit,
		References:  []string{"CMMC L2 AU.2.008", "NIST SP 800-171 §3.3.10"},
	})
}

// checkAuditRecordContent verifies that audit records contain sufficient
// information (event type, timestamp, source, user, result). Maps to AU.2.001.
func (m *CMMCL2Module) checkAuditRecordContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEventType := strings.Contains(inputStr, "event_type") || strings.Contains(inputStr, "event")
	hasTimestamp := strings.Contains(inputStr, "timestamp") || strings.Contains(inputStr, "time")
	hasSource := strings.Contains(inputStr, "source") || strings.Contains(inputStr, "ip")
	hasUser := strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "user") || strings.Contains(inputStr, "identity")
	hasResult := strings.Contains(inputStr, "result") || strings.Contains(inputStr, "outcome")

	fieldsFound := 0
	if hasEventType {
		fieldsFound++
	}
	if hasTimestamp {
		fieldsFound++
	}
	if hasSource {
		fieldsFound++
	}
	if hasUser {
		fieldsFound++
	}
	if hasResult {
		fieldsFound++
	}

	if fieldsFound >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-02",
			ControlName: "Audit Record Content",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit records contain sufficient information",
			Timestamp:   time.Now(),
		}, nil
	}

	missing := []string{}
	if !hasEventType {
		missing = append(missing, "event type")
	}
	if !hasTimestamp {
		missing = append(missing, "timestamp")
	}
	if !hasSource {
		missing = append(missing, "source")
	}
	if !hasUser {
		missing = append(missing, "user identity")
	}
	if !hasResult {
		missing = append(missing, "result/outcome")
	}

	if fieldsFound == 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-02",
			ControlName: "Audit Record Content",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial audit records: " + strings.Join(missing, ", ") + " missing",
			Timestamp:   time.Now(),
			Remediation: "Ensure audit records contain event type, timestamp, source, user, and result",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-02",
		ControlName: "Audit Record Content",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Missing audit record fields: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Ensure audit records contain event type, timestamp, source, user, and result",
	}, nil
}

func (m *CMMCL2Module) checkAuditEvents(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := false
	for _, p := range m.auditPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain")

	if hasAuditLog && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-01",
			ControlName: "Audit Events",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit events verified (logging enabled + integrity protection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuditLog {
		violations = append(violations, "audit logging not enabled")
	}
	if !hasIntegrity {
		violations = append(violations, "audit log integrity protection not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-01",
		ControlName: "Audit Events",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit event gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (audit_log=true) and configure log integrity protection (hash_chain=true)",
	}, nil
}

func (m *CMMCL2Module) checkAuditLogRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "log_retention") || strings.Contains(inputStr, "archive")
	hasTamperEvident := strings.Contains(inputStr, "tamper_evident") || strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "immutable") || strings.Contains(inputStr, "log_integrity")

	if hasRetention && hasTamperEvident {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-05",
			ControlName: "Audit Log Retention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log retention verified (retention policy + tamper-evident storage)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRetention {
		violations = append(violations, "audit log retention policy not configured")
	}
	if !hasTamperEvident {
		violations = append(violations, "tamper-evident audit storage not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-05",
		ControlName: "Audit Log Retention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log retention gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit log retention (log_retention=365d) and enable tamper-evident storage (hash_chain=true, immutable=true)",
	}, nil
}

func (m *CMMCL2Module) checkAuditReviewAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReview := strings.Contains(inputStr, "audit_review") || strings.Contains(inputStr, "review") || strings.Contains(inputStr, "analysis")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "anomaly_detection") || strings.Contains(inputStr, "siem")

	if hasReview && hasAnomaly {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-06",
			ControlName: "Audit Review And Analysis",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit review and analysis verified (review + anomaly detection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasReview {
		violations = append(violations, "audit review process not configured")
	}
	if !hasAnomaly {
		violations = append(violations, "anomaly detection not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-06",
		ControlName: "Audit Review And Analysis",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit review and analysis gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit review (audit_review=true) and anomaly detection (anomaly_detection=true or SIEM)",
	}, nil
}

func (m *CMMCL2Module) checkTimeStamps(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTimestamp := strings.Contains(inputStr, "timestamp") || strings.Contains(inputStr, "time_sync") || strings.Contains(inputStr, "ntp")
	hasSynchronized := strings.Contains(inputStr, "ntp") || strings.Contains(inputStr, "time_sync") || strings.Contains(inputStr, "synchronized") || strings.Contains(inputStr, "synchronization")

	if hasTimestamp && hasSynchronized {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-07",
			ControlName: "Time Stamps",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Time stamps verified (timestamps + synchronized time source)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTimestamp {
		violations = append(violations, "timestamps not configured in audit records")
	}
	if !hasSynchronized {
		violations = append(violations, "time synchronization not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-07",
		ControlName: "Time Stamps",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Time stamp gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure timestamp generation (timestamp=true) and NTP time synchronization (ntp.enabled=true)",
	}, nil
}

// checkAuditReview verifies audit record review. Maps to CMMCL2-AU-03.
func (m *CMMCL2Module) checkAuditReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReview := strings.Contains(inputStr, "audit_review") || strings.Contains(inputStr, "log_review")
	hasAnalysis := strings.Contains(inputStr, "audit_analysis") || strings.Contains(inputStr, "review")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled")

	if hasReview && hasAnalysis && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-03",
			ControlName: "Audit Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit review verified (review + analysis + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasReview {
		violations = append(violations, "audit review not configured")
	}
	if !hasAnalysis {
		violations = append(violations, "audit analysis not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-03",
		ControlName: "Audit Review",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit review gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit review with analysis and audit logging",
	}, nil
}

// checkAuditProtection verifies audit information protection. Maps to CMMCL2-AU-04.
func (m *CMMCL2Module) checkAuditProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasProtection := strings.Contains(inputStr, "audit_protection") || strings.Contains(inputStr, "log_protection")
	hasIntegrity := strings.Contains(inputStr, "audit_integrity") || strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain")
	hasAccess := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "authorized_access")

	if hasProtection && hasIntegrity && hasAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-04",
			ControlName: "Audit Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit protection verified (protection + integrity + access control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasProtection {
		violations = append(violations, "audit protection not configured")
	}
	if !hasIntegrity {
		violations = append(violations, "audit integrity not configured")
	}
	if !hasAccess {
		violations = append(violations, "access control for audit logs not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-04",
		ControlName: "Audit Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit log protection with integrity controls and access restrictions",
	}, nil
}

// checkAuditReduction verifies audit reduction and report generation. Maps to CMMCL2-AU-08.
func (m *CMMCL2Module) checkAuditReduction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReduction := strings.Contains(inputStr, "audit_reduction") || strings.Contains(inputStr, "log_aggregation")
	hasReporting := strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "report_generation") || strings.Contains(inputStr, "siem")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled")

	if hasReduction && hasReporting && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-08",
			ControlName: "Audit Reduction",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Audit reduction verified (reduction + reporting + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasReduction {
		violations = append(violations, "audit reduction not configured")
	}
	if !hasReporting {
		violations = append(violations, "report generation not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-08",
		ControlName: "Audit Reduction",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "Audit reduction gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit reduction with report generation and audit logging",
	}, nil
}
