// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 AU (Audit and Accountability) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Audit and Accountability family (AU)
// Controls for protecting CUI in nonfederal systems.
//
// In-scope AU controls (5 controls: 4 automated + 1 evidence-mapped):
//   AU-1  Audit and Accountability Policy/Procedures  (evidence-mapped)
//   AU-2  Audit Events                                (automated)
//   AU-3  Content of Audit Records                     (automated)
//   AU-6  Audit Review, Analysis, and Reporting        (automated)
//   AU-9  Protection of Audit Information               (automated)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAUControls wires the AU family controls into the module.
func (m *NIST800171Module) registerAUControls() {
	// AU-1: Audit and Accountability Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-1",
		Name:        "Audit and Accountability Policy and Procedures",
		Description: "NIST 800-171 AU-1 (3.3.1): Audit and accountability policy and procedures documented, reviewed, and disseminated",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.1", "NIST SP 800-53 Rev. 5 AU-1"},
	})

	// AU-2: Audit Events (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-2",
		Name:        "Audit Events",
		Description: "NIST 800-171 AU-2 (3.3.1): Audit events identified, recorded, and reviewed across all AegisGate protocol pillars",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditEvents,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.1", "NIST SP 800-53 Rev. 5 AU-2"},
	})

	// AU-3: Content of Audit Records (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-3",
		Name:        "Content of Audit Records",
		Description: "NIST 800-171 AU-3 (3.3.2): Audit records contain sufficient information to establish what, when, where, who, and outcome",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditRecordContent,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.2", "NIST SP 800-53 Rev. 5 AU-3"},
	})

	// AU-6: Audit Review, Analysis, and Reporting (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-6",
		Name:        "Audit Review, Analysis, and Reporting",
		Description: "NIST 800-171 AU-6 (3.3.5): Audit records reviewed and analyzed; anomalous activity reported to authorized personnel",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditReview,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.5", "NIST SP 800-53 Rev. 5 AU-6"},
	})

	// AU-9: Protection of Audit Information (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AU-9",
		Name:        "Protection of Audit Information",
		Description: "NIST 800-171 AU-9 (3.3.8): Audit information protected from unauthorized access, modification, deletion (hash-chain integrity)",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.3.8", "NIST SP 800-53 Rev. 5 AU-9"},
	})
}

// checkAuditEvents verifies audit logging is enabled with integrity
// verification. Maps to NIST 800-171 AU-2.
func (m *NIST800171Module) checkAuditEvents(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := false
	hasIntegrity := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			if strings.Contains(p.String(), "integrity") || strings.Contains(p.String(), "chain") {
				hasIntegrity = true
			}
		}
	}

	if hasAudit && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-2",
			ControlName: "Audit Events",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit events recorded with integrity verification",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-2",
			ControlName: "Audit Events",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit events recorded but integrity verification not detected",
			Timestamp:   time.Now(),
			Remediation: "Enable hash-chain integrity (persistence.log_integrity=true) for tamper-evident audit logs",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-2",
		ControlName: "Audit Events",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit logging not enabled",
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (persistence.audit=true) and the AegisGate audit log middleware",
	}, nil
}

// checkAuditRecordContent verifies audit records contain sufficient
// information (what, when, where, who, outcome). Maps to AU-3.
func (m *NIST800171Module) checkAuditRecordContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasWhat := strings.Contains(inputStr, "event_type") || strings.Contains(inputStr, "action") || strings.Contains(inputStr, "audit_log")
	hasWhen := strings.Contains(inputStr, "timestamp") || strings.Contains(inputStr, "time") || strings.Contains(inputStr, "logged_at")
	hasWhere := strings.Contains(inputStr, "source") || strings.Contains(inputStr, "endpoint") || strings.Contains(inputStr, "ip")
	hasWho := strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "actor") || strings.Contains(inputStr, "authentication")
	hasOutcome := strings.Contains(inputStr, "result") || strings.Contains(inputStr, "status") || strings.Contains(inputStr, "outcome")

	fields := 0
	if hasWhat {
		fields++
	}
	if hasWhen {
		fields++
	}
	if hasWhere {
		fields++
	}
	if hasWho {
		fields++
	}
	if hasOutcome {
		fields++
	}

	if fields >= 4 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-3",
			ControlName: "Content of Audit Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit records contain sufficient fields for forensic analysis",
			Timestamp:   time.Now(),
		}, nil
	}

	if fields >= 2 {
		missing := []string{}
		if !hasWhat {
			missing = append(missing, "event_type/action (what)")
		}
		if !hasWhen {
			missing = append(missing, "timestamp (when)")
		}
		if !hasWhere {
			missing = append(missing, "source/endpoint (where)")
		}
		if !hasWho {
			missing = append(missing, "user_id/actor (who)")
		}
		if !hasOutcome {
			missing = append(missing, "result/outcome (outcome)")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-3",
			ControlName: "Content of Audit Records",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit records missing fields: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Ensure audit records include event_type, timestamp, source, user_id, and result fields",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-3",
		ControlName: "Content of Audit Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit records lack sufficient content fields for NIST 800-171 AU-3",
		Timestamp:   time.Now(),
		Remediation: "Configure audit logging to include: event_type, timestamp, source, user_id, result (5 required fields)",
	}, nil
}

// checkAuditReview verifies audit records are reviewed and analyzed
// for anomalous activity. Maps to AU-6.
func (m *NIST800171Module) checkAuditReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditSearch := strings.Contains(inputStr, "audit_search") || strings.Contains(inputStr, "audit_log")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "anomaly_detection") || strings.Contains(inputStr, "siem")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "monitoring")
	hasReview := strings.Contains(inputStr, "review") || strings.Contains(inputStr, "analysis") || strings.Contains(inputStr, "audit_review")

	if hasAuditSearch && hasAnomaly && (hasAlerting || hasReview) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-6",
			ControlName: "Audit Review, Analysis, and Reporting",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit review and anomaly detection verified",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuditSearch {
		violations = append(violations, "audit search/review capability not detected")
	}
	if !hasAnomaly {
		violations = append(violations, "anomaly detection not configured")
	}
	if !hasAlerting && !hasReview {
		violations = append(violations, "no audit review or alerting process detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-6",
		ControlName: "Audit Review, Analysis, and Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit review gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit log search, anomaly detection, and alerting for anomalous activity",
	}, nil
}

// checkAuditProtection verifies the audit log is protected from
// unauthorized modification. Maps to NIST 800-171 AU-9.
func (m *NIST800171Module) checkAuditProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIntegrity := false
	hasAuth := strings.Contains(inputStr, "auth") || strings.Contains(inputStr, "rbac")
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			if strings.Contains(p.String(), "integrity") || strings.Contains(p.String(), "chain") {
				hasIntegrity = true
			}
		}
	}

	if hasIntegrity && hasAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-9",
			ControlName: "Protection of Audit Information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log protected by hash-chain integrity + RBAC",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AU-9",
			ControlName: "Protection of Audit Information",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Hash-chain integrity detected; recommend RBAC on audit log access",
			Timestamp:   time.Now(),
			Remediation: "Restrict audit log access to admin role (rbac.audit_log_read=admin only)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AU-9",
		ControlName: "Protection of Audit Information",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log protection (integrity + RBAC) not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable both hash-chain integrity (persistence.log_integrity=true) AND RBAC on audit log access",
	}, nil
}
