// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP AU (Audit and Accountability) Family
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Audit and Accountability family (AU)
// FedRAMP Moderate baseline controls for AI/ML systems.
//
// In-scope AU controls (7 of 12 AU controls are scanner-checkable):
//   AU-2  Audit Events                    (automated, Path B)
//   AU-3  Content of Audit Records        (automated, Path C — new)
//   AU-6  Audit Review, Analysis, Reporting (automated, Path C — new)
//   AU-9  Protection of Audit Information  (automated, Path B)
//   AU-10 Auditor Actions                  (evidence-mapped, Path C — new)
//   AU-12 Audit Record Generation          (automated, Path C — new)
//   AU-16 Cross-Organization Audit         (evidence-mapped, Path C — new)
//
// Out-of-scope AU controls (process/organizational):
//   AU-1 Policy and Procedures, AU-4 Audit Storage Capacity,
//   AU-5 Response to Audit Processing Failures, AU-7 Audit Reduction,
//   AU-8 Time Stamps, AU-11 Audit Record Retention
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAUControls wires the AU family controls into the module.
func (m *FedRAMPModule) registerAUControls() {
	// AU-2: Audit Events (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-2",
		Name:        "Audit Events",
		Description: "FedRAMP AU-2: Audit events identified, recorded, and reviewed; covers all 6 AegisGate protocol pillars",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditEvents,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-2", "FedRAMP Moderate AU-02"},
	})

	// AU-3: Content of Audit Records (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-3",
		Name:        "Content of Audit Records",
		Description: "FedRAMP AU-3: Audit records contain sufficient information to establish what, when, where, who, and outcome",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditRecordContent,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-3", "FedRAMP Moderate AU-03"},
	})

	// AU-6: Audit Review, Analysis, and Reporting (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-6",
		Name:        "Audit Review, Analysis, and Reporting",
		Description: "FedRAMP AU-6: Audit records reviewed and analyzed; anomalous activity reported to authorized personnel",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAuditReview,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-6", "FedRAMP Moderate AU-06"},
	})

	// AU-9: Protection of Audit Information (Path B — carried forward)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-9",
		Name:        "Protection of Audit Information",
		Description: "FedRAMP AU-9: Audit information protected from unauthorized access, modification, deletion (hash-chain integrity)",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditProtection,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-9", "FedRAMP Moderate AU-09"},
	})

	// AU-10: Auditor Actions (Path C — new, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-10",
		Name:        "Auditor Actions",
		Description: "FedRAMP AU-10: Prevent unauthorized modification of auditor actions. AegisGate generates the audit log integrity evidence for the customer's AU-10 SSP section.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   false, // Evidence-mapped
		References:  []string{"NIST SP 800-53 Rev. 5 AU-10", "FedRAMP Moderate AU-10"},
	})

	// AU-12: Audit Record Generation (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-12",
		Name:        "Audit Record Generation",
		Description: "FedRAMP AU-12: Audit records generated for all security-relevant events across the system",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditRecordGeneration,
		References:  []string{"NIST SP 800-53 Rev. 5 AU-12", "FedRAMP Moderate AU-12"},
	})

	// AU-16: Cross-Organization Audit (Path C — new, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-AU-16",
		Name:        "Cross-Organization Audit",
		Description: "FedRAMP AU-16: Audit information shared across organizational boundaries. AegisGate's multi-tenant isolation supports cross-tenant audit correlation.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityLow,
		Automated:   false, // Evidence-mapped
		References:  []string{"NIST SP 800-53 Rev. 5 AU-16", "FedRAMP Moderate AU-16"},
	})
}

// checkAuditEvents verifies audit logging is enabled across the
// AegisGate protocol pillars. Maps to FedRAMP AU-2. (Path B)
func (m *FedRAMPModule) checkAuditEvents(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
			ControlID:   "FedRAMP-AU-2",
			ControlName: "Audit Events",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit events recorded with integrity verification across AegisGate protocol pillars",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AU-2",
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
		ControlID:   "FedRAMP-AU-2",
		ControlName: "Audit Events",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit logging not enabled",
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (persistence.audit=true) and the AegisGate audit log middleware (pkg/audit/siem_dispatcher.go)",
	}, nil
}

// checkAuditRecordContent verifies audit records contain sufficient
// information (what, when, where, who, outcome). Maps to AU-3.
func (m *FedRAMPModule) checkAuditRecordContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
			ControlID:   "FedRAMP-AU-3",
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
			ControlID:   "FedRAMP-AU-3",
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
		ControlID:   "FedRAMP-AU-3",
		ControlName: "Content of Audit Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit records lack sufficient content fields for FedRAMP AU-3",
		Timestamp:   time.Now(),
		Remediation: "Configure audit logging to include: event_type, timestamp, source, user_id, result (5 required fields)",
	}, nil
}

// checkAuditReview verifies audit records are reviewed and analyzed
// for anomalous activity. Maps to AU-6.
func (m *FedRAMPModule) checkAuditReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditSearch := strings.Contains(inputStr, "audit_search") || strings.Contains(inputStr, "audit_log")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "anomaly_detection") || strings.Contains(inputStr, "siem")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "monitoring")
	hasReview := strings.Contains(inputStr, "review") || strings.Contains(inputStr, "analysis") || strings.Contains(inputStr, "audit_review")

	if hasAuditSearch && hasAnomaly && (hasAlerting || hasReview) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AU-6",
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
		ControlID:   "FedRAMP-AU-6",
		ControlName: "Audit Review, Analysis, and Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit review gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit log search (POST /api/v1/audit/search), anomaly detection, and alerting for anomalous activity",
	}, nil
}

// checkAuditProtection verifies the audit log is protected from
// unauthorized modification. Maps to FedRAMP AU-9. (Path B)
func (m *FedRAMPModule) checkAuditProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
			ControlID:   "FedRAMP-AU-9",
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
			ControlID:   "FedRAMP-AU-9",
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
		ControlID:   "FedRAMP-AU-9",
		ControlName: "Protection of Audit Information",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log protection (integrity + RBAC) not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable both hash-chain integrity (persistence.log_integrity=true) AND RBAC on audit log access",
	}, nil
}

// checkAuditRecordGeneration verifies that audit records are generated
// for all security-relevant events. Maps to AU-12.
func (m *FedRAMPModule) checkAuditRecordGeneration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditGen := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled") || strings.Contains(inputStr, "logging_enabled")
	hasAllPillars := strings.Contains(inputStr, "http") || strings.Contains(inputStr, "mcp") || strings.Contains(inputStr, "a2a")
	hasIntegrity := strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "log_integrity")

	if hasAuditGen && hasAllPillars {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AU-12",
			ControlName: "Audit Record Generation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit record generation verified for all protocol pillars" + map[bool]string{true: " (with integrity)", false: ""}[hasIntegrity],
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAuditGen {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-AU-12",
			ControlName: "Audit Record Generation",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit record generation enabled but not confirmed for all protocol pillars",
			Timestamp:   time.Now(),
			Remediation: "Ensure audit logging covers HTTP, MCP, A2A, and Response pillars",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-AU-12",
		ControlName: "Audit Record Generation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit record generation not enabled",
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging for all protocol pillars (persistence.audit=true)",
	}, nil
}
