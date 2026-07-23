// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 AU (Audit and Accountability) Domain
// =========================================================================
//
// CMMC Level 2 — Audit and Accountability domain (AU)
// NIST SP 800-171 Rev. 2 §3.3 practices
//
// In-scope AU controls (4 of ~9 AU practices are scanner-checkable):
//   AU.1.001  Audit events                            (automated)
//   AU.2.001  Audit record content                   (automated)
//   AU.2.002  Audit review                           (evidence-mapped)
//   AU.2.003  Audit protection                       (evidence-mapped)
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

	// AU.2.002: Audit review (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-03",
		Name:        "Audit Review",
		Description: "CMMC L2 AU.2.002: Review and analyze audit records. AegisGate generates the audit review evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AU.2.002", "NIST SP 800-171 §3.3.3"},
	})

	// AU.2.003: Audit protection (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AU-04",
		Name:        "Audit Protection",
		Description: "CMMC L2 AU.2.003: Protect audit information and audit tools from unauthorized access, modification, and deletion. AegisGate generates the audit protection evidence for the customer's CMMC assessment.",
		Category:    "Audit and Accountability",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AU.2.003", "NIST SP 800-171 §3.3.7"},
	})
}

// checkAuditEvents verifies audit logging is enabled with integrity
// protection. Maps to CMMC L2 AU.1.001.
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

	if fieldsFound >= 4 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-02",
			ControlName: "Audit Record Content",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit record content verified (sufficient fields present)",
			Timestamp:   time.Now(),
		}, nil
	}

	if fieldsFound >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AU-02",
			ControlName: "Audit Record Content",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Audit records contain some fields but not all required fields",
			Timestamp:   time.Now(),
			Remediation: "Configure audit records to include: event_type, timestamp, source, user_id, result",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AU-02",
		ControlName: "Audit Record Content",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Audit records lack required content fields",
		Timestamp:   time.Now(),
		Remediation: "Configure audit records to include: event_type, timestamp, source, user_id, result",
	}, nil
}
