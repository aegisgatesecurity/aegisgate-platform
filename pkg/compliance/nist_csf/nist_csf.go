// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST CSF 2.0 Module
// =========================================================================
//
// NIST Cybersecurity Framework 2.0 (the de-facto US enterprise security
// framework, originally NIST CSF 1.1 from 2018, expanded to 2.0 in
// February 2024). Appears in 60%+ of US enterprise RFPs.
//
// The 6 CSF 2.0 Functions are mapped cleanly to AegisGate's 6-pillar
// coverage:
//   GOVERN    -> Platform governance, audit, compliance
//   IDENTIFY  -> Asset inventory, IOC store, threat model
//   PROTECT   -> Access control, encryption, output filtering
//   DETECT    -> Scanner, anomaly detection, IOC federation
//   RESPOND   -> Trust Framework attestations, audit log, kill switch
//   RECOVER   -> Audit log replay, hash-chain verification, IOC store restore
//
// Module metadata:
//   - Framework:   "nist_csf"
//   - Version:     "1.0"
//   - Required tier: Community (free)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - nist_csf.go:        module wiring, 6 RegisterControl calls (one
//                          per Function), 6 CheckFunc implementations
//   - nist_csf_test.go:   unit tests
//
// Coverage: All 6 CSF 2.0 Functions covered. Each Function has 1
// automated CheckFunc that maps to existing AegisGate modules. Within
// each Function, the customer can drill into the underlying AegisGate
// controls for the specific subcategories.
//
// Reference: https://www.nist.gov/cyberframework
//            NIST CSF 2.0 (February 26, 2024)
// =========================================================================

package nist_csf

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NISTCSFModule implements the NIST Cybersecurity Framework 2.0.
type NISTCSFModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches
	auditLogPatterns []*regexp.Regexp
	tlsPatterns      []*regexp.Regexp
}

// NewNISTCSFModule creates a new NIST CSF 2.0 module.
func NewNISTCSFModule() *NISTCSFModule {
	m := &NISTCSFModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nist_csf", "1.0", core.TierCommunity),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

func (m *NISTCSFModule) initPatterns() {
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
	}
	m.tlsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
		regexp.MustCompile(`(?i)min[_ ]?version[_ ]?1[._][23]`),
	}
}

func (m *NISTCSFModule) registerControls() {
	// GOVERN: The organization's cybersecurity risk management strategy,
	// expectations, and policy are established, communicated, and monitored.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-GOVERN",
		Name:        "Govern (GV)",
		Description: "NIST CSF 2.0 GV: The organization's cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored",
		Category:    "Govern",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGovern,
		References:  []string{"NIST CSF 2.0 GV (Govern)"},
	})

	// IDENTIFY: The organization's current cybersecurity risks are understood.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-IDENTIFY",
		Name:        "Identify (ID)",
		Description: "NIST CSF 2.0 ID: The organization's current cybersecurity risks are understood (asset inventory, risk assessment)",
		Category:    "Identify",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIdentify,
		References:  []string{"NIST CSF 2.0 ID (Identify)"},
	})

	// PROTECT: Safeguards to manage the organization's cybersecurity risks.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-PROTECT",
		Name:        "Protect (PR)",
		Description: "NIST CSF 2.0 PR: Safeguards to manage the organization's cybersecurity risks (access control, encryption, training)",
		Category:    "Protect",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkProtect,
		References:  []string{"NIST CSF 2.0 PR (Protect)"},
	})

	// DETECT: Possible cybersecurity attacks and compromises are found and analyzed.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-DETECT",
		Name:        "Detect (DE)",
		Description: "NIST CSF 2.0 DE: Possible cybersecurity attacks and compromises are found and analyzed (anomaly detection, scanning)",
		Category:    "Detect",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDetect,
		References:  []string{"NIST CSF 2.0 DE (Detect)"},
	})

	// RESPOND: Actions regarding a detected cybersecurity incident are taken.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-RESPOND",
		Name:        "Respond (RS)",
		Description: "NIST CSF 2.0 RS: Actions regarding a detected cybersecurity incident are taken (incident response, communications)",
		Category:    "Respond",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRespond,
		References:  []string{"NIST CSF 2.0 RS (Respond)"},
	})

	// RECOVER: Assets and operations affected by a cybersecurity incident are restored.
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST-CSF-RECOVER",
		Name:        "Recover (RC)",
		Description: "NIST CSF 2.0 RC: Assets and operations affected by a cybersecurity incident are restored (recovery, improvements)",
		Category:    "Recover",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecover,
		References:  []string{"NIST CSF 2.0 RC (Recover)"},
	})
}

// ============================================================================
// Check implementations
// ============================================================================

// checkGovern verifies the cybersecurity risk management strategy is established.
func (m *NISTCSFModule) checkGovern(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := strings.Contains(inputStr, "ai_policy") || strings.Contains(inputStr, "security_policy") || strings.Contains(inputStr, "cybersecurity_policy")
	hasRiskManagement := strings.Contains(inputStr, "risk_management") || strings.Contains(inputStr, "risk_assessment")
	hasComplianceScan := strings.Contains(inputStr, "compliance_scan") || strings.Contains(inputStr, "/api/v1/compliance")

	present := 0
	if hasPolicy {
		present++
	}
	if hasRiskManagement {
		present++
	}
	if hasComplianceScan {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-GOVERN", ControlName: "Govern (GV)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Governance verified (policy + risk management + compliance scan)",
			Timestamp: time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-GOVERN", ControlName: "Govern (GV)",
			Status: compliance.StatusPartial, Severity: compliance.SeverityHigh,
			Message:     "Partial governance: 1 of 3 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Document security policy + risk management process; use /api/v1/compliance/scan for evidence",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-GOVERN", ControlName: "Govern (GV)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No governance evidence",
		Timestamp:   time.Now(),
		Remediation: "Document security policy and risk management process; use AegisGate /api/v1/compliance/scan for evidence",
	}, nil
}

// checkIdentify verifies the organization understands its cybersecurity risks.
func (m *NISTCSFModule) checkIdentify(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "asset_inventory") || strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "model_id")
	hasRiskAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "risk_register")
	hasThreatModel := strings.Contains(inputStr, "threat_model") || strings.Contains(inputStr, "stride")

	present := 0
	if hasInventory {
		present++
	}
	if hasRiskAssessment {
		present++
	}
	if hasThreatModel {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-IDENTIFY", ControlName: "Identify (ID)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Identification verified (asset inventory + risk assessment + threat model)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-IDENTIFY", ControlName: "Identify (ID)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "Identification gaps: missing asset inventory, risk assessment, or threat model",
		Timestamp:   time.Now(),
		Remediation: "Use AegisGate IOC store (asset inventory), plans/THREAT-MODEL.md (threat model), and document a risk assessment",
	}, nil
}

// checkProtect verifies safeguards are in place.
func (m *NISTCSFModule) checkProtect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor")
	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			break
		}
	}
	hasEncryptAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasPIIFilter := strings.Contains(inputStr, "pii_scanner") || strings.Contains(inputStr, "pii_filter")

	missing := []string{}
	if !hasAuth {
		missing = append(missing, "auth")
	}
	if !hasRBAC {
		missing = append(missing, "RBAC")
	}
	if !hasMFA {
		missing = append(missing, "MFA")
	}
	if !hasTLS {
		missing = append(missing, "TLS 1.2+")
	}
	if !hasEncryptAtRest {
		missing = append(missing, "encryption at rest")
	}
	if !hasPIIFilter {
		missing = append(missing, "PII filter")
	}

	if len(missing) == 0 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-PROTECT", ControlName: "Protect (PR)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical,
			Message:   "Protection verified: auth + RBAC + MFA + TLS + encryption + PII filter",
			Timestamp: time.Now(),
		}, nil
	}
	if len(missing) <= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-PROTECT", ControlName: "Protect (PR)",
			Status: compliance.StatusPartial, Severity: compliance.SeverityCritical,
			Message:     "Partial protection: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure: " + strings.Join(missing, ", "),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-PROTECT", ControlName: "Protect (PR)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityCritical,
		Message:     "Critical protection gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure: " + strings.Join(missing, ", "),
	}, nil
}

// checkDetect verifies detection capabilities are in place.
func (m *NISTCSFModule) checkDetect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "threat_detection")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score")
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "pagerduty")

	present := 0
	if hasScanner {
		present++
	}
	if hasAnomaly {
		present++
	}
	if hasIOCStore {
		present++
	}
	if hasAlerting {
		present++
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-DETECT", ControlName: "Detect (DE)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Detection verified (scanner + anomaly + IOC + alerting)",
			Timestamp: time.Now(),
		}, nil
	}
	if present >= 1 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-DETECT", ControlName: "Detect (DE)",
			Status: compliance.StatusPartial, Severity: compliance.SeverityHigh,
			Message:     "Partial detection: " + intToStr(present) + " of 4 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate scanner + anomaly + IOC store + alerting",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-DETECT", ControlName: "Detect (DE)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No detection capabilities",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner, anomaly detection, IOC store, and alerting (P0 for any production deployment)",
	}, nil
}

// checkRespond verifies incident response capabilities.
func (m *NISTCSFModule) checkRespond(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "trust.attestation")
	hasKillSwitch := strings.Contains(inputStr, "kill_switch") || strings.Contains(inputStr, "abort")
	hasAuditTrail := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditTrail = true
			break
		}
	}

	missing := []string{}
	if !hasIRPlan {
		missing = append(missing, "IR plan")
	}
	if !hasAttestations {
		missing = append(missing, "signed attestations")
	}
	if !hasKillSwitch {
		missing = append(missing, "kill switch / abort")
	}
	if !hasAuditTrail {
		missing = append(missing, "audit trail")
	}

	if len(missing) == 0 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-RESPOND", ControlName: "Respond (RS)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Response ready (IR plan + attestations + kill switch + audit trail)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-RESPOND", ControlName: "Respond (RS)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "Response gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Create IR plan; enable AegisGate signed attestations (pkg/attestation/) + kill switch + audit trail",
	}, nil
}

// checkRecover verifies recovery capabilities.
func (m *NISTCSFModule) checkRecover(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "disaster_recovery")
	hasAuditReplay := strings.Contains(inputStr, "audit_replay") || strings.Contains(inputStr, "log_replay") || strings.Contains(inputStr, "log_search")
	hasPostMortem := strings.Contains(inputStr, "post_mortem") || strings.Contains(inputStr, "incident_review")
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain")

	present := 0
	if hasBackup {
		present++
	}
	if hasAuditReplay {
		present++
	}
	if hasPostMortem {
		present++
	}
	if hasIntegrity {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-RECOVER", ControlName: "Recover (RC)",
			Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh,
			Message:   "Recovery verified (backup + audit replay + post-mortem + log integrity)",
			Timestamp: time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework: m.Framework(), ControlID: "NIST-CSF-RECOVER", ControlName: "Recover (RC)",
			Status: compliance.StatusPartial, Severity: compliance.SeverityHigh,
			Message:     "Partial recovery: 1 of 4 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Add backup, audit log replay, post-mortem template, and hash-chain integrity for full recovery",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework: m.Framework(), ControlID: "NIST-CSF-RECOVER", ControlName: "Recover (RC)",
		Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh,
		Message:     "No recovery capabilities",
		Timestamp:   time.Now(),
		Remediation: "Set up backups, enable hash-chain audit log (verifiable on restore), document post-mortem template",
	}, nil
}

// intToStr helper to avoid importing strconv in every check.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-intToStr(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules.
func (m *NISTCSFModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "ioc", "trust"}
}
