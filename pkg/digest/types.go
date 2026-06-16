// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Posture Digest (TODO-601 + TODO-602)
//
// Package digest is the CISO Posture Digest: a
// branded, regulator-acceptable PDF report that
// summarizes the platform's security posture over
// a period (daily/weekly/monthly). It is the
// primary artifact the CISO hands to auditors,
// boards, and customers.
//
// What v0.1 ships (TODO-601 + TODO-602 combined):
//
//   - Digest struct (Period, IOCsBlocked,
//     AnomaliesDetected, Posture, RegulatorMappings,
//     TopSources, TopThreats, GeneratedAt, etc.)
//
//   - Source interface + 3 adapters:
//     - PostureSource (reads from pkg/posture)
//     - IOCSource (reads from pkg/ioc)
//     - AuditSource (reads from pkg/audit)
//
//   - BuildDigest(ctx, sources, period) (*Digest,
//     error): the producer (TODO-602). Polls each
//     source, aggregates the data into a Digest.
//
//   - RenderDigestPDF(digest) ([]byte, error): the
//     consumer (TODO-601). Uses pkg/pdf to render
//     the Digest to a 3-section PDF (cover page,
//     IOCs blocked, anomalies + posture).
//
//   - SignDigest(digest, kr) (*Envelope, error):
//     signs the Digest with the envelope primitive.
//     The PDF is the payload; the envelope wraps
//     it (subject: aegisgate://digest/<digest-id>).
//
//   - VerifyDigest(env, kr) error: verifies the
//     signed digest (signature + type + subject).
//
//   - CLI: aegisgate digest generate / verify /
//     list
//   - HTTP: POST /api/v1/digest/{generate,verify}
//     (Professional+ tier gated for the publish
//     side; free for verify)
//
// What v0.1 does NOT ship:
//
//   - Real-time streaming of digest updates
//   - Webhook delivery (the upstream Reporter has
//     Email/Webhook fields; v0.2 can use them)
//   - Multi-tenant isolation (the digest is global;
//     per-tenant digests are v0.2)
//   - Custom branding per customer (AegisGate logo
//     only in v0.1; per-customer branding is v0.2)
//
// Design patterns (re-confirmed from the 6 reviews):
//   - Functional options (SourceOption)
//   - No caller mutation (shallow copy the Digest)
//   - Clock injection (Clock interface, defaultClock)
//   - Sentinel errors for errors.Is
//   - go test -count=0 for compile validation
//   - No time.Sleep in tests
//   - Don't "fix" a failing test by changing the
//     expectation (gotcha 58)

package digest

import (
	"errors"
	"fmt"
	"time"
)

// =====================================================================
// Period
// =====================================================================

// Period is the time period the digest covers. The
// default is "last 7 days" (weekly). Other options
// are daily (1 day) and monthly (30 days).
type Period string

const (
	// PeriodDaily covers the last 24 hours.
	PeriodDaily Period = "daily"
	// PeriodWeekly covers the last 7 days.
	PeriodWeekly Period = "weekly"
	// PeriodMonthly covers the last 30 days.
	PeriodMonthly Period = "monthly"
)

// DefaultPeriod is the default digest period.
const DefaultPeriod = PeriodWeekly

// PeriodDuration returns the duration covered by
// the period.
func (p Period) Duration() time.Duration {
	switch p {
	case PeriodDaily:
		return 24 * time.Hour
	case PeriodWeekly:
		return 7 * 24 * time.Hour
	case PeriodMonthly:
		return 30 * 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

// String returns the period as a human-readable string.
func (p Period) String() string {
	return string(p)
}

// =====================================================================
// Digest
// =====================================================================

// Digest is the CISO Posture Digest. It aggregates
// data from posture, IOC, and audit sources into a
// single regulator-acceptable report.
//
// The Digest is the payload that gets signed by
// SignDigest. The PDF rendered from this Digest is
// the user-facing artifact.
type Digest struct {
	// ID is the unique identifier for this digest.
	// Set automatically by BuildDigest if empty.
	ID string `json:"id"`
	// Period is the time period covered.
	Period Period `json:"period"`
	// StartTime is the start of the period.
	StartTime time.Time `json:"start_time"`
	// EndTime is the end of the period.
	EndTime time.Time `json:"end_time"`
	// GeneratedAt is the time the digest was
	// generated. Set automatically.
	GeneratedAt time.Time `json:"generated_at"`
	// Title is the digest title (e.g., "AegisGate
	// Posture Digest — Week of 2026-06-09").
	Title string `json:"title"`
	// OverallStatus is the overall posture status
	// (green, yellow, red, unknown).
	OverallStatus string `json:"overall_status"`
	// IOCsBlocked is the count of IOCs blocked in
	// the period, broken down by category, framework,
	// and protocol.
	IOCsBlocked *IOCSummary `json:"iocs_blocked"`
	// AnomaliesDetected is the count of anomalies
	// detected in the period, broken down by
	// protocol and severity.
	AnomaliesDetected *AnomalySummary `json:"anomalies_detected"`
	// Posture is the platform's posture status
	// across compliance frameworks.
	Posture *PostureSummary `json:"posture"`
	// TopSources is a list of top sources (by event
	// count) in the period.
	TopSources []SourceSummary `json:"top_sources,omitempty"`
	// TopThreats is a list of top threats (by event
	// count) in the period.
	TopThreats []ThreatSummary `json:"top_threats,omitempty"`
	// RegulatorMappings is a list of regulator-
	// relevant control mappings (SOC 2, ISO 27001,
	// EU AI Act, etc.).
	RegulatorMappings []RegulatorMapping `json:"regulator_mappings,omitempty"`
}

// Validate checks that the Digest is well-formed.
// Returns an error on the first invalid field.
func (d *Digest) Validate() error {
	if d == nil {
		return errors.New("digest: Digest is nil")
	}
	if d.Period == "" {
		return errors.New("digest: Period is required")
	}
	if d.StartTime.IsZero() {
		return errors.New("digest: StartTime is required")
	}
	if d.EndTime.IsZero() {
		return errors.New("digest: EndTime is required")
	}
	if d.EndTime.Before(d.StartTime) {
		return fmt.Errorf("digest: EndTime (%v) is before StartTime (%v)", d.EndTime, d.StartTime)
	}
	return nil
}

// =====================================================================
// Sub-types
// =====================================================================

// IOCSummary is the IOC breakdown for the digest.
type IOCSummary struct {
	// Total is the total number of IOCs blocked.
	Total int `json:"total"`
	// ByCategory is the count by IOC category
	// (e.g., "phishing", "malware", "data-exfil").
	ByCategory map[string]int `json:"by_category,omitempty"`
	// ByFramework is the count by compliance
	// framework (e.g., "mitre_atlas", "owasp_llm").
	ByFramework map[string]int `json:"by_framework,omitempty"`
	// ByProtocol is the count by protocol pillar
	// (http, mcp, a2a, acp, anp).
	ByProtocol map[string]int `json:"by_protocol,omitempty"`
}

// AnomalySummary is the anomaly breakdown for the digest.
type AnomalySummary struct {
	// Total is the total number of anomalies.
	Total int `json:"total"`
	// ByProtocol is the count by protocol pillar.
	ByProtocol map[string]int `json:"by_protocol,omitempty"`
	// BySeverity is the count by severity
	// (low, medium, high, critical).
	BySeverity map[string]int `json:"by_severity,omitempty"`
}

// PostureSummary is the platform's posture status.
type PostureSummary struct {
	// Overall is the overall posture status
	// (green, yellow, red, unknown).
	Overall string `json:"overall"`
	// ComplianceFrameworks is the list of compliance
	// frameworks and their posture.
	ComplianceFrameworks []ComplianceFrameworkStatus `json:"compliance_frameworks,omitempty"`
	// Uptime is the platform's uptime string
	// (e.g., "30 days").
	Uptime string `json:"uptime,omitempty"`
}

// ComplianceFrameworkStatus is the posture of a
// single compliance framework.
type ComplianceFrameworkStatus struct {
	// Framework is the framework name
	// (e.g., "soc2", "iso27001").
	Framework string `json:"framework"`
	// DisplayName is the human-readable name
	// (e.g., "SOC 2 Type II").
	DisplayName string `json:"display_name"`
	// Enforced is true if the framework is enforced.
	Enforced bool `json:"enforced"`
	// HasImplementation is true if the framework
	// has an implementation.
	HasImplementation bool `json:"has_implementation"`
}

// SourceSummary is a top source (by event count) in
// the period.
type SourceSummary struct {
	// Source is the source identifier
	// (e.g., an IP, agent ID, or user ID).
	Source string `json:"source"`
	// EventCount is the number of events from this
	// source.
	EventCount int `json:"event_count"`
	// ThreatCount is the number of threats from
	// this source.
	ThreatCount int `json:"threat_count"`
}

// ThreatSummary is a top threat (by event count) in
// the period.
type ThreatSummary struct {
	// ThreatType is the threat type
	// (e.g., "prompt-injection", "data-exfil").
	ThreatType string `json:"threat_type"`
	// EventCount is the number of events of this
	// threat type.
	EventCount int `json:"event_count"`
	// Severity is the highest severity observed.
	Severity string `json:"severity"`
}

// RegulatorMapping is a regulator-relevant control
// mapping (e.g., SOC 2 CC7.2 → AegisGate's IOC
// blocking).
type RegulatorMapping struct {
	// Framework is the regulator framework
	// (e.g., "soc2", "iso27001", "eu_ai_act").
	Framework string `json:"framework"`
	// ControlID is the control ID within the
	// framework (e.g., "CC7.2", "A.16.1.2",
	// "Article 9").
	ControlID string `json:"control_id"`
	// ControlName is the human-readable name
	// (e.g., "Monitoring and Detection").
	ControlName string `json:"control_name"`
	// AegisGateFeature is the AegisGate feature
	// that satisfies this control
	// (e.g., "IOC blocking (pkg/ioc)").
	AegisGateFeature string `json:"aegisgate_feature"`
}

// =====================================================================
// Sentinel errors
// =====================================================================

// ErrNoSources is returned by BuildDigest when no
// sources are configured.
var ErrNoSources = errors.New("digest: no sources configured")

// ErrInvalidPeriod is returned by BuildDigest when
// the period is invalid.
var ErrInvalidPeriod = errors.New("digest: invalid period")

// ErrDigestNotFound is returned by Verify when the
// envelope's payload is not a valid Digest.
var ErrDigestNotFound = errors.New("digest: envelope payload is not a valid Digest")
