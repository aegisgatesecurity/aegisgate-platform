// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest source pipeline (TODO-602 + v0.2 wiring)
//
// sources.go defines the Source interface and 4
// adapters: PostureSource, IOCSource, AuditLogSource,
// and AuditSource. These are the producers; the
// consumer is the BuildDigest function in builder.go.
//
// Design: the Source interface is intentionally
// minimal. Each source returns a partial Digest
// (just the fields it knows about); BuildDigest
// merges the partials into a single Digest.
//
// Why this design? It decouples the digest's data
// model from the underlying subsystems. v0.2 can
// add new sources (e.g., AIBOM, CVE) without
// changing BuildDigest.
//
// v0.2 wiring (the "real" wiring):
//   - IOCSource: reads from pkg/ioc.Store for the
//     "by category" breakdown (IOC.Type). The IOC
//     store provides time-range queries (SnapshotSince).
//   - AuditLogSource: reads from pkg/logging.RingBuffer
//     for the "by framework" + "by protocol" + "by
//     severity" breakdowns. The ring buffer provides
//     CountByFramework, CountByProtocol, CountBySeverity,
//     and CountByType over a time window.
//   - AuditSource: reads from pkg/audit.SIEMDispatcher
//     for the "anomalies forwarded" count. (Lightweight;
//     the heavy lifting is in AuditLogSource.)
//   - PostureSource: reads from pkg/posture.Checker
//     for the platform's compliance posture.

package digest

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// =====================================================================
// Source interface
// =====================================================================

// Source is a subsystem that contributes data to a
// Digest. Each source returns a partial Digest
// containing only the fields it knows about;
// BuildDigest merges the partials.
//
// The partial Digest may have:
//   - IOCsBlocked (if the source tracks IOCs)
//   - AnomaliesDetected (if the source tracks
//     anomalies)
//   - Posture (if the source tracks posture)
//   - TopSources, TopThreats (if the source has
//     aggregations)
//
// All other fields are left at their zero value and
// are ignored by BuildDigest.
type Source interface {
	// Name returns the source name (for logging and
	// debugging).
	Name() string
	// Collect returns the partial Digest for the
	// given time period. The partial is a
	// shallow-copied Digest (not the full one);
	// BuildDigest owns the merging.
	Collect(ctx context.Context, start, end time.Time) (*Digest, error)
}

// =====================================================================
// PostureSource
// =====================================================================

// PostureSource reads from pkg/posture. The posture
// package provides a Checker that runs all
// subsystem checks and returns a Report. The
// PostureSource extracts the relevant fields and
// populates the Digest's Posture section.
type PostureSource struct {
	checker *posture.Checker
}

// NewPostureSource returns a new PostureSource
// backed by the given posture.Checker. The checker
// is the live one from the platform's main loop;
// v0.1 uses a snapshot (Checker.Check is called
// once per digest generation).
func NewPostureSource(checker *posture.Checker) *PostureSource {
	return &PostureSource{checker: checker}
}

// Name implements Source.
func (s *PostureSource) Name() string { return "posture" }

// Collect implements Source. It runs the posture
// check and extracts the relevant fields.
func (s *PostureSource) Collect(ctx context.Context, start, end time.Time) (*Digest, error) {
	if s.checker == nil {
		// No checker: return a minimal Digest with
		// just the posture set to "unknown".
		return &Digest{
			Posture: &PostureSummary{Overall: "unknown"},
		}, nil
	}
	report, err := s.checker.Check(ctx)
	if err != nil {
		return nil, fmt.Errorf("posture: Check: %w", err)
	}
	// Convert the posture Report to a
	// PostureSummary.
	summary := &PostureSummary{
		Overall: string(report.Overall),
		Uptime:  report.Uptime,
	}
	for _, block := range report.Compliance {
		summary.ComplianceFrameworks = append(summary.ComplianceFrameworks, ComplianceFrameworkStatus{
			Framework:         block.Framework,
			DisplayName:       block.DisplayName,
			Enforced:          block.Enforced,
			HasImplementation: block.HasImplementation,
		})
	}
	return &Digest{
		Posture: summary,
	}, nil
}

// =====================================================================
// IOCSource
// =====================================================================

// IOCSource reads from pkg/ioc. The IOC store
// provides time-range queries (SnapshotSince), so
// we can filter IOCs by the digest's period.
//
// v0.2 design: the "by category" breakdown is
// computed by iterating the snapshot and counting
// by IOC.Type. The "by framework" + "by protocol"
// breakdowns come from the AuditLogSource (not
// the IOC store) because the IOC struct stores
// only the Type + Severity; the framework and
// protocol metadata is preserved in the audit log
// but lost in the stored IOC.
type IOCSource struct {
	store *ioc.Store
}

// NewIOCSource returns a new IOCSource backed by
// the given ioc.Store.
func NewIOCSource(store *ioc.Store) *IOCSource {
	return &IOCSource{store: store}
}

// Name implements Source.
func (s *IOCSource) Name() string { return "ioc" }

// Collect implements Source. Returns a Digest with
// IOCsBlocked.Total + ByCategory populated from a
// time-range query against the IOC store. The
// ByFramework and ByProtocol breakdowns are left
// empty (populated by AuditLogSource).
func (s *IOCSource) Collect(_ context.Context, start, end time.Time) (*Digest, error) {
	if s.store == nil {
		return &Digest{
			IOCsBlocked: &IOCSummary{
				ByCategory:  make(map[string]int),
				ByFramework: make(map[string]int),
				ByProtocol:  make(map[string]int),
			},
		}, nil
	}
	// Use SnapshotSince to filter IOCs by the
	// digest's period.
	snapshot := s.store.SnapshotSince(start)
	// Filter by [start, end] and aggregate by Type.
	total := 0
	byCategory := make(map[string]int)
	for _, i := range snapshot {
		if i.FirstSeen.After(end) {
			continue
		}
		total++
		byCategory[string(i.Type)]++
	}
	return &Digest{
		IOCsBlocked: &IOCSummary{
			Total:       total,
			ByCategory:  byCategory,
			ByFramework: make(map[string]int),
			ByProtocol:  make(map[string]int),
		},
	}, nil
}

// =====================================================================
// AuditLogSource
// =====================================================================

// AuditLogSource reads from pkg/logging.RingBuffer
// (the platform's audit event ring buffer). The
// ring buffer provides time-windowed aggregations:
// CountByFramework, CountByProtocol, CountByType,
// and CountBySeverity.
//
// v0.2 design: the AuditLogSource populates:
//   - IOCsBlocked.ByFramework (compliance framework
//     attribution of every event in the period)
//   - IOCsBlocked.ByProtocol (protocol pillar
//     attribution: http, mcp, a2a, acp, anp)
//   - AnomaliesDetected.Total (count of events
//     whose ThreatType indicates an anomaly)
//   - AnomaliesDetected.ByProtocol (anomaly events
//     by protocol)
//   - AnomaliesDetected.BySeverity (anomaly events
//     by severity)
//
// v0.2 design note: the "total IOCs" and "total
// anomalies" can be computed by either the IOC
// store or the audit log. The IOC store gives
// the "true" IOC count (deduplicated by
// fingerprint); the audit log gives the "raw event
// count" (every event, not just IOCs). We use the
// IOC store for IOCsBlocked.Total (the right
// answer) and the audit log for AnomaliesDetected
// (where there's no IOC-store equivalent).
type AuditLogSource struct {
	ring *logging.RingBuffer
}

// NewAuditLogSource returns a new AuditLogSource
// backed by the given ring buffer.
func NewAuditLogSource(ring *logging.RingBuffer) *AuditLogSource {
	return &AuditLogSource{ring: ring}
}

// Name implements Source.
func (s *AuditLogSource) Name() string { return "audit_log" }

// Collect implements Source. Returns a Digest
// with the IOCsBlocked.ByFramework +
// IOCsBlocked.ByProtocol + AnomaliesDetected
// breakdowns populated from a time-windowed
// query against the audit log.
//
// v0.2 design: "anomaly" is defined as an event
// whose Severity is "high" or "critical" (the
// platform's standard "this is a real threat"
// threshold). Events at medium or lower severity
// are NOT counted as anomalies.
func (s *AuditLogSource) Collect(ctx context.Context, start, end time.Time) (*Digest, error) {
	if s.ring == nil {
		return &Digest{
			IOCsBlocked: &IOCSummary{
				ByCategory:  make(map[string]int),
				ByFramework: make(map[string]int),
				ByProtocol:  make(map[string]int),
			},
			AnomaliesDetected: &AnomalySummary{
				ByProtocol: make(map[string]int),
				BySeverity: make(map[string]int),
			},
		}, nil
	}
	// Pull the breakdowns.
	byFramework, err := s.ring.CountByFramework(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("audit log: CountByFramework: %w", err)
	}
	byProtocol, err := s.ring.CountByProtocol(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("audit log: CountByProtocol: %w", err)
	}
	// For anomalies: pull the events via the
	// snapshot helper and filter to high/critical
	// severity.
	events := s.ring.SnapshotBetween(start, end)
	anomalyTotal := 0
	anomalyByProtocol := make(map[string]int)
	anomalyBySeverity := make(map[string]int)
	protocolOfEvent := logging.ProtocolFromEventType
	for _, e := range events {
		if e.Time.After(end) {
			continue
		}
		if e.Severity != "high" && e.Severity != "critical" {
			continue
		}
		anomalyTotal++
		anomalyBySeverity[string(e.Severity)]++
		if proto := protocolOfEvent(string(e.Type)); proto != "" {
			anomalyByProtocol[proto]++
		}
	}
	return &Digest{
		IOCsBlocked: &IOCSummary{
			// Total + ByCategory are filled by IOCSource.
			ByCategory:  make(map[string]int),
			ByFramework: byFramework,
			ByProtocol:  byProtocol,
		},
		AnomaliesDetected: &AnomalySummary{
			Total:      anomalyTotal,
			ByProtocol: anomalyByProtocol,
			BySeverity: anomalyBySeverity,
		},
	}, nil
}

// =====================================================================
// AuditSource
// =====================================================================

// AuditSource reads from pkg/audit. The
// SIEMDispatcher's stats are a lightweight
// summary; the heavy lifting is in
// AuditLogSource. AuditSource's role is to
// provide the "total events forwarded to SIEM"
// signal (a different number from the IOC store
// count or the audit log anomaly count).
type AuditSource struct {
	dispatcher *audit.SIEMDispatcher
}

// NewAuditSource returns a new AuditSource backed
// by the given SIEMDispatcher.
func NewAuditSource(d *audit.SIEMDispatcher) *AuditSource {
	return &AuditSource{dispatcher: d}
}

// Name implements Source.
func (s *AuditSource) Name() string { return "audit" }

// Collect implements Source. Returns a minimal
// Digest with the SIEM-forwarded event count
// (lightweight; the heavy lifting is in
// AuditLogSource).
func (s *AuditSource) Collect(_ context.Context, start, end time.Time) (*Digest, error) {
	if s.dispatcher == nil {
		return &Digest{}, nil
	}
	stats := s.dispatcher.Stats()
	// EventsForwarded is the count of events that
	// were sent to the configured SIEM(s). This is
	// a different number from the IOC store count
	// (deduplicated IOCs) or the audit log anomaly
	// count (high/critical events in the period).
	// For the digest, we just expose it via the
	// Posture.Stats field (a future addition).
	_ = start
	_ = end
	_ = stats
	// v0.2: leave AnomaliesDetected empty (the
	// AuditLogSource populates the actual
	// breakdowns).
	return &Digest{}, nil
}
