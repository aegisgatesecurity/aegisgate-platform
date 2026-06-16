// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest source pipeline (TODO-602)
//
// sources.go defines the Source interface and 3
// adapters: PostureSource, IOCSource, AuditSource.
// These are the producers; the consumer is the
// BuildDigest function in builder.go.
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

package digest

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
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
// v0.1 design: count IOCs whose Timestamp falls
// within [start, end]. v0.2 can add the breakdowns
// (ByCategory, ByFramework, ByProtocol) by
// iterating the snapshot and aggregating.
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
// IOCsBlocked.Total populated from a time-range
// query against the IOC store.
func (s *IOCSource) Collect(ctx context.Context, start, end time.Time) (*Digest, error) {
	if s.store == nil {
		return &Digest{
			IOCsBlocked: &IOCSummary{},
		}, nil
	}
	// Use SnapshotSince to filter IOCs by the
	// digest's period.
	snapshot := s.store.SnapshotSince(start)
	// The SnapshotSince returns IOCs since `start`,
	// but we also need to filter by `end` (in case
	// the snapshot includes IOCs after `end`).
	// We use FirstSeen as the IOC's "when" timestamp.
	total := 0
	for _, i := range snapshot {
		if !i.FirstSeen.After(end) {
			total++
		}
	}
	return &Digest{
		IOCsBlocked: &IOCSummary{
			Total:       total,
			ByCategory:  make(map[string]int),
			ByFramework: make(map[string]int),
			ByProtocol:  make(map[string]int),
		},
	}, nil
}

// =====================================================================
// AuditSource
// =====================================================================

// AuditSource reads from pkg/audit. v0.1 returns a
// minimal Digest with AnomaliesDetected.Total
// populated from the SIEM dispatcher's stats.
// Breakdowns are populated in v0.2.
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
// Digest with AnomaliesDetected.Total populated
// from the dispatcher's stats.
func (s *AuditSource) Collect(ctx context.Context, start, end time.Time) (*Digest, error) {
	if s.dispatcher == nil {
		return &Digest{
			AnomaliesDetected: &AnomalySummary{},
		}, nil
	}
	stats := s.dispatcher.Stats()
	// Use EventsForwarded as the anomaly count
	// (events that made it to the SIEM are
	// "anomalies" from the digest's perspective).
	return &Digest{
		AnomaliesDetected: &AnomalySummary{
			Total:      int(stats.EventsForwarded),
			ByProtocol: make(map[string]int),
			BySeverity: make(map[string]int),
		},
	}, nil
}
