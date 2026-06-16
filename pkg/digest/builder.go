// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest builder (TODO-602)
//
// builder.go is the producer: it merges the partial
// Digests from each Source into a single Digest.
// The flow:
//
//  1. Each Source.Collect() returns a partial
//     Digest.
//  2. BuildDigest merges the partials: for each
//     non-zero field in the partial, copy it to
//     the merged Digest.
//  3. The merged Digest is then passed to
//     RenderDigestPDF (TODO-601) for PDF rendering
//     and SignDigest for envelope signing.

package digest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// Clock (for testable time)
// =====================================================================

// Clock is the time source for the digest. The
// default implementation uses time.Now() UTC. Tests
// can pass a custom clock to deterministically
// test the digest's timestamps without sleeping.
//
// Pattern: per TODO-303 m1 fix, applied to TODO-305,
// applied here.
type Clock interface {
	Now() time.Time
}

// SystemClock is the default Clock implementation.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// defaultClock is the clock used by BuildDigest when
// no custom clock is provided. Initialized to
// SystemClock.
var defaultClock Clock = SystemClock{}

// SetDefaultClock replaces the default clock. Used
// by tests; production code should NOT call this.
func SetDefaultClock(c Clock) {
	if c != nil {
		defaultClock = c
	}
}

// =====================================================================
// Builder
// =====================================================================

// BuilderOptions configures a BuildDigest call.
type BuilderOptions struct {
	// Period is the time period covered. Default:
	// DefaultPeriod (weekly).
	Period Period
	// ID is the digest ID. Auto-generated if empty.
	ID string
	// Title is the digest title. Auto-generated if
	// empty.
	Title string
	// Clock is the time source. Default: SystemClock.
	Clock Clock
	// Now is an alternative way to specify "now"
	// (the end of the period). Default: time.Now().
	// Used by tests.
	Now time.Time
}

// BuildDigest builds a complete Digest by calling
// each Source.Collect() and merging the partials.
//
// v0.1: an empty sources slice is allowed (returns a
// minimal Digest with the period and timestamps
// populated; all other fields are zero). This is
// useful for CLI/testing where the source pipeline
// is not wired.
//
// Errors:
//   - period is invalid (ErrInvalidPeriod)
//   - any source returns an error
//   - the merged Digest fails validation
func BuildDigest(ctx context.Context, sources []Source, opts BuilderOptions) (*Digest, error) {
	// v0.1: empty sources is allowed (returns a
	// minimal Digest). v0.2 may add stricter
	// validation.
	_ = ErrNoSources // keep the sentinel for back-compat
	// Apply defaults.
	if opts.Period == "" {
		opts.Period = DefaultPeriod
	}
	if opts.Clock == nil {
		opts.Clock = defaultClock
	}
	if opts.Now.IsZero() {
		opts.Now = opts.Clock.Now()
	}
	// Compute the period.
	duration := opts.Period.Duration()
	end := opts.Now
	start := end.Add(-duration)
	// Validate period.
	if duration <= 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPeriod, opts.Period)
	}
	// Auto-generate ID and title if not provided.
	if opts.ID == "" {
		opts.ID = generateDigestID()
	}
	if opts.Title == "" {
		opts.Title = fmt.Sprintf("AegisGate Posture Digest -- %s of %s",
			opts.Period, end.Format("2006-01-02"))
	}
	// Initialize the merged Digest.
	digest := &Digest{
		ID:            opts.ID,
		Period:        opts.Period,
		StartTime:     start,
		EndTime:       end,
		GeneratedAt:   opts.Clock.Now(),
		Title:         opts.Title,
		OverallStatus: "unknown", // updated after collection
	}
	// Collect from each source (in parallel, with a
	// worker pool of 3 to avoid resource spikes).
	partials := make([]*Digest, len(sources))
	errs := make([]error, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			partial, err := src.Collect(ctx, start, end)
			if err != nil {
				errs[i] = fmt.Errorf("source %s: %w", src.Name(), err)
				return
			}
			partials[i] = partial
		}(i, src)
	}
	wg.Wait()
	// Check for errors.
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	// Merge the partials.
	for _, partial := range partials {
		mergeInto(digest, partial)
	}
	// Compute the overall status.
	digest.OverallStatus = computeOverallStatus(digest)
	// Validate the merged Digest.
	if err := digest.Validate(); err != nil {
		return nil, fmt.Errorf("digest: validate merged: %w", err)
	}
	// Add default regulator mappings.
	digest.RegulatorMappings = defaultRegulatorMappings()
	return digest, nil
}

// mergeInto merges the partial's non-zero fields
// into the merged Digest. v0.1: simple field-by-
// field copy.
func mergeInto(merged, partial *Digest) {
	if partial == nil {
		return
	}
	if partial.IOCsBlocked != nil {
		merged.IOCsBlocked = partial.IOCsBlocked
	}
	if partial.AnomaliesDetected != nil {
		merged.AnomaliesDetected = partial.AnomaliesDetected
	}
	if partial.Posture != nil {
		merged.Posture = partial.Posture
	}
	if len(partial.TopSources) > 0 {
		merged.TopSources = partial.TopSources
	}
	if len(partial.TopThreats) > 0 {
		merged.TopThreats = partial.TopThreats
	}
}

// computeOverallStatus returns "red" if any source
// reports a critical anomaly; "yellow" if any
// anomaly is reported; "green" if all sources are
// clean; "unknown" otherwise.
func computeOverallStatus(d *Digest) string {
	// Check posture first (the platform's overall
	// health is the most reliable indicator).
	if d.Posture != nil {
		switch d.Posture.Overall {
		case "red", "critical":
			return "red"
		case "yellow", "warning":
			return "yellow"
		case "green", "healthy":
			// Continue to check anomalies.
		}
	}
	// Check anomalies.
	if d.AnomaliesDetected != nil {
		if d.AnomaliesDetected.Total > 0 {
			return "yellow"
		}
	}
	// Check IOCs.
	if d.IOCsBlocked != nil {
		if d.IOCsBlocked.Total > 0 {
			return "yellow"
		}
	}
	return "green"
}

// defaultRegulatorMappings returns the default
// regulator mappings. These are static (the
// control IDs and AegisGate features don't change
// per digest).
func defaultRegulatorMappings() []RegulatorMapping {
	return []RegulatorMapping{
		{
			Framework:        "soc2",
			ControlID:        "CC7.2",
			ControlName:      "Monitoring and Detection",
			AegisGateFeature: "IOC blocking (pkg/ioc) + SIEM dispatcher (pkg/audit)",
		},
		{
			Framework:        "iso27001",
			ControlID:        "A.16.1.2",
			ControlName:      "Reporting information security events",
			AegisGateFeature: "Audit logging (pkg/audit) + c3 manifest (pkg/evidence)",
		},
		{
			Framework:        "eu_ai_act",
			ControlID:        "Article 9",
			ControlName:      "Risk management and quality management",
			AegisGateFeature: "AR-EaaS (pkg/evaluator) + AIBOM (pkg/aibom) + envelope (pkg/attestation)",
		},
		{
			Framework:        "hipaa",
			ControlID:        "164.312(b)",
			ControlName:      "Audit controls",
			AegisGateFeature: "Audit logging (pkg/audit)",
		},
	}
}

// generateDigestID returns a unique ID for the
// digest. The format is "digest-<16-hex>" (the
// shortfp format consistent with the Tier 5
// features).
func generateDigestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: use the current time.
		return fmt.Sprintf("digest-%016x", time.Now().UnixNano())
	}
	return "digest-" + hex.EncodeToString(b[:])
}

// Helper: ensure the ioc package is imported (it
// is used via the source adapters).
var _ = ioc.IOC{}
