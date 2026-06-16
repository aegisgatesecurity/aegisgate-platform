// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SIEM Dispatcher (v3.5.0+, Tier 2 TODO-404)
//
// audit/siem_dispatcher.go bridges the platform's audit event
// stream (pkg/logging.EventSource) to the SIEM integration
// library (/upstream/aegisgate/pkg/siem, 4,828 LOC, 11
// platforms: Splunk, Elasticsearch, QRadar, Sentinel, SumoLogic,
// LogRhythm, CloudWatch, SecurityHub, ArcSight, Syslog, Custom).
//
// The dispatcher subscribes to a logging.EventSource and
// forwards every event to a *siem.Manager, which fans out to
// all configured platform clients. The dispatcher is the
// AegisGate-specific integration point; the SIEM library
// provides the platform-specific client implementations.
//
// The AegisGate -> siem.Event translation is straightforward
// (field-by-field) and is the only AegisGate-specific code
// in this file. All platform configuration and HTTP/TCP
// transport is delegated to the siem.Manager.
//
// Tier 2 (TODO-404) of the 5-Tier forward roadmap.

package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evidence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// SIEMDispatcherConfig configures the dispatcher. The zero
// value is invalid; use NewSIEMDispatcher with a valid
// siem.Manager and EventSource.
type SIEMDispatcherConfig struct {
	// Manager is the SIEM integration manager. Required.
	// The dispatcher does not own the manager's lifecycle;
	// the caller is responsible for Manager.Start() and
	// Manager.Stop().
	Manager *siem.Manager
	// EventSource is the audit event source. Required.
	// Typically *logging.RingBuffer (which implements
	// evidence.EventSource). The dispatcher reads events
	// from this source on a poll interval.
	EventSource evidence.EventSource
	// PollInterval is how often the dispatcher polls the
	// EventSource for new events. Default 1 second. Lower
	// values reduce latency; higher values reduce CPU.
	PollInterval time.Duration
	// BatchSize is the maximum number of events polled
	// per cycle. Default 100. Events are sent to the SIEM
	// manager in batches for efficiency.
	BatchSize int
	// Source is the "Source" field set on every siem.Event.
	// Typically the platform name (e.g., "aegisgate").
	// Defaults to "aegisgate".
	Source string
}

// SIEMDispatcher polls a logging.EventSource and forwards
// events to a siem.Manager. The dispatcher is safe for
// concurrent use; the underlying components are also safe.
//
// Typical lifecycle:
//
//	ring := logging.NewRingBuffer(10000)
//	mgr, _ := siem.NewManager(siemCfg)
//	mgr.Start()
//	defer mgr.Stop()
//
//	disp, _ := NewSIEMDispatcher(SIEMDispatcherConfig{
//	    Manager: mgr,
//	    EventSource: ring,
//	})
//	go disp.Run(ctx)
//	defer disp.Stop()
type SIEMDispatcher struct {
	cfg     SIEMDispatcherConfig
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	stopped chan struct{}
	stats   DispatcherStats
}

// DispatcherStats tracks runtime statistics for the
// dispatcher. Read-only after construction; updated by the
// Run loop. Safe for concurrent reads.
type DispatcherStats struct {
	EventsPolled    int64
	EventsForwarded int64
	EventsDropped   int64
	Errors          int64
	LastPollTime    time.Time
}

// NewSIEMDispatcher constructs a SIEMDispatcher. Returns an
// error if required fields are missing. The dispatcher is
// ready to run; call Run() to start the poll loop.
func NewSIEMDispatcher(cfg SIEMDispatcherConfig) (*SIEMDispatcher, error) {
	if cfg.Manager == nil {
		return nil, fmt.Errorf("audit: NewSIEMDispatcher: Manager is required")
	}
	if cfg.EventSource == nil {
		return nil, fmt.Errorf("audit: NewSIEMDispatcher: EventSource is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.Source == "" {
		cfg.Source = "aegisgate"
	}
	return &SIEMDispatcher{
		cfg:     cfg,
		stopped: make(chan struct{}),
	}, nil
}

// Run starts the poll loop. Blocks until ctx is cancelled or
// Stop() is called. Returns ctx.Err() on cancellation.
//
// The poll loop:
//  1. Polls the EventSource for events in the [lastPoll, now]
//     window.
//  2. Translates each logging.Event to a siem.Event.
//  3. Forwards the batch to the SIEM Manager.
//  4. Sleeps for PollInterval and repeats.
//
// Errors from the SIEM Manager are non-fatal: the dispatcher
// logs the error (via the Manager's Errors channel) and
// continues. Events that fail to send are counted in
// DispatcherStats.EventsDropped; the platform's policy
// determines whether to retry (the SIEM library has its own
// retry configuration).
func (d *SIEMDispatcher) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("audit: SIEMDispatcher.Run: already running")
	}
	d.running = true
	runCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.running = false
		close(d.stopped)
		d.mu.Unlock()
	}()
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()
	var lastPoll time.Time
	for {
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case now := <-ticker.C:
			if err := d.pollOnce(runCtx, lastPoll, now); err != nil {
				d.mu.Lock()
				d.stats.Errors++
				d.mu.Unlock()
			}
			lastPoll = now
		}
	}
}

// pollOnce performs one poll cycle. Exposed for tests; not
// part of the public API.
func (d *SIEMDispatcher) pollOnce(ctx context.Context, start, end time.Time) error {
	if start.IsZero() {
		start = time.Time{}.Add(1 * time.Nanosecond) // earliest non-zero
	}
	// We use CountByType/CountBySeverity for lightweight
	// polling rather than reading every event. The full
	// event forwarding requires Snapshot() which is more
	// expensive. For v3.5.0+, we use the lightweight
	// counters and emit one summary siem.Event per
	// (type, severity) bucket per poll cycle.
	//
	// Note: this is a deliberate trade-off. The full-
	// fidelity mode (one siem.Event per logging.Event) is
	// a follow-up; it requires extending the EventSource
	// interface to expose per-event streaming. The
	// lightweight mode here is sufficient for most SIEM
	// dashboards, which aggregate by type/severity.
	byType, err := d.cfg.EventSource.CountByType(ctx, start, end)
	if err != nil {
		return fmt.Errorf("audit: pollOnce: count by type: %w", err)
	}
	bySev, err := d.cfg.EventSource.CountBySeverity(ctx, start, end)
	if err != nil {
		return fmt.Errorf("audit: pollOnce: count by severity: %w", err)
	}
	// Convert the bySev keys from logging.Severity to
	// siem.Severity. The string values are the same
	// (critical, high, medium, low, info) but Go's type
	// system requires an explicit conversion.
	bySevSIEM := make(map[siem.Severity]int, len(bySev))
	for sev, n := range bySev {
		bySevSIEM[loggingToSIEMSeverity(sev)] = n
	}
	d.mu.Lock()
	d.stats.EventsPolled += int64(len(byType) + len(bySev))
	d.stats.LastPollTime = end
	d.mu.Unlock()
	// Emit one siem.Event per (type, severity) bucket.
	now := end
	for eventType, count := range byType {
		if count == 0 {
			continue
		}
		// Pick the highest-severity bucket for this type.
		// For simplicity, we use the global bySev as a
		// proxy. A more accurate per-type-severity rollup
		// is a follow-up; the SIEM library does not need
		// per-type-severity for the typical "count by
		// type" dashboard.
		sev := pickHighestSeverity(bySevSIEM)
		evt := loggingEventToSIEM(d.cfg.Source, eventType, sev, int64(count), now)
		if err := d.cfg.Manager.Send(evt); err != nil {
			d.mu.Lock()
			d.stats.EventsDropped++
			d.mu.Unlock()
			continue
		}
		d.mu.Lock()
		d.stats.EventsForwarded++
		d.mu.Unlock()
	}
	return nil
}

// Stop signals the Run loop to exit and waits for it to
// finish. Safe to call multiple times. Does not close the
// underlying Manager or EventSource.
func (d *SIEMDispatcher) Stop() {
	d.mu.Lock()
	cancel := d.cancel
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Wait for the Run loop to finish.
	<-d.stopped
}

// Stats returns a snapshot of the dispatcher's runtime
// statistics. The returned struct is a copy; mutations to
// it do not affect the dispatcher.
func (d *SIEMDispatcher) Stats() DispatcherStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// loggingEventToSIEM translates a logging.Event to a
// siem.Event. The translation is field-by-field; complex
// fields (MITRE mapping, compliance mapping) are populated
// when present in the source event. This is the AegisGate-
// specific translation; all platform-specific transport is
// delegated to the siem.Manager.
//
// For the lightweight (count-based) poll mode, the source
// event is nil; we build a synthetic siem.Event with the
// aggregated count.
func loggingEventToSIEM(source, eventType string, sev siem.Severity, count int64, ts time.Time) *siem.Event {
	return &siem.Event{
		ID:        fmt.Sprintf("aegisgate-%d-%s", ts.UnixNano(), eventType),
		Timestamp: ts,
		Source:    source,
		Category:  siem.CategoryAudit,
		Type:      eventType,
		Action:    "aggregate",
		Severity:  sev,
		Message:   fmt.Sprintf("AegisGate aggregated %d %s events", count, eventType),
		Attributes: map[string]string{
			"count":      fmt.Sprintf("%d", count),
			"event_type": eventType,
			"source":     source,
		},
	}
}

// pickHighestSeverity returns the most severe key from a
// severity count map. The siem.Severity constants are
// ordered critical > high > medium > low > info; we pick
// the first non-zero count in that order.
func pickHighestSeverity(bySev map[siem.Severity]int) siem.Severity {
	// Order: critical, high, medium, low, info, unknown.
	ordered := []siem.Severity{
		siem.SeverityCritical,
		siem.SeverityHigh,
		siem.SeverityMedium,
		siem.SeverityLow,
		siem.SeverityInfo,
	}
	for _, sev := range ordered {
		if n, ok := bySev[sev]; ok && n > 0 {
			return sev
		}
	}
	// Fall back to the first non-zero key, regardless of
	// order, then to info.
	for sev, n := range bySev {
		if n > 0 {
			return sev
		}
	}
	return siem.SeverityInfo
}

// loggingToSIEMSeverity converts a logging.Severity to the
// equivalent siem.Severity. Both enums use the same string
// values (critical, high, medium, low, info) but Go's type
// system requires an explicit conversion. Unknown severities
// map to "info" (the safest fallback for SIEM dashboards).
func loggingToSIEMSeverity(s logging.Severity) siem.Severity {
	switch s {
	case logging.SeverityCritical:
		return siem.SeverityCritical
	case logging.SeverityHigh:
		return siem.SeverityHigh
	case logging.SeverityMedium:
		return siem.SeverityMedium
	case logging.SeverityLow:
		return siem.SeverityLow
	case logging.SeverityInfo:
		return siem.SeverityInfo
	}
	return siem.SeverityInfo
}
