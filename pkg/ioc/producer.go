// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// producer.go bridges the platform event stream (logging.Record /
// logging.QuickEvent) to the IOC store. The producer subscribes
// to the global recorder, filters events through an allow-list
// policy, computes the fingerprint, and writes IOCs into the
// store.
//
// Allow-list policy (locked decision Q4, 2026-06-15):
//
//   - "proxy_response"   events with severity >= warn   -> IOCTypeProxyResponse
//   - "anomaly_score"    events with severity >= high   -> IOCTypeAnomalyScore
//   - "response_*"       events with severity >= warn   -> IOCTypeProxyResponse
//     (the response scan subsystem emits "response_pii",
//      "response_injection", etc.; the wildcard captures them all)
//
// The producer NEVER reads SourceIP, User, ClientID, or any
// other identifying field from the event. The Detection struct
// (fingerprint.go) is the privacy boundary, and the producer
// constructs it explicitly from only the non-identifying fields.
//
// Wire-up: main.go constructs the store, constructs the producer,
// calls producer.Attach(store), and the producer registers itself
// as the package-level recorder via a small shim. Because the
// platform's recorder (logging.Recorder) is an interface, the
// producer can be a logging.Recorder that wraps the existing
// *logging.RingBuffer (so the platform's existing audit path
// keeps working) and ALSO records into the IOC store.
//
// The flow:
//
//   subsystem -> logging.Record(evt)
//   -> producer (the installed recorder) -> RingBuffer (existing)
//                                       -> IOC store (new)
//
// This is the same pattern the proxy recorder middleware uses in
// Track 6 Task 2: layered recorders, no new primitive.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// ProducerConfig configures the IOC producer. All fields are
// optional; zero values get sensible defaults.
type ProducerConfig struct {
	// MinSeverityProxyResponse is the minimum severity for a
	// proxy_response event to become an IOC. Default: "medium".
	// ("warn" is the typical proxy response trigger; we accept
	// medium and above to bias toward signal.)
	MinSeverityProxyResponse Severity

	// MinSeverityAnomalyScore is the minimum severity for an
	// anomaly_score event to become an IOC. Default: "high".
	// Anomaly scores are noisy at low severities; we only want
	// the high-confidence ones.
	MinSeverityAnomalyScore Severity

	// MinSeverityResponse is the minimum severity for a
	// response_* event to become an IOC. Default: "medium".
	MinSeverityResponse Severity
}

// Producer is the bridge from logging events to the IOC store.
// One Producer per process; Attach() installs it as the
// additional recorder layered on top of the existing ring
// buffer.
//
// Concurrency: Add() is the hot path. It runs on every event
// the platform emits. The lock holds only long enough to copy
// the relevant fields out of the event and call store.Observe();
// this is on the order of a few hundred nanoseconds.
type Producer struct {
	cfg   ProducerConfig
	store *Store

	// enabled is a runtime toggle; 0 = disabled, 1 = enabled.
	// Can be flipped at runtime via SetEnabled (e.g., from an
	// admin API that toggles IOC sharing).
	enabled atomic.Bool

	// eventsObserved counts every event the producer saw.
	// eventsRecorded counts the ones that passed the allow-list.
	// eventsRejected counts the ones that failed. Useful for
	// observability and for the "how is the producer doing" lab
	// test.
	eventsObserved atomic.Uint64
	eventsRecorded atomic.Uint64
	eventsRejected atomic.Uint64

	// inner is the recorder that the producer wraps. We do NOT
	// replace it; we are an additional sink. Set via Attach().
	mu    sync.RWMutex
	inner logging.Recorder
}

// NewProducer creates a Producer with the given config.
// store may be nil; if nil, the producer is a no-op until
// Attach() is called.
func NewProducer(cfg ProducerConfig, store *Store) *Producer {
	if cfg.MinSeverityProxyResponse == "" {
		cfg.MinSeverityProxyResponse = SeverityMedium
	}
	if cfg.MinSeverityAnomalyScore == "" {
		cfg.MinSeverityAnomalyScore = SeverityHigh
	}
	if cfg.MinSeverityResponse == "" {
		cfg.MinSeverityResponse = SeverityMedium
	}
	return &Producer{
		cfg:     cfg,
		store:   store,
		enabled: atomic.Bool{},
	}
}

// SetEnabled enables or disables the producer. When disabled,
// Add() is a fast no-op (one atomic load, one comparison). The
// toggle exists so the operator can disable IOC sharing at
// runtime without restarting the process.
func (p *Producer) SetEnabled(enabled bool) {
	p.enabled.Store(enabled)
}

// Enabled returns the current enabled state.
func (p *Producer) Enabled() bool {
	return p.enabled.Load()
}

// Attach stores the inner recorder so the producer can fan out
// to it. The platform's main.go calls this after constructing
// the ring buffer, so the existing audit path is preserved.
func (p *Producer) Attach(inner logging.Recorder) {
	p.mu.Lock()
	p.inner = inner
	p.mu.Unlock()
}

// Add implements logging.Recorder. It is the hot path: every
// event the platform emits flows through here.
//
// Step 1: bump the observed counter.
// Step 2: if disabled, no-op.
// Step 3: if no store, no-op.
// Step 4: filter via allow-list. If the event is not IOC-worthy,
//
//	do nothing (this is the common case for most events).
//
// Step 5: build a Detection, compute the fingerprint, build an
//
//	IOC, and write to the store.
//
// Step 6: fan out to the inner recorder (if any) so the existing
//
//	audit path is preserved.
func (p *Producer) Add(e logging.Event) {
	p.eventsObserved.Add(1)
	if !p.enabled.Load() {
		p.fanOut(e)
		return
	}
	p.mu.RLock()
	store := p.store
	p.mu.RUnlock()
	if store == nil {
		p.fanOut(e)
		return
	}

	// Allow-list filter.
	iocType, ok := p.classify(e)
	if !ok {
		p.eventsRejected.Add(1)
		p.fanOut(e)
		return
	}
	if !p.meetsMinSeverity(iocType, Severity(e.Severity)) {
		p.eventsRejected.Add(1)
		p.fanOut(e)
		return
	}

	// Build the privacy-safe Detection.
	d := Detection{
		Type:                e.Type,
		Severity:            Severity(e.Severity),
		Pattern:             e.Pattern,
		ThreatType:          e.ThreatType,
		ThreatLevel:         e.ThreatLevel,
		ComplianceFramework: e.ComplianceFramework,
		ComplianceControl:   e.ComplianceControl,
	}

	// Compute fingerprint and IOC.
	fp := Fingerprint(d)
	if fp == "" {
		p.eventsRejected.Add(1)
		p.fanOut(e)
		return
	}

	now := time.Now().UTC()
	ioc := IOC{
		Fingerprint: fp,
		Type:        iocType,
		Severity:    Severity(e.Severity),
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
		Source:      shortSourceFromEventType(e.Type),
	}
	if _, err := store.Observe(ioc); err != nil {
		// Invalid IOC (shouldn't happen; we built it ourselves).
		// Count as rejected and continue.
		p.eventsRejected.Add(1)
		p.fanOut(e)
		return
	}
	p.eventsRecorded.Add(1)
	p.fanOut(e)
}

// fanOut sends the event to the inner recorder (the one
// installed before the producer was attached, typically the
// RingBuffer). This preserves the existing audit path.
func (p *Producer) fanOut(e logging.Event) {
	p.mu.RLock()
	inner := p.inner
	p.mu.RUnlock()
	if inner != nil {
		inner.Add(e)
	}
}

// classify maps a logging.Event to an IOC type, returning the
// type and a bool indicating whether the event was in the
// allow-list. The allow-list is the locked decision Q4:
//
//   - "proxy_response"  -> IOCTypeProxyResponse
//   - "anomaly_score"   -> IOCTypeAnomalyScore
//   - "response_*"      -> IOCTypeProxyResponse
//
// Everything else returns ok=false and is dropped.
func (p *Producer) classify(e logging.Event) (IOCType, bool) {
	switch e.Type {
	case "proxy_response":
		return IOCTypeProxyResponse, true
	case "anomaly_score":
		return IOCTypeAnomalyScore, true
	}
	if strings.HasPrefix(e.Type, "response_") {
		return IOCTypeProxyResponse, true
	}
	return "", false
}

// meetsMinSeverity checks whether the observed severity meets
// the configured minimum for the given IOC type.
func (p *Producer) meetsMinSeverity(iocType IOCType, observed Severity) bool {
	var min Severity
	switch iocType {
	case IOCTypeProxyResponse:
		min = p.cfg.MinSeverityProxyResponse
	case IOCTypeAnomalyScore:
		min = p.cfg.MinSeverityAnomalyScore
	default:
		return false
	}
	return severityRank(observed) >= severityRank(min)
}

// shortSourceFromEventType returns a short, non-identifying
// source label for the IOC. Used as the IOC.Source field.
func shortSourceFromEventType(eventType string) string {
	switch eventType {
	case "proxy_response":
		return "proxy"
	case "anomaly_score":
		return "anomaly"
	}
	if strings.HasPrefix(eventType, "response_") {
		return "response_scan"
	}
	return "platform"
}

// Stats returns a snapshot of the producer's counters. Used
// by tests and by an admin endpoint to display "IOC library
// health".
type ProducerStats struct {
	Enabled        bool   `json:"enabled"`
	EventsObserved uint64 `json:"eventsObserved"`
	EventsRecorded uint64 `json:"eventsRecorded"`
	EventsRejected uint64 `json:"eventsRejected"`
}

// Stats returns the current counter snapshot.
func (p *Producer) Stats() ProducerStats {
	return ProducerStats{
		Enabled:        p.enabled.Load(),
		EventsObserved: p.eventsObserved.Load(),
		EventsRecorded: p.eventsRecorded.Load(),
		EventsRejected: p.eventsRejected.Load(),
	}
}
