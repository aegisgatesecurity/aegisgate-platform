// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Audit Ring Recorder (v3.3.0+ Track 6)
//
// auditring.go provides a small global recorder that subsystems
// call to record events into the shared in-memory ring buffer.
// The recorder is the bridge between the event-emitting subsystems
// (HTTP proxy, MCP server, A2A, ACP, ANP, response scans, anomaly
// scores) and the compliance evidence package EventSource.
//
// Pattern: similar to Go stdlib log.Default() - a package-level
// recorder is set once at process startup (in main.go) and then
// used by any subsystem that wants to record events. This avoids
// threading a *RingBuffer through every constructor in the codebase.
//
// Thread-safety: SetDefault and Record are safe for concurrent use.
// GetDefault is read-only.
//
// v3.3.0+ Track 6 (B1 from deferred-work).

package logging

import (
	"sync"
	"sync/atomic"
)

// Recorder is the interface for adding events to a backing store.
// The default implementation is *RingBuffer; tests can substitute a
// mock recorder to capture events without setting up a real ring.
type Recorder interface {
	Add(e Event)
}

var (
	recorderMu sync.RWMutex
	recorder   atomic.Pointer[Recorder] // nil = recording disabled
)

// SetDefault installs the process-wide event recorder. Called once
// at startup from main.go, after the *RingBuffer is constructed.
// Passing nil disables recording (the recorder becomes a no-op).
//
// Safe to call multiple times - the last call wins. This is useful
// for tests that want to substitute a mock recorder.
func SetDefault(r Recorder) {
	recorderMu.Lock()
	defer recorderMu.Unlock()
	if r == nil {
		recorder.Store(nil)
		return
	}
	recorder.Store(&r)
}

// GetDefault returns the current recorder, or nil if none is set.
// The returned recorder is safe for concurrent use.
func GetDefault() Recorder {
	recorderMu.RLock()
	defer recorderMu.RUnlock()
	rp := recorder.Load()
	if rp == nil {
		return nil
	}
	return *rp
}

// Record is the convenience function for emitting an event to the
// default recorder. If no recorder is set (or it was explicitly
// disabled), this is a no-op. The ZeroAllocs design avoids any
// allocation on the hot path when recording is disabled.
//
// Subsystems should call this AFTER they have already emitted the
// event to their existing syslog/audit path. The ring recorder is
// a SECONDARY sink, not a replacement.
//
// Tier 1 (TODO-401): if a global FrameworkRefCache is installed
// (see SetGlobalRefCache), Record() also populates
// Event.FrameworkRefs with cross-framework references for the
// detection tuple (Type, ThreatType, Pattern). When no global
// cache is installed, this is a no-op (the helper returns an
// empty non-nil map without touching the cache). The lookup is
// lock-free and bounded by the seed table size, so the hot path
// cost is approximately 200ns on a typical x86_64.
func Record(e Event) {
	// Tier 1 (TODO-401): cross-framework reference lookup.
	// This is lock-free when the global cache is unset. When set,
	// the cost is 1 sync.Map.Load + 1 map clone, bounded by the
	// seed table size. See framework_refs.go for the full contract.
	if refs := GlobalRefCacheFor(DetectionKey{
		Type:       e.Type,
		ThreatType: e.ThreatType,
		Pattern:    e.Pattern,
	}); len(refs) > 0 {
		e.FrameworkRefs = refs
	}

	rp := recorder.Load()
	if rp == nil {
		return
	}
	(*rp).Add(e)
}

// IsEnabled returns true if a recorder is currently installed.
// Subsystems can use this to skip Record() entirely on hot paths
// where the cost of constructing an Event is non-trivial.
//
// Typical pattern:
//
//	if auditring.IsEnabled() {
//	    auditring.Record(auditring.Event{...})
//	}
func IsEnabled() bool {
	return recorder.Load() != nil
}

// QuickEvent is a helper for the common case of recording a single
// event with just Type, Severity, and Message. It allocates an
// Event on the stack (via the named return) and is safe to call
// from hot paths.
//
// Use the full Event struct for events that need more fields
// (ComplianceFramework, ComplianceControl, Action, etc.).
func QuickEvent(eventType string, sev Severity, msg string) {
	rp := recorder.Load()
	if rp == nil {
		return
	}
	(*rp).Add(Event{
		Type:     eventType,
		Severity: sev,
		Message:  msg,
	})
}
