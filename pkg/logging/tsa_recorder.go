// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TSA Recording Wrapper (v3.5.0+)
// =========================================================================
//
// tsa_recorder.go provides a Recorder wrapper that cryptographically
// timestamps each audit event using an RFC 3161 Time Stamp Authority.
// When TSA is enabled, every event in the audit ring buffer carries
// proof-of-existence from an independent third party.
//
// Architecture:
//
//	auditRing → TSARecordingWrapper(inner=auditRing, signer=signer)
//	                    │
//	                    ├── 1. Add(event) is called
//	                    ├── 2. Serialize event to JSON
//	                    ├── 3. Call signer.SignAuditEvent(id, data)
//	                    ├── 4. If success: attach EventTSA to event
//	                    ├── 5. If failure: log warning, continue without TSA
//	                    └── 6. Call inner.Add(event) with TSA data attached
//
// This provides non-repudiation evidence for compliance frameworks:
//   - FedRAMP AU-10 (Non-repudiation)
//   - FedRAMP AU-11 (Protection of Audit Information)
//   - ISO 27001 A.12.4.3 (Secure Audit Trails)
//   - SOC 2 CC7.3 (Detective Controls)
//
// When TSA is disabled (nil signer), the wrapper is a transparent
// pass-through with zero overhead on the hot path.
//
// =========================================================================

package logging

import (
	"encoding/json"
	"log"
	"sync/atomic"
	"time"
)

// AuditEventSigner is the interface for RFC 3161 timestamp signing.
// This interface is satisfied by audit.TSAClient, but defined here
// to avoid an import cycle (pkg/logging cannot import pkg/audit).
type AuditEventSigner interface {
	// SignAuditEvent requests an RFC 3161 timestamp for the given
	// event data and returns an AuditEventSigned with the proof.
	SignAuditEvent(eventID string, data []byte) (*AuditEventSigned, error)

	// Endpoints returns the configured TSA endpoint URLs.
	Endpoints() []string
}

// AuditEventSigned is the result of an RFC 3161 timestamp signing
// operation. This mirrors audit.AuditEventTSA but is defined here
// to avoid an import cycle.
type AuditEventSigned struct {
	// EventID is the unique identifier of the original audit event.
	EventID string

	// DataHash is the SHA-256 hash of the original event data.
	DataHash []byte

	// GenTime is the UTC timestamp from the TSA token.
	GenTime time.Time

	// TSAEndpoint is the URL of the TSA that issued the token.
	TSAEndpoint string

	// Verified indicates whether the token was successfully verified.
	Verified bool
}

// TSARecordingWrapper wraps a Recorder and cryptographically timestamps
// each event using an RFC 3161 Time Stamp Authority. It implements the
// Recorder interface so it can be installed as the default recorder via
// SetDefault(), replacing or wrapping the existing RingBuffer.
//
// Thread-safety: TSARecordingWrapper is safe for concurrent use. The
// inner recorder's Add() method must also be safe for concurrent use
// (RingBuffer.Add() is).
//
// When signer is nil, the wrapper is a transparent pass-through —
// events are forwarded to inner without any TSA processing.
type TSARecordingWrapper struct {
	inner   Recorder
	signer  AuditEventSigner
	enabled atomic.Bool
	signed  atomic.Int64 // count of successfully signed events
	failed  atomic.Int64 // count of TSA signing failures
}

// NewTSARecordingWrapper creates a new TSA recording wrapper.
// If signer is nil, events are passed through without TSA timestamping.
func NewTSARecordingWrapper(inner Recorder, signer AuditEventSigner) *TSARecordingWrapper {
	w := &TSARecordingWrapper{
		inner:  inner,
		signer: signer,
	}
	w.enabled.Store(signer != nil)
	return w
}

// Add records an event. If TSA is enabled, the event is cryptographically
// timestamped before being forwarded to the inner recorder. If TSA
// timestamping fails, the event is still recorded (with a warning log)
// but without the TSA proof — graceful degradation.
//
// The serialization for TSA hashing uses JSON encoding of the event
// (excluding the TSA field itself, which would be circular). The hash
// is computed over this canonical JSON representation.
func (w *TSARecordingWrapper) Add(e Event) {
	if w.signer != nil && w.enabled.Load() {
		w.timestampEvent(&e)
	}
	w.inner.Add(e)
}

// timestampEvent attempts to cryptographically timestamp the event
// using the TSA signer. On success, the EventTSA data is attached.
// On failure, a warning is logged and the event proceeds without
// TSA proof — this is graceful degradation, not a fatal error.
func (w *TSARecordingWrapper) timestampEvent(e *Event) {
	// Generate a stable event ID if not set.
	eventID := e.ID
	if eventID == "" {
		eventID = generateEventID(e)
		e.ID = eventID
	}

	// Serialize the event for hashing. We exclude the TSA field
	// to avoid circular dependency (the TSA field is populated
	// after hashing). Create a clean copy for serialization.
	serializable := *e
	serializable.TSA = nil
	data, err := json.Marshal(serializable)
	if err != nil {
		w.failed.Add(1)
		log.Printf("⚠️  TSA: failed to serialize event %s for timestamping: %v", eventID, err)
		return
	}

	// Request RFC 3161 timestamp from the TSA signer.
	signed, err := w.signer.SignAuditEvent(eventID, data)
	if err != nil {
		w.failed.Add(1)
		log.Printf("⚠️  TSA: failed to get timestamp for event %s: %v", eventID, err)
		return
	}

	// Attach the TSA proof to the event.
	e.TSA = &EventTSA{
		EventID:     signed.EventID,
		DataHash:    signed.DataHash,
		Timestamp:   signed.GenTime,
		TSAEndpoint: signed.TSAEndpoint,
		Verified:    signed.Verified,
	}
	w.signed.Add(1)
}

// generateEventID creates a stable event ID from the event's type,
// time, and severity. This is used when the caller hasn't set an ID.
func generateEventID(e *Event) string {
	ts := e.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	// Use type + timestamp + severity as a stable identifier.
	// This isn't unique, but it's deterministic and sufficient
	// for TSA timestamping (the real uniqueness comes from the
	// hash of the full event data).
	return e.Type + "-" + ts.Format("20060102150405") + "-" + string(e.Severity)
}

// Stats returns the number of successfully signed events and TSA
// failures since the wrapper was created. Used by the /api/v1/tsa/status
// endpoint to report health.
func (w *TSARecordingWrapper) Stats() (signed, failed int64) {
	return w.signed.Load(), w.failed.Load()
}

// Disable stops TSA timestamping. Events will be passed through
// without TSA processing. Used for graceful shutdown.
func (w *TSARecordingWrapper) Disable() {
	w.enabled.Store(false)
}
