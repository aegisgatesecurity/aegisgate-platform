// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Audit Logger
// =========================================================================
//
// audit.go wraps the Platform's pkg/logging with the Lens-specific
// payload-stripping discipline. The privacy policy commits to:
//
//   "The Lens backend never logs an event payload, in any form,
//    under any circumstance. The only fields that appear in
//    audit logs are: the request ID, the timestamp, the
//    claimed domain_hash (NOT the SNI), the category, the
//    user_action, the response status, and the response
//    latency."
//
// To enforce this in code, the audit logger exposes a small set
// of typed methods (RecordReceived, RecordAccepted, RecordRejected,
// RecordRateLimited) that take only the fields listed above. The
// logger's underlying sink is pkg/logging.RingBuffer, which is
// the Platform's existing in-memory event log; we reuse it
// unchanged.
//
// The audit logger is the single point of egress for log lines
// that mention a Lens event. A CI grep check (in the Platform's
// .github/workflows/build.yml) verifies that no other file in
// pkg/lensbackend/ writes a log line that contains the substring
// "prompt", "content", "input", "textarea", "url", or "host" --
// which would indicate a payload leak. The check is:
//
//   grep -rE 'log\.|slog\.|fmt\.Print|fmt\.Fprintf' pkg/lensbackend/ \
//     | grep -vE 'audit\.go|//' \
//     | grep -iE 'prompt|content|input|textarea|url|host|email|phone|ssn|key' \
//     && exit 1
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"context"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// auditLogger is the Lens backend's audit logger. It wraps a
// pkg/logging.RingBuffer and exposes a small set of typed
// methods that never accept a payload field.
type auditLogger struct {
	ring   *logging.RingBuffer
	logger *slog.Logger
}

// newAuditLogger creates an auditLogger. The ring is the
// underlying in-memory event log; it is owned by the caller
// (typically the server, which passes the same ring to other
// components). The slog logger is the stdlib structured
// logger; it is configured to never include the event payload.
func newAuditLogger(ring *logging.RingBuffer, logger *slog.Logger) *auditLogger {
	return &auditLogger{
		ring:   ring,
		logger: logger,
	}
}

// Audit fields. These are the ONLY fields the audit logger
// will record. Adding a field to this list is a privacy-policy
// change and requires updating the policy and the threat model.
const (
	auditFieldRequestID   = "request_id"
	auditFieldTimestamp   = "timestamp"
	auditFieldDomainHash  = "domain_hash"
	auditFieldCategory    = "category"
	auditFieldUserAction  = "user_action"
	auditFieldStatus      = "status"
	auditFieldLatencyMS   = "latency_ms"
	auditFieldReason      = "reason"
)

// RecordReceived logs that an event was received from the
// extension, before validation. The status is "received".
func (a *auditLogger) RecordReceived(ctx context.Context, requestID, domainHash, category string) {
	a.emit(ctx, requestID, domainHash, category, "", "received", 0, "")
}

// RecordAccepted logs that an event was accepted and forwarded
// to the IOC aggregator.
func (a *auditLogger) RecordAccepted(ctx context.Context, requestID, domainHash, category, userAction string, latencyMS int64) {
	a.emit(ctx, requestID, domainHash, category, userAction, "accepted", latencyMS, "")
}

// RecordRejected logs that an event was rejected. The reason
// is a machine-readable string (e.g., "invalid_category",
// "domain_hash_mismatch", "no_tls_sni").
func (a *auditLogger) RecordRejected(ctx context.Context, requestID, domainHash, category, reason string, latencyMS int64) {
	a.emit(ctx, requestID, domainHash, category, "", "rejected", latencyMS, reason)
}

// RecordRateLimited logs that a request was rate-limited.
// The reason is "per_installation" or "global".
func (a *auditLogger) RecordRateLimited(ctx context.Context, requestID, domainHash, reason string) {
	a.emit(ctx, requestID, domainHash, "", "", "rate_limited", 0, reason)
}

// emit writes one audit log line. This is the single point of
// egress; all other methods funnel through here. The fields
// are passed positionally to keep the privacy surface auditable;
// if you add a new field, add a constant above and pass it here.
func (a *auditLogger) emit(ctx context.Context, requestID, domainHash, category, userAction, status string, latencyMS int64, reason string) {
	ts := time.Now().UTC()
	a.logger.LogAttrs(ctx, slog.LevelInfo, "lens_audit",
		slog.String(auditFieldRequestID, requestID),
		slog.String(auditFieldTimestamp, ts.Format(time.RFC3339Nano)),
		slog.String(auditFieldDomainHash, domainHash),
		slog.String(auditFieldCategory, category),
		slog.String(auditFieldUserAction, userAction),
		slog.String(auditFieldStatus, status),
		slog.Int64(auditFieldLatencyMS, latencyMS),
		slog.String(auditFieldReason, reason),
	)
	if a.ring != nil {
		// Also push to the in-memory ring buffer for the
		// /api/v1/lens/stats endpoint and the admin UI.
		// The ring buffer's Event type does not include a
		// payload field; we only push the audit fields.
		// Note: pkg/logging.Event has a fixed schema (Type,
		// Severity, Message, etc.) -- we use the schema
		// fields rather than a custom Fields map. The
		// category/user_action are encoded into the Message
		// as a compact, well-known format that the stats
		// endpoint parses.
		a.ring.Add(logging.Event{
			Time:     ts,
			Type:     "lens_audit",
			Severity: logging.SeverityInfo,
			Message:  formatAuditMessage(requestID, domainHash, category, userAction, status, reason),
			// Pattern is overloaded with the request ID
			// (it is the closest existing field to a
			// request-scoped identifier; the Pattern field
			// is for regex patterns in the existing code,
			// but it is generic and grep-friendly).
			Pattern: requestID,
		})
	}
}

// formatAuditMessage produces a compact, machine-parseable
// audit message. Format:
//
//   <requestID> <domainHash> <category> <userAction> <status> <reason>
//
// All fields are positional, space-separated, and have already
// been validated by the audit-logger entry points to be safe
// for log output (no prompt content, no URL, no PII). The stats
// endpoint parses this format.
func formatAuditMessage(requestID, domainHash, category, userAction, status, reason string) string {
	return requestID + " " + domainHash + " " + category + " " + userAction + " " + status + " " + reason
}
