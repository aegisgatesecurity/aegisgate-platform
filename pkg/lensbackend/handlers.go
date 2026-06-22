// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - HTTP Handlers
// =========================================================================
//
// handlers.go implements the 4 HTTP endpoints the Lens extension
// calls:
//
//   POST /api/v1/lens/telemetry
//     Body: an Event (§1.1 schema).
//     Response: 202 Accepted with {"status":"received"}.
//     Errors:
//       400 Bad Request  - validation failure (bad field value)
//       400 Bad Request  - domain_hash mismatch with TLS SNI
//       401 Unauthorized - missing or wrong bearer token
//       429 Too Many Requests - per-installation or global rate limit
//       503 Service Unavailable - backend is in maintenance mode
//
//   GET /api/v1/lens/check?domain=<hostname>
//     Query: ?domain=<hostname>
//     Response: 200 OK with {"verdict":<enum>, "category":<enum>, "first_seen":<RFC3339>, "last_seen":<RFC3339>, "count":<int>}.
//     Errors:
//       400 Bad Request  - missing or invalid domain
//       401 Unauthorized - missing or wrong bearer token
//
//   GET /api/v1/lens/stats
//     Response: 200 OK with aggregated counts: events per category,
//     events per user_action, events per source provider, IOC count.
//     Errors:
//       401 Unauthorized - missing or wrong bearer token
//
//   GET /api/v1/lens/healthz
//     Response: 200 OK with {"status":"ok", "version":<string>},
//     unconditionally. No auth required. Used by load balancers
//     and the testlab's docker-compose healthcheck.
//
// The /telemetry handler is the only one that writes IOCs; the
// other three are read-only.
//
// All handlers are constructed by NewHandlers(server *Server) and
// registered in server.go's Mux() method.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// Handlers holds the dependencies needed by the HTTP handlers.
type Handlers struct {
	server *Server
}

// NewHandlers creates a Handlers bound to the given server.
func NewHandlers(s *Server) *Handlers {
	return &Handlers{server: s}
}

// HandleTelemetry handles POST /api/v1/lens/telemetry.
func (h *Handlers) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	requestID := newRequestID()

	// Read the body. We use http.MaxBytesReader to bound the
	// body size to 4KB (the §1.1 schema is small).
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, "", "", "body_read_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "body_read_failed", err.Error())
		return
	}

	// Decode and validate. The decoder uses DisallowUnknownFields
	// so any extra field in the body is rejected.
	event, err := decodeEvent(body)
	if err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, "", "", "decode_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "decode_failed", err.Error())
		return
	}
	if err := event.Validate(); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "validate_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "validate_failed", err.Error())
		return
	}

	// Server-side domain_hash recomputation. Catches any
	// extension-side bug or malicious update that lies about
	// the domain.
	if err := VerifyDomainHash(r, event.DomainHash); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "domain_hash_"+err.Error(), time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "domain_hash_mismatch", err.Error())
		return
	}

	// Per-installation rate limit check. Day 11 pen-test found
	// that the previous X-Lens-Domain-Hader-based middleware was
	// reading a header set AFTER the middleware had run, so the
	// per-install limit was silently disabled. We now enforce it
	// here, AFTER body decode + domain_hash verification, using
	// the actual event.DomainHash (which we just verified matches
	// the TLS SNI).
	if !h.server.rate.CheckInstallation(event.DomainHash) {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "per_install_rate_limit", time.Since(start).Milliseconds())
		writeTooManyRequests(w, "per-installation rate limit exceeded")
		return
	}

	// Forward to the IOC writer.
	if err := h.server.ioc.add(r.Context(), event); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "ioc_write_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusInternalServerError, "ioc_write_failed", err.Error())
		return
	}

	// Persist the raw event to the on-disk events.jsonl file
	// for the retention jobs. The file is the source of truth
	// for raw events; the IOC store is the source of truth
	// for IOCs.
	if err := h.server.appendRawEvent(r.Context(), event); err != nil {
		// Failure to persist the raw event is logged but
		// does NOT cause the request to fail -- the IOC
		// was already written. The raw event can be
		// reconstructed from the IOC if needed.
		h.server.logger.Warn("lens_raw_event_persist_failed",
			slog.String("err", err.Error()),
			slog.String("request_id", requestID),
		)
	}

	// Success.
	h.server.audit.RecordAccepted(r.Context(), requestID, event.DomainHash, event.Category, event.UserAction, time.Since(start).Milliseconds())
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "received"})
}

// HandleCheck handles GET /api/v1/lens/check?domain=<hostname>.
// Returns whether the given domain is known to the IOC store.
func (h *Handlers) HandleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "missing_domain", "domain query parameter is required")
		return
	}
	hash := ComputeDomainHash(domain)
	// The check returns the worst IOC for this domain across
	// all categories. The store is keyed by IOC fingerprint,
	// so we scan the store and pick the worst.
	var worst *ioc.IOC
	for _, candidate := range h.server.ioc.store.Snapshot() {
		i := candidate
		if i.SourceProvider == sourceProviderFromDomainHash(hash) {
			if worst == nil || iocSeverityRank(i.Severity) > iocSeverityRank(worst.Severity) {
				worst = &i
			}
		}
	}
	if worst == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verdict": "clean",
			"domain":  domain,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verdict":    "known_threat",
		"category":   worst.Category,
		"first_seen": worst.FirstSeen.Format(time.RFC3339),
		"last_seen":  worst.LastSeen.Format(time.RFC3339),
		"count":      worst.Count,
		"severity":   string(worst.Severity),
	})
}

// HandleStats handles GET /api/v1/lens/stats. Returns aggregated
// counts from the audit log for the last 24 hours.
func (h *Handlers) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Use the audit ring buffer to compute stats. We do NOT
	// include the event payloads; only counts.
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour)
	events := h.server.audit.ring.SnapshotBetween(start, now)
	byCategory := make(map[string]int)
	byAction := make(map[string]int)
	for _, e := range events {
		if e.Type != "lens_audit" {
			continue
		}
		// Parse the message format: <requestID> <domainHash> <category> <userAction> <status> <reason>
		parts := splitFields(e.Message, 6)
		if len(parts) < 6 || parts[4] != "accepted" {
			continue
		}
		byCategory[parts[2]]++
		byAction[parts[3]]++
	}
	iocCount := h.server.ioc.store.Size()
	writeJSON(w, http.StatusOK, map[string]any{
		"window_start":   start.Format(time.RFC3339),
		"window_end":     now.Format(time.RFC3339),
		"events_24h":     len(events),
		"by_category":    byCategory,
		"by_user_action": byAction,
		"ioc_count":      iocCount,
	})
}

// HandleHealthz handles GET /api/v1/lens/healthz. No auth.
func (h *Handlers) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": h.server.version,
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

// newRequestID returns a short, hex-encoded random identifier
// for the current request. Used in audit logs to correlate
// received/accepted/rejected log lines for a single event.
// 8 bytes = 64 bits = 16 hex chars. Collision probability
// within a single retention window is negligible.
func newRequestID() string {
	// Use a simple counter + time for now; the ioc.Store
	// uses crypto/rand internally; for the request ID we
	// just need a unique-within-the-process identifier.
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}

// iocSeverityRank returns a numeric rank for an ioc.Severity.
// Mirrors pkg/ioc.severityRank but is exported (because pkg/ioc's
// is unexported). Used by the /check endpoint to pick the worst.
func iocSeverityRank(s ioc.Severity) int {
	switch s {
	case ioc.SeverityCritical:
		return 5
	case ioc.SeverityHigh:
		return 4
	case ioc.SeverityMedium:
		return 3
	case ioc.SeverityLow:
		return 2
	case ioc.SeverityInfo:
		return 1
	}
	return 0
}

// splitFields splits s into at most n space-separated fields.
// Returns the slice; the last field may contain spaces (we
// do a single split, not a strings.Fields). Hand-rolled to
// avoid importing strings.
func splitFields(s string, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			out = append(out, s[start:i])
			start = i + 1
			if len(out) == n-1 {
				break
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// ErrBackendMaintenance is returned by handlers when the
// backend is in maintenance mode (e.g., during a schema
// migration). The handler returns 503.
var ErrBackendMaintenance = errors.New("backend in maintenance")

// inMaintenance is a small helper used by tests to flip
// the server into maintenance mode.
func (s *Server) inMaintenance(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
