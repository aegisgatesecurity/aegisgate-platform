// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - FP-Report Bridge Handler
// =========================================================================
//
// fp_report.go implements the POST /api/v1/lens/fp-report endpoint that
// accepts the Lens extension's simplified 4-field FP report format and
// converts it to a full Event before passing it through the existing
// telemetry pipeline (validation, domain hash verification, rate
// limiting, IOC aggregation).
//
// The Lens extension v0.2.x sends FP reports as individual POST requests
// with this JSON body:
//
//	{
//	  "hashed_domain": "a1b2c3d4e5f6a7b8",
//	  "category":      "pii_email",
//	  "severity":      "high",
//	  "action":        "send"
//	}
//
// This endpoint bridges the 4-field format to the full v0.2 Event
// schema by filling in defaults:
//
//   - lens_event_version: 1
//   - domain_hash: from hashed_domain
//   - facet: derived from category prefix (e.g. "pii_email" → "pii")
//   - category: as-is
//   - severity: as-is (low, medium, high)
//   - user_action: from action field
//   - timestamp: current server time
//   - model_version: "0.2.0-bridge"
//   - lens_version: "0.2.0-bridge"
//   - confidence: 0.8 (default for FP reports)
//
// v3.5.0+ Phase 3.
// =========================================================================

package lensbackend

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// FPReport is the simplified 4-field format the Lens extension sends
// for false-positive reports. This is the v0.2.x Cloudflare Worker
// contract.
type FPReport struct {
	HashedDomain string `json:"hashed_domain"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Action       string `json:"action"`
	// client_id is used for dedup but not validated server-side.
	ClientID string `json:"client_id,omitempty"`
}

// ValidFPReportActions are the 4 actions the Lens extension sends.
var validFPReportActions = map[string]string{
	"cancel":         "cancel",
	"redact":         "redact",
	"send":           "send",
	"false_positive": "false_positive",
}

// fpReportSeverityMap maps the FP report's 3 severity levels to the
// Event schema's severity levels. The FP report uses a subset
// (low, medium, high — no "critical" or "info").
var fpReportSeverityMap = map[string]string{
	"low":    "low",
	"medium": "medium",
	"high":   "high",
}

// HandleFPReport handles POST /api/v1/lens/fp-report.
// It accepts the Lens extension's simplified 4-field FP report,
// converts it to a full Event, and processes it through the
// existing telemetry pipeline.
func (h *Handlers) HandleFPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	requestID := newRequestID()

	// Read the body (4-field FP report is small).
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, "", "", "fp_report_body_read_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "body_read_failed", err.Error())
		return
	}

	// Decode the 4-field FP report.
	var report FPReport
	if err := json.Unmarshal(body, &report); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, "", "", "fp_report_decode_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "decode_failed", err.Error())
		return
	}

	// Validate hashed_domain (16 hex chars).
	if len(report.HashedDomain) != 16 {
		h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_invalid_hash", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "invalid_hash", "hashed_domain must be 16 hex chars")
		return
	}
	for _, c := range report.HashedDomain {
		if !isLowerHex(c) {
			h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_invalid_hash", time.Since(start).Milliseconds())
			writeError(w, http.StatusBadRequest, "invalid_hash", "hashed_domain must be lowercase hex")
			return
		}
	}

	// Validate category (must be a known Lens category).
	if !isValidFPReportCategory(report.Category) {
		h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_invalid_category", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "invalid_category", fmt.Sprintf("unknown category: %q", report.Category))
		return
	}

	// Validate severity (low, medium, high only).
	mappedSeverity, ok := fpReportSeverityMap[report.Severity]
	if !ok {
		h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_invalid_severity", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "invalid_severity", fmt.Sprintf("severity must be low, medium, or high, got %q", report.Severity))
		return
	}

	// Validate action (cancel, redact, send, false_positive).
	mappedAction, ok := validFPReportActions[report.Action]
	if !ok {
		h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_invalid_action", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "invalid_action", fmt.Sprintf("action must be cancel, redact, send, or false_positive, got %q", report.Action))
		return
	}

	// Derive facet from category prefix.
	facet := facetFromCategoryPrefix(report.Category)
	if facet == "" {
		h.server.audit.RecordRejected(r.Context(), requestID, report.HashedDomain, report.Category, "fp_report_unknown_facet", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "unknown_facet", fmt.Sprintf("cannot derive facet from category %q", report.Category))
		return
	}

	// Bridge to a full Event.
	event := Event{
		LensEventVersion: 1,
		DomainHash:       report.HashedDomain,
		Facet:            string(facet),
		Category:         report.Category,
		Severity:         mappedSeverity,
		UserAction:       mappedAction,
		Timestamp:        time.Now().Unix(),
		ModelVersion:     "0.2.0-bridge",
		LensVersion:      "0.2.0-bridge",
		Confidence:       0.8,
	}

	// Server-side domain_hash recomputation (same as HandleTelemetry).
	if err := VerifyDomainHash(r, event.DomainHash); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "fp_report_domain_hash_"+err.Error(), time.Since(start).Milliseconds())
		writeError(w, http.StatusBadRequest, "domain_hash_mismatch", err.Error())
		return
	}

	// Per-installation rate limit check.
	if !h.server.rate.CheckInstallation(event.DomainHash) {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "fp_report_per_install_rate_limit", time.Since(start).Milliseconds())
		writeTooManyRequests(w, "per-installation rate limit exceeded")
		return
	}

	// Forward to the IOC writer.
	if err := h.server.ioc.add(r.Context(), event); err != nil {
		h.server.audit.RecordRejected(r.Context(), requestID, event.DomainHash, event.Category, "fp_report_ioc_write_failed", time.Since(start).Milliseconds())
		writeError(w, http.StatusInternalServerError, "ioc_write_failed", err.Error())
		return
	}

	// Persist the raw event.
	if err := h.server.appendRawEvent(r.Context(), event); err != nil {
		h.server.logger.Warn("fp_report_raw_event_persist_failed",
			slog.String("err", err.Error()),
			slog.String("request_id", requestID),
		)
	}

	// Success.
	h.server.audit.RecordAccepted(r.Context(), requestID, event.DomainHash, event.Category, event.UserAction, time.Since(start).Milliseconds())
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "received"})
}

// isValidFPReportCategory checks whether a category string is a known
// Lens category. This is a fast path that avoids creating a full Event
// just to validate the category.
func isValidFPReportCategory(cat string) bool {
	_, ok := categoryFacetIndex[cat]
	return ok
}

// facetFromCategoryPrefix derives the facet from a category prefix.
// Uses the same prefix-based logic as categoryToIOCType.
func facetFromCategoryPrefix(category string) string {
	switch {
	case strings.HasPrefix(category, "pii_"):
		return string(FacetPII)
	case strings.HasPrefix(category, "secret_"), category == "source_code":
		return string(FacetSecrets)
	case strings.HasPrefix(category, "xss_"):
		return string(FacetXSS)
	case strings.HasPrefix(category, "owasp_"), strings.HasPrefix(category, "atlas_"),
		strings.HasPrefix(category, "eu_ai_act_"), strings.HasPrefix(category, "anp_"),
		strings.HasPrefix(category, "cu_"), strings.HasPrefix(category, "ccpa_"),
		strings.HasPrefix(category, "iso_"), strings.HasPrefix(category, "lgpd_"),
		strings.HasPrefix(category, "nist_"), strings.HasPrefix(category, "pipeda_"),
		strings.HasPrefix(category, "popia_"), strings.HasPrefix(category, "mitre_atlas_"):
		return string(FacetCompliance)
	case strings.HasPrefix(category, "toxicity_"):
		return string(FacetToxicity)
	case strings.HasPrefix(category, "pi_"):
		return string(FacetPromptInjection)
	default:
		return ""
	}
}
