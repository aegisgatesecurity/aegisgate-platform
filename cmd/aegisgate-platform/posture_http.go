// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Posture Check HTTP endpoints (D19, P1 #8)
// =========================================================================
//
// posture_http.go wires the posture check (pkg/posture) into the HTTP
// API as
//   - GET  /api/v1/posture          → JSON report (compact)
//   - GET  /api/v1/posture/verbose  → JSON report (with per-subsystem detail)
//   - GET  /api/v1/posture/text     → plain-text report (matches `aegisgate status` output)
//
// The posture check is READ-ONLY: it never mutates state. It is the
// founder-facing install story and the operator-level signal that
// closes the gap between the Trust Framework (developer-level signal),
// the public trust page (marketing-level signal), and the on-call
// runbook (operator-level signal).
//
// This file supersedes the un-wired `handlePostureAPI` in
// posture_subcommand.go (which was marked `//nolint:unused // reserved
// for v0.2`). The HTTP handler logic is the same; this file provides
// the proper wire*Handlers entry point and the full set of routes
// (verbose + text).
//
// Auth: all 3 endpoints require auth (license key) — same pattern as
// the other v3.4.0+ feature HTTP handlers. The posture report is
// per-instance, not per-user, so the auth requirement is operational
// rather than user-scoped.
// =========================================================================

package main

import (
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// postureLicenseMgr is the in-process license manager used by the
// posture HTTP handlers. Set by wirePostureHandlers.
//
//nolint:unused // assigned at wire time
var postureLicenseMgr *license.Manager

// postureMode is the operational mode used by the posture HTTP
// handlers ("production", "demo", or "staging"). Set by wirePostureHandlers.
//
//nolint:unused // assigned at wire time
var postureMode string

// wirePostureHandlers registers the /api/v1/posture/* HTTP routes.
// Call this from main() after the license manager is initialized.
//
// D19 (audit P1 #8): supersedes the un-wired `handlePostureAPI`
// in posture_subcommand.go. The function name follows the
// wire*Handlers convention used by the other v3.4.0+ feature
// endpoints (wireAIBOMHandlers, wireCVEHandlers, etc.).
func wirePostureHandlers(mux *http.ServeMux, authMW *auth.Middleware, licenseMgr *license.Manager, mode string) {
	postureLicenseMgr = licenseMgr
	postureMode = mode

	mux.HandleFunc("/api/v1/posture", authMW.RequireAuth(handlePostureJSON))
	mux.HandleFunc("/api/v1/posture/verbose", authMW.RequireAuth(handlePostureVerbose))
	mux.HandleFunc("/api/v1/posture/text", authMW.RequireAuth(handlePostureText))
}

// handlePostureJSON is the HTTP handler for GET /api/v1/posture.
// Returns the posture report as compact JSON (the same shape as
// `aegisgate status --json`).
func handlePostureJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed (use GET)")
		return
	}
	report, err := runPostureCheck(postureLicenseMgr, postureMode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "posture check failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data, err := posture.FormatJSON(report)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "json encoding failed: "+err.Error())
		return
	}
	writeBytes(w, data)
}

// handlePostureVerbose is the HTTP handler for
// GET /api/v1/posture/verbose. Returns the posture report with
// per-subsystem detail (the same shape as `aegisgate status --verbose`).
//
// The verbose shape is the same as the compact JSON — the
// distinction in the CLI is text-vs-verbose-text. For the HTTP
// API, the report struct already contains all per-subsystem
// fields; the difference is in how the CLI formats them.
// Therefore `/api/v1/posture/verbose` returns the same JSON
// shape as `/api/v1/posture` (the entire report). The distinction
// is the text endpoint below.
func handlePostureVerbose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed (use GET)")
		return
	}
	report, err := runPostureCheck(postureLicenseMgr, postureMode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "posture check failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data, err := posture.FormatJSON(report)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "json encoding failed: "+err.Error())
		return
	}
	writeBytes(w, data)
}

// handlePostureText is the HTTP handler for GET /api/v1/posture/text.
// Returns the posture report as plain text (the same format as
// `aegisgate status`). This is the endpoint to use in shell scripts
// and CI gates.
func handlePostureText(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed (use GET)")
		return
	}
	report, err := runPostureCheck(postureLicenseMgr, postureMode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "posture check failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writeBytes(w, []byte(posture.FormatText(report)))
}

// writeJSONError writes a JSON error response with the given HTTP
// status code and message. Local helper to avoid repeating the
// Content-Type + writeJSON pattern in every handler.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": msg})
}
