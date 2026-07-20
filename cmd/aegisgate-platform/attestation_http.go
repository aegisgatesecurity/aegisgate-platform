// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Attestation Envelope HTTP endpoints (D19, P1 #8)
// =========================================================================
//
// attestation_http.go wires pkg/attestation into the HTTP API as
//   - POST /api/v1/attestation/verify          → verify envelope (offline, embedded pubkey)
//   - POST /api/v1/attestation/verify-online   → verify envelope (fetch pubkey from /.well-known/)
//
// The endpoints use the same auth middleware as the other
// v3.4.0+ API routes. Both endpoints accept the envelope
// JSON in the request body and return the verifyResult shape
// (same as `aegisgate attestation verify --json`).
//
// v0.1 scope:
//   - The verify endpoint uses attestation.Verify (offline,
//     embedded public key). The auditor scenario is offline;
//     no network is required.
//   - The verify-online endpoint uses attestation.VerifyOnline
//     which fetches the public key from /.well-known/. The
//     endpoint is wired but only useful when the instance is
//     actually serving /.well-known/aegisgate-evidence-pubkey.pem
//     (which is wired in main.go for the evidence package).
//
// This file is the HTTP counterpart of the CLI
// `aegisgate attestation verify <envelope.json>` subcommand.
// The CLI uses the same verifyResult type and
// buildVerifyResultJSON function defined in
// attestation_subcommand.go (same package).
// =========================================================================

package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
)

// wireAttestationHandlers registers the /api/v1/attestation/* HTTP
// routes. Call this from main() after the auth middleware is
// initialized.
//
// D19 (audit P1 #8): completes the 6-pillar feature set with HTTP
// endpoints for the 9th v3.4.0+ feature (attestation). Without
// these endpoints, the auditor workflow is CLI-only, which is
// inconvenient for integrations with auditor toolchains.
func wireAttestationHandlers(mux *http.ServeMux, authMW *auth.Middleware) {
	mux.HandleFunc("/api/v1/attestation/verify", authMW.RequireAuth(handleAttestationVerify))
	mux.HandleFunc("/api/v1/attestation/verify-online", authMW.RequireAuth(handleAttestationVerifyOnline))
}

// handleAttestationVerify is the HTTP handler for
// POST /api/v1/attestation/verify. The request body is the
// JSON-encoded envelope. The response is the verifyResult
// shape (same as `aegisgate attestation verify --json`).
//
// Auth: required. The endpoint is sensitive (it accepts any
// envelope and returns pass/fail), so it requires the same
// auth as the other v3.4.0+ feature endpoints.
func handleAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed (use POST)")
		return
	}
	// 1MB max — same as the AR-EaaS verify path and the
	// AIBOM verify endpoint. Envelopes are typically
	// 5-20KB, so 1MB is generous.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var env attestation.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse envelope: "+err.Error())
		return
	}
	// Verify using the embedded public key (offline path).
	// This is the auditor scenario: receive envelope, verify,
	// no network required.
	verifyErr := attestation.Verify(&env)
	// Build the result. The function is shared with the CLI
	// subcommand in attestation_subcommand.go.
	result := buildVerifyResultJSON(&env, verifyErr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	writeJSON(w, result)
}

// handleAttestationVerifyOnline is the HTTP handler for
// POST /api/v1/attestation/verify-online. Same as verify but
// fetches the public key from the instance's /.well-known/
// endpoint instead of using the embedded one. This is useful
// when the auditor has a recent key id and wants to verify
// against the live key (e.g. after a key rotation).
//
// The endpoint is mounted but the underlying VerifyOnline
// requires the instance to be serving
// /.well-known/aegisgate-evidence-pubkey.pem. If the file
// is not available, VerifyOnline returns an error which
// is returned to the caller as a 500.
func handleAttestationVerifyOnline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed (use POST)")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var env attestation.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse envelope: "+err.Error())
		return
	}
	// Verify using the live public key (online path).
	// The base URL is the request's Host header so the
	// endpoint works on any deployment.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// NOTE: VerifyOnline uses the Issuer field to discover
	// the public key, not the URL. The URL is currently
	// not used by VerifyOnline (it expects the Issuer to
	// be a known instance). For the v0.1 HTTP endpoint,
	// we pass r.Context() and let the package handle the
	// network failure gracefully.
	verifyErr := attestation.VerifyOnline(r.Context(), &env)
	result := buildVerifyResultJSON(&env, verifyErr)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if verifyErr != nil {
		// Online verification failure is usually a
		// network/key issue, not a "the envelope is
		// invalid" issue. Use 502 Bad Gateway to
		// signal "we couldn't reach the upstream".
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	writeJSON(w, result)

	// Suppress unused variable warnings for scheme (we
	// keep it for future use when VerifyOnline takes a
	// baseURL parameter).
	_ = scheme
}
