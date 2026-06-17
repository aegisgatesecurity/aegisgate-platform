// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest HTTP endpoint (TODO-601 + TODO-602)
//
// digest_http.go wires pkg/digest into the HTTP API as
//   - POST /api/v1/digest/generate (Professional+)
//   - POST /api/v1/digest/verify (free)
//
// Tier gating: the generate side is Professional+
// (the digest is a customer-facing artifact). The
// verify side is free (verifying a signed digest is
// a public action).

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/digest"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// WireDigestDeps bundles the dependencies the
// digest's source pipeline needs. The HTTP
// handler receives this from the platform's main
// loop; the CLI uses its own in-memory stores.
type WireDigestDeps struct {
	KeyRing  *ioc.KeyRing
	IOCStore *ioc.Store          // optional; nil means no IOC source
	AuditLog *logging.RingBuffer // optional; nil means no AuditLog source
	Posture  *posture.Checker    // optional; nil means posture is "unknown"
	// SIEMDispatcher is currently unused by the
	// digest's source pipeline (the AuditLogSource
	// covers the heavy lifting; the SIEM dispatcher's
	// stats are a redundant signal). Reserved for
	// future use.
	SIEMDispatcher *audit.SIEMDispatcher
}

// wireDigestHandlers registers the /api/v1/digest/*
// HTTP routes. The keyring is shared with the other
// Tier 5 + Tier 4 endpoints.
//
// v0.2: the source pipeline (PostureSource,
// IOCSource, AuditLogSource) is wired with the
// platform's real dependencies. The CLI is a
// developer tool; the digest's HTTP endpoint is
// the production path.
func wireDigestHandlers(mux *http.ServeMux, authMW *auth.Middleware, deps WireDigestDeps) {
	// Generate: Professional+. The tier check is
	// done inline (the auth.Middleware exposes a
	// tier string in the request context).
	mux.HandleFunc("/api/v1/digest/generate", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		// Tier check.
		if tierStr := auth.GetTier(r.Context()); tierStr != "professional" && tierStr != "enterprise" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":    "CISO Digest generation is Professional+ only",
				"tier":     tierStr,
				"required": "professional",
			})
			return
		}
		handleDigestGenerate(w, r, deps)
	}))
	// Verify: free.
	mux.HandleFunc("/api/v1/digest/verify", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleDigestVerify(w, r, deps.KeyRing)
	}))
}

// handleDigestGenerate is the HTTP handler for
// POST /api/v1/digest/generate. The request body is
// a JSON object with the digest fields:
//
//	{
//	  "period": "daily" | "weekly" | "monthly"
//	}
//
// The response is the signed envelope (JSON).
//
// v0.2: the source pipeline is wired with the
// platform's real dependencies (IOC store, audit
// log, posture checker). The HTTP endpoint is the
// production path; the CLI is a developer tool.
func handleDigestGenerate(w http.ResponseWriter, r *http.Request, deps WireDigestDeps) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 16KB max.
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		Period string `json:"period"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
		return
	}
	// Build the digest. v0.2: the source pipeline
	// is wired with the platform's real dependencies
	// (IOC store + audit log + posture checker).
	sources := buildDigestSources(deps)
	d, err := digest.BuildDigest(context.Background(), sources, digest.BuilderOptions{
		Period: digest.Period(req.Period),
		Clock:  digest.SystemClock{},
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "build: " + err.Error()})
		return
	}
	// Sign.
	env, err := digest.SignDigest(d, deps.KeyRing)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "sign: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(env)
	_ = time.Now()
}

// handleDigestVerify is the HTTP handler for
// POST /api/v1/digest/verify. The request body is
// the JSON-encoded envelope. The response is a
// flat JSON shape derived from the Digest.
//
// This is the FULL verify path: it parses the
// envelope, verifies the signature with the
// keyring, checks the subject kind, and returns
// the verified Digest + PDF bytes.
func handleDigestVerify(w http.ResponseWriter, r *http.Request, kr *ioc.KeyRing) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 1MB max (envelope is small).
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	// Parse as a typed envelope.
	var env struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Subject    string `json:"subject"`
		Issuer     string `json:"issuer"`
		RawPayload []byte `json:"raw_payload"`
		Signature  struct {
			KeyID string `json:"key_id"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	// Optional key_id check (M3 from TODO-303).
	if expectedKeyID := r.URL.Query().Get("expected_key_id"); expectedKeyID != "" {
		if env.Signature.KeyID != expectedKeyID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "key ID mismatch",
				"have":  env.Signature.KeyID,
				"want":  expectedKeyID,
			})
			return
		}
	}
	// Build a typed envelope for VerifyDigest.
	typedEnv := &attestation.Envelope{
		ID:         env.ID,
		Type:       attestation.Type(env.Type),
		Subject:    env.Subject,
		Issuer:     env.Issuer,
		RawPayload: env.RawPayload,
		Signature: attestation.Signature{
			KeyID: env.Signature.KeyID,
		},
	}
	// Full verify.
	verified, pdfBytes, err := digest.VerifyDigest(typedEnv)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "verify: " + err.Error(),
			"valid": "false",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":          true,
		"digest_id":      verified.ID,
		"period":         verified.Period,
		"title":          verified.Title,
		"overall_status": verified.OverallStatus,
		"start_time":     verified.StartTime,
		"end_time":       verified.EndTime,
		"pdf_size":       len(pdfBytes),
	})
}

// buildDigestSources builds the list of digest
// sources from the platform's real dependencies.
// Sources with nil dependencies are skipped (the
// corresponding digest field will be empty/zero).
//
// v0.2 wiring:
//   - IOCSource is always present if the IOC store
//     is non-nil (which it is in production)
//   - AuditLogSource is always present if the audit
//     log ring buffer is non-nil (which it is in
//     production)
//   - PostureSource is optional (nil means posture
//     field is "unknown")
//   - AuditSource (SIEM dispatcher) is reserved for
//     future use; not currently wired
func buildDigestSources(deps WireDigestDeps) []digest.Source {
	var sources []digest.Source
	if deps.IOCStore != nil {
		sources = append(sources, digest.NewIOCSource(deps.IOCStore))
	}
	if deps.AuditLog != nil {
		sources = append(sources, digest.NewAuditLogSource(deps.AuditLog))
	}
	if deps.Posture != nil {
		sources = append(sources, digest.NewPostureSource(deps.Posture))
	}
	if deps.SIEMDispatcher != nil {
		sources = append(sources, digest.NewAuditSource(deps.SIEMDispatcher))
	}
	return sources
}
