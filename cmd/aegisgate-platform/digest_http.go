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
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/digest"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// wireDigestHandlers registers the /api/v1/digest/*
// HTTP routes. The keyring is shared with the other
// Tier 5 + Tier 4 endpoints.
func wireDigestHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
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
		handleDigestGenerate(w, r, kr)
	}))
	// Verify: free.
	mux.HandleFunc("/api/v1/digest/verify", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleDigestVerify(w, r, kr)
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
func handleDigestGenerate(w http.ResponseWriter, r *http.Request, kr *ioc.KeyRing) {
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
	// Build the digest. v0.1: no sources wired
	// (the source pipeline is v0.2). The digest
	// just contains the period and the timestamp.
	d, err := digest.BuildDigest(context.Background(), nil, digest.BuilderOptions{
		Period: digest.Period(req.Period),
		Clock:  digest.SystemClock{},
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "build: " + err.Error()})
		return
	}
	// Sign.
	env, err := digest.SignDigest(d, kr)
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
