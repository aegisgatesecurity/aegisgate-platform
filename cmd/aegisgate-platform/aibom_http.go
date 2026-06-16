// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM HTTP endpoint (TODO-302)
//
// aibom_http.go wires pkg/aibom into the HTTP API as
//   - POST /api/v1/aibom/generate
//   - POST /api/v1/aibom/verify
//
// The endpoints use the same auth middleware as the
// other v3.5.0+ API routes (authMiddleware.RequireAuth).
// The verify endpoint does NOT use the same KeyRing as
// the generate endpoint (it verifies offline), so the
// caller is responsible for supplying a valid envelope.
//
// # v0.1 scope
//
//   - The generate endpoint uses placeholder data for the
//     5 protocol pillars (per the v0.1 AIBOM spec). v0.2
//     will wire the pillars to the live platform config.
//   - The verify endpoint accepts the envelope JSON in
//     the request body and returns the VerifyResultJSON.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// aibomKeyRing is the in-process keyring used by the
// generate HTTP handler. Set by wireAIBOMHandlers.
var aibomKeyRing *ioc.KeyRing

// wireAIBOMHandlers registers the /api/v1/aibom/* HTTP
// routes. Call this from main after the keyring is
// initialized. The keyring is shared with the AR-EaaS
// HTTP endpoint (both use the IOC's in-process ring).
func wireAIBOMHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
	aibomKeyRing = kr
	mux.HandleFunc("/api/v1/aibom/generate", authMW.RequireAuth(handleAIBOMGenerate))
	mux.HandleFunc("/api/v1/aibom/verify", authMW.RequireAuth(handleAIBOMVerify))
}

// handleAIBOMGenerate is the HTTP handler for
// POST /api/v1/aibom/generate. The request body is a
// JSON object with the AIBOM options:
//
//	{
//	  "tier":             "professional",
//	  "platform_version": "3.4.0-beta.1",
//	  "instance_id":      "inst-123",
//	  "notes":            "weekly prod snapshot"
//	}
//
// The response is the signed envelope (JSON).
func handleAIBOMGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// Parse the request body. The request is small
	// (a few hundred bytes of JSON), so 64KB is more
	// than enough.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		Tier            string `json:"tier"`
		PlatformVersion string `json:"platform_version"`
		InstanceID      string `json:"instance_id"`
		Notes           string `json:"notes"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
			return
		}
	}
	// Defaults for missing fields.
	if req.Tier == "" {
		req.Tier = "unknown"
	}
	if req.PlatformVersion == "" {
		req.PlatformVersion = "unknown"
	}
	// Build the AIBOM and BOM. v0.1: the per-pillar data
	// is left as zero values (the BOM still emits the 5
	// pillars, but with Enabled=false). v0.2 will read
	// the live platform config and populate them.
	aibomOpts := aibom.AIBOMOptions{
		Tier:            req.Tier,
		PlatformVersion: req.PlatformVersion,
		InstanceID:      req.InstanceID,
		GeneratorNotes:  req.Notes,
	}
	a := aibom.BuildAIBOMFromOptions(aibomOpts)
	bom, err := aibom.GenerateFromAIBOM(a)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "generate: " + err.Error()})
		return
	}
	// Sign.
	env, err := aibom.Sign(bom, aibomKeyRing)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "sign: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(env)
}

// handleAIBOMVerify is the HTTP handler for
// POST /api/v1/aibom/verify. The request body is the
// JSON-encoded envelope. The response is the
// VerifyResultJSON shape.
func handleAIBOMVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 1MB max — same as the AR-EaaS verify path.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	vr, err := aibom.VerifyEnvelopeJSON(context.Background(), body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	if !vr.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(vr.ToJSON())
}
