// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection HTTP endpoint (TODO-304)
//
// prompt_cache_http.go wires pkg/promptcache into the HTTP
// API as
//   - POST /api/v1/prompt-cache/attest
//   - GET  /api/v1/prompt-cache/verify/:hash
//
// The endpoints use the same auth middleware as the other
// Tier 5 routes (authMiddleware.RequireAuth). The attest
// endpoint uses the IOC's in-process keyring (shared with
// TODO-301/302/303). The verify endpoint does not need a
// keyring (it verifies offline).
//
// The GET /api/v1/prompt-cache/verify/:hash endpoint is
// the "lookup" endpoint: the caller passes a prompt hash
// (URL path parameter) and a URL-encoded JSON
// envelope (passed as ?envelope=...). The response is
// the VerifyResultJSON shape. If the envelope's subject
// hash doesn't match the :hash path parameter, the
// result is marked invalid with a "prompt hash
// mismatch" reason (in addition to the verify-time hash
// check).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/promptcache"
)

// wirePromptCacheHandlers registers the /api/v1/prompt-cache/*
// HTTP routes. The keyring is shared with the other Tier 5
// endpoints (TODO-301/302/303).
func wirePromptCacheHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
	mux.HandleFunc("/api/v1/prompt-cache/attest", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlePromptCacheAttest(w, r, kr)
	}))
	// The verify handler matches both POST (body is the
	// envelope) and GET (envelope is in ?envelope= query
	// parameter, ?expected_key_id= for the key check).
	mux.HandleFunc("/api/v1/prompt-cache/verify", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlePromptCacheVerify(w, r)
	}))
	// The :hash lookup endpoint: GET
	// /api/v1/prompt-cache/verify/:hash?envelope=...
	// This is the "verify this envelope against this hash"
	// endpoint suggested by the resume.
	mux.HandleFunc("/api/v1/prompt-cache/verify/", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlePromptCacheVerifyByHash(w, r)
	}))
}

// handlePromptCacheAttest is the HTTP handler for
// POST /api/v1/prompt-cache/attest. The request body is
// a JSON object with the attestation fields:
//
//	{
//	  "prompt":       "What is the capital of France?",
//	  "source":       "user-supplied",
//	  "model_id":     "claude-3-5-sonnet-20241022",
//	  "attestor_id":  "acme-corp:prod-gateway",
//	  "cache_key":    "anthropic:cache:abc123",
//	  "metadata":     "session=abc",
//	  "ttl_seconds":  3600
//	}
//
// The response is the signed envelope (JSON). The raw
// "prompt" is hashed locally (lowercase + whitespace-
// collapse + SHA-256) and never stored in the signed
// payload.
func handlePromptCacheAttest(w http.ResponseWriter, r *http.Request, kr *ioc.KeyRing) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 64KB max (the request includes the raw prompt,
	// which is small).
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		Prompt     string `json:"prompt"`
		Source     string `json:"source"`
		ModelID    string `json:"model_id"`
		AttestorID string `json:"attestor_id"`
		CacheKey   string `json:"cache_key"`
		Metadata   string `json:"metadata"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
		return
	}
	if req.Prompt == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "prompt is required"})
		return
	}
	if req.Source == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "source is required"})
		return
	}
	if req.ModelID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "model_id is required"})
		return
	}
	if req.AttestorID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "attestor_id is required"})
		return
	}
	// Build the attestation. The raw prompt is hashed
	// locally; only the hash is stored in the signed
	// payload.
	att := &promptcache.PromptAttestation{
		PromptHash: promptcache.HashPrompt(req.Prompt),
		Source:     req.Source,
		ModelID:    req.ModelID,
		AttestorID: req.AttestorID,
		CacheKey:   req.CacheKey,
		Metadata:   req.Metadata,
	}
	// Sign. Use ttl_seconds if provided; otherwise the
	// default (1h).
	var signOpts []promptcache.AttestorOption
	if req.TTLSeconds > 0 {
		signOpts = append(signOpts, promptcache.WithTTL(time.Duration(req.TTLSeconds)*time.Second))
	}
	env, err := promptcache.Attest(att, kr, signOpts...)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "attest: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(env)
}

// handlePromptCacheVerify is the HTTP handler for
// POST /api/v1/prompt-cache/verify. The request body is
// the JSON-encoded envelope. The response is the
// VerifyResultJSON shape.
//
// M3 fix (TODO-303 review), applied to TODO-304: supports
// an optional `expected_key_id` query parameter (consistent
// with the CLI's --key-id flag and with the other Tier 5
// verify handlers). If supplied, the envelope's signature
// key id must match; otherwise the result is marked
// invalid with a "key ID mismatch" reason.
//
// v0.1: POST only. The verify-by-hash endpoint (GET
// /api/v1/prompt-cache/verify/:hash) is the suggested
// lookup path per the TODO-304 spec.
func handlePromptCacheVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 1MB max (envelope is small but allow room for padding).
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	vr, err := promptcache.VerifyJSON(context.Background(), body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	// Optional expected_key_id check (query parameter).
	// Consistent with the CLI's --key-id flag and the
	// other Tier 5 verify handlers (TODO-303 M3).
	if expectedKeyID := r.URL.Query().Get("expected_key_id"); expectedKeyID != "" {
		if vr.Valid && vr.Envelope.Signature.KeyID != expectedKeyID {
			vr.Valid = false
			vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
				vr.Envelope.Signature.KeyID, expectedKeyID)
		}
	}
	if !vr.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(vr.ToJSON())
}

// handlePromptCacheVerifyByHash is the HTTP handler for
// GET /api/v1/prompt-cache/verify/:hash?envelope=...
// The :hash path parameter is the expected prompt hash
// (the envelope's subject hash must match this). The
// ?envelope= query parameter is the URL-encoded JSON
// envelope. The ?expected_key_id= query parameter is
// the optional key id check (TODO-303 M3).
//
// The response is the VerifyResultJSON shape. If the
// envelope's subject hash doesn't match the :hash path
// parameter, the result is marked invalid with a
// "prompt hash mismatch" reason (in addition to the
// verify-time hash check).
func handlePromptCacheVerifyByHash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use GET)"})
		return
	}
	// Extract :hash from the URL path. The mux pattern
	// /api/v1/prompt-cache/verify/ matches anything
	// after /verify/, so we strip the prefix.
	prefix := "/api/v1/prompt-cache/verify/"
	hashParam := strings.TrimPrefix(r.URL.Path, prefix)
	if hashParam == "" || strings.Contains(hashParam, "/") {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing or malformed 'hash' path parameter"})
		return
	}
	// Validate :hash is 64 hex chars.
	if len(hashParam) != 64 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid hash length: %d, want 64", len(hashParam))})
		return
	}
	for _, c := range hashParam {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid hash: must be hex"})
			return
		}
	}
	// Get the envelope. We expect URL-encoded JSON
	// (the caller URL-encodes the envelope and passes
	// it as ?envelope=...). Go's URL.Query().Get
	// already URL-decodes the value, so envBytes is
	// the raw JSON envelope.
	envParam := r.URL.Query().Get("envelope")
	if envParam == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing 'envelope' query parameter"})
		return
	}
	envBytes := []byte(envParam)
	vr, err := promptcache.VerifyJSON(context.Background(), envBytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	// Check the envelope's subject hash matches the :hash
	// path parameter.
	if vr.Valid {
		expectedSubject := "aegisgate://prompt/" + hashParam
		if vr.Envelope.Subject != expectedSubject {
			vr.Valid = false
			vr.Reason = fmt.Sprintf("prompt hash mismatch: envelope subject is %q, want %q",
				vr.Envelope.Subject, expectedSubject)
		}
	}
	// Optional expected_key_id check.
	if expectedKeyID := r.URL.Query().Get("expected_key_id"); expectedKeyID != "" {
		if vr.Valid && vr.Envelope.Signature.KeyID != expectedKeyID {
			vr.Valid = false
			vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
				vr.Envelope.Signature.KeyID, expectedKeyID)
		}
	}
	if !vr.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(vr.ToJSON())
}
