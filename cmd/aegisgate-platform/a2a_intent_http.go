// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - A2A Intent HTTP endpoint (TODO-303)
//
// a2a_intent_http.go wires pkg/agentintentsign into the
// HTTP API as
//   - POST /api/v1/a2a/intent/sign
//   - POST /api/v1/a2a/intent/verify
//
// The endpoints use the same auth middleware as the
// other Tier 5 routes (authMiddleware.RequireAuth).
// The sign endpoint uses the IOC's in-process keyring
// (shared with TODO-301/302). The verify endpoint does
// not need a keyring (it verifies offline).

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/agentintentsign"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// wireA2AIntentHandlers registers the /api/v1/a2a/intent/*
// HTTP routes. The keyring is shared with the other
// Tier 5 endpoints (TODO-301/302).
func wireA2AIntentHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
	mux.HandleFunc("/api/v1/a2a/intent/sign", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleA2AIntentSign(w, r, kr)
	}))
	mux.HandleFunc("/api/v1/a2a/intent/verify", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleA2AIntentVerify(w, r, kr)
	}))
}

// handleA2AIntentSign is the HTTP handler for
// POST /api/v1/a2a/intent/sign. The request body is a
// JSON object with the intent fields:
//
//	{
//	  "agent_id":      "agent:acme-corp/customer-support@v1",
//	  "intent":        "Read the user's calendar for tomorrow",
//	  "justification": "User asked me to summarize their meetings",
//	  "context":       "session-abc",
//	  "ttl_seconds":   3600
//	}
//
// The response is the signed envelope (JSON).
func handleA2AIntentSign(w http.ResponseWriter, r *http.Request, kr *ioc.KeyRing) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 64KB max (small request, like the other sign endpoints).
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		AgentID       string `json:"agent_id"`
		Intent        string `json:"intent"`
		Justification string `json:"justification"`
		Context       string `json:"context"`
		TTLSeconds    int64  `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
		return
	}
	if req.AgentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "agent_id is required"})
		return
	}
	if req.Intent == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "intent is required"})
		return
	}
	if req.Justification == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "justification is required"})
		return
	}
	// Build the tuple.
	tuple := &agentintentsign.IntentTuple{
		AgentID:       req.AgentID,
		Intent:        req.Intent,
		Justification: req.Justification,
		Context:       req.Context,
	}
	// Sign. Use ttl_seconds if provided; otherwise the
	// default (1h).
	var signOpts []agentintentsign.SignerOption
	if req.TTLSeconds > 0 {
		signOpts = append(signOpts, agentintentsign.WithTTL(time.Duration(req.TTLSeconds)*time.Second))
	}
	env, err := agentintentsign.Sign(tuple, kr, signOpts...)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "sign: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(env)
}

// handleA2AIntentVerify is the HTTP handler for
// POST /api/v1/a2a/intent/verify. The request body is the
// JSON-encoded envelope. The response is the
// VerifyResultJSON shape.
func handleA2AIntentVerify(w http.ResponseWriter, r *http.Request, _ *ioc.KeyRing) {
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
	vr, err := agentintentsign.VerifyJSON(context.Background(), body)
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
