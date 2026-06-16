// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS HTTP endpoint (TODO-301)
//
// evaluator_http.go wires pkg/evaluator into the HTTP API as
//   - POST /api/v1/evaluator/run
//   - GET  /api/v1/evaluator/verify (verifies an envelope from the request body)
//
// The endpoints use the same auth middleware as /api/v1/audit
// and /api/v1/compliance (authMiddleware.RequireAuth).
//
// # v0.1 scope
//
//   - The HTTP endpoint uses an in-process stub target (always
//     refuses) for the run path. A v0.2 will add a Go-plugin
//     loader for caller-supplied targets (same as the CLI verb).
//   - The verify path uses the same VerifyEnvelope helper as
//     the CLI verb; the auditor passes the envelope JSON in
//     the request body.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evaluator"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// evaluatorKeyRing is the in-process keyring used by the HTTP
// handler. Set by wireEvaluatorHandlers (called from main).
// The HTTP handler is not safe to invoke before this is set.
var evaluatorKeyRing *ioc.KeyRing

// wireEvaluatorHandlers registers the /api/v1/evaluator/* HTTP
// routes. Call this from main after the keyring is initialized.
// The keyring is the IOC's in-process ring (the same one that
// the CLI verb's ephemeral keyring uses). Sharing the keyring
// across CLI and HTTP paths means envelopes produced by either
// path can be verified by the other.
func wireEvaluatorHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
	evaluatorKeyRing = kr
	mux.HandleFunc("/api/v1/evaluator/run", authMW.RequireAuth(handleEvaluatorRun))
	mux.HandleFunc("/api/v1/evaluator/verify", authMW.RequireAuth(handleEvaluatorVerify))
}

// handleEvaluatorRun is the HTTP handler for POST /api/v1/evaluator/run.
// The request body is a JSON object with:
//
//	{
//	  "target_ref":  "model:openai/gpt-4-turbo",
//	  "pattern_ids": ["atlas-t0018-001-direct-override"],   // optional
//	  "notes":       "weekly prod check"                    // optional
//	}
//
// The response is a JSON object with the RunResult summary and
// the signed envelope. Critical failures (severity_breakdown.critical > 0)
// produce a 422 status code; other failures produce 200.
func handleEvaluatorRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// Parse the request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req evaluator.RunRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
			return
		}
	}
	if req.TargetRef == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "target_ref is required"})
		return
	}
	// Build the runner. Use the default corpus.
	corpus := evaluator.DefaultCorpus()
	runner, err := evaluator.NewRunner(corpus, evaluatorKeyRing)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "build runner: " + err.Error()})
		return
	}
	// Build the in-process stub target. v0.1; v0.2 will add a
	// Go-plugin loader for caller-supplied targets.
	target := &evaluator.FuncTarget{
		AnswerFn:         httpStubAnswer,
		RefValue:         req.TargetRef,
		FingerprintValue: httpFingerprintFromString(req.TargetRef),
	}
	// Run.
	out, err := runner.Run(context.Background(), target, req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "run: " + err.Error()})
		return
	}
	// Build the response. The envelope is the canonical artifact;
	// the result is included for convenience.
	summary := evaluator.Summarize(out.Result)
	resp := struct {
		Summary  evaluator.ResultSummary `json:"summary"`
		Result   *evaluator.RunResult    `json:"result"`
		Envelope *attestation.Envelope   `json:"envelope"`
	}{
		Summary:  summary,
		Result:   out.Result,
		Envelope: out.Envelope,
	}
	w.Header().Set("Content-Type", "application/json")
	if summary.CriticalFails > 0 {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleEvaluatorVerify is the HTTP handler for POST /api/v1/evaluator/verify.
// The request body is the JSON-encoded envelope. The response is the
// VerifyResultJSON shape. Critical failures (verification failure or
// critical-severity runs) produce 422; valid envelopes produce 200.
func handleEvaluatorVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB max
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	vr, err := evaluator.VerifyEnvelopeJSON(context.Background(), body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	out := vr.ToJSON()
	if !vr.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else if vr.Result != nil && evaluator.Summarize(vr.Result).CriticalFails > 0 {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// httpStubAnswer is the v0.1 in-process stub target. Always
// refuses. The v0.2 HTTP path will add a Go-plugin loader for
// caller-supplied targets.
func httpStubAnswer(ctx context.Context, prompt string) (string, error) {
	return "I'm sorry, but I cannot help with that.", nil
}

// httpFingerprintFromString returns a stable hex fingerprint of s.
// Used to derive a deterministic TargetFingerprint from the
// target-ref so the signed result is reproducible. The CLI verb
// has an identical helper (fingerprintFromString); duplicated
// here to keep the HTTP file self-contained.
func httpFingerprintFromString(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}
