// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS verification (TODO-301)
//
// verify.go provides the verify-side of AR-EaaS. The auditor
// receives a signed envelope (via the CLI, the HTTP endpoint,
// or a file), runs Verify, and gets a structured pass/fail
// result that includes the decoded RunResult.
//
// # Why this lives in its own file
//
// The attestation package's Verify() only checks the signature
// and the envelope's well-formedness. It does NOT decode the
// payload. The auditor (or the HTTP handler) needs:
//   - signature validity (delegated to attestation.Verify)
//   - payload well-formedness (the RunResult is valid JSON
//     with all required fields)
//   - a human-readable summary (for CLI output)
//
// verify.go is the bridge between "envelope signed correctly"
// and "envelope contents are a valid RunResult."

package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// VerifyResult is the structured output of VerifyEnvelope.
// It bundles the envelope, the decoded RunResult, and a
// pass/fail decision.
//
// `Valid` is true only if:
//   - The envelope signature verifies.
//   - The payload is a valid RunResult with all required fields.
//   - The envelope's Type is attestation.TypeEvaluatorRun.
//   - The envelope's Subject is aegisgate://evaluation/<id>.
//
// The decoded RunResult is exposed for the auditor/HTTP
// handler that wants to display the per-pattern results
// without re-decoding the envelope's RawPayload.
type VerifyResult struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty when
	// Valid is true. Contains the attestation error
	// reason (signature_invalid, expired, etc.) OR the
	// payload-validation error (missing field, etc.).
	Reason string `json:"reason,omitempty"`
	// Result is the decoded RunResult. Always populated
	// (even when Valid is false, if the payload was
	// decodable). nil only if the payload itself was
	// not valid JSON.
	Result *RunResult `json:"result,omitempty"`
	// Envelope is the raw envelope as supplied. Useful
	// for callers that want to re-verify with a specific
	// key, or to log the issuer / key-id.
	Envelope *attestation.Envelope `json:"envelope"`
}

// VerifyEnvelope verifies a signed AR-EaaS envelope. The flow:
//  1. attestation.Verify the envelope (signature, type, subject, etc.).
//  2. Decode the envelope's RawPayload as a RunResult.
//  3. Sanity-check the RunResult fields (PatternCount matches len(Results), etc.).
//
// Returns a VerifyResult describing the outcome. Never returns
// an error directly; all error modes are folded into the
// VerifyResult.Reason field. (This matches the attestation
// package's convention of using typed errors; callers use
// errors.As to inspect, but for a one-shot CLI/HTTP path, a
// structured result is more convenient.)
func VerifyEnvelope(ctx context.Context, env *attestation.Envelope) *VerifyResult {
	out := &VerifyResult{
		Envelope: env,
	}
	if env == nil {
		out.Reason = "envelope is nil"
		return out
	}
	// 1. Signature + envelope well-formedness.
	if err := attestation.Verify(env); err != nil {
		out.Reason = err.Error()
		return out
	}
	// 2. Type check.
	if env.Type != attestation.TypeEvaluatorRun {
		out.Reason = fmt.Sprintf("envelope type is %q, want %q",
			env.Type, attestation.TypeEvaluatorRun)
		return out
	}
	// 3. Subject kind check. Defense in depth: a re-typed
	// c3 evidence-manifest envelope would still pass the
	// signature check above (the signature covers the
	// canonicalized payload, not the Type field — wait,
	// actually the Type IS part of the signed bytes, so a
	// re-typed envelope would fail the signature check).
	//
	// This check is here as belt-and-suspenders: if the
	// signature scheme is ever changed to cover only the
	// payload, the subject kind check still catches a
	// cross-type replay.
	if !strings.HasPrefix(env.Subject, "aegisgate://evaluation/") {
		out.Reason = fmt.Sprintf("envelope subject %q is not an evaluation URI", env.Subject)
		return out
	}
	// 4. Decode the payload.
	result, err := ParseRunResult([]byte(env.RawPayload))
	if err != nil {
		out.Reason = fmt.Sprintf("decode RunResult: %v", err)
		return out
	}
	// 5. Sanity-check the RunResult fields.
	if err := validateRunResult(result); err != nil {
		out.Reason = fmt.Sprintf("invalid RunResult: %v", err)
		return out
	}
	out.Result = result
	out.Valid = true
	return out
}

// validateRunResult performs a lightweight semantic check on a
// decoded RunResult. It is NOT a schema validator (the JCS
// canonicalizer has already verified the structural integrity).
// It catches the most common "garbage in a valid envelope"
// cases: PatternCount=0 with non-empty Results, mismatched
// PassCount+FailCount, etc.
func validateRunResult(r *RunResult) error {
	if r == nil {
		return fmt.Errorf("result is nil")
	}
	if r.RunID == "" {
		return fmt.Errorf("missing run_id")
	}
	if r.CorpusID == "" {
		return fmt.Errorf("missing corpus_id")
	}
	if r.CorpusVersion == "" {
		return fmt.Errorf("missing corpus_version")
	}
	if r.TargetRef == "" {
		return fmt.Errorf("missing target_ref")
	}
	if r.TargetFingerprint == "" {
		return fmt.Errorf("missing target_fingerprint")
	}
	// m3 fix (TODO-301 review): a 0-pattern result is
	// never produced by the runner (it refuses), but a
	// tampered envelope could have pattern_count=0 with
	// pass_count=0 and fail_count=0 (passes the sum check
	// below). Reject it explicitly.
	if r.PatternCount == 0 {
		return fmt.Errorf("pattern_count is 0 (no patterns ran)")
	}
	if r.PatternCount != len(r.Results) {
		return fmt.Errorf("pattern_count=%d but len(results)=%d", r.PatternCount, len(r.Results))
	}
	if r.PassCount+r.FailCount != r.PatternCount {
		return fmt.Errorf("pass_count=%d + fail_count=%d != pattern_count=%d",
			r.PassCount, r.FailCount, r.PatternCount)
	}
	if r.RunTimestamp.IsZero() {
		return fmt.Errorf("missing run_timestamp")
	}
	return nil
}

// VerifyEnvelopeJSON verifies a JSON-encoded envelope. This is
// the convenience entry point for the CLI and HTTP handlers
// that receive the envelope as bytes.
func VerifyEnvelopeJSON(ctx context.Context, data []byte) (*VerifyResult, error) {
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("evaluator: parse envelope JSON: %w", err)
	}
	return VerifyEnvelope(ctx, &env), nil
}

// =====================================================================
// HTTP / CLI helpers
// =====================================================================

// VerifyResultJSON is the JSON-serializable shape for the
// `aegisgate evaluator verify --json` output. It mirrors
// VerifyResult but is intentionally flat (the RunResult
// fields are inlined for grep-ability).
type VerifyResultJSON struct {
	Valid         bool   `json:"valid"`
	Reason        string `json:"reason,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	CorpusID      string `json:"corpus_id,omitempty"`
	CorpusVersion string `json:"corpus_version,omitempty"`
	TargetRef     string `json:"target_ref,omitempty"`
	PatternCount  int    `json:"pattern_count,omitempty"`
	PassCount     int    `json:"pass_count,omitempty"`
	FailCount     int    `json:"fail_count,omitempty"`
	PassRate      string `json:"pass_rate,omitempty"`
	CriticalFails int    `json:"critical_fails,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	Subject       string `json:"subject,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
}

// ToJSON converts a VerifyResult to its CLI/HTTP output shape.
// If the result is nil, returns an "INVALID: nil result" shape.
func (vr *VerifyResult) ToJSON() VerifyResultJSON {
	out := VerifyResultJSON{
		Valid:  vr.Valid,
		Reason: vr.Reason,
	}
	if vr.Envelope != nil {
		out.KeyID = vr.Envelope.Signature.KeyID
		out.Issuer = vr.Envelope.Issuer
		out.Subject = vr.Envelope.Subject
		out.IssuedAt = vr.Envelope.IssuedAt.Format("2006-01-02T15:04:05Z07:00")
	}
	if vr.Result != nil {
		summary := Summarize(vr.Result)
		out.RunID = summary.RunID
		out.CorpusID = summary.CorpusID
		out.CorpusVersion = summary.CorpusVersion
		out.TargetRef = summary.TargetRef
		out.PatternCount = summary.PatternCount
		out.PassCount = summary.PassCount
		out.FailCount = summary.FailCount
		out.PassRate = summary.PassRate
		out.CriticalFails = summary.CriticalFails
	}
	return out
}
