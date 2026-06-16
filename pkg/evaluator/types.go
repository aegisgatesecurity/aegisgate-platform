// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS types (TODO-301)
//
// types.go defines the data structures for the evaluator package.
// The shapes here are the contract between the runner, the corpus,
// the target, and the signed envelope payload.
//
// Design rule: the RunResult struct is what gets wrapped by the
// attestation envelope. Its fields are stable, sorted at the top
// level, and serializable to JSON deterministically. The MITRE
// ATLAS references are preserved (uppercase, as the framework
// emits them) so a downstream auditor can correlate the patterns
// with the public MITRE ATLAS catalog.

package evaluator

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// Severity is the per-pattern severity. The AegisGate convention
// matches pkg/logging.Severity (low/medium/high) plus a "critical"
// tier for patterns that demonstrate a system-level compromise.
//
// The numeric values are stable (do not renumber; this is wire-
// compatible with downstream tooling). The mapping:
//
//	0 = low       (informational; pattern did not bypass target)
//	1 = medium    (pattern exposed minor information disclosure)
//	2 = high      (pattern bypassed guardrail or extracted data)
//	3 = critical  (pattern achieved full system compromise)
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the canonical name. Used in JSON.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// AttackPattern is one corpus entry. It pairs a single MITRE ATLAS
// tactic/technique with:
//   - The prompt sent to the target.
//   - The severity if the pattern bypasses the target's guardrails.
//   - The EvalFunc that scores pass/fail (pure function, no I/O).
//
// EvalFunc is a function value, not an interface, so the corpus
// can be a static value (no init-time side effects). It receives
// the target's response and returns (pass, reason):
//
//	pass=true  -> the target handled the pattern correctly.
//	pass=false -> the target was bypassed; the reason describes how.
//
// The EvalFunc MUST be a pure function. The runner is free to call
// it multiple times for debugging. It MUST NOT mutate the response
// string (we hash the response for the audit trail).
type AttackPattern struct {
	// ID is the AegisGate-internal ID (e.g., "atlas-t0018-001").
	// Stable across corpus versions.
	ID string `json:"id"`
	// ATLASTactic is the MITRE ATLAS tactic ID (e.g., "AML.T0018").
	// May be empty for non-ATLAS patterns (e.g., generic prompts).
	ATLASTactic string `json:"atlas_tactic,omitempty"`
	// TechniqueName is the human-readable name of the technique
	// (e.g., "LLM Prompt Injection: Direct").
	TechniqueName string `json:"technique_name"`
	// Category groups patterns for reporting (e.g., "prompt_injection",
	// "jailbreak", "data_extraction", "model_dos").
	Category string `json:"category"`
	// Prompt is the input sent to the target. Stored verbatim.
	Prompt string `json:"prompt"`
	// Severity is the severity if the pattern bypasses the target.
	Severity Severity `json:"severity"`
	// EvalFunc scores pass/fail. Not serialized.
	EvalFunc func(response string) (pass bool, reason string) `json:"-"`
}

// PatternResult is the per-pattern outcome. The Pass field is the
// truth: true = target handled correctly, false = target was bypassed.
//
// The Response field is the target's actual response. It is captured
// for audit purposes (the auditor can read what the target said) and
// for re-running the EvalFunc deterministically.
//
// The Reason field is the EvalFunc's explanation; for pass=true, it
// may be empty.
type PatternResult struct {
	// PatternID references the AttackPattern.ID.
	PatternID string `json:"pattern_id"`
	// ATLASTactic is copied from the pattern for convenience.
	ATLASTactic string `json:"atlas_tactic,omitempty"`
	// TechniqueName is copied from the pattern.
	TechniqueName string `json:"technique_name"`
	// Category is copied from the pattern.
	Category string `json:"category"`
	// Severity is copied from the pattern.
	Severity Severity `json:"severity"`
	// Pass is true if the target handled the pattern correctly.
	Pass bool `json:"pass"`
	// Reason is the EvalFunc's explanation. For pass=true, may be
	// empty; for pass=false, explains how the target was bypassed.
	Reason string `json:"reason,omitempty"`
	// Response is the target's response (truncated to 4KB).
	Response string `json:"response"`
	// ResponseLen is the full response length before truncation.
	ResponseLen int `json:"response_len"`
	// ResponseHash is the SHA-256 hex hash of the full response.
	// Lets the auditor verify the truncated response matches.
	ResponseHash string `json:"response_hash"`
	// DurationMillis is the wall-clock time for the target call.
	DurationMillis int64 `json:"duration_millis"`
}

// RunRequest is the caller-supplied input. The TargetRef is an
// opaque string that identifies the target (e.g., "agent:customer-x
// /v1.2.0" or "model:gpt-4-turbo"); the runner does not interpret it.
//
// Optional: PatternIDs restricts the run to a subset of corpus
// patterns. If nil/empty, all patterns in the corpus are used.
type RunRequest struct {
	// TargetRef is an opaque identifier for the target under test.
	// Examples: "agent:acme-corp/customer-support@v1.2.0",
	// "model:openai/gpt-4-turbo", "tool:mcp/filesystem@v2.0".
	// The runner does not interpret this; it is stored verbatim
	// in the signed result so the auditor knows what was tested.
	TargetRef string `json:"target_ref"`
	// TargetFingerprint is an optional hash of the target's binary
	// or config. The Target interface provides a Fingerprint() method
	// to compute it deterministically. If empty, the runner computes
	// it from the Target itself.
	TargetFingerprint string `json:"target_fingerprint,omitempty"`
	// PatternIDs is the optional subset of patterns to run. Empty
	// means "run the whole corpus."
	PatternIDs []string `json:"pattern_ids,omitempty"`
	// Notes is an optional free-form note from the caller. Stored
	// verbatim in the signed result.
	Notes string `json:"notes,omitempty"`
}

// RunResult is the aggregate outcome. It is the payload of the
// signed envelope (after canonicalization). The struct is sorted
// alphabetically at the top level by JSON tag for deterministic
// serialization.
//
// Field order in the Go struct is not significant (Go's encoding/json
// uses the struct tag order, but for top-level determinism the
// JCS canonicalizer sorts the keys at every level).
type RunResult struct {
	// RunID is the unique run identifier (UUIDv4).
	RunID string `json:"run_id"`
	// RunTimestamp is when the run started (UTC, RFC 3339).
	RunTimestamp time.Time `json:"run_timestamp"`
	// CorpusID is the corpus identifier (e.g., "atlas-v0.1").
	CorpusID string `json:"corpus_id"`
	// CorpusVersion is the corpus version (semver).
	CorpusVersion string `json:"corpus_version"`
	// TargetRef is copied from the request.
	TargetRef string `json:"target_ref"`
	// TargetFingerprint is the target's identity hash.
	TargetFingerprint string `json:"target_fingerprint"`
	// PatternCount is the number of patterns in this run.
	PatternCount int `json:"pattern_count"`
	// PassCount is the number of patterns the target handled correctly.
	PassCount int `json:"pass_count"`
	// FailCount is PatternCount - PassCount. Included for convenience.
	FailCount int `json:"fail_count"`
	// PassRate is PassCount / PatternCount * 100, with 4-decimal
	// precision. 0 if PatternCount is 0.
	PassRate float64 `json:"pass_rate"`
	// SeverityBreakdown counts the number of failures by severity.
	// A target that fails 0 critical patterns and 1 low-severity
	// pattern is in much better shape than one that fails 1 critical
	// pattern, even though both have FailCount=1.
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	// CategoryBreakdown counts the number of failures by category.
	// Useful for "you failed 3/5 prompt-injection patterns but
	// 0/3 data-extraction patterns" reporting.
	CategoryBreakdown map[string]int `json:"category_breakdown"`
	// Results is the per-pattern outcome, sorted by PatternID for
	// determinism. The runner sorts before serializing.
	Results []PatternResult `json:"results"`
	// Notes is copied from the request.
	Notes string `json:"notes,omitempty"`
	// RunnerVersion is the AegisGate version that ran this eval.
	RunnerVersion string `json:"runner_version"`
	// DurationMillis is the total wall-clock time for the run.
	DurationMillis int64 `json:"duration_millis"`
}

// RunOutput is what the runner returns. It is a thin wrapper around
// the signed envelope, exposing the inner RunResult for in-process
// callers (HTTP handlers, CLI, etc.) that want to read the result
// without re-decoding the envelope's payload.
type RunOutput struct {
	// Result is the RunResult (also serialized inside the envelope).
	Result *RunResult
	// Envelope is the signed attestation envelope. Verifiers use
	// attestation.Verify to confirm tamper-evidence.
	Envelope *attestation.Envelope
}

// Target is the interface a caller implements to define the AI
// system under test. The runner calls Answer() for each pattern's
// prompt; the implementation calls the agent/model/tool and
// returns the response.
//
// Answer() MUST be safe for concurrent use (the runner may fan
// out across goroutines for performance). The context is used
// for cancellation and per-pattern timeouts.
//
// Fingerprint() returns a stable identifier for the target.
// Examples: a hash of the agent's binary, a config fingerprint,
// a model+version string. The runner stores this in the signed
// result so the auditor can correlate "this exact target was
// tested."
type Target interface {
	// Answer is the entry point for each AttackPattern's Prompt.
	// Returns the response string (any size) and an error if
	// the target could not be reached. Errors are treated as
	// a fail (the target was unreachable).
	Answer(ctx context.Context, prompt string) (response string, err error)
	// Fingerprint returns a stable identifier for the target.
	// Must be deterministic across calls (same target = same
	// fingerprint) and unique across distinct targets.
	Fingerprint() string
	// Ref is a human-readable identifier (e.g.,
	// "model:openai/gpt-4-turbo"). Stored verbatim in the
	// signed result for the auditor.
	Ref() string
}

// FuncTarget is a convenience adapter that wraps a plain function
// as a Target. The Fingerprint is computed once at construction
// time from the function's source location. The Ref is supplied
// by the caller.
//
// Use FuncTarget for tests and for in-process evaluations where
// the target is a Go function (e.g., a stub that always refuses
// a prompt, or a wrapper around an LLM SDK call).
type FuncTarget struct {
	// AnswerFn is the function that produces responses.
	AnswerFn func(ctx context.Context, prompt string) (string, error)
	// RefValue is the human-readable target identifier.
	RefValue string
	// FingerprintValue is the stable target identifier.
	FingerprintValue string
}

// Answer calls AnswerFn.
func (f *FuncTarget) Answer(ctx context.Context, prompt string) (string, error) {
	return f.AnswerFn(ctx, prompt)
}

// Fingerprint returns the pre-computed fingerprint.
func (f *FuncTarget) Fingerprint() string { return f.FingerprintValue }

// Ref returns the pre-computed ref.
func (f *FuncTarget) Ref() string { return f.RefValue }
