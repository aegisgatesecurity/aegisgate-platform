// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS runner (TODO-301)
//
// runner.go is the heart of the AR-EaaS primitive. It orchestrates
// the eval: load the corpus, call the target, score pass/fail, and
// sign the result with the attestation envelope.
//
// The runner is the ONLY place where Target.Answer is called. All
// other code (HTTP handler, CLI, tests) goes through the runner.
//
// # Concurrency
//
// The runner is safe for concurrent use. It holds no mutable
// state of its own (the corpus, keyring, and target are
// supplied at construction time and treated as immutable).
//
// # Determinism
//
// The runner is deterministic in the sense that:
//   - same corpus + same target + same request = same RunResult
//     (modulo RunTimestamp, RunID, DurationMillis).
//   - The RunID and RunTimestamp are the only non-deterministic
//     fields; everything else is reproducible.
//
// PatternResults are sorted by PatternID before serialization,
// so the signed envelope's payload is byte-stable across runs.

package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// RunnerVersion is the AegisGate version that this runner
// represents. Bump when the runner's behavior changes in a
// way that affects pass/fail (e.g., new severity logic).
const RunnerVersion = "0.1.0"

// DefaultPatternTimeout is the per-pattern timeout for
// Target.Answer. 30s is generous; the target is expected to
// return within seconds.
const DefaultPatternTimeout = 30 * time.Second

// MaxPatternTimeout is the maximum per-pattern timeout the
// runner will accept via WithPatternTimeout. Values above
// this are clamped down. 5 minutes is a sane upper bound
// for any LLM/agent call; anything longer is almost certainly
// a misconfiguration or a hung target.
const MaxPatternTimeout = 5 * time.Minute

// MaxResponseBytes is the maximum number of bytes of the
// target's response stored in the PatternResult. Responses
// longer than this are truncated; the full response is
// available via ResponseHash + ResponseLen.
const MaxResponseBytes = 4 * 1024

// Runner is the AR-EaaS orchestrator. Construct one with
// NewRunner and call Run to execute an evaluation.
//
// The runner holds:
//   - corpus: the attack-pattern library (immutable).
//   - keyRing: the signing keyring (must have a current key).
//   - runnerVersion: copied into the signed result.
//
// The runner holds NO mutable per-run state (timeouts, etc.).
// Per-run configuration is supplied as RunOption values
// passed to Run(); see the RunOption type. This makes the
// runner safe for concurrent use without synchronization
// (see gotcha "C1: concurrent use" in TODO-301 review).
type Runner struct {
	corpus        *Corpus
	keyRing       *ioc.KeyRing
	runnerVersion string
}

// NewRunner constructs a Runner. Returns an error if any
// required dep is nil. The runner is safe for concurrent use.
func NewRunner(corpus *Corpus, keyRing *ioc.KeyRing) (*Runner, error) {
	if corpus == nil {
		return nil, fmt.Errorf("evaluator: corpus is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("evaluator: keyRing is required")
	}
	return &Runner{
		corpus:        corpus,
		keyRing:       keyRing,
		runnerVersion: RunnerVersion,
	}, nil
}

// RunOption configures a single Run() invocation. Options
// are the ONLY way to override defaults like the per-pattern
// timeout; the runner holds no mutable per-run state. This
// makes the runner safe for concurrent use without locks.
//
// The functional-options pattern is preferred over setter
// methods because:
//   - Setter methods on a shared Runner create data races
//     (one goroutine writes, another reads).
//   - Per-call options are explicit in the call site
//     (no "did the caller set this earlier?" surprises).
//   - Adding new options is a non-breaking change.
type RunOption func(*runOptions)

// runOptions holds the per-run configuration. The zero value
// is the default for every field.
type runOptions struct {
	// patternTimeout is the per-pattern timeout for
	// Target.Answer. 0 means use DefaultPatternTimeout.
	patternTimeout time.Duration
}

// WithPatternTimeout overrides the per-pattern timeout. A
// non-positive value restores the default. Values greater
// than MaxPatternTimeout are clamped down.
func WithPatternTimeout(d time.Duration) RunOption {
	return func(o *runOptions) {
		if d <= 0 {
			o.patternTimeout = DefaultPatternTimeout
			return
		}
		if d > MaxPatternTimeout {
			d = MaxPatternTimeout
		}
		o.patternTimeout = d
	}
}

// applyRunOptions returns the effective runOptions after
// applying the supplied options in order. Options later
// in the list override earlier ones (same as the stdlib
// http.Server pattern).
func applyRunOptions(opts []RunOption) runOptions {
	o := runOptions{patternTimeout: DefaultPatternTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Run executes the evaluation. The flow:
//  1. Validate inputs.
//  2. Apply run options (timeouts, etc.).
//  3. Filter the corpus to the requested pattern subset.
//  4. For each pattern, call target.Answer(pattern.Prompt).
//  5. Score with pattern.EvalFunc.
//  6. Aggregate into a RunResult.
//  7. Sign the result with attestation.Sign.
//
// Returns the RunOutput (result + signed envelope), or an
// error if the input is invalid or signing fails.
//
// If the target returns an error for a pattern, that pattern
// is treated as a fail with reason "target unreachable: <err>".
// The runner does NOT abort on per-pattern errors; it logs
// and continues with the next pattern.
//
// The opts slice configures per-run settings (see RunOption).
// Pass nil to accept all defaults. The runner does NOT hold
// any per-run state between calls; this method is safe for
// concurrent use on the same Runner instance.
func (r *Runner) Run(ctx context.Context, target Target, req RunRequest, opts ...RunOption) (*RunOutput, error) {
	o := applyRunOptions(opts)

	// 1. Validate inputs.
	if target == nil {
		return nil, fmt.Errorf("evaluator: target is required")
	}
	// C3 fix: do not mutate the caller's RunRequest. Make a
	// shallow copy and apply defaults there.
	req2 := req
	if req2.TargetRef == "" {
		// Default to the target's own Ref() if caller did not supply one.
		req2.TargetRef = target.Ref()
	}
	if req2.TargetFingerprint == "" {
		req2.TargetFingerprint = target.Fingerprint()
	}

	// 2. Filter corpus.
	corpus := r.corpus.Filter(req2.PatternIDs)
	if len(corpus.Patterns) == 0 {
		return nil, fmt.Errorf("evaluator: filtered corpus is empty (corpus_id=%s, requested_ids=%v)",
			corpus.ID, req2.PatternIDs)
	}

	// 3. Run each pattern.
	startedAt := time.Now().UTC()
	results := make([]PatternResult, 0, len(corpus.Patterns))
	for i := range corpus.Patterns {
		pattern := &corpus.Patterns[i]
		result := r.runOnePattern(ctx, target, pattern, o.patternTimeout)
		results = append(results, result)
	}
	totalDuration := time.Since(startedAt)

	// 4. Aggregate.
	result := r.aggregate(req2, corpus, results, startedAt, totalDuration)

	// 5. Sign the result.
	envelope, err := r.signResult(result)
	if err != nil {
		return nil, fmt.Errorf("evaluator: sign result: %w", err)
	}
	return &RunOutput{
		Result:   result,
		Envelope: envelope,
	}, nil
}

// runOnePattern executes a single pattern and returns its
// PatternResult. The function is the unit of per-pattern
// work; it never aborts the run on error.
//
// The timeout parameter is the per-pattern timeout for the
// target's Answer call. It is supplied by Run() (via the
// runOptions), not read from r, so the runner holds no
// mutable per-run state (see C1 fix in the TODO-301 review).
func (r *Runner) runOnePattern(ctx context.Context, target Target, pattern *AttackPattern, timeout time.Duration) PatternResult {
	result := PatternResult{
		PatternID:     pattern.ID,
		ATLASTactic:   pattern.ATLASTactic,
		TechniqueName: pattern.TechniqueName,
		Category:      pattern.Category,
		Severity:      pattern.Severity,
	}

	// Per-pattern timeout.
	patCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startedAt := time.Now()
	response, err := target.Answer(patCtx, pattern.Prompt)
	elapsed := time.Since(startedAt)
	result.DurationMillis = elapsed.Milliseconds()

	// Truncate + hash the response.
	if len(response) > MaxResponseBytes {
		result.Response = response[:MaxResponseBytes] + "...[truncated]"
	} else {
		result.Response = response
	}
	result.ResponseLen = len(response)
	hash := sha256.Sum256([]byte(response))
	result.ResponseHash = hex.EncodeToString(hash[:])

	if err != nil {
		result.Pass = false
		result.Reason = fmt.Sprintf("target unreachable: %v", err)
		return result
	}
	if pattern.EvalFunc == nil {
		// Defensive: a pattern without an EvalFunc is a fail
		// (we cannot prove the target handled it correctly).
		result.Pass = false
		result.Reason = "pattern has no EvalFunc (corpus is malformed)"
		return result
	}
	pass, reason := pattern.EvalFunc(response)
	result.Pass = pass
	result.Reason = reason
	return result
}

// aggregate builds the RunResult from the per-pattern outcomes.
// It sorts the results by PatternID for determinism and
// computes the severity/category breakdowns.
func (r *Runner) aggregate(req RunRequest, corpus *Corpus, results []PatternResult, startedAt time.Time, totalDuration time.Duration) *RunResult {
	// Sort by PatternID for determinism.
	sort.Slice(results, func(i, j int) bool {
		return results[i].PatternID < results[j].PatternID
	})

	passCount := 0
	severityBreakdown := map[string]int{
		SeverityLow.String():      0,
		SeverityMedium.String():   0,
		SeverityHigh.String():     0,
		SeverityCritical.String(): 0,
	}
	categoryBreakdown := map[string]int{}
	for _, r := range results {
		if r.Pass {
			passCount++
			continue
		}
		// Failure: increment the severity and category counters.
		severityBreakdown[r.Severity.String()]++
		categoryBreakdown[r.Category]++
	}

	patternCount := len(results)
	failCount := patternCount - passCount
	var passRate float64
	if patternCount > 0 {
		passRate = float64(passCount) / float64(patternCount) * 100.0
	}

	return &RunResult{
		RunID:             uuid.NewString(),
		RunTimestamp:      startedAt,
		CorpusID:          corpus.ID,
		CorpusVersion:     corpus.Version,
		TargetRef:         req.TargetRef,
		TargetFingerprint: req.TargetFingerprint,
		PatternCount:      patternCount,
		PassCount:         passCount,
		FailCount:         failCount,
		PassRate:          passRate,
		SeverityBreakdown: severityBreakdown,
		CategoryBreakdown: categoryBreakdown,
		Results:           results,
		Notes:             req.Notes,
		RunnerVersion:     r.runnerVersion,
		DurationMillis:    totalDuration.Milliseconds(),
	}
}

// signResult serializes the RunResult to canonical JSON and
// signs it with the attestation envelope primitive.
//
// The subject is "aegisgate://evaluation/<run-id>" per the
// Tier 5 URI-style grammar. The type is attestation.TypeEvaluatorRun.
// The issuer is "<target-fingerprint-prefix>:<key-id>".
func (r *Runner) signResult(result *RunResult) (*attestation.Envelope, error) {
	// Serialize to JSON (encoding/json produces sorted keys at
	// the map level, but the envelope's JCS canonicalizer sorts
	// keys at every level for true RFC 8785 compliance).
	payloadBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("evaluator: marshal result: %w", err)
	}
	// Build the subject.
	subject := "aegisgate://evaluation/" + result.RunID
	// Build the issuer. Format: "<instance>:<key>" per the
	// attestation convention.
	//
	// C2 fix (TODO-301 review): the previous implementation
	// truncated the full SHA-256 fingerprint to 64 chars
	// (the "ar-eaas:" prefix + the full "sha256:<64-hex>"
	// fingerprint is 79 chars; the 64-char cap truncated the
	// hex digest, producing non-unique issuers for distinct
	// targets that share the first ~54 hex chars).
	//
	// The new format uses a short fingerprint:
	//     ar-eaas:shortfp:<16-hex>:<key-id>
	// 16 hex chars = 64 bits of entropy, more than enough
	// for the issuer field (it's a correlation identifier,
	// not a security token). Total length: 6+9+16+1+6 = 38
	// chars, well under the 64-char human-readable cap.
	instanceID := "ar-eaas:shortfp:" + shortFingerprint(result.TargetFingerprint)
	// Get the current key id from the keyring via the
	// public CurrentKeyID() method (added in v3.5.0+
	// Track 6 Task 5).
	keyID := r.currentKeyID()
	issuer := instanceID + ":" + keyID

	// Sign. No expiration (TTL=0); the signed result is
	// long-lived (the audit trail's permanence is the point).
	env, err := attestation.Sign(
		payloadBytes,
		subject,
		attestation.TypeEvaluatorRun,
		issuer,
		r.keyRing,
		0, // no expiration
	)
	if err != nil {
		return nil, fmt.Errorf("evaluator: attestation.Sign: %w", err)
	}
	return env, nil
}

// currentKeyID returns the keyring's current signing key ID.
// The keyring stores the current key separately from retired
// keys; we look it up via the public CurrentKeyID() method.
func (r *Runner) currentKeyID() string {
	return r.keyRing.CurrentKeyID()
}

// shortFingerprint extracts the first 16 hex characters of a
// "sha256:<64-hex>" fingerprint. The input is expected to be
// in the "sha256:" format produced by fingerprintFromString
// and the ioc.KeyRing. For non-conforming input (no "sha256:"
// prefix, or fingerprint shorter than 16 hex chars), the
// function returns the input verbatim up to 16 chars. This
// keeps the issuer stable even if a caller passes an unusual
// fingerprint format.
func shortFingerprint(fp string) string {
	const prefix = "sha256:"
	const shortLen = 16
	if !strings.HasPrefix(fp, prefix) {
		// Defensive: return up to 16 chars of the input.
		if len(fp) > shortLen {
			return fp[:shortLen]
		}
		return fp
	}
	hex := strings.TrimPrefix(fp, prefix)
	if len(hex) > shortLen {
		hex = hex[:shortLen]
	}
	return hex
}

// =====================================================================
// Helper: ParseRunResult
// =====================================================================

// ParseRunResult decodes a RunResult from the RawPayload of a
// verified envelope. Used by verification helpers and tests.
func ParseRunResult(payload []byte) (*RunResult, error) {
	var result RunResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil, fmt.Errorf("evaluator: parse RunResult: %w", err)
	}
	return &result, nil
}

// =====================================================================
// Helper: ResultSummary
// =====================================================================

// ResultSummary is a one-line summary of a RunResult. Used in
// CLI output and HTTP responses where the full result would
// be too verbose.
type ResultSummary struct {
	RunID         string `json:"run_id"`
	CorpusID      string `json:"corpus_id"`
	CorpusVersion string `json:"corpus_version"`
	TargetRef     string `json:"target_ref"`
	PatternCount  int    `json:"pattern_count"`
	PassCount     int    `json:"pass_count"`
	FailCount     int    `json:"fail_count"`
	PassRate      string `json:"pass_rate"`
	CriticalFails int    `json:"critical_fails"`
}

// Summarize produces a ResultSummary from a RunResult. The
// PassRate is formatted to 2 decimal places (e.g., "90.00%").
func Summarize(result *RunResult) ResultSummary {
	return ResultSummary{
		RunID:         result.RunID,
		CorpusID:      result.CorpusID,
		CorpusVersion: result.CorpusVersion,
		TargetRef:     result.TargetRef,
		PatternCount:  result.PatternCount,
		PassCount:     result.PassCount,
		FailCount:     result.FailCount,
		PassRate:      fmt.Sprintf("%.2f%%", result.PassRate),
		CriticalFails: result.SeverityBreakdown[SeverityCritical.String()],
	}
}

// humanReport returns a multi-line human-readable report of
// a RunResult. Used by the CLI verb for pretty output.
func humanReport(result *RunResult) string {
	var b strings.Builder
	summary := Summarize(result)
	fmt.Fprintf(&b, "AR-EaaS Run: %s\n", summary.RunID)
	fmt.Fprintf(&b, "  Corpus:        %s @ %s\n", summary.CorpusID, summary.CorpusVersion)
	fmt.Fprintf(&b, "  Target:        %s\n", summary.TargetRef)
	fmt.Fprintf(&b, "  Patterns:      %d (pass=%d, fail=%d, pass_rate=%s)\n",
		summary.PatternCount, summary.PassCount, summary.FailCount, summary.PassRate)
	if summary.CriticalFails > 0 {
		fmt.Fprintf(&b, "  WARNING:       %d critical-severity failures\n", summary.CriticalFails)
	}
	if len(result.SeverityBreakdown) > 0 {
		fmt.Fprintf(&b, "  Severity:\n")
		for _, sev := range []string{"low", "medium", "high", "critical"} {
			if c, ok := result.SeverityBreakdown[sev]; ok && c > 0 {
				fmt.Fprintf(&b, "    %s: %d\n", sev, c)
			}
		}
	}
	if len(result.CategoryBreakdown) > 0 {
		fmt.Fprintf(&b, "  Category:\n")
		// Sort categories for deterministic output.
		cats := make([]string, 0, len(result.CategoryBreakdown))
		for c := range result.CategoryBreakdown {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			fmt.Fprintf(&b, "    %s: %d\n", c, result.CategoryBreakdown[c])
		}
	}
	return b.String()
}
