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
//   - patternTimeout: per-pattern timeout for Target.Answer.
type Runner struct {
	corpus         *Corpus
	keyRing        *ioc.KeyRing
	runnerVersion  string
	patternTimeout time.Duration
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
		corpus:         corpus,
		keyRing:        keyRing,
		runnerVersion:  RunnerVersion,
		patternTimeout: DefaultPatternTimeout,
	}, nil
}

// SetPatternTimeout overrides the per-pattern timeout. A
// non-positive value restores the default.
func (r *Runner) SetPatternTimeout(d time.Duration) {
	if d <= 0 {
		r.patternTimeout = DefaultPatternTimeout
		return
	}
	r.patternTimeout = d
}

// Run executes the evaluation. The flow:
//  1. Filter the corpus to the requested pattern subset.
//  2. For each pattern, call target.Answer(pattern.Prompt).
//  3. Score with pattern.EvalFunc.
//  4. Aggregate into a RunResult.
//  5. Sign the result with attestation.Sign.
//
// Returns the RunOutput (result + signed envelope), or an
// error if the input is invalid or signing fails.
//
// If the target returns an error for a pattern, that pattern
// is treated as a fail with reason "target unreachable: <err>".
// The runner does NOT abort on per-pattern errors; it logs
// and continues with the next pattern.
func (r *Runner) Run(ctx context.Context, target Target, req RunRequest) (*RunOutput, error) {
	// 1. Validate inputs.
	if target == nil {
		return nil, fmt.Errorf("evaluator: target is required")
	}
	if req.TargetRef == "" {
		// Default to the target's own Ref() if caller did not supply one.
		req.TargetRef = target.Ref()
	}
	if req.TargetFingerprint == "" {
		req.TargetFingerprint = target.Fingerprint()
	}

	// 2. Filter corpus.
	corpus := r.corpus.Filter(req.PatternIDs)
	if len(corpus.Patterns) == 0 {
		return nil, fmt.Errorf("evaluator: filtered corpus is empty (corpus_id=%s, requested_ids=%v)",
			corpus.ID, req.PatternIDs)
	}

	// 3. Run each pattern.
	startedAt := time.Now().UTC()
	results := make([]PatternResult, 0, len(corpus.Patterns))
	for i := range corpus.Patterns {
		pattern := &corpus.Patterns[i]
		result := r.runOnePattern(ctx, target, pattern)
		results = append(results, result)
	}
	totalDuration := time.Since(startedAt)

	// 4. Aggregate.
	result := r.aggregate(req, corpus, results, startedAt, totalDuration)

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
func (r *Runner) runOnePattern(ctx context.Context, target Target, pattern *AttackPattern) PatternResult {
	result := PatternResult{
		PatternID:     pattern.ID,
		ATLASTactic:   pattern.ATLASTactic,
		TechniqueName: pattern.TechniqueName,
		Category:      pattern.Category,
		Severity:      pattern.Severity,
	}

	// Per-pattern timeout.
	patCtx, cancel := context.WithTimeout(ctx, r.patternTimeout)
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
	// attestation convention. We use the target fingerprint
	// as the instance-id (a stable, unique identifier for the
	// entity that ran the eval). The key-id is the current
	// keyring key id.
	instanceID := "ar-eaas:" + result.TargetFingerprint
	// Truncate the instance-id to a reasonable length so it
	// fits in the issuer field (which has no hard limit, but
	// 64 chars is a sensible cap for human readability).
	if len(instanceID) > 64 {
		instanceID = instanceID[:64]
	}
	// Get the current key id from the keyring. The keyring
	// has a "current" key with a unique id; we look it up
	// via the public ExportKey() method (it exists on the
	// keyring for this purpose).
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
// keys; we look it up via the public CurrentKey() method
// (added to the keyring in v3.5.0+ Track 6 Task 5).
func (r *Runner) currentKeyID() string {
	// The ioc.KeyRing type exposes the current key id via
	// the KeyID() method (added for the c3 envelope migration).
	// We use the keyring's CurrentKeyID() method.
	return r.keyRing.CurrentKeyID()
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
