// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS CLI subcommand (TODO-301)
//
// evaluator_subcommand.go wires pkg/evaluator into the CLI binary
// as `aegisgate evaluator run` and `aegisgate evaluator verify`.
// The run verb is the operator's primary interface for executing
// an AR-EaaS eval; the verify verb is the auditor's primary
// interface for verifying a signed result offline.
//
// CLI surface:
//
//	aegisgate evaluator run --target-ref=model:openai/gpt-4-turbo
//	aegisgate evaluator verify <envelope.json>
//	aegisgate evaluator list-patterns
//
// The subcommand is detected from os.Args[1] == "evaluator".
// It uses the same init() pattern as the attestation and
// evidence subcommands.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evaluator"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// runEvaluatorSubcommand implements the "aegisgate evaluator"
// CLI subcommand. The verbs are: run, verify, list-patterns.
//
// init wires the subcommand detection hook. The subcommand is
// detected from os.Args[1] == "evaluator".
//
// This dispatcher calls os.Exit(0) on success, unlike the
// attestation/evidence subcommands which fall through to
// main(). The evaluator verb produces a complete result
// (the run/verify is the entire purpose of the invocation),
// so suppressing the platform startup is the correct
// behavior. (See gotcha #53 in plans/SESSION-ANCHOR-... for
// why the older subcommands don't exit explicitly.)
func runEvaluatorSubcommand(args []string) {
	if len(args) == 0 {
		evaluatorUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "run":
		exitCode = runEvaluatorRun(rest)
	case "verify":
		exitCode = runEvaluatorVerify(rest)
	case "list-patterns":
		runEvaluatorListPatterns(rest)
	case "-help", "--help", "help":
		evaluatorUsage()
	default:
		fmt.Fprintf(os.Stderr, "evaluator: unknown verb %q\n", verb)
		evaluatorUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// evaluatorUsage prints the help text for the evaluator
// subcommand. The output is terse by design (CLI idiom).
func evaluatorUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate evaluator — Adversarial Robustness Evals-as-a-Service (AR-EaaS)

Usage:
  aegisgate evaluator run --target-ref=TARGET [flags]
  aegisgate evaluator verify <envelope.json> [flags]
  aegisgate evaluator list-patterns

Flags (run):
  --target-ref        opaque target identifier (e.g., "model:openai/gpt-4-turbo")
                      (REQUIRED)
  --corpus            corpus ID (default: atlas-v0.1)
  --pattern           restrict to a single pattern ID (repeatable)
  --out               write the signed envelope to this file (default: stdout)
  --key-ring          path to the keyring file (default: ephemeral)
  --notes             free-form note from the caller
  --json              emit JSON only (default: human-readable)
  --no-verify-stub    (internal) skip target verification (test-only)

Flags (verify):
  --json              emit JSON only (default: human-readable)
  --key-id            expected key ID (refuse if mismatch)

Examples:
  # Run a full AR-EaaS eval against a stub target
  aegisgate evaluator run --target-ref=model:my-model@v1

  # Run a single pattern
  aegisgate evaluator run --target-ref=model:my-model@v1 \
      --pattern=atlas-t0018-001-direct-override

  # Verify a signed envelope
  aegisgate evaluator verify result.json
`)
}

// runEvaluatorRun is the implementation of
// "aegisgate evaluator run". Returns the exit code:
//
//	0 = success (including cases with low/medium/high fails
//	    but no critical fails)
//	2 = usage error (missing --target-ref, unknown corpus)
//	3 = critical-severity failures
//
// The v0.1 implementation uses an in-process stub target
// (always refuses) so the operator can exercise the full
// pipeline without a live AI model. A future v0.2 will add
// a Go-plugin loader for caller-supplied targets.
func runEvaluatorRun(args []string) int {
	fs := flag.NewFlagSet("evaluator run", flag.ExitOnError)
	targetRef := fs.String("target-ref", "", "opaque target identifier (REQUIRED)")
	corpusID := fs.String("corpus", "atlas-v0.1", "corpus ID")
	var patternIDs multiFlag
	fs.Var(&patternIDs, "pattern", "restrict to a single pattern ID (repeatable)")
	outFile := fs.String("out", "", "write the signed envelope to this file (default: stdout)")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	notes := fs.String("notes", "", "free-form note from the caller")
	jsonOut := fs.Bool("json", false, "emit JSON only (default: human-readable)")
	noVerifyStub := fs.Bool("no-verify-stub", false, "(internal) skip target verification (test-only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *targetRef == "" {
		fmt.Fprintf(os.Stderr, "evaluator run: --target-ref is required\n")
		evaluatorUsage()
		return 2
	}

	// 1. Load the corpus. v0.1 ships only the default corpus.
	corpus := evaluator.DefaultCorpus()
	if *corpusID != "" && *corpusID != corpus.ID {
		fmt.Fprintf(os.Stderr, "evaluator run: unknown corpus %q (v0.1 supports %q only)\n",
			*corpusID, corpus.ID)
		return 2
	}

	// 2. Build (or load) the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluator run: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// 3. Build the runner.
	runner, err := evaluator.NewRunner(corpus, kr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluator run: NewRunner: %v\n", err)
		return 1
	}

	// 4. Build the in-process stub target. The v0.1 stub always
	// refuses; the operator can verify the pipeline end-to-end
	// without a live AI model. A future v0.2 will add a Go-plugin
	// loader for caller-supplied targets.
	target := &evaluator.FuncTarget{
		AnswerFn: stubAnswerFunc(*noVerifyStub),
		RefValue: *targetRef,
		// Deterministic fingerprint: hash of the target-ref.
		// Operators who want a different fingerprint can extend
		// the FuncTarget adapter.
		FingerprintValue: fingerprintFromString(*targetRef),
	}

	// 5. Run.
	patternIDsSlice := []string(patternIDs)
	out, err := runner.Run(context.Background(), target, evaluator.RunRequest{
		TargetRef:  *targetRef,
		PatternIDs: patternIDsSlice,
		Notes:      *notes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluator run: %v\n", err)
		return 1
	}

	// 6. Output.
	if *outFile != "" {
		envelopeBytes, err := json.MarshalIndent(out.Envelope, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "evaluator run: marshal envelope: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "evaluator run: write %s: %v\n", *outFile, err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Wrote signed envelope to %s\n", *outFile)
			fmt.Println(runnerReportToString(out.Result))
		}
	} else {
		if *jsonOut {
			envelopeBytes, err := json.MarshalIndent(out.Envelope, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluator run: marshal envelope: %v\n", err)
				return 1
			}
			fmt.Println(string(envelopeBytes))
		} else {
			fmt.Println(runnerReportToString(out.Result))
		}
	}

	// Exit code: 0 on pass, 3 on critical failures.
	// (A target that fails N low-severity patterns but 0
	// critical-severity patterns is still considered passing
	// at the CI level; the operator can inspect the
	// ResultSummary.CriticalFails for details.)
	summary := evaluator.Summarize(out.Result)
	if summary.CriticalFails > 0 {
		return 3 // critical failures
	}
	return 0
}

// runEvaluatorVerify is the implementation of
// "aegisgate evaluator verify <envelope.json>". Returns
// 0 on valid, 1 on invalid.
func runEvaluatorVerify(args []string) int {
	fs := flag.NewFlagSet("evaluator verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "evaluator verify: expected exactly one envelope file argument, got %d\n", len(positional))
		evaluatorUsage()
		return 2
	}
	path := positional[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluator verify: read %s: %v\n", path, err)
		return 1
	}
	vr, err := evaluator.VerifyEnvelopeJSON(context.Background(), data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluator verify: parse %s: %v\n", path, err)
		return 1
	}
	// Optional key-id check.
	if vr.Valid && *expectedKeyID != "" && vr.Envelope.Signature.KeyID != *expectedKeyID {
		vr.Valid = false
		vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
			vr.Envelope.Signature.KeyID, *expectedKeyID)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(vr.ToJSON(), "", "  ")
		fmt.Println(string(out))
	} else {
		printEvaluatorVerifyHuman(vr)
	}
	if !vr.Valid {
		return 1
	}
	return 0
}

// runEvaluatorListPatterns lists the corpus patterns.
func runEvaluatorListPatterns(_ []string) {
	c := evaluator.DefaultCorpus()
	fmt.Printf("Corpus: %s @ %s\n", c.ID, c.Version)
	fmt.Printf("Patterns: %d\n\n", len(c.Patterns))
	fmt.Printf("%-45s %-14s %-14s %s\n", "ID", "TACTIC", "CATEGORY", "SEVERITY")
	for _, p := range c.Patterns {
		fmt.Printf("%-45s %-14s %-14s %s\n",
			p.ID, p.ATLASTactic, p.Category, p.Severity.String())
	}
}

// =====================================================================
// Helpers
// =====================================================================

// multiFlag is a flag.Value that accumulates repeated --pattern
// values into a slice.
type multiFlag []string

// String returns the flag's value as a comma-separated string.
func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

// Set appends a value to the flag.
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// loadOrEphemeralKeyRing loads a keyring from the given path. If
// path is empty, it creates an ephemeral keyring (in-memory + temp
// file). Returns the keyring, a cleanup func (nil if no cleanup
// is needed), and any error.
func loadOrEphemeralKeyRing(path string) (*ioc.KeyRing, func(), error) {
	if path == "" {
		// Ephemeral: write to a temp file, then we can leave it.
		tmpDir, err := os.MkdirTemp("", "aegisgate-evaluator-kr-")
		if err != nil {
			return nil, nil, fmt.Errorf("create temp dir: %w", err)
		}
		kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, nil, fmt.Errorf("load ephemeral keyring: %w", err)
		}
		if _, err := kr.Rotate(); err != nil {
			os.RemoveAll(tmpDir)
			return nil, nil, fmt.Errorf("rotate ephemeral keyring: %w", err)
		}
		return kr, func() { os.RemoveAll(tmpDir) }, nil
	}
	// Persistent: load the file (or create + rotate if missing).
	kr, err := ioc.LoadKeyRing(path)
	if err != nil {
		return nil, nil, fmt.Errorf("load keyring %s: %w", path, err)
	}
	if kr.CurrentKeyID() == "" {
		if _, err := kr.Rotate(); err != nil {
			return nil, nil, fmt.Errorf("rotate keyring %s: %w", path, err)
		}
	}
	return kr, nil, nil
}

// stubAnswerFunc returns the v0.1 stub Answer function. The stub
// always refuses. The noVerify flag is reserved for future use
// (e.g., a "no-verify" target that always returns "ok" so the
// operator can see the failure path).
func stubAnswerFunc(noVerify bool) func(ctx context.Context, prompt string) (string, error) {
	if noVerify {
		// Reserved for future use; for now treat as a no-op.
		_ = noVerify
	}
	return func(ctx context.Context, prompt string) (string, error) {
		// v0.1 stub: always refuse. The v0.2 will add a Go-plugin
		// loader for caller-supplied targets.
		return "I'm sorry, but I cannot help with that.", nil
	}
}

// fingerprintFromString returns a stable hex fingerprint of s.
// Used to derive a deterministic TargetFingerprint from the
// target-ref so the signed result is reproducible.
func fingerprintFromString(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// runnerReportToString returns a human-readable summary of a
// RunResult. We re-implement the formatting here (rather than
// using evaluator.humanReport, which is unexported) so the CLI
// verb can use it from outside the package.
func runnerReportToString(r *evaluator.RunResult) string {
	summary := evaluator.Summarize(r)
	var b strings.Builder
	fmt.Fprintf(&b, "AR-EaaS Run: %s\n", summary.RunID)
	fmt.Fprintf(&b, "  Corpus:        %s @ %s\n", summary.CorpusID, summary.CorpusVersion)
	fmt.Fprintf(&b, "  Target:        %s\n", summary.TargetRef)
	fmt.Fprintf(&b, "  Patterns:      %d (pass=%d, fail=%d, pass_rate=%s)\n",
		summary.PatternCount, summary.PassCount, summary.FailCount, summary.PassRate)
	if summary.CriticalFails > 0 {
		fmt.Fprintf(&b, "  WARNING:       %d critical-severity failures\n", summary.CriticalFails)
	}
	if len(r.SeverityBreakdown) > 0 {
		fmt.Fprintf(&b, "  Severity:\n")
		for _, sev := range []string{"low", "medium", "high", "critical"} {
			if c, ok := r.SeverityBreakdown[sev]; ok && c > 0 {
				fmt.Fprintf(&b, "    %s: %d\n", sev, c)
			}
		}
	}
	if len(r.CategoryBreakdown) > 0 {
		fmt.Fprintf(&b, "  Category:\n")
		// Sort categories for deterministic output.
		cats := make([]string, 0, len(r.CategoryBreakdown))
		for c := range r.CategoryBreakdown {
			cats = append(cats, c)
		}
		sortStrings(cats)
		for _, c := range cats {
			fmt.Fprintf(&b, "    %s: %d\n", c, r.CategoryBreakdown[c])
		}
	}
	return b.String()
}

// sortStrings sorts a slice of strings in ascending order.
// Inlined to avoid importing "sort" (which would also be
// a valid choice; we keep the dependency footprint small).
func sortStrings(s []string) {
	// Simple insertion sort; the slice is small (<= 10 entries).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// printEvaluatorVerifyHuman prints a verify result in
// human-readable form.
func printEvaluatorVerifyHuman(vr *evaluator.VerifyResult) {
	if !vr.Valid {
		fmt.Printf("INVALID: %s\n", vr.Reason)
		if vr.Envelope != nil {
			fmt.Printf("  Type:    %s\n", vr.Envelope.Type)
			fmt.Printf("  Subject: %s\n", vr.Envelope.Subject)
			fmt.Printf("  Issuer:  %s\n", vr.Envelope.Issuer)
			fmt.Printf("  KeyID:   %s\n", vr.Envelope.Signature.KeyID)
		}
		return
	}
	fmt.Println("VALID")
	if vr.Result != nil {
		fmt.Println(runnerReportToString(vr.Result))
	}
}

// isEvaluatorSubcommand returns true if args look like the
// "aegisgate evaluator" subcommand.
func isEvaluatorSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == "evaluator"
}

// stripEvaluatorSubcommand removes the "evaluator" prefix from args.
func stripEvaluatorSubcommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

// init wires the evaluator subcommand detection hook. Runs
// BEFORE main() and BEFORE flag.Parse() consumes the args.
// Mirrors the pattern in attestation_subcommand.go and
// evidence_subcommand.go.
func init() {
	if isEvaluatorSubcommand(os.Args[1:]) {
		args := stripEvaluatorSubcommand(os.Args[1:])
		runEvaluatorSubcommand(args)
		// Unreachable: runEvaluatorSubcommand calls os.Exit.
		return
	}
	// Suppress unused-import warnings for rand and time.
	_ = rand.Reader
	_ = time.Now
}
