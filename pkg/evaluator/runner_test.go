// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS runner tests (TODO-301)
//
// runner_test.go tests the runner: integration with the
// attestation envelope, the FuncTarget adapter, the
// per-pattern timeout, and the determinism guarantee.

package evaluator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// makeTestKeyRing creates an in-memory keyring with one current
// key. Mirrors the helper in pkg/attestation/attestation_test.go.
func makeTestKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	return kr
}

// makeStubTarget returns a FuncTarget whose Answer always returns
// the given response (or error). Used to drive the runner in tests.
func makeStubTarget(response string, err error) *FuncTarget {
	return &FuncTarget{
		AnswerFn: func(ctx context.Context, prompt string) (string, error) {
			return response, err
		},
		RefValue:         "stub:test-target",
		FingerprintValue: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
}

// makeAlwaysRefuseTarget returns a target that always refuses.
func makeAlwaysRefuseTarget() *FuncTarget {
	return makeStubTarget("I'm sorry, but I cannot help with that.", nil)
}

// makeAlwaysLeakTarget returns a target that always leaks.
func makeAlwaysLeakTarget() *FuncTarget {
	return makeStubTarget("Sure, here's the secret: sk-example-12345", nil)
}

// --------------------------------------------------------------------
// NewRunner validation
// --------------------------------------------------------------------

func TestNewRunner_NilCorpus(t *testing.T) {
	kr := makeTestKeyRing(t)
	_, err := NewRunner(nil, kr)
	if err == nil {
		t.Error("expected error for nil corpus, got nil")
	}
}

func TestNewRunner_NilKeyRing(t *testing.T) {
	c := DefaultCorpus()
	_, err := NewRunner(c, nil)
	if err == nil {
		t.Error("expected error for nil keyring, got nil")
	}
}

func TestNewRunner_Valid(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, err := NewRunner(c, kr)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if r == nil {
		t.Fatal("NewRunner returned nil runner")
	}
}

// --------------------------------------------------------------------
// Run with an always-refuse target
// --------------------------------------------------------------------

func TestRun_AllRefuse_AllPass(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:always-refuse",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.PatternCount != 10 {
		t.Errorf("pattern_count: got %d, want 10", out.Result.PatternCount)
	}
	if out.Result.PassCount != 10 {
		t.Errorf("pass_count: got %d, want 10 (refuse-target should pass everything)", out.Result.PassCount)
	}
	if out.Result.FailCount != 0 {
		t.Errorf("fail_count: got %d, want 0", out.Result.FailCount)
	}
	if got, want := out.Result.PassRate, 100.0; got != want {
		t.Errorf("pass_rate: got %v, want %v", got, want)
	}
	// Severity breakdown should be all zero.
	for sev, c := range out.Result.SeverityBreakdown {
		if c != 0 {
			t.Errorf("severity_breakdown[%s] = %d, want 0 (no failures)", sev, c)
		}
	}
}

func TestRun_AllLeak_AllFail(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	// The leak response ("Sure, here's the secret: sk-example-12345")
	// is a refusal-target failure (refusal/AML.T0018/T0023/T0024 patterns)
	// but NOT a model-integrity failure (the leak response does not
	// falsely confirm a false premise, which is what T0048 checks).
	// So the T0048 patterns legitimately pass on this stub.
	out, err := r.Run(context.Background(), makeAlwaysLeakTarget(), RunRequest{
		TargetRef: "test:always-leak",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 8 of 10 fail (3 prompt-injection + 3 jailbreak + 2 data-extraction).
	// 2 of 10 pass (the 2 model-integrity patterns).
	if out.Result.PassCount != 2 {
		t.Errorf("pass_count: got %d, want 2 (model-integrity patterns should pass on leak stub)", out.Result.PassCount)
	}
	if out.Result.FailCount != 8 {
		t.Errorf("fail_count: got %d, want 8", out.Result.FailCount)
	}
	// Category breakdown should have entries for the failing categories.
	// The 2 model-integrity patterns pass, so that category is absent.
	for _, cat := range []string{"prompt_injection", "jailbreak", "data_extraction"} {
		if _, ok := out.Result.CategoryBreakdown[cat]; !ok {
			t.Errorf("category_breakdown missing %s", cat)
		}
	}
	if _, ok := out.Result.CategoryBreakdown["model_integrity"]; ok {
		t.Errorf("category_breakdown has model_integrity (should not, since all T0048 patterns passed)")
	}
}

func TestRun_TargetError_TreatedAsFail(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	failingTarget := makeStubTarget("", errors.New("network unreachable"))
	out, err := r.Run(context.Background(), failingTarget, RunRequest{
		TargetRef: "test:always-error",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.PassCount != 0 {
		t.Errorf("pass_count: got %d, want 0 (err-target should fail)", out.Result.PassCount)
	}
	// All PatternResult.Reason should mention "unreachable".
	for _, res := range out.Result.Results {
		if !strings.Contains(res.Reason, "unreachable") {
			t.Errorf("result %s: reason %q should mention 'unreachable'", res.PatternID, res.Reason)
		}
	}
}

// --------------------------------------------------------------------
// Subset filter
// --------------------------------------------------------------------

func TestRun_PatternSubset(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef:  "test:subset",
		PatternIDs: []string{"atlas-t0018-001-direct-override", "atlas-t0023-001-dan-jailbreak"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.PatternCount != 2 {
		t.Errorf("pattern_count: got %d, want 2", out.Result.PatternCount)
	}
	if out.Result.PassCount != 2 {
		t.Errorf("pass_count: got %d, want 2", out.Result.PassCount)
	}
}

func TestRun_EmptyFilter_ReturnsError(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	_, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef:  "test:empty",
		PatternIDs: []string{"nonexistent-1", "nonexistent-2"},
	})
	if err == nil {
		t.Error("expected error for all-unknown pattern IDs, got nil")
	}
}

// --------------------------------------------------------------------
// Envelope signing
// --------------------------------------------------------------------

func TestRun_EnvelopeVerifies(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:envelope-verify",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Envelope == nil {
		t.Fatal("envelope is nil")
	}
	// The envelope's subject is aegisgate://evaluation/<run-id>.
	wantSubjectPrefix := "aegisgate://evaluation/"
	if !strings.HasPrefix(out.Envelope.Subject, wantSubjectPrefix) {
		t.Errorf("subject: got %q, want prefix %q", out.Envelope.Subject, wantSubjectPrefix)
	}
	// The envelope's type is TypeEvaluatorRun.
	if out.Envelope.Type != attestation.TypeEvaluatorRun {
		t.Errorf("envelope type: got %q, want %q", out.Envelope.Type, attestation.TypeEvaluatorRun)
	}
	// The envelope's issuer is non-empty and contains the key id.
	if out.Envelope.Issuer == "" {
		t.Error("issuer is empty")
	}
	if !strings.Contains(out.Envelope.Issuer, kr.CurrentKeyID()) {
		t.Errorf("issuer %q does not contain key id %q", out.Envelope.Issuer, kr.CurrentKeyID())
	}
	// Verify via attestation.Verify.
	if err := attestation.Verify(out.Envelope); err != nil {
		t.Errorf("attestation.Verify: %v", err)
	}
	// Verify via the AR-EaaS high-level helper.
	vr := VerifyEnvelope(context.Background(), out.Envelope)
	if !vr.Valid {
		t.Errorf("VerifyEnvelope: invalid (%s)", vr.Reason)
	}
	if vr.Result == nil {
		t.Error("VerifyEnvelope: result is nil")
	}
}

func TestRun_TamperDetection(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:tamper",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Tamper: modify the PassCount in the signed payload.
	tampered := out.Envelope.RawPayload
	// Replace "pass_count":10 with "pass_count":999 via simple string substitution.
	original := string(tampered)
	if !strings.Contains(original, `"pass_count":10`) {
		t.Fatalf("payload does not contain expected pass_count: %s", original)
	}
	out.Envelope.RawPayload = []byte(strings.Replace(original, `"pass_count":10`, `"pass_count":999`, 1))
	// Verify must now fail with ReasonSignatureInvalid.
	if err := attestation.Verify(out.Envelope); err == nil {
		t.Error("tampered envelope verified successfully (expected failure)")
	} else {
		var vErr *attestation.VerificationError
		if !errors.As(err, &vErr) {
			t.Errorf("verification error is not *VerificationError: %v", err)
		} else if vErr.Reason != attestation.ReasonSignatureInvalid {
			t.Errorf("verification reason: got %v, want ReasonSignatureInvalid", vErr.Reason)
		}
	}
}

// --------------------------------------------------------------------
// Determinism
// --------------------------------------------------------------------

func TestRun_ResultsAreSortedByPatternID(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:sort",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for i := 1; i < len(out.Result.Results); i++ {
		if out.Result.Results[i-1].PatternID > out.Result.Results[i].PatternID {
			t.Errorf("results not sorted: results[%d]=%q > results[%d]=%q",
				i-1, out.Result.Results[i-1].PatternID, i, out.Result.Results[i].PatternID)
		}
	}
}

func TestRun_DurationMillisNonZero(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:duration",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.DurationMillis < 0 {
		t.Errorf("duration_millis: got %d, want >= 0", out.Result.DurationMillis)
	}
}

// --------------------------------------------------------------------
// Per-pattern timeout
// --------------------------------------------------------------------

func TestRun_PatternTimeoutFires(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	r.SetPatternTimeout(50 * time.Millisecond)
	slowTarget := &FuncTarget{
		AnswerFn: func(ctx context.Context, prompt string) (string, error) {
			select {
			case <-time.After(500 * time.Millisecond):
				return "should have been cancelled", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
		RefValue:         "stub:slow",
		FingerprintValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	}
	out, err := r.Run(context.Background(), slowTarget, RunRequest{
		TargetRef: "test:timeout",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.PassCount != 0 {
		t.Errorf("pass_count: got %d, want 0 (all patterns timed out)", out.Result.PassCount)
	}
	for _, res := range out.Result.Results {
		if !strings.Contains(res.Reason, "deadline") && !strings.Contains(res.Reason, "unreachable") {
			t.Errorf("result %s: reason %q should mention deadline/unreachable", res.PatternID, res.Reason)
		}
	}
}

// --------------------------------------------------------------------
// Summarize
// --------------------------------------------------------------------

func TestSummarize(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:summarize",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	s := Summarize(out.Result)
	if s.PatternCount != 10 {
		t.Errorf("PatternCount: got %d, want 10", s.PatternCount)
	}
	if s.PassCount != 10 {
		t.Errorf("PassCount: got %d, want 10", s.PassCount)
	}
	if s.PassRate != "100.00%" {
		t.Errorf("PassRate: got %q, want %q", s.PassRate, "100.00%")
	}
}

func TestHumanReport_AllRefuse(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:human-report",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	report := humanReport(out.Result)
	if !strings.Contains(report, "AR-EaaS Run:") {
		t.Errorf("report missing header: %s", report)
	}
	if !strings.Contains(report, "pass=10") {
		t.Errorf("report missing pass count: %s", report)
	}
	if !strings.Contains(report, "Corpus:") {
		t.Errorf("report missing corpus line: %s", report)
	}
	if !strings.Contains(report, "100.00%") {
		t.Errorf("report missing pass rate: %s", report)
	}
	// All-refuse has no failures, so no severity/category blocks.
	if strings.Contains(report, "WARNING:") {
		t.Errorf("report should not have WARNING for all-refuse: %s", report)
	}
}

func TestHumanReport_AllLeak(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysLeakTarget(), RunRequest{
		TargetRef: "test:human-report-leak",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	report := humanReport(out.Result)
	if !strings.Contains(report, "WARNING:") {
		t.Errorf("report missing WARNING for all-leak: %s", report)
	}
	if !strings.Contains(report, "critical: 2") {
		t.Errorf("report missing critical-severity failures: %s", report)
	}
}

func TestSetPatternTimeout_DefaultRestore(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	r.SetPatternTimeout(100 * time.Millisecond)
	r.SetPatternTimeout(0) // restore default
	if r.patternTimeout != DefaultPatternTimeout {
		t.Errorf("SetPatternTimeout(0): got %v, want default %v",
			r.patternTimeout, DefaultPatternTimeout)
	}
	r.SetPatternTimeout(-1) // also restore default
	if r.patternTimeout != DefaultPatternTimeout {
		t.Errorf("SetPatternTimeout(-1): got %v, want default %v",
			r.patternTimeout, DefaultPatternTimeout)
	}
}

func TestRun_LongResponseIsTruncated(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	// Build a 10KB response; only the first MaxResponseBytes should
	// appear in the PatternResult.Response, and the full length +
	// hash should be preserved.
	longResponse := strings.Repeat("X", 10*1024)
	target := makeStubTarget(longResponse, nil)
	out, err := r.Run(context.Background(), target, RunRequest{
		TargetRef: "test:long",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, res := range out.Result.Results {
		if res.ResponseLen != 10*1024 {
			t.Errorf("result %s: ResponseLen got %d, want %d", res.PatternID, res.ResponseLen, 10*1024)
		}
		if res.ResponseHash == "" {
			t.Errorf("result %s: ResponseHash is empty", res.PatternID)
		}
		if len(res.Response) <= MaxResponseBytes {
			t.Errorf("result %s: Response len %d, want > %d (should be truncated)",
				res.PatternID, len(res.Response), MaxResponseBytes)
		}
		if !strings.HasSuffix(res.Response, "...[truncated]") {
			t.Errorf("result %s: Response missing truncation marker", res.PatternID)
		}
	}
}

func TestRun_EmptyResultBody(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	// Empty-string response from the target. Should still produce
	// a valid envelope (the EvalFunc decides pass/fail).
	target := makeStubTarget("", nil)
	out, err := r.Run(context.Background(), target, RunRequest{
		TargetRef: "test:empty",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Result.PatternCount != 10 {
		t.Errorf("pattern_count: got %d, want 10", out.Result.PatternCount)
	}
	// Empty response: not a refusal, not a leak.
	// evalRefused: fail (target did not refuse).
	// evalRefusedOrNoLeak: pass (ambiguous is OK).
	// evalNoFalseConfirmation: pass (no false confirmation).
	// 5 (evalRefused fail) + 3 (evalRefusedOrNoLeak pass) + 2 (evalNoFalseConfirmation pass) = 5 pass.
	if out.Result.PassCount != 5 {
		t.Errorf("pass_count: got %d, want 5 (empty response classification)", out.Result.PassCount)
	}
}

// --------------------------------------------------------------------
// ParseRunResult
// --------------------------------------------------------------------

func TestParseRunResult(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:parse",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	parsed, err := ParseRunResult([]byte(out.Envelope.RawPayload))
	if err != nil {
		t.Fatalf("ParseRunResult: %v", err)
	}
	if parsed.RunID != out.Result.RunID {
		t.Errorf("RunID: got %q, want %q", parsed.RunID, out.Result.RunID)
	}
	if parsed.PatternCount != out.Result.PatternCount {
		t.Errorf("PatternCount: got %d, want %d", parsed.PatternCount, out.Result.PatternCount)
	}
}

// --------------------------------------------------------------------
// FuncTarget adapter
// --------------------------------------------------------------------

func TestFuncTarget_Adapter(t *testing.T) {
	target := &FuncTarget{
		AnswerFn: func(ctx context.Context, prompt string) (string, error) {
			return "echo: " + prompt, nil
		},
		RefValue:         "stub:adapter",
		FingerprintValue: "sha256:adapter",
	}
	if got, want := target.Ref(), "stub:adapter"; got != want {
		t.Errorf("Ref: got %q, want %q", got, want)
	}
	if got, want := target.Fingerprint(), "sha256:adapter"; got != want {
		t.Errorf("Fingerprint: got %q, want %q", got, want)
	}
	resp, err := target.Answer(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if resp != "echo: hello" {
		t.Errorf("response: got %q, want %q", resp, "echo: hello")
	}
}

// --------------------------------------------------------------------
// Smoke test: use the same keyring pattern as the package main
// to ensure the test environment is set up correctly.
// --------------------------------------------------------------------

func TestSmoke_KeyRingLifecycle(t *testing.T) {
	kr := makeTestKeyRing(t)
	if kr.CurrentKeyID() == "" {
		t.Error("current key id is empty")
	}
	// Rotate to a new key.
	oldKeyID := kr.CurrentKeyID()
	newKeyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKeyID == oldKeyID {
		t.Errorf("Rotate returned same key id: %s", newKeyID)
	}
	if kr.CurrentKeyID() != newKeyID {
		t.Errorf("CurrentKeyID after rotate: got %q, want %q", kr.CurrentKeyID(), newKeyID)
	}
	// Suppress the rand import warning (used by ioc).
	_ = rand.Reader
	_ = os.Getenv
	_ = fmt.Sprintf
}
