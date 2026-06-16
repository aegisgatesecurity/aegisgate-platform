// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS CLI subcommand tests (TODO-301)
//
// evaluator_subcommand_test.go exercises the CLI verb end-to-end:
// run + verify, JSON output, key-id check, and the
// pattern-filtering flag. The test binary is pre-built in
// TestMain so each test is fast (no `go run` overhead).

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evaluator"
)

// testBinaryPath is the path to the pre-built aegisgate binary
// used by the CLI tests. Built once in TestMain, reused across
// all tests. This avoids the slow `go run` path.
var testBinaryPath string

// TestMain pre-builds the aegisgate binary for the CLI tests.
// This is the test-only setup; production builds are unaffected.
func TestMain(m *testing.M) {
	// Find the cmd directory (the current working dir when
	// `go test ./cmd/aegisgate-platform/` runs is this dir).
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain getwd: %v\n", err)
		os.Exit(1)
	}
	// Build to a temp file.
	tmpDir, err := os.MkdirTemp("", "aegisgate-cli-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain mkdir: %v\n", err)
		os.Exit(1)
	}
	testBinaryPath = filepath.Join(tmpDir, "aegisgate")
	buildCmd := &testCmd{
		Name: "go",
		Args: []string{"build", "-o", testBinaryPath, "."},
		Dir:  dir,
	}
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain build: %v\n%s\n", err, out)
		os.RemoveAll(tmpDir)
		os.Exit(1)
	}
	// Run the tests.
	code := m.Run()
	// Cleanup.
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

// runEvaluatorInProcess runs the CLI verb via the pre-built
// test binary. The subcommand's init() pattern calls os.Exit(0)
// on success, so the test binary does not start the platform.
//
// Returns the captured stdout and exit code.
func runEvaluatorInProcess(t *testing.T, args []string) (stdout string, exitCode int) {
	t.Helper()
	cmd := &testCmd{
		Name: testBinaryPath,
		Args: append([]string{"evaluator"}, args...),
	}
	// Set HOME to a temp dir so the keyring (if persisted) doesn't
	// pollute the user's home directory.
	tmpHome := t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+tmpHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr.Code
		}
		t.Fatalf("evaluator subcommand failed unexpectedly: %v\noutput: %s", err, string(out))
	}
	return string(out), 0
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

func TestEvaluatorCLI_Run_DefaultStub(t *testing.T) {
	stdout, _ := runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
		"--json",
	})
	// The output should be a valid JSON envelope.
	var env attestation.Envelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("CLI output is not valid envelope JSON: %v\noutput: %s", err, stdout)
	}
	if env.Type != attestation.TypeEvaluatorRun {
		t.Errorf("envelope type: got %q, want %q", env.Type, attestation.TypeEvaluatorRun)
	}
	if !strings.HasPrefix(env.Subject, "aegisgate://evaluation/") {
		t.Errorf("envelope subject: got %q, want aegisgate://evaluation/... prefix", env.Subject)
	}
}

func TestEvaluatorCLI_Run_HumanReadable(t *testing.T) {
	stdout, _ := runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
	})
	if !strings.Contains(stdout, "AR-EaaS Run:") {
		t.Errorf("CLI output missing human-readable header: %s", stdout)
	}
	if !strings.Contains(stdout, "pass=") {
		t.Errorf("CLI output missing pass count: %s", stdout)
	}
}

func TestEvaluatorCLI_Run_PatternFilter(t *testing.T) {
	stdout, _ := runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
		"--pattern=atlas-t0018-001-direct-override",
		"--json",
	})
	var env attestation.Envelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("CLI output is not valid envelope JSON: %v\noutput: %s", err, stdout)
	}
	var result evaluator.RunResult
	if err := json.Unmarshal(env.RawPayload, &result); err != nil {
		t.Fatalf("RunResult decode: %v", err)
	}
	if result.PatternCount != 1 {
		t.Errorf("PatternCount: got %d, want 1 (single pattern filter)", result.PatternCount)
	}
}

func TestEvaluatorCLI_Run_OutFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "envelope.json")
	_, _ = runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
		"--out=" + outPath,
	})
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("envelope JSON: %v", err)
	}
	if env.Type != attestation.TypeEvaluatorRun {
		t.Errorf("envelope type: got %q, want %q", env.Type, attestation.TypeEvaluatorRun)
	}
}

func TestEvaluatorCLI_Run_MissingTargetRef(t *testing.T) {
	// Missing --target-ref should exit with code 2 (usage error).
	_, exitCode := runEvaluatorInProcess(t, []string{"run"})
	if exitCode != 2 {
		t.Errorf("missing --target-ref: exit code got %d, want 2", exitCode)
	}
}

func TestEvaluatorCLI_ListPatterns(t *testing.T) {
	stdout, _ := runEvaluatorInProcess(t, []string{"list-patterns"})
	if !strings.Contains(stdout, "Corpus:") {
		t.Errorf("list-patterns output missing header: %s", stdout)
	}
	if !strings.Contains(stdout, "atlas-t0018-001-direct-override") {
		t.Errorf("list-patterns output missing pattern: %s", stdout)
	}
}

func TestEvaluatorCLI_Verify_Roundtrip(t *testing.T) {
	// 1. Run to produce an envelope.
	tmpDir := t.TempDir()
	envelopePath := filepath.Join(tmpDir, "envelope.json")
	_, _ = runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
		"--out=" + envelopePath,
		"--json",
	})
	// 2. Verify the envelope. Flags must come before positional args.
	stdout, _ := runEvaluatorInProcess(t, []string{
		"verify", "--json", envelopePath,
	})
	var result evaluator.VerifyResultJSON
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("verify output is not JSON: %v\noutput: %s", err, stdout)
	}
	if !result.Valid {
		t.Errorf("verify: Valid=false (reason=%s)", result.Reason)
	}
	if result.PatternCount != 10 {
		t.Errorf("verify: PatternCount got %d, want 10", result.PatternCount)
	}
}

func TestEvaluatorCLI_Verify_TamperedEnvelope(t *testing.T) {
	// 1. Run to produce an envelope.
	tmpDir := t.TempDir()
	envelopePath := filepath.Join(tmpDir, "envelope.json")
	_, _ = runEvaluatorInProcess(t, []string{
		"run",
		"--target-ref=model:test-cli@v1",
		"--out=" + envelopePath,
		"--json",
	})
	// 2. Tamper with the envelope.
	data, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	tampered := strings.Replace(string(data), `"pass_count": 10`, `"pass_count": 999`, 1)
	if tampered == string(data) {
		t.Fatalf("envelope does not contain expected pass_count to tamper")
	}
	if err := os.WriteFile(envelopePath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered envelope: %v", err)
	}
	// 3. Verify the tampered envelope. Should be invalid. Flags
	// must come before positional args.
	stdout, exitCode := runEvaluatorInProcess(t, []string{
		"verify", "--json", envelopePath,
	})
	if exitCode == 0 {
		t.Errorf("tampered envelope verified successfully (expected non-zero exit)")
	}
	var result evaluator.VerifyResultJSON
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("verify output is not JSON: %v\noutput: %s", err, stdout)
	}
	if result.Valid {
		t.Errorf("tampered envelope: Valid=true (expected false)")
	}
	if !strings.Contains(strings.ToLower(result.Reason), "signature") {
		t.Errorf("tampered envelope: reason %q should mention signature", result.Reason)
	}
}
