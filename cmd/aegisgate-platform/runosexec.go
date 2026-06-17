// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CLI test helper for evaluator_subcommand_test.go
//
// runosexec.go bridges the testCmd helper in
// evaluator_subcommand_test.go to the real os/exec package. The
// split exists so the test file can use a typed wrapper without
// pulling os/exec into its own imports (which would couple the
// test to the host's os/exec availability).

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
)

// testCmd is a small wrapper around exec.Cmd used by the CLI
// subcommand tests. We define it in this file (the os/exec
// bridge) so the test files don't need to import os/exec
// directly. The fields are exported as needed by the tests.
type testCmd struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

// CombinedOutput runs the command and returns the combined
// stdout+stderr output. On non-zero exit, the returned error
// is a *exitError (defined below).
func (c *testCmd) CombinedOutput() ([]byte, error) {
	return runOSExec(c.Name, c.Args, c.Dir, c.Env)
}

// runOSExec runs name with args in dir, with the given env. The
// combined stdout+stderr is returned. If the process exits with
// a non-zero code, the returned error is a *testExitError.
//
// G204 (CodeQL): the call site is a test harness (cmd/aegisgate-
// platform/evaluator_subcommand_test.go) that only invokes `go
// build` and the test binary. The allowlist below restricts
// the executable name to those two cases, satisfying the
// linter's "no subprocess with a variable" check.
//
// nolint:gosec // G204 (subprocess with variable): the allowlist
// check above (`switch base { case "go", "aegisgate": ... }`)
// is the security control; the explicit nolint documents the
// allowlist validation that precedes the exec.Command call.
func runOSExec(name string, args []string, dir string, env []string) ([]byte, error) {
	// G204 linter guard: only allow the test-harness commands.
	// The base name (no directory component) must be in the
	// allowlist. This prevents path-traversal-style attacks
	// even though the call site is internal.
	base := filepath.Base(name)
	switch base {
	case "go", "aegisgate":
		// allowed
	default:
		return nil, fmt.Errorf("runOSExec: executable %q not in allowlist", name)
	}
	// G204 (CodeQL): the allowlist check above
	// ensures the executable name is one of {"go",
	// "aegisgate"}. We dispatch via a switch on the
	// validated `base` value. The exec.Command call
	// uses a constant string for the executable name;
	// the args slice is constructed by the test caller
	// and is not user-controlled (the test harness
	// passes a fixed args slice for each invocation).
	//
	// nolint:gosec // G204 (subprocess with variable): the
	// allowlist check above and the constant-string
	// dispatch below are the security controls; the
	// explicit nolint documents the allowlist
	// validation that precedes the exec.Command call.
	var cmd *exec.Cmd
	switch base {
	case "go":
		// nolint:gosec // G204: base is validated above
		cmd = exec.Command("go", args...)
	case "aegisgate":
		// nolint:gosec // G204: base is validated above
		cmd = exec.Command("aegisgate", args...)
	}
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err == nil {
		return buf.Bytes(), nil
	}
	// Extract the exit code.
	if exitErr, ok := err.(*exec.ExitError); ok {
		// Try to get the wait status (Unix only).
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return buf.Bytes(), &exitError{Code: status.ExitStatus()}
		}
		// Fallback: use ExitCode() (added in Go 1.12).
		return buf.Bytes(), &exitError{Code: exitErr.ExitCode()}
	}
	return buf.Bytes(), err
}

// exitError is the error returned when a subprocess
// exits with a non-zero code. Defined here (not in the test
// file) so the runOSExec function can construct it.
type exitError struct {
	Code int
}

// Error implements the error interface.
func (e *exitError) Error() string {
	return "exit code " + intToStrCmd(e.Code)
}

// intToStrCmd formats a small non-negative int as a string.
// Kept in the cmd package to avoid the strconv import in the
// test file (it lives in the same package).
func intToStrCmd(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
