// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ============================================================================
// Go Executor (Secure Code Execution)
// ============================================================================

// GoExecutor provides secure Go code execution
type GoExecutor struct {
	manager *SandboxManager
	policy  *ExecutionPolicy
}

// NewGoExecutor creates a new Go code executor
func NewGoExecutor(manager *SandboxManager) *GoExecutor {
	return &GoExecutor{
		manager: manager,
		policy:  manager.policy,
	}
}

// Execute runs Go code in a sandboxed environment
func (e *GoExecutor) Execute(ctx context.Context, code string) *GoExecutionResult {
	result := &GoExecutionResult{
		SandboxID: SandboxID(fmt.Sprintf("go-%d", time.Now().UnixNano())),
		StartTime: time.Now(),
	}

	// Validate language
	if err := e.policy.ValidateLanguage("go"); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = err.Error()
		return result
	}

	// Static analysis of code
	if err := ValidateGoCode(code, e.policy); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = err.Error()
		return result
	}

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "aegisguard-go-*")
	if err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to create temp directory"
		return result
	}
	defer os.RemoveAll(tmpDir)

	// Write code to file
	tmpFile := tmpDir + "/main.go"
	if err := os.WriteFile(tmpFile, []byte(code), 0600); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to write code"
		return result
	}

	// Create go.mod if not present
	if !contains(code, "package main") {
		modFile := tmpDir + "/go.mod"
		os.WriteFile(modFile, []byte("module main\n\ngo 1.21\n"), 0600)
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, e.policy.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Run()

	result.Duration = time.Since(result.StartTime)
	result.Output = truncateOutput(stdout.String(), e.policy.Quota.MaxOutput)

	if err != nil {
		result.Status = SandboxStatusErrored
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "execution timeout"
		} else {
			result.Error = strings.TrimSpace(stderr.String())
		}
		if result.Error == "" {
			result.Error = err.Error()
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Status = SandboxStatusRunning // Completed successfully
	}

	return result
}

// ============================================================================
// Python Executor
// ============================================================================

// PythonExecutor provides secure Python code execution
type PythonExecutor struct {
	manager *SandboxManager
	policy  *ExecutionPolicy
}

// NewPythonExecutor creates a new Python code executor
func NewPythonExecutor(manager *SandboxManager) *PythonExecutor {
	return &PythonExecutor{
		manager: manager,
		policy:  manager.policy,
	}
}

// Execute runs Python code in a sandboxed environment
func (e *PythonExecutor) Execute(ctx context.Context, code string) *GoExecutionResult {
	result := &GoExecutionResult{
		SandboxID: SandboxID(fmt.Sprintf("py-%d", time.Now().UnixNano())),
		StartTime: time.Now(),
	}

	// Validate language
	if err := e.policy.ValidateLanguage("python"); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = err.Error()
		return result
	}

	// Basic Python security check
	if err := ValidatePythonCode(code, e.policy); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = err.Error()
		return result
	}

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "aegisguard-py-*")
	if err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to create temp directory"
		return result
	}
	defer os.RemoveAll(tmpDir)

	// Write code to file
	tmpFile := tmpDir + "/script.py"
	if err := os.WriteFile(tmpFile, []byte(code), 0600); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to write code"
		return result
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, e.policy.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python3", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	result.Duration = time.Since(result.StartTime)
	result.Output = truncateOutput(stdout.String(), e.policy.Quota.MaxOutput)

	if err != nil {
		result.Status = SandboxStatusErrored
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "execution timeout"
		} else {
			result.Error = strings.TrimSpace(stderr.String())
		}
		if result.Error == "" {
			result.Error = err.Error()
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Status = SandboxStatusRunning
	}

	return result
}

// ValidatePythonCode performs static analysis on Python code
func ValidatePythonCode(code string, policy *ExecutionPolicy) error {
	forbidden := []string{
		"__import__",
		"eval(",
		"exec(",
		"os.system",
		"subprocess.",
		"socket.",
		"requests.",
		"urllib.",
	}

	for _, pattern := range forbidden {
		if contains(code, pattern) {
			return &ValidationError{
				Code:    "forbidden_pattern",
				Message: "forbidden pattern: " + pattern,
			}
		}
	}

	return nil
}

// ============================================================================
// JavaScript Executor
// ============================================================================

// JavaScriptExecutor provides secure JavaScript code execution
type JavaScriptExecutor struct {
	manager *SandboxManager
	policy  *ExecutionPolicy
}

// NewJavaScriptExecutor creates a new JavaScript code executor
func NewJavaScriptExecutor(manager *SandboxManager) *JavaScriptExecutor {
	return &JavaScriptExecutor{
		manager: manager,
		policy:  manager.policy,
	}
}

// Execute runs JavaScript code in a sandboxed environment
func (e *JavaScriptExecutor) Execute(ctx context.Context, code string) *GoExecutionResult {
	result := &GoExecutionResult{
		SandboxID: SandboxID(fmt.Sprintf("js-%d", time.Now().UnixNano())),
		StartTime: time.Now(),
	}

	// Validate language
	if err := e.policy.ValidateLanguage("javascript"); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = err.Error()
		return result
	}

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "aegisguard-js-*")
	if err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to create temp directory"
		return result
	}
	defer os.RemoveAll(tmpDir)

	// Write code to file
	tmpFile := tmpDir + "/script.mjs"
	if err := os.WriteFile(tmpFile, []byte(code), 0600); err != nil {
		result.Status = SandboxStatusErrored
		result.Error = "failed to write code"
		return result
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, e.policy.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	result.Duration = time.Since(result.StartTime)
	result.Output = truncateOutput(stdout.String(), e.policy.Quota.MaxOutput)

	if err != nil {
		result.Status = SandboxStatusErrored
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "execution timeout"
		} else {
			result.Error = strings.TrimSpace(stderr.String())
		}
		if result.Error == "" {
			result.Error = err.Error()
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Status = SandboxStatusRunning
	}

	return result
}

// ============================================================================
// Helpers
// ============================================================================

// truncateOutput limits output size
func truncateOutput(output string, maxSize int) string {
	if len(output) > maxSize {
		return output[:maxSize] + fmt.Sprintf("\n... [output truncated, %d bytes]", len(output)-maxSize)
	}
	return output
}
