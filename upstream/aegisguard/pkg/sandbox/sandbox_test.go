// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// ResourceQuota Tests
// ============================================================================

func TestDefaultResourceQuota(t *testing.T) {
	quota := DefaultResourceQuota()

	if quota.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", quota.Timeout)
	}
	if quota.MemoryLimit != 512<<20 {
		t.Errorf("MemoryLimit = %d, want 512MB", quota.MemoryLimit)
	}
	if quota.MaxOutput != 1<<20 {
		t.Errorf("MaxOutput = %d, want 1MB", quota.MaxOutput)
	}
}

// ============================================================================
// ExecutionPolicy Tests
// ============================================================================

func TestDefaultExecutionPolicy(t *testing.T) {
	policy := DefaultExecutionPolicy()

	if len(policy.AllowedLanguages) == 0 {
		t.Error("AllowedLanguages should not be empty")
	}

	found := false
	for _, lang := range policy.AllowedLanguages {
		if lang == "go" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Go should be in AllowedLanguages")
	}

	if policy.AllowNetwork {
		t.Error("AllowNetwork should be false by default")
	}
}

func TestExecutionPolicy_ValidateLanguage(t *testing.T) {
	policy := DefaultExecutionPolicy()

	tests := []struct {
		lang    string
		allowed bool
	}{
		{"go", true},
		{"python", true},
		{"javascript", true},
		{"ruby", false},
		{"bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.lang, func(t *testing.T) {
			err := policy.ValidateLanguage(tt.lang)
			if tt.allowed && err != nil {
				t.Errorf("ValidateLanguage(%s) returned error: %v", tt.lang, err)
			}
			if !tt.allowed && err == nil {
				t.Errorf("ValidateLanguage(%s) should have returned error", tt.lang)
			}
		})
	}
}

// ============================================================================
// SandboxManager Tests
// ============================================================================

func TestNewSandboxManager(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 5)

	if manager == nil {
		t.Fatal("NewSandboxManager returned nil")
	}
	if manager.maxSandboxes != 5 {
		t.Errorf("maxSandboxes = %d, want 5", manager.maxSandboxes)
	}
}

func TestSandboxManager_Create(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	sandbox, err := manager.Create("test-sandbox")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sandbox.ID != "test-sandbox" {
		t.Errorf("ID = %q, want %q", sandbox.ID, "test-sandbox")
	}
	if sandbox.Status != SandboxStatusCreated {
		t.Errorf("Status = %v, want %v", sandbox.Status, SandboxStatusCreated)
	}
}

func TestSandboxManager_Create_Duplicate(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	manager.Create("test-sandbox")
	_, err := manager.Create("test-sandbox")

	if err == nil {
		t.Error("Create() should return error for duplicate sandbox")
	}
}

func TestSandboxManager_Create_MaxSandboxes(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 2)

	manager.Create("sandbox-1")
	manager.Create("sandbox-2")

	_, err := manager.Create("sandbox-3")
	if err == nil {
		t.Error("Create() should return error when max sandboxes reached")
	}
}

func TestSandboxManager_Get(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	manager.Create("test-sandbox")

	sandbox, err := manager.Get("test-sandbox")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if sandbox.ID != "test-sandbox" {
		t.Errorf("ID = %q, want %q", sandbox.ID, "test-sandbox")
	}
}

func TestSandboxManager_Get_NotFound(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	_, err := manager.Get("nonexistent")
	if err == nil {
		t.Error("Get() should return error for nonexistent sandbox")
	}
}

func TestSandboxManager_Destroy(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	manager.Create("test-sandbox")

	err := manager.Destroy("test-sandbox")
	if err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}

	_, err = manager.Get("test-sandbox")
	if err == nil {
		t.Error("Get() should return error after Destroy()")
	}
}

func TestSandboxManager_List(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	manager.Create("sandbox-1")
	manager.Create("sandbox-2")
	manager.Create("sandbox-3")

	list := manager.List()
	if len(list) != 3 {
		t.Errorf("List() count = %d, want 3", len(list))
	}
}

func TestSandboxManager_Count(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	if count := manager.Count(); count != 0 {
		t.Errorf("Count() = %d, want 0", count)
	}

	manager.Create("sandbox-1")
	manager.Create("sandbox-2")

	if count := manager.Count(); count != 2 {
		t.Errorf("Count() = %d, want 2", count)
	}
}

func TestSandboxManager_Cleanup(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 10)

	s1, _ := manager.Create("sandbox-1")
	s1.Status = SandboxStatusStopped
	// Backdate ActiveAt to simulate idle sandbox
	s1.ActiveAt = time.Now().Add(-2 * time.Hour)

	s2, _ := manager.Create("sandbox-2")
	s2.Status = SandboxStatusRunning

	removed := manager.Cleanup(1 * time.Hour)

	if removed != 1 {
		t.Errorf("Cleanup() removed = %d, want 1", removed)
	}

	if manager.Count() != 1 {
		t.Errorf("Count() after cleanup = %d, want 1", manager.Count())
	}
}

// ============================================================================
// Code Validation Tests
// ============================================================================

func TestValidateGoCode_Basic(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `package main
import "fmt"
func main() {
    fmt.Println("Hello")
}`
	if err := ValidateGoCode(code, &policy); err != nil {
		t.Errorf("Valid code returned error: %v", err)
	}
}

func TestValidateGoCode_ForbiddenSyscall(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `package main
import "syscall"
func main() {
    syscall.Exit(1)
}`
	err := ValidateGoCode(code, &policy)
	if err == nil {
		t.Error("syscall should be forbidden")
	}
}

func TestValidateGoCode_ForbiddenExec(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `package main
import "os/exec"
func main() {
    exec.Command("ls")
}`
	err := ValidateGoCode(code, &policy)
	if err == nil {
		t.Error("exec.Command should be forbidden")
	}
}

func TestValidateGoCode_ForbiddenOsExit(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `package main
import "os"
func main() {
    os.Exit(0)
}`
	err := ValidateGoCode(code, &policy)
	if err == nil {
		t.Error("os.Exit should be forbidden")
	}
}

func TestValidateGoCode_NetworkAllowed(t *testing.T) {
	policy := DefaultExecutionPolicy()
	policy.AllowNetwork = true

	code := `package main
import "net/http"
func main() {
    http.Get("http://example.com")
}`
	if err := ValidateGoCode(code, &policy); err != nil {
		t.Errorf("http.Get should be allowed with AllowNetwork=true: %v", err)
	}
}

func TestValidatePythonCode_Basic(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `print("Hello")`
	if err := ValidatePythonCode(code, &policy); err != nil {
		t.Errorf("Valid code returned error: %v", err)
	}
}

func TestValidatePythonCode_ForbiddenEval(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `eval("print('hack')")`
	err := ValidatePythonCode(code, &policy)
	if err == nil {
		t.Error("eval should be forbidden")
	}
}

func TestValidatePythonCode_ForbiddenSubprocess(t *testing.T) {
	policy := DefaultExecutionPolicy()

	code := `import subprocess
subprocess.run(["ls"])`
	err := ValidatePythonCode(code, &policy)
	if err == nil {
		t.Error("subprocess should be forbidden")
	}
}

// ============================================================================
// Executor Tests
// ============================================================================

func TestGoExecutor_ValidationError(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 5)
	executor := NewGoExecutor(manager)

	code := `package main
import "syscall"
func main() {
    _ = syscall.SYS_EXIT
}`

	result := executor.Execute(context.Background(), code)
	if result.Status != SandboxStatusErrored {
		t.Errorf("Status = %v, want %v", result.Status, SandboxStatusErrored)
	}
	if result.Error == "" {
		t.Error("Error should be set for invalid code")
	}
}

func TestGoExecutor_Timeout(t *testing.T) {
	policy := DefaultExecutionPolicy()
	policy.Timeout = 100 * time.Millisecond
	manager := NewSandboxManager(&policy, 5)
	executor := NewGoExecutor(manager)

	code := `package main
import "time"
func main() {
    time.Sleep(10 * time.Second)
}`

	result := executor.Execute(context.Background(), code)
	if result.Status != SandboxStatusErrored {
		t.Errorf("Status = %v, want %v", result.Status, SandboxStatusErrored)
	}
	if !strings.Contains(result.Error, "timeout") {
		t.Errorf("Error should mention timeout, got: %s", result.Error)
	}
}

func TestPythonExecutor_ValidationError(t *testing.T) {
	policy := DefaultExecutionPolicy()
	manager := NewSandboxManager(&policy, 5)
	executor := NewPythonExecutor(manager)

	code := `exec("print('hack')")`

	result := executor.Execute(context.Background(), code)
	if result.Status != SandboxStatusErrored {
		t.Errorf("Status = %v, want %v", result.Status, SandboxStatusErrored)
	}
}

// ============================================================================
// ValidationError Tests
// ============================================================================

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Code: "test_code", Message: "test message"}
	if err.Error() != "test message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test message")
	}
}

func TestValidationError_ErrorNoMessage(t *testing.T) {
	err := &ValidationError{Code: "test_code"}
	if err.Error() != "validation error: test_code" {
		t.Errorf("Error() = %q, want %q", err.Error(), "validation error: test_code")
	}
}

// ============================================================================
// TruncateOutput Tests
// ============================================================================

func TestTruncateOutput(t *testing.T) {
	// Test truncation behavior
	result := truncateOutput("12345678901", 10) // 11 chars > 10 max
	if !strings.Contains(result, "truncated") {
		t.Errorf("11-char string with max=10 should be truncated, got: %s", result)
	}

	// Test no truncation when exactly at limit
	result2 := truncateOutput("1234567890", 10) // exactly 10 chars
	if result2 != "1234567890" {
		t.Errorf("10-char string with max=10 should not be truncated, got: %s", result2)
	}

	// Test no truncation when under limit
	result3 := truncateOutput("12345", 10) // 5 chars
	if result3 != "12345" {
		t.Errorf("5-char string with max=10 should not be truncated, got: %s", result3)
	}
}
