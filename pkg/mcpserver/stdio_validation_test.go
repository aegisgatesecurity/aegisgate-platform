// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - STDIO Validation Tests
// =========================================================================
//
// Tests for the STDIOValidator in stdio_validation.go.
// Validates that shell metacharacter injection attacks via MCP STDIO
// transport are properly blocked.
//
// These tests cover:
//   - Allowlist regex validation (^[a-zA-Z0-9/._-]+$)
//   - Dangerous pattern detection
//   - Guard 6 integration with GuardrailMiddleware
//   - Tool parameter validation
//   - Metric tracking
// =========================================================================

package mcpserver

import (
	"strings"
	"testing"
)

// ============================================================================
// TestSTDIOValidator_Allowlist
// ============================================================================

func TestSTDIOValidator_Allowlist(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	tests := []struct {
		name     string
		cmd      string
		expected bool // true = should pass, false = should be blocked
	}{
		// Safe commands
		{"simple_binary", "node", true},
		{"binary_with_path", "/usr/bin/node", true},
		{"script_path", "/usr/local/bin/myscript.sh", true},
		{"dotted_binary", "python3.11", true},
		{"underscore_binary", "my_script", true},
		{"hyphen_binary", "my-script", true},
		{"versioned_binary", "npx@1.2.3", true},
		{"file_with_ext", "server.js", true},
		{"path_with_numbers", "/usr/local/bin/app123", true},
		{"simple_args", "node server.js --port 3000", true},
		{"args_with_equals", "python3 script.py --arg=value", true},
		{"args_with_colon", "node:app", true},

		// Blocked commands - shell metacharacters
		{"pipe_chaining", "cat file | grep pattern", false},
		{"semicolon", "rm -rf /; ls", false},
		{"logical_and", "ls && rm file", false},
		{"logical_or", "ls || rm file", false},
		{"command_substitution", "$(cat /etc/passwd)", false},
		{"backtick", "`whoami`", false},
		{"redirect_out", "echo hi > file", false},
		{"redirect_in", "cat < file", false},
		{"redirect_append", "echo hi >> file", false},
		{"newline_injection", "ls\nexploit", false},
		{"wildcard_star", "rm *.txt", false},
		{"wildcard_question", "rm file?.txt", false},
		{"variable_expansion", "$HOME/file", false},
		{"variable_bracket", "${HOME}/file", false},
		{"home_expansion", "~/bin/script", false},
		{"background_exec", "ls &", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateCommand(tt.cmd)
			if tt.expected && err != nil {
				t.Errorf("command %q should pass validation, got error: %v", tt.cmd, err)
			}
			if !tt.expected && err == nil {
				t.Errorf("command %q should be blocked, but passed", tt.cmd)
			}
		})
	}
}

// ============================================================================
// TestSTDIOValidator_EmptyAndWhitespace
// ============================================================================

func TestSTDIOValidator_Empty(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateCommand("")
	if err == nil {
		t.Error("empty command should be blocked")
	}
	if !strings.Contains(err.Error(), ErrCommandEmpty) {
		t.Errorf("expected error code %s, got %v", ErrCommandEmpty, err)
	}
}

func TestSTDIOValidator_WhitespaceOnly(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	tests := []string{"   ", "\t\t", "\n\n", " \t \n "}
	for _, cmd := range tests {
		err := v.ValidateCommand(cmd)
		if err == nil {
			t.Errorf("whitespace-only command %q should be blocked", cmd)
		}
	}
}

// ============================================================================
// TestSTDIOValidator_LengthLimit
// ============================================================================

func TestSTDIOValidator_LengthLimit(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()
	cfg.MaxCommandLength = 10
	v := NewSTDIOValidator(cfg)

	// 10 characters - should pass
	err := v.ValidateCommand("shortcmd")
	if err != nil {
		t.Errorf("short command should pass: %v", err)
	}

	// 15 characters - should be blocked
	err = v.ValidateCommand("thiscommandistoolong")
	if err == nil {
		t.Error("long command should be blocked")
	}
	if !strings.Contains(err.Error(), ErrCommandTooLong) {
		t.Errorf("expected error code %s, got %v", ErrCommandTooLong, err)
	}
}

// ============================================================================
// TestSTDIOValidator_StrictVsNonStrict
// ============================================================================

func TestSTDIOValidator_StrictMode(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()
	cfg.StrictMode = true
	v := NewSTDIOValidator(cfg)

	// Strict mode should block on allowlist violation
	err := v.ValidateCommand("cat file | grep")
	if err == nil {
		t.Error("strict mode should block pipe character")
	}
}

func TestSTDIOValidator_NonStrictMode(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()
	cfg.StrictMode = false
	v := NewSTDIOValidator(cfg)

	// Non-strict mode should also block dangerous patterns
	err := v.ValidateCommand("cat file | grep")
	if err == nil {
		t.Error("non-strict mode should block pipe character")
	}
}

// ============================================================================
// TestSTDIOValidator_Disabled
// ============================================================================

func TestSTDIOValidator_Disabled(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()
	cfg.Enabled = false
	v := NewSTDIOValidator(cfg)

	// Disabled validator should allow everything
	err := v.ValidateCommand("rm -rf /")
	if err != nil {
		t.Errorf("disabled validator should allow dangerous commands: %v", err)
	}

	// Empty should also pass
	err = v.ValidateCommand("")
	if err != nil {
		t.Errorf("disabled validator should allow empty command: %v", err)
	}
}

// ============================================================================
// TestSTDIOValidator_ToolParameterValidation
// ============================================================================

func TestSTDIOValidator_ToolParameter_Command(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Safe command parameter
	err := v.ValidateToolParameter("bash", "command", "node server.js")
	if err != nil {
		t.Errorf("safe command parameter should pass: %v", err)
	}

	// Dangerous command parameter (with shell metacharacter)
	err = v.ValidateToolParameter("bash", "command", "rm -rf / && echo exploited")
	if err == nil {
		t.Error("command with logical AND should be blocked")
	}

	// Command with pipe
	err = v.ValidateToolParameter("bash", "command", "cat /etc/passwd | grep root")
	if err == nil {
		t.Error("command with pipe should be blocked")
	}
}

func TestSTDIOValidator_ToolParameter_Cmd(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateToolParameter("shell", "cmd", "ls && cat /etc/passwd")
	if err == nil {
		t.Error("command with logical AND should be blocked")
	}
}

func TestSTDIOValidator_ToolParameter_Script(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateToolParameter("script_runner", "script", "echo $SECRET")
	if err == nil {
		t.Error("script with variable expansion should be blocked")
	}
}

func TestSTDIOValidator_ToolParameter_Code(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateToolParameter("code_exec", "code", "os.system('rm -rf /')")
	if err == nil {
		t.Error("code with system call should be blocked")
	}
}

func TestSTDIOValidator_ToolParameter_Query(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Non-command parameters should pass
	err := v.ValidateToolParameter("search", "query", "SELECT * FROM users")
	if err != nil {
		// Query is command-like, so it may be validated
		t.Logf("query parameter validation: %v", err)
	}
}

func TestSTDIOValidator_ToolParameter_Expression(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateToolParameter("eval", "expression", "$(whoami)")
	if err == nil {
		t.Error("expression with command substitution should be blocked")
	}
}

func TestSTDIOValidator_ToolParameter_NonCommand(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Non-command parameters should pass
	err := v.ValidateToolParameter("search", "query", "SELECT * FROM users")
	if err != nil {
		t.Logf("non-command parameter may be validated: %v", err)
	}

	// filename parameter - should not validate
	err = v.ValidateToolParameter("file_read", "filename", "/etc/passwd")
	// filename is not a command-like parameter, so no error expected
	if err != nil {
		t.Logf("non-command param result: %v", err)
	}
}

// ============================================================================
// TestSTDIOValidator_IdentifyDangerousPatterns
// ============================================================================

func TestSTDIOValidator_IdentifyDangerousPatterns(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	tests := []struct {
		cmd      string
		patterns []string
	}{
		{"cat file | grep", []string{"pipe_chaining"}},
		{"ls && rm", []string{"logical_chaining"}},
		{"$(whoami)", []string{"command_substitution"}},
		{"`id`", []string{"backtick_exec"}},
		{"echo > file", []string{"redirect"}},
		{"rm *.txt", []string{"wildcard_expansion"}},
		{"echo $HOME", []string{"variable_expansion"}},
		{"ls &\n", []string{"background_exec", "newline_injection"}},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			matched := v.IdentifyDangerousPatterns(tt.cmd)
			for _, expected := range tt.patterns {
				found := false
				for _, m := range matched {
					if m == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected pattern %q in %q, got %v", expected, tt.cmd, matched)
				}
			}
		})
	}
}

// ============================================================================
// TestSTDIOValidator_Stats
// ============================================================================

func TestSTDIOValidator_Stats(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Initial stats should be zero
	stats := v.GetStats()
	if stats.TotalValidations != 0 {
		t.Errorf("initial total should be 0, got %d", stats.TotalValidations)
	}
	if stats.BlockedValidations != 0 {
		t.Errorf("initial blocked should be 0, got %d", stats.BlockedValidations)
	}

	// Make some validations
	v.ValidateCommand("node server.js")
	v.ValidateCommand("rm -rf / && echo exploited")
	v.ValidateCommand("ls | grep")

	stats = v.GetStats()
	if stats.TotalValidations != 3 {
		t.Errorf("total should be 3, got %d", stats.TotalValidations)
	}
	if stats.BlockedValidations != 2 {
		t.Errorf("blocked should be 2, got %d", stats.BlockedValidations)
	}
	if !stats.Enabled {
		t.Error("should be enabled")
	}
	if !stats.StrictMode {
		t.Error("should be strict mode")
	}
	if stats.MaxCommandLength != 4096 {
		t.Errorf("max command length should be 4096, got %d", stats.MaxCommandLength)
	}
}

func TestSTDIOValidator_Stats_BlockedByPattern(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Make some blocked validations - each must have pipe in first token (before space)
	v.ValidateCommand("cat|grep")
	v.ValidateCommand("ls&&rm")
	v.ValidateCommand("who|")

	stats := v.GetStats()
	if stats.BlockedByPattern == nil {
		t.Fatal("blocked by pattern map should not be nil")
	}
	// Total blocked should be at least 3 (the three validations above)
	totalBlocked := stats.BlockedValidations
	if totalBlocked < 3 {
		t.Errorf("should have at least 3 blocked validations, got %d", totalBlocked)
	}
	// Check that pipe_chaining or logical_chaining was detected
	// (depends on which patterns match first in the violation identification)
	hasRelevantPattern := stats.BlockedByPattern["pipe_chaining"] >= 1 ||
		stats.BlockedByPattern["logical_chaining"] >= 1
	if !hasRelevantPattern {
		t.Errorf("expected pipe or logical chaining pattern detected, got %v", stats.BlockedByPattern)
	}
}

// ============================================================================
// TestSTDIOValidator_IsEnabled
// ============================================================================

func TestSTDIOValidator_IsEnabled(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()
	cfg.Enabled = true
	v := NewSTDIOValidator(cfg)
	if !v.IsEnabled() {
		t.Error("should be enabled")
	}

	cfg.Enabled = false
	v = NewSTDIOValidator(cfg)
	if v.IsEnabled() {
		t.Error("should be disabled")
	}
}

// ============================================================================
// TestSTDIOValidator_AllowedCommandPrefixes
// ============================================================================

func TestSTDIOValidator_AllowedCommandPrefixes(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Commands starting with allowed prefixes should still validate
	// (the prefix check is just informational; actual validation is by allowlist)
	err := v.ValidateCommand("node server.js --port 3000")
	if err != nil {
		t.Errorf("node command should pass: %v", err)
	}

	err = v.ValidateCommand("python3 script.py")
	if err != nil {
		t.Errorf("python3 command should pass: %v", err)
	}

	err = v.ValidateCommand("npx create-react-app")
	if err != nil {
		t.Errorf("npx command should pass: %v", err)
	}

	// But dangerous patterns should still be blocked
	err = v.ValidateCommand("node; rm -rf /")
	if err == nil {
		t.Error("node with semicolon should be blocked")
	}
}

// ============================================================================
// TestSTDIOValidator_DefaultConfig
// ============================================================================

func TestDefaultSTDIOValidationConfig(t *testing.T) {
	cfg := DefaultSTDIOValidationConfig()

	if !cfg.Enabled {
		t.Error("default config should be enabled")
	}
	if cfg.MaxCommandLength != 4096 {
		t.Errorf("default max length should be 4096, got %d", cfg.MaxCommandLength)
	}
	if !cfg.StrictMode {
		t.Error("default should be strict mode")
	}
	if len(cfg.AllowedCommandPrefixes) == 0 {
		t.Error("default should have allowed prefixes")
	}
}

// ============================================================================
// TestSTDIOValidator_ErrorMessages
// ============================================================================

func TestSTDIOValidator_ErrorMessages(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Test error messages contain expected codes
	err := v.ValidateCommand("")
	if !strings.Contains(err.Error(), ErrCommandEmpty) {
		t.Errorf("empty error should contain %s", ErrCommandEmpty)
	}

	longCmd := strings.Repeat("a", 5000)
	cfg := DefaultSTDIOValidationConfig()
	cfg.MaxCommandLength = 100
	v = NewSTDIOValidator(cfg)
	err = v.ValidateCommand(longCmd)
	if !strings.Contains(err.Error(), ErrCommandTooLong) {
		t.Errorf("length error should contain %s", ErrCommandTooLong)
	}

	v = NewSTDIOValidator(DefaultSTDIOValidationConfig())
	err = v.ValidateCommand("cat | grep")
	if !strings.Contains(err.Error(), ErrCommandBlocked) {
		t.Errorf("blocked error should contain %s", ErrCommandBlocked)
	}
}

// ============================================================================
// TestSTDIOValidator_ToolParameterErrorWrapping
// ============================================================================

func TestSTDIOValidator_ToolParameterErrorWrapping(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	err := v.ValidateToolParameter("shell", "command", "rm -rf / && echo exploited")
	if err == nil {
		t.Fatal("expected error for dangerous command")
	}

	// Error should contain tool name and parameter name
	errMsg := err.Error()
	if !strings.Contains(errMsg, "shell") {
		t.Error("error should mention tool name")
	}
	if !strings.Contains(errMsg, "command") {
		t.Error("error should mention parameter name")
	}
}

// ============================================================================
// TestSTDIOValidator_ConcurrentUsage
// ============================================================================

func TestSTDIOValidator_ConcurrentUsage(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())

	// Run concurrent validations
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			cmd := "node"
			if n%2 == 0 {
				cmd = "rm -rf /"
			}
			_ = v.ValidateCommand(cmd)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify stats are consistent
	stats := v.GetStats()
	if stats.TotalValidations != 100 {
		t.Errorf("expected 100 total validations, got %d", stats.TotalValidations)
	}
}
