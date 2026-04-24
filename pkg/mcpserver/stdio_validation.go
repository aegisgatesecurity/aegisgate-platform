// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - STDIO Command Validation
// =========================================================================
//
// Validates commands received through MCP STDIO transport to prevent
// shell metacharacter injection attacks. This directly addresses the
// vulnerability described in OX Security's "Mother of All AI Supply Chains"
// advisory (2026-04) and Anthropic MCP SDK design vulnerability
// CVE-2025-XXXXX.
//
// The MCP STDIO transport executes arbitrary OS commands by design.
// AegisGate validates and rejects commands containing shell metacharacters
// before they reach the OS shell, enforcing an allowlist of safe characters.
//
// Architecture:
//   - OnSessionCreate: validates MCP server startup commands
//   - OnToolCall: validates command parameters in tool calls
//   - Standalone ValidateCommand(): reusable by any caller
//
// Allowlist: ^[a-zA-Z0-9/._-]+$
//   Letters, digits, forward slash, dot, underscore, hyphen.
//   This permits standard binary paths (e.g., /usr/bin/node, npx@1.2.3)
//   but rejects all shell metacharacters that enable injection.
//
// Blocklist patterns (from OX Security article):
//   Pipe:              |  (command chaining)
//   Semicolon:         ;  (command separator)
//   Logical AND/OR:    && ||  (conditional chaining)
//   Command substitution: $()  (subshell execution)
//   Backtick:          `  (command substitution)
//   Redirect:          > >> <  (file manipulation)
//   Newline:           \n  (command injection via multiline)
//   Wildcard:          * ?  (unintended file expansion)
//   Environment var:   $  (variable expansion)
//   Home dir:          ~  (path expansion)
//   Ampersand:         &  (background execution)
// =========================================================================

package mcpserver

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// ErrCommandBlocked is the error code returned when a command fails validation
	ErrCommandBlocked = "stdio_command_blocked"

	// ErrCommandEmpty is the error code for empty/whitespace-only commands
	ErrCommandEmpty = "stdio_command_empty"

	// ErrCommandTooLong is the error code when a command exceeds maximum length
	ErrCommandTooLong = "stdio_command_too_long"
)

// --------------------------------------------------------------------------
// Validation config
// --------------------------------------------------------------------------

// STDIOValidationConfig controls STDIO command validation behavior.
type STDIOValidationConfig struct {
	// Enabled controls whether STDIO command validation is active
	Enabled bool

	// MaxCommandLength is the maximum allowed command string length (0 = no limit)
	MaxCommandLength int

	// StrictMode uses the allowlist regex exclusively.
	// Non-strict mode additionally scans for known dangerous patterns.
	StrictMode bool

	// AllowedCommandPrefixes lists commands that are always allowed
	// regardless of other validation (e.g., "node", "python3", "npx").
	// These still undergo metacharacter checks.
	AllowedCommandPrefixes []string
}

// DefaultSTDIOValidationConfig returns secure defaults for Community tier.
func DefaultSTDIOValidationConfig() STDIOValidationConfig {
	return STDIOValidationConfig{
		Enabled:                true,
		MaxCommandLength:        4096,
		StrictMode:             true,
		AllowedCommandPrefixes: []string{"node", "python3", "python", "npx", "uvx", "bun", "deno"},
	}
}

// --------------------------------------------------------------------------
// Validation engine
// --------------------------------------------------------------------------

var (
	// commandAllowlist matches safe command characters only.
	// Permits: letters, digits, forward slash, dot, underscore, hyphen, at-sign (npm versions).
	// Blocks: |;&$`\><!*?~(){}[]^%#@"' space and newline
	// Note: hyphen is first in class to be treated as literal; @ is at the end.
	commandAllowlist = regexp.MustCompile(`^[a-zA-Z0-9/._@\-]+$`)

	// dangerousPatterns maps metacharacter classes to their descriptions.
	// Used in non-strict mode and for detailed error reporting.
	dangerousPatterns = map[string]*regexp.Regexp{
		"pipe_chaining":        regexp.MustCompile(`\|`),
		"command_separator":   regexp.MustCompile(`;`),
		"logical_chaining":    regexp.MustCompile(`&&|\|\|`),
		"command_substitution": regexp.MustCompile(`\$\(|\)`),
		"backtick_exec":       regexp.MustCompile("`"),
		"redirect":            regexp.MustCompile(`>|<|>>`),
		"newline_injection":   regexp.MustCompile(`\n|\r`),
		"wildcard_expansion":  regexp.MustCompile(`\*|\?`),
		"variable_expansion":  regexp.MustCompile(`\$[a-zA-Z_]|$\{`),
		"home_expansion":      regexp.MustCompile(`~`),
		"background_exec":     regexp.MustCompile(`&`),
	}

	// argSeparatorPattern matches characters used to separate arguments
	// that are NOT shell metacharacters (space, equals, colon)
	argSeparatorPattern = regexp.MustCompile(`[\s=:]`)
)

// STDIOValidator validates MCP STDIO commands against injection attacks.
type STDIOValidator struct {
	config STDIOValidationConfig

	// Metrics
	totalValidations   int64
	blockedValidations int64
	blockedByPattern   map[string]int64
	mu                  sync.RWMutex
}

// NewSTDIOValidator creates a new validator with the given config.
func NewSTDIOValidator(cfg STDIOValidationConfig) *STDIOValidator {
	return &STDIOValidator{
		config:           cfg,
		blockedByPattern:  make(map[string]int64),
	}
}

// ValidateCommand checks whether a command string is safe to execute.
// Returns nil if the command passes validation, or an error describing
// why it was blocked.
//
// Validation order:
//  1. Empty/whitespace check
//  2. Length check
//  3. Allowlist regex check (strict: primary; non-strict: first pass)
//  4. Known dangerous pattern scan (non-strict mode, or for error detail in strict mode)
func (v *STDIOValidator) ValidateCommand(cmd string) error {
	if !v.config.Enabled {
		return nil
	}

	atomic.AddInt64(&v.totalValidations, 1)

	// Guard 1: Empty or whitespace-only command
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		atomic.AddInt64(&v.blockedValidations, 1)
		v.recordBlock("empty_command")
		return fmt.Errorf("%s: command is empty or whitespace-only", ErrCommandEmpty)
	}

	// Guard 1b: Newline injection check (before trimming changes the input)
	if strings.ContainsAny(cmd, "\n\r") {
		atomic.AddInt64(&v.blockedValidations, 1)
		v.recordBlock("newline_injection")
		return fmt.Errorf("%s: command contains newline (command injection attempt)", ErrCommandBlocked)
	}

	// Guard 2: Command length limit
	if v.config.MaxCommandLength > 0 && len(cmd) > v.config.MaxCommandLength {
		atomic.AddInt64(&v.blockedValidations, 1)
		v.recordBlock("length_exceeded")
		return fmt.Errorf("%s: command length %d exceeds maximum %d",
			ErrCommandTooLong, len(cmd), v.config.MaxCommandLength)
	}

	// Guard 3: Allowlist check (strict mode — primary gate)
	// Split on argument separators to validate each token independently.
	// This allows commands like "node server.js --port 3000" where spaces
	// separate safe tokens, while still blocking "node; rm -rf /".
	tokens := argSeparatorPattern.Split(trimmed, -1)
	for _, token := range tokens {
		if token == "" {
			continue // skip empty tokens from consecutive separators
		}
		if !commandAllowlist.MatchString(token) {
			// Token contains disallowed characters — find which ones
			violations := v.identifyViolations(token)
			atomic.AddInt64(&v.blockedValidations, 1)

			if len(violations) > 0 {
				v.recordBlock(violations[0].Pattern)
				return fmt.Errorf("%s: command contains shell metacharacter [%s] in token %q (%s)",
					ErrCommandBlocked, violations[0].Metachar, token, violations[0].Description)
			}

			v.recordBlock("allowlist_violation")
			return fmt.Errorf("%s: command token %q contains disallowed characters", ErrCommandBlocked, token)
		}
	}

	// Guard 4: Dangerous pattern scan (non-strict mode, also used for logging in strict mode)
	if !v.config.StrictMode {
		for patternName, pattern := range dangerousPatterns {
			if pattern.MatchString(cmd) {
				atomic.AddInt64(&v.blockedValidations, 1)
				v.recordBlock(patternName)
				return fmt.Errorf("%s: command matches dangerous pattern %q",
					ErrCommandBlocked, patternName)
			}
		}
	}

	return nil
}

// ValidateToolParameter validates a command-like parameter within a tool call.
// This is the key integration point for the GuardrailHandler: when a tool like
// shell_command or bash receives a "command" argument, ValidateToolParameter
// checks it before execution.
//
// Returns nil if the parameter is safe, or an error if it should be blocked.
func (v *STDIOValidator) ValidateToolParameter(toolName, paramName, paramValue string) error {
	if !v.config.Enabled {
		return nil
	}

	// Only validate command-like parameters
	lowerParam := strings.ToLower(paramName)
	if lowerParam != "command" && lowerParam != "cmd" && lowerParam != "script" &&
		lowerParam != "code" && lowerParam != "query" && lowerParam != "expression" {
		return nil
	}

	// Always validate command parameters regardless of tool
	// (even "safe" tools shouldn't inject shell commands)
	if err := v.ValidateCommand(paramValue); err != nil {
		return fmt.Errorf("tool %s parameter %q failed STDIO validation: %w",
			toolName, paramName, err)
	}

	return nil
}

// IsEnabled returns whether STDIO validation is active.
func (v *STDIOValidator) IsEnabled() bool {
	return v.config.Enabled
}

// IdentifyDangerousPatterns returns a list of dangerous pattern names
// matched in the given command string. Used for detailed logging.
func (v *STDIOValidator) IdentifyDangerousPatterns(cmd string) []string {
	var matched []string
	for name, pattern := range dangerousPatterns {
		if pattern.MatchString(cmd) {
			matched = append(matched, name)
		}
	}
	return matched
}

// Stats returns current validation statistics.
type STDIOValidationStats struct {
	TotalValidations   int64            `json:"total_validations"`
	BlockedValidations int64            `json:"blocked_validations"`
	BlockedByPattern   map[string]int64 `json:"blocked_by_pattern"`
	Enabled            bool             `json:"enabled"`
	StrictMode         bool             `json:"strict_mode"`
	MaxCommandLength   int              `json:"max_command_length"`
}

// GetStats returns a snapshot of validation statistics.
func (v *STDIOValidator) GetStats() STDIOValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	blockedByPattern := make(map[string]int64, len(v.blockedByPattern))
	for k, val := range v.blockedByPattern {
		blockedByPattern[k] = atomic.LoadInt64(&val)
	}

	return STDIOValidationStats{
		TotalValidations:   atomic.LoadInt64(&v.totalValidations),
		BlockedValidations: atomic.LoadInt64(&v.blockedValidations),
		BlockedByPattern:   blockedByPattern,
		Enabled:            v.config.Enabled,
		StrictMode:         v.config.StrictMode,
		MaxCommandLength:   v.config.MaxCommandLength,
	}
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// violation describes a single metacharacter violation in a command token.
type violation struct {
	Pattern     string // e.g., "pipe_chaining"
	Metachar   string // e.g., "|"
	Description string // e.g., "pipe/command chaining"
}

// identifyViolations finds which dangerous patterns are present in a token.
// Used for detailed error reporting when the allowlist check fails.
func (v *STDIOValidator) identifyViolations(token string) []violation {
	var violations []violation

	for name, pattern := range dangerousPatterns {
		loc := pattern.FindStringIndex(token)
		if loc != nil {
			matched := token[loc[0]:loc[1]]
			violations = append(violations, violation{
				Pattern:     name,
				Metachar:   matched,
				Description: dangerousPatternDescription(name),
			})
		}
	}

	return violations
}

// dangerousPatternDescription returns a human-readable description for a pattern name.
func dangerousPatternDescription(name string) string {
	descriptions := map[string]string{
		"pipe_chaining":         "pipe/command chaining",
		"command_separator":     "command separator",
		"logical_chaining":      "logical AND/OR chaining",
		"command_substitution":  "command substitution/subshell",
		"backtick_exec":         "backtick command substitution",
		"redirect":              "file redirect",
		"newline_injection":     "newline injection",
		"wildcard_expansion":    "wildcard expansion",
		"variable_expansion":    "variable expansion",
		"home_expansion":        "home directory expansion",
		"background_exec":       "background execution",
	}
	if desc, ok := descriptions[name]; ok {
		return desc
	}
	return "unknown dangerous pattern"
}

// recordBlock increments the block counter for a specific pattern.
func (v *STDIOValidator) recordBlock(pattern string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	current, exists := v.blockedByPattern[pattern]
	if !exists {
		v.blockedByPattern[pattern] = 1
	} else {
		v.blockedByPattern[pattern] = current + 1
	}
}