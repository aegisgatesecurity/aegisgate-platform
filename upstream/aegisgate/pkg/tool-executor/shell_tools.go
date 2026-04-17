// Package tool-executor - Shell tool implementations
package toolexecutor

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// ShellTools provides shell command execution tools
type ShellTools struct {
	allowedCommands []string
	blockedCommands []string
	timeout        time.Duration
}

// NewShellTools creates a new shell tools executor
func NewShellTools(allowedCommands, blockedCommands []string, timeout time.Duration) *ShellTools {
	return &ShellTools{
		allowedCommands: allowedCommands,
		blockedCommands: blockedCommands,
		timeout:        timeout,
	}
}

// ShellCommandExecutor handles shell command execution
type ShellCommandExecutor struct {
	tools *ShellTools
}

// NewShellCommandExecutor creates a new shell command executor
func NewShellCommandExecutor(tools *ShellTools) *ShellCommandExecutor {
	return &ShellCommandExecutor{tools: tools}
}

// validateCommand delegates to ShellTools
func (e *ShellCommandExecutor) validateCommand(command string) error {
	return e.tools.validateCommand(command)
}

// validateScript delegates to ShellTools
func (e *ShellCommandExecutor) validateScript(script string) error {
	return e.tools.validateScript(script)
}

// Name returns the tool name
func (e *ShellCommandExecutor) Name() string {
	return "shell_command"
}

// Execute runs a shell command
func (e *ShellCommandExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	command, ok := params["command"].(string)
	if !ok || command == "" {
		return nil, errors.New("command parameter required")
	}

	// Security: validate command
	if err := e.validateCommand(command); err != nil {
		return nil, err
	}

	// Parse command and args
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, errors.New("empty command")
	}

	// Determine shell
	var cmd *exec.Cmd
	if len(parts) == 1 {
		cmd = exec.Command(parts[0])
	} else {
		// Use shell for complex commands
		cmd = exec.Command("sh", "-c", command)
	}

	cmd.Dir = "/" // Restrict to root

	// Execute with timeout
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("command timeout")
	case err := <-done:
		result := map[string]interface{}{
			"command":  command,
			"exit_code": -1,
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				result["exit_code"] = exitErr.ExitCode()
				result["error"] = "exit_error"
			} else {
				result["error"] = err.Error()
			}
		} else {
			result["exit_code"] = 0
		}

		result["stdout"] = stdout.String()
		result["stderr"] = stderr.String()

		return result, nil
	}
}

// Validate checks parameters
func (e *ShellCommandExecutor) Validate(params map[string]interface{}) error {
	command, ok := params["command"].(string)
	if !ok || command == "" {
		return errors.New("command parameter required")
	}

	// Block dangerous patterns
	dangerous := []string{"rm -rf", "dd if=", "mkfs", ":(){:|:&};:", "> /dev/sda", "| sh", "curl | sh", "wget -O- | sh"}
	for _, pattern := range dangerous {
		if strings.Contains(command, pattern) {
			return errors.New("command contains dangerous pattern")
		}
	}

	return e.validateCommand(command)
}

// Timeout returns the execution timeout
func (e *ShellCommandExecutor) Timeout() time.Duration {
	if e.tools.timeout > 0 {
		return e.tools.timeout
	}
	return 120 * time.Second // 2 minutes max
}

// RiskLevel returns the risk level
func (e *ShellCommandExecutor) RiskLevel() int {
	return int(RiskCritical)
}

// Description returns a description
func (e *ShellCommandExecutor) Description() string {
	return "Execute shell commands (HIGH RISK)"
}

// validateCommand checks if command is allowed
func (e *ShellTools) validateCommand(command string) error {
	// Check blocked commands
	for _, blocked := range e.blockedCommands {
		if strings.Contains(command, blocked) {
			return errors.New("command blocked by policy")
		}
	}

	// If allowed list is empty, allow all non-blocked
	if len(e.allowedCommands) == 0 {
		return nil
	}

	// Check allowed commands
	baseCmd := strings.Fields(command)[0]
	for _, allowed := range e.allowedCommands {
		if baseCmd == allowed || strings.HasPrefix(command, allowed+" ") {
			return nil
		}
	}

	return errors.New("command not in allowed list")
}

// BashExecutor handles bash script execution
type BashExecutor struct {
	tools *ShellTools
}

// NewBashExecutor creates a new bash executor
func NewBashExecutor(tools *ShellTools) *BashExecutor {
	return &BashExecutor{tools: tools}
}

// validateCommand delegates to ShellTools
func (e *BashExecutor) validateCommand(command string) error {
	return e.tools.validateCommand(command)
}

// validateScript delegates to ShellTools
func (e *BashExecutor) validateScript(script string) error {
	return e.tools.validateScript(script)
}

// Name returns the tool name
func (e *BashExecutor) Name() string {
	return "bash"
}

// Execute runs a bash script
func (e *BashExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	script, ok := params["script"].(string)
	if !ok || script == "" {
		return nil, errors.New("script parameter required")
	}

	// Security: validate script
	if err := e.validateScript(script); err != nil {
		return nil, err
	}

	cmd := exec.Command("bash", "-c", script)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("script timeout")
	case err := <-done:
		result := map[string]interface{}{
			"exit_code": -1,
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				result["exit_code"] = exitErr.ExitCode()
			}
		} else {
			result["exit_code"] = 0
		}

		result["stdout"] = stdout.String()
		result["stderr"] = stderr.String()

		return result, nil
	}
}

// Validate checks parameters
func (e *BashExecutor) Validate(params map[string]interface{}) error {
	script, ok := params["script"].(string)
	if !ok || script == "" {
		return errors.New("script parameter required")
	}
	return e.validateScript(script)
}

// Timeout returns the execution timeout
func (e *BashExecutor) Timeout() time.Duration {
	if e.tools.timeout > 0 {
		return e.tools.timeout
	}
	return 180 * time.Second // 3 minutes max
}

// RiskLevel returns the risk level
func (e *BashExecutor) RiskLevel() int {
	return int(RiskCritical)
}

// Description returns a description
func (e *BashExecutor) Description() string {
	return "Execute bash scripts (CRITICAL RISK)"
}

// validateScript checks if script is allowed
func (e *ShellTools) validateScript(script string) error {
	// Block dangerous patterns
	dangerous := []string{
		"rm -rf /",
		"dd if=",
		"mkfs",
		":(){:|:&};:",
		"> /dev/sda",
		"> /dev/hda",
		"curl | sh",
		"wget -O- | sh",
		":() { :|:& }; :",
		"forkbomb",
	}

	lower := strings.ToLower(script)
	for _, pattern := range dangerous {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return errors.New("script contains dangerous pattern")
		}
	}

	return nil
}

// PingExecutor handles ping operations
type PingExecutor struct {
	tools *ShellTools
}

// NewPingExecutor creates a new ping executor
func NewPingExecutor(tools *ShellTools) *PingExecutor {
	return &PingExecutor{tools: tools}
}

// Name returns the tool name
func (e *PingExecutor) Name() string {
	return "ping"
}

// Execute pings a host
func (e *PingExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	host, ok := params["host"].(string)
	if !ok || host == "" {
		return nil, errors.New("host parameter required")
	}

	// Limit to prevent abuse
	count := 4
	if c, ok := params["count"].(float64); ok {
		count = int(c)
		if count > 10 {
			count = 10
		}
	}

	cmd := exec.Command("ping", "-c", string(rune(count)), host)
	cmd.Dir = "/"

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("ping timeout")
	case err := <-done:
		result := map[string]interface{}{
			"host": host,
			"count": count,
		}

		if err != nil {
			result["error"] = stderr.String()
		} else {
			result["output"] = stdout.String()
		}

		return result, nil
	}
}

// Validate checks parameters
func (e *PingExecutor) Validate(params map[string]interface{}) error {
	host, ok := params["host"].(string)
	if !ok || host == "" {
		return errors.New("host parameter required")
	}
	return nil
}

// Timeout returns the execution timeout
func (e *PingExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *PingExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *PingExecutor) Description() string {
	return "Ping a host to check connectivity"
}
