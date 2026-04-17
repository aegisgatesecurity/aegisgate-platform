// Package tool-executor - Code execution tools
package toolexecutor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CodeTools provides code execution tools
type CodeTools struct {
	sandboxDir string
	timeout    time.Duration
}

// NewCodeTools creates a new code tools executor
func NewCodeTools(sandboxDir string, timeout time.Duration) *CodeTools {
	if sandboxDir == "" {
		sandboxDir = "/tmp/aegisguard-sandbox"
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return &CodeTools{
		sandboxDir: sandboxDir,
		timeout:    timeout,
	}
}

// GoExecutor handles Go code execution
type GoExecutor struct {
	tools *CodeTools
}

// NewGoExecutor creates a new Go executor
func NewGoExecutor(tools *CodeTools) *GoExecutor {
	return &GoExecutor{tools: tools}
}

// Name returns the tool name
func (e *GoExecutor) Name() string {
	return "code_execute_go"
}

// Execute runs Go code
func (e *GoExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code parameter required")
	}

	// Security: validate code
	if err := e.validateCode(code); err != nil {
		return nil, err
	}

	// Create temporary file
	tmpFile := "/tmp/aegisguard_go_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".go"
	defer func() {
		// Cleanup handled by OS
	}()

	// Write code
	// Note: In production, use secure file operations
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > %s", strings.ReplaceAll(code, "'", "'\"'\"'"), tmpFile))

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to write code: %w", err)
	}

	// Run code
	execCmd := exec.CommandContext(ctx, "go", "run", tmpFile)
	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- execCmd.Run()
	}()

	select {
	case <-ctx.Done():
		execCmd.Process.Kill()
		return nil, errors.New("execution timeout")
	case err := <-done:
		result := map[string]interface{}{
			"language": "go",
			"exit_code": -1,
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				result["exit_code"] = exitErr.ExitCode()
			}
			result["stderr"] = stderr.String()
		} else {
			result["exit_code"] = 0
			result["stdout"] = stdout.String()
		}

		return result, nil
	}
}

// Validate checks parameters
func (e *GoExecutor) Validate(params map[string]interface{}) error {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return errors.New("code parameter required")
	}

	// Block dangerous imports
	dangerous := []string{"os/exec", "syscall", "net/http/httputil", "crypto/tls"}
	for _, pattern := range dangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden import: %s", pattern)
		}
	}

	return nil
}

// Timeout returns the execution timeout
func (e *GoExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *GoExecutor) RiskLevel() int {
	return int(RiskHigh)
}

// Description returns a description
func (e *GoExecutor) Description() string {
	return "Execute Go code"
}

// validateCode validates code for safety
func (e *GoExecutor) validateCode(code string) error {
	// Block network operations
	networkDangerous := []string{"http.Get", "http.Post", "net.Dial", "net.Listen"}
	for _, pattern := range networkDangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden network operation: %s", pattern)
		}
	}
	return nil
}

// PythonExecutor handles Python code execution
type PythonExecutor struct {
	tools *CodeTools
}

// NewPythonExecutor creates a new Python executor
func NewPythonExecutor(tools *CodeTools) *PythonExecutor {
	return &PythonExecutor{tools: tools}
}

// Name returns the tool name
func (e *PythonExecutor) Name() string {
	return "code_execute_python"
}

// Execute runs Python code
func (e *PythonExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code parameter required")
	}

	// Security: validate code
	if err := e.validateCode(code); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "python3", "-c", code)

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
		return nil, errors.New("execution timeout")
	case err := <-done:
		result := map[string]interface{}{
			"language": "python",
			"exit_code": -1,
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				result["exit_code"] = exitErr.ExitCode()
			}
			result["stderr"] = stderr.String()
		} else {
			result["exit_code"] = 0
			result["stdout"] = stdout.String()
		}

		return result, nil
	}
}

// Validate checks parameters
func (e *PythonExecutor) Validate(params map[string]interface{}) error {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return errors.New("code parameter required")
	}

	// Block dangerous imports
	dangerous := []string{"subprocess", "os.system", "os.popen", "pty", "tty", "fcntl.ioctl", "resource.setrlimit"}
	for _, pattern := range dangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden import/function: %s", pattern)
		}
	}

	return nil
}

// Timeout returns the execution timeout
func (e *PythonExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *PythonExecutor) RiskLevel() int {
	return int(RiskHigh)
}

// Description returns a description
func (e *PythonExecutor) Description() string {
	return "Execute Python code"
}

// validateCode validates Python code for safety
func (e *PythonExecutor) validateCode(code string) error {
	// Block file operations
	fileDangerous := []string{"open(", "io.open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}
	for _, pattern := range fileDangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden file operation: %s", pattern)
		}
	}
	return nil
}

// JavaScriptExecutor handles JavaScript code execution
type JavaScriptExecutor struct {
	tools *CodeTools
}

// NewJavaScriptExecutor creates a new JavaScript executor
func NewJavaScriptExecutor(tools *CodeTools) *JavaScriptExecutor {
	return &JavaScriptExecutor{tools: tools}
}

// Name returns the tool name
func (e *JavaScriptExecutor) Name() string {
	return "code_execute_javascript"
}

// Execute runs JavaScript code
func (e *JavaScriptExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code parameter required")
	}

	// Security: validate code
	if err := e.validateCode(code); err != nil {
		return nil, err
	}

	// Try Node.js first, then Deno
	var stdout, stderr bytes.Buffer
	var runErr error

	nodeCmd := exec.CommandContext(ctx, "node", "-e", code)
	nodeCmd.Stdout = &stdout
	nodeCmd.Stderr = &stderr
	runErr = nodeCmd.Run()

	if runErr != nil {
		// Try Deno as fallback
		denoCmd := exec.CommandContext(ctx, "deno", "eval", code)
		denoCmd.Stdout = &stdout
		denoCmd.Stderr = &stderr
		runErr = denoCmd.Run()
	}

	result := map[string]interface{}{
		"language": "javascript",
		"exit_code": -1,
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result["exit_code"] = exitErr.ExitCode()
		}
		result["stderr"] = stderr.String()
	} else {
		result["exit_code"] = 0
		result["stdout"] = stdout.String()
	}

	return result, nil
}

// Validate checks parameters
func (e *JavaScriptExecutor) Validate(params map[string]interface{}) error {
	code, ok := params["code"].(string)
	if !ok || code == "" {
		return errors.New("code parameter required")
	}

	// Block dangerous APIs
	dangerous := []string{"require('child_process')", "eval(", "Function(", "vm.compileFunction", "fs.writeFile", "fs.unlink"}
	for _, pattern := range dangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden API: %s", pattern)
		}
	}

	return nil
}

// Timeout returns the execution timeout
func (e *JavaScriptExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *JavaScriptExecutor) RiskLevel() int {
	return int(RiskHigh)
}

// Description returns a description
func (e *JavaScriptExecutor) Description() string {
	return "Execute JavaScript code"
}

// validateCode validates JavaScript code for safety
func (e *JavaScriptExecutor) validateCode(code string) error {
	// Block network operations
	networkDangerous := []string{"http.request", "https.request", "net.connect", "tls.connect", "dns.lookup"}
	for _, pattern := range networkDangerous {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("code contains forbidden network API: %s", pattern)
		}
	}
	return nil
}

// CodeSearchExecutor handles code search operations
type CodeSearchExecutor struct{}

// NewCodeSearchExecutor creates a new code search executor
func NewCodeSearchExecutor() *CodeSearchExecutor {
	return &CodeSearchExecutor{}
}

// Name returns the tool name
func (e *CodeSearchExecutor) Name() string {
	return "code_search"
}

// Execute searches for code patterns
func (e *CodeSearchExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	pattern, ok := params["pattern"].(string)
	if !ok || pattern == "" {
		return nil, errors.New("pattern parameter required")
	}

	path := "/"
	if p, ok := params["path"].(string); ok {
		path = p
	}

	maxResults := 100
	if m, ok := params["max_results"].(float64); ok {
		maxResults = int(m)
	}

	// Use grep for search
	cmd := exec.CommandContext(ctx, "grep", "-r", "-n", "-m", fmt.Sprintf("%d", maxResults), pattern, path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	results := make([]map[string]string, 0)
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) >= 3 {
			results = append(results, map[string]string{
				"file":   parts[0],
				"line":   parts[1],
				"match":  parts[2],
			})
		}
	}

	return map[string]interface{}{
		"pattern":    pattern,
		"path":       path,
		"results":    results,
		"count":      len(results),
		"exit_code":  0,
	}, nil
}

// Validate checks parameters
func (e *CodeSearchExecutor) Validate(params map[string]interface{}) error {
	pattern, ok := params["pattern"].(string)
	if !ok || pattern == "" {
		return errors.New("pattern parameter required")
	}
	if len(pattern) > 200 {
		return errors.New("pattern too long")
	}
	return nil
}

// Timeout returns the execution timeout
func (e *CodeSearchExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *CodeSearchExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *CodeSearchExecutor) Description() string {
	return "Search for code patterns in files"
}
