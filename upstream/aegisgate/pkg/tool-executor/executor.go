// Package tool-executor - Tool execution service for AegisGuard
// Provides secure execution of AI agent tool calls with authorization
package toolexecutor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Manager manages tool executors and routes execution requests
type Manager struct {
	mu        sync.RWMutex
	executors map[string]ToolExecutor
	timeout   time.Duration
	logger    *slog.Logger
}

// NewManager creates a new tool executor manager
func NewManager() *Manager {
	return &Manager{
		executors: make(map[string]ToolExecutor),
		timeout:   5 * time.Minute,
		logger:    slog.Default(),
	}
}

// Register registers a tool executor
func (m *Manager) Register(executor ToolExecutor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if executor == nil {
		return fmt.Errorf("executor cannot be nil")
	}

	name := executor.Name()
	if name == "" {
		return fmt.Errorf("executor name cannot be empty")
	}

	if _, exists := m.executors[name]; exists {
		return fmt.Errorf("executor already registered: %s", name)
	}

	m.executors[name] = executor
	m.logger.Info("tool executor registered", "name", name, "risk_level", executor.RiskLevel())
	return nil
}

// Unregister removes a tool executor
func (m *Manager) Unregister(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.executors[name]; !exists {
		return fmt.Errorf("executor not found: %s", name)
	}

	delete(m.executors, name)
	m.logger.Info("tool executor unregistered", "name", name)
	return nil
}

// Get retrieves an executor by name
func (m *Manager) Get(name string) (ToolExecutor, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	executor, exists := m.executors[name]
	return executor, exists
}

// List returns all registered executor names
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.executors))
	for name := range m.executors {
		names = append(names, name)
	}
	return names
}

// Execute routes and executes a tool call
func (m *Manager) Execute(ctx context.Context, req *ExecutionRequest) *ExecutionResult {
	startTime := time.Now()

	result := &ExecutionResult{
		RequestID: req.RequestID,
		ToolName:  req.ToolName,
		Timestamp: startTime,
	}

	// Get executor
	executor, exists := m.Get(req.ToolName)
	if !exists {
		result.Error = fmt.Sprintf("tool not found: %s", req.ToolName)
		result.ErrorCode = "TOOL_NOT_FOUND"
		result.Duration = time.Since(startTime)
		return result
	}

	// Create execution context with timeout
	execCtx, cancelExec := m.createExecutionContext(ctx, req, executor)
	defer cancelExec()

	// Validate parameters
	if err := executor.Validate(req.Parameters); err != nil {
		result.Error = fmt.Sprintf("validation failed: %s", err.Error())
		result.ErrorCode = "VALIDATION_ERROR"
		result.Duration = time.Since(startTime)
		return result
	}

	// Execute with timeout
	done := make(chan struct{})
	var execResult interface{}
	var execErr error

	go func() {
		execResult, execErr = executor.Execute(execCtx, req.Parameters)
		close(done)
	}()

	select {
	case <-execCtx.Done():
		result.Error = "execution timeout"
		result.ErrorCode = "TIMEOUT"
		result.Duration = time.Since(startTime)
		return result
	case <-done:
		// Execution completed
	}

	if execErr != nil {
		result.Error = execErr.Error()
		result.ErrorCode = "EXECUTION_ERROR"
		result.Duration = time.Since(startTime)
		return result
	}

	result.Success = true
	result.Result = execResult
	result.Duration = time.Since(startTime)

	m.logger.Debug("tool executed",
		"tool", req.ToolName,
		"session", req.SessionID,
		"agent", req.AgentID,
		"duration", result.Duration,
	)

	return result
}

// createExecutionContext creates the execution context for a tool
func (m *Manager) createExecutionContext(ctx context.Context, req *ExecutionRequest, executor ToolExecutor) (context.Context, context.CancelFunc) {
	timeout := executor.Timeout()
	if timeout == 0 {
		timeout = m.timeout
	}

	// Apply rate limiting based on risk level
	// Higher risk = shorter timeouts
	riskTimeout := DefaultTimeout(RiskLevel(executor.RiskLevel()))
	if timeout > riskTimeout {
		timeout = riskTimeout
	}

	return context.WithTimeout(ctx, timeout)
}

// GetExecutorInfo returns information about all registered executors
func (m *Manager) GetExecutorInfo() []ExecutorInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info := make([]ExecutorInfo, 0, len(m.executors))
	for _, executor := range m.executors {
		info = append(info, ExecutorInfo{
			Name:      executor.Name(),
			RiskLevel: executor.RiskLevel(),
			Timeout:   executor.Timeout(),
			Desc:      executor.Description(),
		})
	}
	return info
}

// ExecutorInfo contains information about an executor
type ExecutorInfo struct {
	Name      string
	RiskLevel int
	Timeout   time.Duration
	Desc      string
}

// Count returns the number of registered executors
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.executors)
}

// SetLogger sets the logger for the manager
func (m *Manager) SetLogger(logger *slog.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger = logger
}

// SetDefaultTimeout sets the default timeout for all tools
func (m *Manager) SetDefaultTimeout(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeout = timeout
}
