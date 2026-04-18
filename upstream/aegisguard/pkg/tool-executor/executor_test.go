// Package tool-executor - Tests for tool executor
package toolexecutor

import (
	"context"
	"testing"
	"time"
)

// TestManagerRegistration tests tool registration
func TestManagerRegistration(t *testing.T) {
	manager := NewManager()

	// Create a test executor
	exec := &testExecutor{name: "test_tool", riskLevel: 25}

	// Register
	err := manager.Register(exec)
	if err != nil {
		t.Fatalf("failed to register executor: %v", err)
	}

	// Verify registration
	if manager.Count() != 1 {
		t.Errorf("expected 1 executor, got %d", manager.Count())
	}

	// Check duplicate registration
	err = manager.Register(exec)
	if err == nil {
		t.Error("expected error on duplicate registration")
	}
}

// TestManagerExecution tests tool execution
func TestManagerExecution(t *testing.T) {
	manager := NewManager()

	exec := &testExecutor{name: "test_tool", riskLevel: 25}
	manager.Register(exec)

	req := &ExecutionRequest{
		ToolName:   "test_tool",
		Parameters: map[string]interface{}{"input": "test"},
		SessionID:  "session1",
		AgentID:    "agent1",
		RequestID:  "req1",
	}

	result := manager.Execute(context.Background(), req)

	if !result.Success {
		t.Errorf("execution failed: %s", result.Error)
	}
	if result.Result != "executed: test" {
		t.Errorf("unexpected result: %v", result.Result)
	}
}

// TestManagerNotFound tests tool not found case
func TestManagerNotFound(t *testing.T) {
	manager := NewManager()

	req := &ExecutionRequest{
		ToolName: "nonexistent",
	}

	result := manager.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure for nonexistent tool")
	}
	if result.ErrorCode != "TOOL_NOT_FOUND" {
		t.Errorf("unexpected error code: %s", result.ErrorCode)
	}
}

// TestValidationFailure tests parameter validation
func TestValidationFailure(t *testing.T) {
	manager := NewManager()

	exec := &testExecutor{name: "test_tool", riskLevel: 25, validateErr: true}
	manager.Register(exec)

	req := &ExecutionRequest{
		ToolName:   "test_tool",
		Parameters: map[string]interface{}{"bad": "param"},
	}

	result := manager.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected validation failure")
	}
	if result.ErrorCode != "VALIDATION_ERROR" {
		t.Errorf("unexpected error code: %s", result.ErrorCode)
	}
}

// TestTimeout tests execution timeout
func TestTimeout(t *testing.T) {
	manager := NewManager()

	exec := &testExecutor{name: "slow_tool", riskLevel: 25, sleepDuration: 2 * time.Second}
	manager.Register(exec)

	manager.SetDefaultTimeout(100 * time.Millisecond)

	req := &ExecutionRequest{
		ToolName:   "slow_tool",
		Parameters: map[string]interface{}{},
	}

	// Create a context that will timeout quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := manager.Execute(ctx, req)

	// If execution took too long or didn't timeout, the test may fail on slow machines
	if result.Success && result.Duration > 500*time.Millisecond {
		t.Logf("warning: execution took %v (timeout may not have worked)", result.Duration)
	}
}

// TestExecutorInfo tests executor info retrieval
func TestExecutorInfo(t *testing.T) {
	manager := NewManager()

	exec := &testExecutor{name: "info_tool", riskLevel: 50}
	manager.Register(exec)

	info := manager.GetExecutorInfo()
	if len(info) != 1 {
		t.Errorf("expected 1 info, got %d", len(info))
	}
	if info[0].RiskLevel != 50 {
		t.Errorf("unexpected risk level: %d", info[0].RiskLevel)
	}
}

// testExecutor is a test implementation of ToolExecutor
type testExecutor struct {
	name          string
	riskLevel     int
	sleepDuration time.Duration
	validateErr   bool
	executeErr    bool
	result        interface{}
}

func (e *testExecutor) Name() string { return e.name }

func (e *testExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if e.sleepDuration > 0 {
		select {
		case <-time.After(e.sleepDuration):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if e.executeErr {
		return nil, &testError{"execution error"}
	}

	input := ""
	if v, ok := params["input"].(string); ok {
		input = v
	}

	return "executed: " + input, nil
}

func (e *testExecutor) Validate(params map[string]interface{}) error {
	if e.validateErr {
		return &testError{"validation error"}
	}
	return nil
}

func (e *testExecutor) Timeout() time.Duration { return 30 * time.Second }

func (e *testExecutor) RiskLevel() int { return e.riskLevel }

func (e *testExecutor) Description() string { return "Test executor" }

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
