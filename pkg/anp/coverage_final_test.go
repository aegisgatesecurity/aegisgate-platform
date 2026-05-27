package anp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestANPNewTask(t *testing.T) {
	task := NewTask("task-1", "session-1", "agent-1")
	if task.ID != "task-1" {
		t.Error("Task ID mismatch")
	}
}

func TestANPNewStep(t *testing.T) {
	step := NewStep("task-1", 0, json.RawMessage(`{"input":"test"}`))
	if step.TaskID != "task-1" {
		t.Error("Step TaskID mismatch")
	}
}

func TestANPGuardWithNilConfig(t *testing.T) {
	g := NewGuardWithConfig(nil)
	if g == nil {
		t.Error("Guard should not be nil")
	}
}

func TestANPGuardDefault(t *testing.T) {
	g := NewGuard()
	if g == nil {
		t.Error("Guard should not be nil")
	}
}

func TestANPGuardTask(t *testing.T) {
	g := NewGuard()
	task := NewTask("task-1", "session-1", "agent-1")
	secCtx := &SecurityContext{AgentID: "agent-1", SessionID: "session-1"}
	result, err := g.GuardTask(context.Background(), task, secCtx)
	if err != nil {
		t.Errorf("GuardTask failed: %v", err)
	}
	if result == nil {
		t.Error("GuardTask returned nil")
	}
}

func TestANPGuardTaskOutput(t *testing.T) {
	g := NewGuard()
	task := NewTask("task-1", "session-1", "agent-1")
	secCtx := &SecurityContext{AgentID: "agent-1"}
	result, err := g.GuardTaskOutput(context.Background(), task, "clean output", secCtx)
	if err != nil {
		t.Errorf("GuardTaskOutput failed: %v", err)
	}
	if result == nil {
		t.Error("GuardTaskOutput returned nil")
	}
}

func TestANPGuardStep(t *testing.T) {
	g := NewGuard()
	step := NewStep("task-1", 0, json.RawMessage(`{"input":"test"}`))
	secCtx := &SecurityContext{AgentID: "agent-1"}
	result, err := g.GuardStep(context.Background(), step, secCtx)
	if err != nil {
		t.Errorf("GuardStep failed: %v", err)
	}
	if result == nil {
		t.Error("GuardStep returned nil")
	}
}

func TestANPGuardStepOutput(t *testing.T) {
	g := NewGuard()
	step := NewStep("task-1", 0, json.RawMessage(`{"input":"test"}`))
	secCtx := &SecurityContext{AgentID: "agent-1"}
	result, err := g.GuardStepOutput(context.Background(), step, "clean output", secCtx)
	if err != nil {
		t.Errorf("GuardStepOutput failed: %v", err)
	}
	if result == nil {
		t.Error("GuardStepOutput returned nil")
	}
}

func TestANPGuardArtifact(t *testing.T) {
	g := NewGuard()
	artifact := &Artifact{
		ID:          "artifact-1",
		TaskID:      "task-1",
		Filename:    "test.txt",
		ContentType: "text/plain",
		Size:        100,
		CreatedAt:   time.Now(),
	}
	secCtx := &SecurityContext{AgentID: "agent-1"}
	result, err := g.GuardArtifact(context.Background(), artifact, secCtx)
	if err != nil {
		t.Errorf("GuardArtifact failed: %v", err)
	}
	if result == nil {
		t.Error("GuardArtifact returned nil")
	}
}

func TestANPContainsPII(t *testing.T) {
	g := NewGuard()
	// Test that method runs without panicking
	_ = g.containsPII("123-45-6789")
}

func TestANPDetectInjection(t *testing.T) {
	g := NewGuard()
	// Test that method runs without panicking
	_ = g.detectInjection("some text")
}
