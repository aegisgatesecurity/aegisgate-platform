package workflowguard

import (
	"context"
	"testing"
	"time"

	agentprotocol "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol"
)

func TestNewSandbox(t *testing.T) {
	sandbox := NewSandbox()
	if sandbox == nil {
		t.Fatal("NewSandbox() returned nil")
	}
	if sandbox.allowedActions == nil {
		t.Error("allowedActions map not initialized")
	}
	if sandbox.approvals == nil {
		t.Error("approvals map not initialized")
	}
}

func TestSandboxCheckWorkflowAllowed(t *testing.T) {
	sandbox := NewSandbox()

	// file_read is allowed by default
	call := &agentprotocol.ToolCall{
		ID:      "test-1",
		Name:    "file_read",
		AgentID: "agent-1",
	}

	allowed, err := sandbox.CheckWorkflow(context.Background(), call)
	if err != nil {
		t.Fatalf("CheckWorkflow() error = %v", err)
	}
	if !allowed {
		t.Error("CheckWorkflow() expected allowed=true for file_read")
	}
}

func TestSandboxCheckWorkflowDenied(t *testing.T) {
	sandbox := NewSandbox()

	// shell_command is denied by default
	call := &agentprotocol.ToolCall{
		ID:      "test-2",
		Name:    "shell_command",
		AgentID: "agent-1",
	}

	allowed, err := sandbox.CheckWorkflow(context.Background(), call)
	if err != nil {
		t.Fatalf("CheckWorkflow() error = %v", err)
	}
	if allowed {
		t.Error("CheckWorkflow() expected allowed=false for shell_command")
	}
}

func TestSandboxCheckWorkflowUnknownAction(t *testing.T) {
	sandbox := NewSandbox()

	call := &agentprotocol.ToolCall{
		ID:      "test-3",
		Name:    "unknown_action",
		AgentID: "agent-1",
	}

	allowed, err := sandbox.CheckWorkflow(context.Background(), call)
	if err != nil {
		t.Fatalf("CheckWorkflow() error = %v", err)
	}
	if allowed {
		t.Error("CheckWorkflow() expected allowed=false for unknown action")
	}
}

func TestSandboxRequestApproval(t *testing.T) {
	sandbox := NewSandbox()

	call := &agentprotocol.ToolCall{
		ID:      "test-4",
		Name:    "file_write",
		AgentID: "agent-1",
	}

	approval, err := sandbox.RequestApproval(context.Background(), call, "Need to write config")
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}
	if approval == nil {
		t.Fatal("RequestApproval() returned nil")
	}
	if approval.Status != ApprovalPending {
		t.Errorf("Status = %s, want %s", approval.Status, ApprovalPending)
	}
	if approval.Reason != "Need to write config" {
		t.Errorf("Reason = %s, want 'Need to write config'", approval.Reason)
	}
}

func TestSandboxApprove(t *testing.T) {
	sandbox := NewSandbox()

	call := &agentprotocol.ToolCall{
		ID:      "test-5",
		Name:    "network_call",
		AgentID: "agent-1",
	}

	approval, _ := sandbox.RequestApproval(context.Background(), call, "API call needed")

	err := sandbox.Approve(context.Background(), approval.ID, "admin-1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	if approval.Status != ApprovalApproved {
		t.Errorf("Status = %s, want %s", approval.Status, ApprovalApproved)
	}
	if approval.ApproverID != "admin-1" {
		t.Errorf("ApproverID = %s, want admin-1", approval.ApproverID)
	}
}

func TestSandboxDeny(t *testing.T) {
	sandbox := NewSandbox()

	call := &agentprotocol.ToolCall{
		ID:      "test-6",
		Name:    "code_execute",
		AgentID: "agent-1",
	}

	approval, _ := sandbox.RequestApproval(context.Background(), call, "Execute code")

	err := sandbox.Deny(context.Background(), approval.ID, "admin-1", "Security policy violation")
	if err != nil {
		t.Fatalf("Deny() error = %v", err)
	}

	if approval.Status != ApprovalDenied {
		t.Errorf("Status = %s, want %s", approval.Status, ApprovalDenied)
	}
	if approval.Reason != "Security policy violation" {
		t.Errorf("Reason = %s, want 'Security policy violation'", approval.Reason)
	}
}

func TestSandboxApproveNotFound(t *testing.T) {
	sandbox := NewSandbox()

	err := sandbox.Approve(context.Background(), "nonexistent", "admin-1")
	if err != ErrApprovalNotFound {
		t.Errorf("Approve() error = %v, want ErrApprovalNotFound", err)
	}
}

func TestSandboxApproveNotPending(t *testing.T) {
	sandbox := NewSandbox()

	call := &agentprotocol.ToolCall{
		ID:      "test-7",
		Name:    "db_query",
		AgentID: "agent-1",
	}

	approval, _ := sandbox.RequestApproval(context.Background(), call, "DB access")
	sandbox.Approve(context.Background(), approval.ID, "admin-1")

	// Try to approve again
	err := sandbox.Approve(context.Background(), approval.ID, "admin-2")
	if err != ErrApprovalNotPending {
		t.Errorf("Approve() again error = %v, want ErrApprovalNotPending", err)
	}
}

func TestSandboxStartSequence(t *testing.T) {
	sandbox := NewSandbox()

	steps := []ActionStep{
		{ToolName: "file_read", Parameters: map[string]interface{}{"path": "/tmp/a"}},
		{ToolName: "file_read", Parameters: map[string]interface{}{"path": "/tmp/b"}},
	}

	seq, err := sandbox.StartSequence(context.Background(), steps)
	if err != nil {
		t.Fatalf("StartSequence() error = %v", err)
	}
	if seq == nil {
		t.Fatal("StartSequence() returned nil")
	}
	if seq.Status != SequenceActive {
		t.Errorf("Status = %s, want %s", seq.Status, SequenceActive)
	}
	if len(seq.Steps) != 2 {
		t.Errorf("Steps length = %d, want 2", len(seq.Steps))
	}
}

func TestSandboxStartSequenceTooDeep(t *testing.T) {
	sandbox := NewSandbox()
	sandbox.maxDepth = 2

	steps := []ActionStep{
		{ToolName: "step1"},
		{ToolName: "step2"},
		{ToolName: "step3"},
	}

	_, err := sandbox.StartSequence(context.Background(), steps)
	if err != ErrSequenceTooDeep {
		t.Errorf("StartSequence() error = %v, want ErrSequenceTooDeep", err)
	}
}

func TestSandboxNextStep(t *testing.T) {
	sandbox := NewSandbox()

	steps := []ActionStep{
		{ToolName: "step1"},
		{ToolName: "step2"},
	}

	seq, _ := sandbox.StartSequence(context.Background(), steps)

	err := sandbox.NextStep(context.Background(), seq.ID, "result1")
	if err != nil {
		t.Fatalf("NextStep() error = %v", err)
	}

	// Find the sequence and check
	for i := range sandbox.sequences {
		if sandbox.sequences[i].ID == seq.ID {
			if sandbox.sequences[i].CurrentStep != 1 {
				t.Errorf("CurrentStep = %d, want 1", sandbox.sequences[i].CurrentStep)
			}
			if !sandbox.sequences[i].Steps[0].Completed {
				t.Error("First step should be marked completed")
			}
			break
		}
	}
}

func TestSandboxNextStepSequenceComplete(t *testing.T) {
	sandbox := NewSandbox()

	steps := []ActionStep{
		{ToolName: "step1"},
	}

	seq, _ := sandbox.StartSequence(context.Background(), steps)
	sandbox.NextStep(context.Background(), seq.ID, "done")

	// Find and check
	for i := range sandbox.sequences {
		if sandbox.sequences[i].ID == seq.ID {
			if sandbox.sequences[i].Status != SequenceComplete {
				t.Errorf("Status = %s, want %s", sandbox.sequences[i].Status, SequenceComplete)
			}
			break
		}
	}
}

func TestSandboxNextStepNotFound(t *testing.T) {
	sandbox := NewSandbox()

	err := sandbox.NextStep(context.Background(), "nonexistent", nil)
	if err != ErrSequenceNotFound {
		t.Errorf("NextStep() error = %v, want ErrSequenceNotFound", err)
	}
}

func TestSandboxApproveExpired(t *testing.T) {
	sandbox := NewSandbox()
	sandbox.timeout = time.Millisecond // Very short timeout

	call := &agentprotocol.ToolCall{
		ID:      "test-expire",
		Name:    "file_write",
		AgentID: "agent-1",
	}

	approval, _ := sandbox.RequestApproval(context.Background(), call, "Test expiry")

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	err := sandbox.Approve(context.Background(), approval.ID, "admin-1")
	if err != ErrApprovalExpired {
		t.Errorf("Approve() after expiry error = %v, want ErrApprovalExpired", err)
	}
}

func TestWorkflowError(t *testing.T) {
	err := &WorkflowError{"test error"}
	if err.Error() != "test error" {
		t.Errorf("WorkflowError.Error() = %s, want 'test error'", err.Error())
	}
}

func TestApprovalStatus(t *testing.T) {
	tests := []struct {
		status ApprovalStatus
		want   string
	}{
		{ApprovalPending, "pending"},
		{ApprovalApproved, "approved"},
		{ApprovalDenied, "denied"},
		{ApprovalExpired, "expired"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("ApprovalStatus = %s, want %s", tt.status, tt.want)
		}
	}
}

func TestSequenceStatus(t *testing.T) {
	tests := []struct {
		status SequenceStatus
		want   string
	}{
		{SequenceActive, "active"},
		{SequenceComplete, "complete"},
		{SequenceAborted, "aborted"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("SequenceStatus = %s, want %s", tt.status, tt.want)
		}
	}
}
