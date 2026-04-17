// Package workflowguard - Workflow sandboxing and approval for AI agents
package workflowguard

import (
	"context"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol"
)

// Sandbox provides workflow-level security controls
type Sandbox struct {
	allowedActions map[string]bool
	maxDepth       int
	timeout        time.Duration
	approvals      map[string]*ApprovalRequest
	sequences      []ActionSequence
}

// ApprovalRequest represents a pending approval request
type ApprovalRequest struct {
	ID          string
	ToolCall    *agentprotocol.ToolCall
	RequesterID string
	ApproverID  string
	Reason      string
	RequestedAt time.Time
	ExpiresAt   time.Time
	Status      ApprovalStatus
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

// ActionSequence represents a sequence of actions
type ActionSequence struct {
	ID          string
	Steps       []ActionStep
	CurrentStep int
	Status      SequenceStatus
}

// ActionStep represents a single step in an action sequence
type ActionStep struct {
	ToolName   string
	Parameters map[string]interface{}
	Completed  bool
	Result     interface{}
}

// SequenceStatus represents the status of an action sequence
type SequenceStatus string

const (
	SequenceActive   SequenceStatus = "active"
	SequenceComplete SequenceStatus = "complete"
	SequenceAborted  SequenceStatus = "aborted"
)

// NewSandbox creates a new workflow sandbox
func NewSandbox() *Sandbox {
	return &Sandbox{
		allowedActions: map[string]bool{
			"file_read":      true,
			"file_write":     false, // Requires approval
			"network_call":   false, // Requires approval
			"code_execute":   false, // Requires approval
			"shell_command":  false, // Requires approval
			"database_query": false, // Requires approval
		},
		maxDepth:  5,
		timeout:   5 * time.Minute,
		approvals: make(map[string]*ApprovalRequest),
	}
}

// CheckWorkflow evaluates whether a tool call is allowed in the current workflow context
func (s *Sandbox) CheckWorkflow(ctx context.Context, call *agentprotocol.ToolCall) (bool, error) {
	// Check if action is allowed
	allowed, ok := s.allowedActions[call.Name]
	if !ok {
		// Unknown action - deny by default
		return false, nil
	}

	if allowed {
		return true, nil
	}

	// Check for pending approval
	if approval, ok := s.approvals[call.ID]; ok {
		switch approval.Status {
		case ApprovalApproved:
			return true, nil
		case ApprovalDenied, ApprovalExpired:
			return false, nil
		case ApprovalPending:
			return false, nil
		}
	}

	// Action requires approval
	return false, nil
}

// RequestApproval creates a new approval request
func (s *Sandbox) RequestApproval(ctx context.Context, call *agentprotocol.ToolCall, reason string) (*ApprovalRequest, error) {
	approval := &ApprovalRequest{
		ID:          generateApprovalID(),
		ToolCall:    call,
		RequesterID: call.AgentID,
		Reason:      reason,
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(s.timeout),
		Status:      ApprovalPending,
	}

	s.approvals[approval.ID] = approval
	return approval, nil
}

// Approve approves a pending request
func (s *Sandbox) Approve(ctx context.Context, approvalID, approverID string) error {
	approval, ok := s.approvals[approvalID]
	if !ok {
		return ErrApprovalNotFound
	}

	if approval.Status != ApprovalPending {
		return ErrApprovalNotPending
	}

	if time.Now().After(approval.ExpiresAt) {
		approval.Status = ApprovalExpired
		return ErrApprovalExpired
	}

	approval.ApproverID = approverID
	approval.Status = ApprovalApproved
	return nil
}

// Deny denies a pending request
func (s *Sandbox) Deny(ctx context.Context, approvalID, approverID, reason string) error {
	approval, ok := s.approvals[approvalID]
	if !ok {
		return ErrApprovalNotFound
	}

	if approval.Status != ApprovalPending {
		return ErrApprovalNotPending
	}

	approval.ApproverID = approverID
	approval.Reason = reason
	approval.Status = ApprovalDenied
	return nil
}

// StartSequence starts a new action sequence
func (s *Sandbox) StartSequence(ctx context.Context, steps []ActionStep) (*ActionSequence, error) {
	if len(steps) > s.maxDepth {
		return nil, ErrSequenceTooDeep
	}

	seq := &ActionSequence{
		ID:          generateSequenceID(),
		Steps:       steps,
		CurrentStep: 0,
		Status:      SequenceActive,
	}

	s.sequences = append(s.sequences, *seq)
	return seq, nil
}

// NextStep advances to the next step in a sequence
func (s *Sandbox) NextStep(ctx context.Context, seqID string, result interface{}) error {
	for i := range s.sequences {
		if s.sequences[i].ID == seqID {
			if s.sequences[i].Status != SequenceActive {
				return ErrSequenceNotActive
			}

			s.sequences[i].Steps[s.sequences[i].CurrentStep].Completed = true
			s.sequences[i].Steps[s.sequences[i].CurrentStep].Result = result
			s.sequences[i].CurrentStep++

			if s.sequences[i].CurrentStep >= len(s.sequences[i].Steps) {
				s.sequences[i].Status = SequenceComplete
			}

			return nil
		}
	}

	return ErrSequenceNotFound
}

// generateApprovalID creates a unique approval ID
func generateApprovalID() string {
	return "apr_" + time.Now().Format("20060102150405")
}

// generateSequenceID creates a unique sequence ID
func generateSequenceID() string {
	return "seq_" + time.Now().Format("20060102150405")
}

// Errors
var (
	ErrApprovalNotFound   = &WorkflowError{"approval request not found"}
	ErrApprovalNotPending = &WorkflowError{"approval is not pending"}
	ErrApprovalExpired    = &WorkflowError{"approval request expired"}
	ErrSequenceTooDeep    = &WorkflowError{"action sequence too deep"}
	ErrSequenceNotFound   = &WorkflowError{"sequence not found"}
	ErrSequenceNotActive  = &WorkflowError{"sequence is not active"}
)

// WorkflowError represents a workflow-related error
type WorkflowError struct {
	message string
}

func (e *WorkflowError) Error() string {
	return e.message
}
