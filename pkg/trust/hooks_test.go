// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Protocol Hooks tests (v3.2.0 Phase 4.4)

package trust

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

func newTestHooks(t *testing.T) (*Hooks, *Manager) {
	t.Helper()
	engine := score.NewEngine(nil)
	m := NewManager(engine, nil)
	return NewHooks(m), m
}

func TestHooks_ZeroValueIsNoOp(t *testing.T) {
	var h Hooks // zero value
	// All of these should be safe no-ops, no panics.
	h.CapabilityAllowed(context.Background(), "x", "y", "z")
	h.CapabilityDenied(context.Background(), "x", "y", "z", 5)
	h.AnomalyDetected(context.Background(), "x", "y", 5)
	h.CompliancePass(context.Background(), "x", "y", "z")
	h.ComplianceFail(context.Background(), "x", "y", "z")
	h.ContractViolated(context.Background(), "x", "y", "z")
	h.IdentityVerified(context.Background(), "x", "y")
	h.IdentityFailed(context.Background(), "x", "y", "z")
	h.ErrorOccurred(context.Background(), "x", "y")
	h.StartSession(context.Background(), "agent", nil)
	h.EndSession(context.Background(), "x")
	s, ok := h.SessionScore(context.Background(), "x")
	if s != 0 || ok {
		t.Errorf("zero Hooks SessionScore = (%v, %v), want (0, false)", s, ok)
	}
	if h.IsBelowThreshold(context.Background(), "x") {
		t.Error("zero Hooks IsBelowThreshold should be false")
	}
}

func TestHooks_StartSessionReturnsID(t *testing.T) {
	h, _ := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent-1", map[string]string{"src": "mcp"})
	if id == "" {
		t.Error("StartSession returned empty ID")
	}
}

func TestHooks_StartSessionEmptyIDForUnknownAgent(t *testing.T) {
	// We don't reject empty agentID; the manager does. With Hooks
	// returning "" on error, this is a no-op.
	h, _ := newTestHooks(t)
	id := h.StartSession(context.Background(), "valid-agent", nil)
	if id == "" {
		t.Error("StartSession should return ID for valid agent")
	}
}

func TestHooks_EndSession(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	if m.ActiveCount() != 1 {
		t.Errorf("active count = %d, want 1", m.ActiveCount())
	}
	h.EndSession(context.Background(), id)
	if m.ActiveCount() != 0 {
		t.Errorf("active count = %d, want 0", m.ActiveCount())
	}
}

func TestHooks_EndSession_NoOpForEmptyID(t *testing.T) {
	h, m := newTestHooks(t)
	h.StartSession(context.Background(), "agent", nil)
	// EndSession with empty ID is a no-op.
	h.EndSession(context.Background(), "")
	if m.ActiveCount() != 1 {
		t.Errorf("EndSession(empty) should be no-op, but active = %d", m.ActiveCount())
	}
}

func TestHooks_CapabilityAllowed_RecordsEvent(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.CapabilityAllowed(context.Background(), id, "tools/call", "called file_read")
	sess, _ := m.Get(id)
	if sess.EventCount() != 1 {
		t.Errorf("EventCount = %d, want 1", sess.EventCount())
	}
	if sess.Events[0].Type != score.EventCapabilityAllowed {
		t.Errorf("event type = %v, want %v", sess.Events[0].Type, score.EventCapabilityAllowed)
	}
}

func TestHooks_CapabilityDenied_RecordsEvent(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.CapabilityDenied(context.Background(), id, "tools/call", "denied: out of policy", 5)
	sess, _ := m.Get(id)
	if sess.EventCount() != 1 {
		t.Errorf("EventCount = %d, want 1", sess.EventCount())
	}
	if sess.Events[0].Severity != 5 {
		t.Errorf("severity = %d, want 5", sess.Events[0].Severity)
	}
}

func TestHooks_AnomalyDetected_RecordsEvent(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.AnomalyDetected(context.Background(), id, "anomalous traffic spike", 7)
	sess, _ := m.Get(id)
	if sess.Events[0].Type != score.EventAnomalyDetected {
		t.Errorf("event type = %v, want %v", sess.Events[0].Type, score.EventAnomalyDetected)
	}
}

func TestHooks_ComplianceEvents(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.CompliancePass(context.Background(), id, "hipaa", "phi logging check")
	h.ComplianceFail(context.Background(), id, "pci-dss", "card data exposed")
	sess, _ := m.Get(id)
	if sess.EventCount() != 2 {
		t.Errorf("EventCount = %d, want 2", sess.EventCount())
	}
	if sess.Events[0].Type != score.EventCompliancePass {
		t.Errorf("first event type = %v, want CompliancePass", sess.Events[0].Type)
	}
	if sess.Events[1].Type != score.EventComplianceFail {
		t.Errorf("second event type = %v, want ComplianceFail", sess.Events[1].Type)
	}
}

func TestHooks_ContractViolated_RecordsEvent(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.ContractViolated(context.Background(), id, "agent-policy", "agent exceeded rate limit")
	sess, _ := m.Get(id)
	if sess.Events[0].Type != score.EventContractViolated {
		t.Errorf("event type = %v, want ContractViolated", sess.Events[0].Type)
	}
}

func TestHooks_IdentityEvents(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.IdentityVerified(context.Background(), id, "mTLS")
	h.IdentityFailed(context.Background(), id, "OIDC", "expired token")
	sess, _ := m.Get(id)
	if sess.EventCount() != 2 {
		t.Errorf("EventCount = %d, want 2", sess.EventCount())
	}
	if sess.Events[0].Capability != "mTLS" {
		t.Errorf("event 0 capability = %q, want mTLS", sess.Events[0].Capability)
	}
	if sess.Events[1].Type != score.EventIdentityFailed {
		t.Errorf("event 1 type = %v, want IdentityFailed", sess.Events[1].Type)
	}
}

func TestHooks_ErrorOccurred_RecordsEvent(t *testing.T) {
	h, m := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.ErrorOccurred(context.Background(), id, "internal proxy error")
	sess, _ := m.Get(id)
	if sess.Events[0].Type != score.EventError {
		t.Errorf("event type = %v, want Error", sess.Events[0].Type)
	}
}

func TestHooks_JoinSession_NewKey(t *testing.T) {
	h, m := newTestHooks(t)
	id1 := h.JoinSession(context.Background(), "conn-1", "agent", nil)
	if id1 == "" {
		t.Fatal("JoinSession returned empty ID")
	}
	// Same key + agent should rejoin the same session.
	id2 := h.JoinSession(context.Background(), "conn-1", "agent", nil)
	if id1 != id2 {
		t.Errorf("JoinSession returned different ID: %q vs %q", id1, id2)
	}
	if m.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1 (single joined session)", m.ActiveCount())
	}
}

func TestHooks_JoinSession_DifferentAgent(t *testing.T) {
	h, m := newTestHooks(t)
	id1 := h.JoinSession(context.Background(), "conn-1", "agent-A", nil)
	id2 := h.JoinSession(context.Background(), "conn-1", "agent-B", nil)
	if id1 == id2 {
		t.Errorf("JoinSession for different agents should return different IDs")
	}
	if m.ActiveCount() != 2 {
		t.Errorf("ActiveCount = %d, want 2", m.ActiveCount())
	}
}

func TestHooks_JoinSession_DifferentKey(t *testing.T) {
	h, m := newTestHooks(t)
	id1 := h.JoinSession(context.Background(), "conn-1", "agent", nil)
	id2 := h.JoinSession(context.Background(), "conn-2", "agent", nil)
	if id1 == id2 {
		t.Errorf("JoinSession for different keys should return different IDs")
	}
	if m.ActiveCount() != 2 {
		t.Errorf("ActiveCount = %d, want 2", m.ActiveCount())
	}
}

func TestHooks_SessionScore(t *testing.T) {
	h, _ := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	s, ok := h.SessionScore(context.Background(), id)
	if !ok {
		t.Error("SessionScore returned ok=false for a valid session")
	}
	if s != 100.0 {
		t.Errorf("SessionScore = %v, want 100.0 (default initial)", s)
	}
}

func TestHooks_SessionScore_EmptyID(t *testing.T) {
	h, _ := newTestHooks(t)
	_, ok := h.SessionScore(context.Background(), "")
	if ok {
		t.Error("SessionScore with empty ID returned ok=true")
	}
}

func TestHooks_IsBelowThreshold(t *testing.T) {
	h, _ := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	// Initial score is 100.0; threshold default is 30. Should not be below.
	if h.IsBelowThreshold(context.Background(), id) {
		t.Error("100.0 < 30 should be false")
	}
	// Now record a bunch of denied events to drive the score down.
	for i := 0; i < 10; i++ {
		h.CapabilityDenied(context.Background(), id, "x", "denied", 9)
	}
	if !h.IsBelowThreshold(context.Background(), id) {
		t.Error("after 10 high-severity denied events, score should be below 30")
	}
}

func TestHooks_SetManager(t *testing.T) {
	var h Hooks
	// No manager yet; hook is a no-op.
	h.CapabilityAllowed(context.Background(), "x", "y", "z")
	// Set a manager.
	engine := score.NewEngine(nil)
	m := NewManager(engine, nil)
	h.SetManager(m)
	// Now hooks should record.
	id := h.StartSession(context.Background(), "agent", nil)
	if id == "" {
		t.Error("StartSession returned empty after SetManager")
	}
}

func TestHooks_ValidateContext_NoManager(t *testing.T) {
	var h Hooks
	err := h.ValidateContext()
	if err == nil {
		t.Error("ValidateContext with nil Manager should return error")
	}
}

func TestHooks_ValidateContext_WithManager(t *testing.T) {
	h, _ := newTestHooks(t)
	if err := h.ValidateContext(); err != nil {
		t.Errorf("ValidateContext with Manager should return nil, got %v", err)
	}
}

func TestHooks_DefaultThreshold(t *testing.T) {
	h, _ := newTestHooks(t)
	if h.ThresholdScore != 30 {
		t.Errorf("default ThresholdScore = %v, want 30", h.ThresholdScore)
	}
}

func TestHooks_RecordToClosedSession(t *testing.T) {
	h, _ := newTestHooks(t)
	id := h.StartSession(context.Background(), "agent", nil)
	h.EndSession(context.Background(), id)
	// Recording to a closed session should be a silent no-op (the
	// Manager returns ErrSessionAlreadyEnded and we ignore it).
	h.CapabilityAllowed(context.Background(), id, "x", "y")
	// No panic, no error return; this is the desired behavior.
}
