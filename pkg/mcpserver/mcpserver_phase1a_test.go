// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	mcp "github.com/aegisgatesecurity/aegisguard/pkg/agent-protocol/mcp"
)

func TestPhase1aSetGuardrails_BothNil(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	es.SetGuardrails(nil, nil, nil)
}

func TestPhase1aSetGuardrails_OnlyResponseGuard(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	rg := NewMCPResponseGuard()
	es.SetGuardrails(nil, rg, nil)
}

func TestPhase1aSetGuardrails_OnlyGuardrails(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	gm := &GuardrailMiddleware{}
	es.SetGuardrails(gm, nil, nil)
}

func TestPhase1aSetGuardrails_BothWithConfig(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	gm := &GuardrailMiddleware{}
	rg := NewMCPResponseGuard()
	cfg := DefaultEmbeddedResponseConfig()
	es.SetGuardrails(gm, rg, cfg)
}

func TestPhase1aSetGuardrails_DisabledConfig(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	rg := NewMCPResponseGuard()
	cfg := &EmbeddedResponseConfig{Enabled: false}
	es.SetGuardrails(nil, rg, cfg)
}

func TestPhase1aExtractToolResponseText_NilResponse(t *testing.T) {
	result := extractToolResponseText(nil)
	if result != "" {
		t.Fatal("expected empty string for nil response")
	}
}

func TestPhase1aExtractToolResponseText_NilResult(t *testing.T) {
	resp := &mcp.JSONRPCResponse{Result: nil}
	result := extractToolResponseText(resp)
	if result != "" {
		t.Fatal("expected empty string for nil result")
	}
}

func TestPhase1aExtractToolResponseText_MarshalFailure(t *testing.T) {
	resp := &mcp.JSONRPCResponse{Result: make(chan int)}
	result := extractToolResponseText(resp)
	if result != "" {
		t.Fatal("expected empty string for marshal failure")
	}
}

func TestPhase1aUpdateToolResponseText_NilResponse(t *testing.T) {
	updateToolResponseText(nil, "new text")
}

func TestPhase1aUpdateToolResponseText_NilResult(t *testing.T) {
	resp := &mcp.JSONRPCResponse{Result: nil}
	updateToolResponseText(resp, "new text")
}

func TestPhase1aUpdateToolResponseText_MarshalFailure(t *testing.T) {
	resp := &mcp.JSONRPCResponse{Result: make(chan int)}
	updateToolResponseText(resp, "new text")
}

func TestPhase1aMCPResponseGuard_GuardResponse_CleanText(t *testing.T) {
	rg := NewMCPResponseGuard()
	allowed, _, err := rg.GuardResponse(context.Background(), "hello world", "session-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed for clean text")
	}
}

func TestPhase1aMCPResponseGuard_GetSessionStats(t *testing.T) {
	rg := NewMCPResponseGuard()
	rg.GuardResponse(context.Background(), "test", "session-1")
	stats := rg.GetSessionStats("session-1")
	_ = stats
}

func TestPhase1aMCPResponseGuard_GetSessionStats_UnknownSession(t *testing.T) {
	rg := NewMCPResponseGuard()
	stats := rg.GetSessionStats("unknown")
	if stats != nil {
		t.Fatal("expected nil stats for unknown session")
	}
}

func TestPhase1aDangerousPatternDescription_KnownPattern(t *testing.T) {
	desc := dangerousPatternDescription("rm -rf")
	if desc == "" {
		t.Fatal("expected non-empty description for dangerous pattern")
	}
}

func TestPhase1aDangerousPatternDescription_UnknownPattern(t *testing.T) {
	desc := dangerousPatternDescription("completely-unknown-pattern-xyz")
	_ = desc
}

func TestPhase1aValidateCommand_EmptyCommand(t *testing.T) {
	v := NewSTDIOValidator(STDIOValidationConfig{})
	err := v.ValidateCommand("")
	_ = err
	_ = v
}

func TestPhase1aValidateCommand_ValidCommand(t *testing.T) {
	v := NewSTDIOValidator(STDIOValidationConfig{})
	err := v.ValidateCommand("ls -la")
	if err != nil {
		t.Logf("error (acceptable): %v", err)
	}
}

func TestPhase1aServer_Stop_NotStarted(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	err := es.Stop()
	if err != nil {
		t.Logf("Stop before Start returned error (acceptable): %v", err)
	}
}

func TestPhase1aSessionManager_CreateSession_UnknownAgent(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create rbac manager: %v", err)
	}
	sm := NewConnectionSessionManager(rbacMgr)
	_, err = sm.CreateSession(context.Background(), "conn-1", "unknown-agent")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestPhase1aSessionManager_CloseSession_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)
	err := sm.CloseSession("nonexistent-conn")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}
