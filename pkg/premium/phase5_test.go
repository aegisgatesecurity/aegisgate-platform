// SPDX-License-Identifier: Apache-2.0

package premium

import (
	"context"
	"testing"
)

// ---- noopSIEMDispatcher: Run, Stop, Stats ----

func TestPhase5_NoopSIEMDispatcher_RunStopStats(t *testing.T) {
	var d SIEMDispatcher = noopSIEMDispatcher{}

	// Run should not block (it's a no-op)
	d.Run(context.Background())

	// Stop should not panic
	d.Stop()

	// Stats should return zero-value stats
	stats := d.Stats()
	if stats.EventsPolled != 0 {
		t.Errorf("EventsPolled: got %d, want 0", stats.EventsPolled)
	}
	if stats.EventsForwarded != 0 {
		t.Errorf("EventsForwarded: got %d, want 0", stats.EventsForwarded)
	}
	if stats.EventsDropped != 0 {
		t.Errorf("EventsDropped: got %d, want 0", stats.EventsDropped)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors: got %d, want 0", stats.Errors)
	}
}

// ---- noopSIEMDispatcher via custom factory ----

func TestPhase5_NoopSIEMDispatcher_ViaFactory(t *testing.T) {
	// The customSIEMFactory in interfaces_test.go returns noopSIEMDispatcher{}
	factory := customSIEMFactory{}
	disp, err := factory.New(SIEMDispatcherConfig{})
	if err != nil {
		t.Fatalf("factory.New: %v", err)
	}

	// Exercise all methods
	disp.Run(context.Background())
	disp.Stop()
	stats := disp.Stats()
	_ = stats // just verify it doesn't panic
}

// ---- noopTrustSession: ID, AgentID, Score, End ----

func TestPhase5_NoopTrustSession(t *testing.T) {
	var s TrustSession = noopTrustSession{}

	if s.ID() != "" {
		t.Errorf("ID: got %q, want \"\"", s.ID())
	}
	if s.AgentID() != "" {
		t.Errorf("AgentID: got %q, want \"\"", s.AgentID())
	}
	if s.Score() != 0 {
		t.Errorf("Score: got %f, want 0", s.Score())
	}

	delta, err := s.End()
	if err == nil {
		t.Error("End should return ErrEnterpriseOnly")
	}
	if err != ErrEnterpriseOnly {
		t.Errorf("End error: got %v, want ErrEnterpriseOnly", err)
	}
	if delta != 0 {
		t.Errorf("End delta: got %f, want 0", delta)
	}
}

// ---- noopTrustManager via custom provider: full session lifecycle ----

func TestPhase5_NoopTrustManager_FullLifecycle(t *testing.T) {
	// customTrustProvider returns noopTrustManager{}
	provider := customTrustProvider{}
	mgr, err := provider.NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// StartSession should fail with ErrEnterpriseOnly
	_, err = mgr.StartSession(context.Background(), "agent-1")
	if err != ErrEnterpriseOnly {
		t.Errorf("StartSession: got %v, want ErrEnterpriseOnly", err)
	}

	// Close should succeed
	if err := mgr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
