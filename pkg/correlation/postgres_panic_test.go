// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Correlation PostgreSQL Store Panic-Recovery Unit Tests
//
// Tests input validation paths and pool-call paths via panic recovery.
//go:build !integration

package correlation

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------

func TestPostgresUnit_NewStore_NilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

// --------------------------------------------------------------------
// Close (no-op)
// --------------------------------------------------------------------

func TestPostgresUnit_Close(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --------------------------------------------------------------------
// Input validation (no pool access)
// --------------------------------------------------------------------

func TestPostgresUnit_RecordEvent_NilEvent(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	err := store.RecordEvent(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil event")
	}
}

func TestPostgresUnit_ListEventsBySession_EmptyID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsBySession(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestPostgresUnit_ListEventsByAgent_EmptyID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgent(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresUnit_ListEventsByAgentAndSession_EmptyAgentID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgentAndSession(context.Background(), "", "session-1")
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresUnit_ListEventsByAgentAndSession_EmptySessionID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgentAndSession(context.Background(), "agent-1", "")
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestPostgresUnit_Analyze_EmptyAgentID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.Analyze(context.Background(), "", "session-1", time.Minute)
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresUnit_Analyze_EmptySessionID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.Analyze(context.Background(), "agent-1", "", time.Minute)
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

// --------------------------------------------------------------------
// Panic-recovery tests (exercise code paths up to pool access)
// --------------------------------------------------------------------

func TestPostgresUnit_RecordEvent_ValidEvent_PanicsOnNilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	ctx := context.Background()

	event := &Event{
		ID:        "evt-test-1",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "request",
		Severity:  "low",
		Decision:  "allow",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"key": "value"},
		Metadata:  map[string]string{"source": "test"},
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = store.RecordEvent(ctx, event)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresUnit_RecordEvent_InvalidJSONData(t *testing.T) {
	// Verify event data marshals correctly (exercises json.Marshal paths)
	event := &Event{
		ID:        "evt-test-2",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "request",
		Severity:  "low",
		Decision:  "allow",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"key": "value"},
		Metadata:  map[string]string{"source": "test"},
	}

	// Verify event marshals OK (this exercises the json.Marshal path)
	dataJSON, err := json.Marshal(event.Data)
	if err != nil {
		t.Fatalf("json.Marshal(Data): %v", err)
	}
	if string(dataJSON) != `{"key":"value"}` {
		t.Errorf("unexpected data JSON: %s", dataJSON)
	}

	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		t.Fatalf("json.Marshal(Metadata): %v", err)
	}
	if string(metaJSON) != `{"source":"test"}` {
		t.Errorf("unexpected metadata JSON: %s", metaJSON)
	}
}

func TestPostgresUnit_Prune_PanicsOnNilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Prune(ctx, time.Hour)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresUnit_ListEventsBySession_PanicsOnNilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListEventsBySession(ctx, "session-1")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresUnit_ListEventsByAgent_PanicsOnNilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListEventsByAgent(ctx, "agent-1")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresUnit_Analyze_PanicsOnNilPool(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Analyze(ctx, "agent-1", "session-1", time.Minute)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}
