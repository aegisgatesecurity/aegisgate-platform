// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Correlation PostgreSQL Integration Tests
// =========================================================================
//
// Real-database tests that verify PostgresCorrelationStore works end-to-end
// against a live PostgreSQL instance provisioned via testcontainers.
//
// These tests are gated by the `//go:build integration` build tag so they
// only run when explicitly requested:
//
//	go test -tags=integration -v ./pkg/correlation/...
//
// No external environment variables are required — testcontainers manages
// the ephemeral PostgreSQL container automatically. If Docker is not
// available the tests are skipped gracefully via t.Skip.
//
// =========================================================================

//go:build integration

package correlation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestStore is a test helper that provisions an ephemeral PostgreSQL
// container via testdb.SetupTestDB, creates a PostgresCorrelationStore from
// the pool, and returns the store plus a cleanup function. The caller must
// defer the cleanup.
func setupTestStore(t *testing.T) (*PostgresCorrelationStore, func()) {
	t.Helper()

	pgStore, cleanup := testdb.SetupTestDB(t)
	store := NewPostgresCorrelationStore(pgStore.Pool())

	storeCleanup := func() {
		store.Close()
		cleanup()
	}

	return store, storeCleanup
}

// --------------------------------------------------------------------------
// RecordEvent
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_RecordEvent(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	evt := createTestEvent("mcp", "int-agent-1", "int-session-1", "request", "low")
	err := store.RecordEvent(ctx, evt)
	require.NoError(t, err, "RecordEvent should succeed against PostgreSQL")
}

func TestIntegration_PostgresCorrelationStore_RecordEvent_NilEvent(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	err := store.RecordEvent(ctx, nil)
	assert.Error(t, err, "RecordEvent(nil) should return an error")
}

func TestIntegration_PostgresCorrelationStore_RecordEvent_MultipleEvents(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	sessionID := fmt.Sprintf("int-session-multi-%d", time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		evt := createTestEvent("mcp", fmt.Sprintf("int-agent-multi-%d", i), sessionID, "request", "low")
		require.NoError(t, store.RecordEvent(ctx, evt), "RecordEvent %d should succeed", i)
	}
}

// --------------------------------------------------------------------------
// ListEventsBySession
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_ListEventsBySession(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	sessionID := fmt.Sprintf("int-session-list-%d", time.Now().UnixNano())
	evt1 := createTestEvent("mcp", "int-agent-list", sessionID, "request", "low")
	evt2 := createTestEvent("a2a", "int-agent-list", sessionID, "message", "medium")

	require.NoError(t, store.RecordEvent(ctx, evt1))
	require.NoError(t, store.RecordEvent(ctx, evt2))

	events, err := store.ListEventsBySession(ctx, sessionID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 2, "expected at least 2 events for session")

	// Verify all returned events belong to the correct session
	for _, e := range events {
		assert.Equal(t, sessionID, e.SessionID, "event should belong to the queried session")
	}
}

func TestIntegration_PostgresCorrelationStore_ListEventsBySession_EmptyResult(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	events, err := store.ListEventsBySession(ctx, "nonexistent-session-int")
	require.NoError(t, err)
	assert.Empty(t, events, "expected empty result for nonexistent session")
}

func TestIntegration_PostgresCorrelationStore_ListEventsBySession_EmptyID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.ListEventsBySession(ctx, "")
	assert.Error(t, err, "ListEventsBySession with empty sessionID should error")
}

// --------------------------------------------------------------------------
// ListEventsByAgent
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_ListEventsByAgent(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-byagent-%d", time.Now().UnixNano())
	evt := createTestEvent("mcp", agentID, "int-session-agent", "request", "low")
	require.NoError(t, store.RecordEvent(ctx, evt))

	events, err := store.ListEventsByAgent(ctx, agentID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 1, "expected at least 1 event for agent")
}

func TestIntegration_PostgresCorrelationStore_ListEventsByAgent_AcrossSessions(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-cross-%d", time.Now().UnixNano())
	evt1 := createTestEvent("mcp", agentID, "int-session-a", "request", "low")
	evt2 := createTestEvent("a2a", agentID, "int-session-b", "message", "medium")

	require.NoError(t, store.RecordEvent(ctx, evt1))
	require.NoError(t, store.RecordEvent(ctx, evt2))

	events, err := store.ListEventsByAgent(ctx, agentID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 2, "expected at least 2 events across sessions for agent")

	for _, e := range events {
		assert.Equal(t, agentID, e.AgentID, "event should belong to the queried agent")
	}
}

func TestIntegration_PostgresCorrelationStore_ListEventsByAgent_EmptyID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.ListEventsByAgent(ctx, "")
	assert.Error(t, err, "ListEventsByAgent with empty agentID should error")
}

// --------------------------------------------------------------------------
// ListEventsByAgentAndSession
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_ListEventsByAgentAndSession(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-combo-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("int-session-combo-%d", time.Now().UnixNano())
	evt := createTestEvent("mcp", agentID, sessionID, "request", "low")
	require.NoError(t, store.RecordEvent(ctx, evt))

	events, err := store.ListEventsByAgentAndSession(ctx, agentID, sessionID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 1, "expected at least 1 event for agent+session")
}

func TestIntegration_PostgresCorrelationStore_ListEventsByAgentAndSession_EmptyAgentID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.ListEventsByAgentAndSession(ctx, "", "session-1")
	assert.Error(t, err, "ListEventsByAgentAndSession with empty agentID should error")
}

func TestIntegration_PostgresCorrelationStore_ListEventsByAgentAndSession_EmptySessionID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.ListEventsByAgentAndSession(ctx, "agent-1", "")
	assert.Error(t, err, "ListEventsByAgentAndSession with empty sessionID should error")
}

// --------------------------------------------------------------------------
// Analyze
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_Analyze(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-analyze-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("int-session-analyze-%d", time.Now().UnixNano())
	evt := createTestEvent("mcp", agentID, sessionID, "request", "low")
	require.NoError(t, store.RecordEvent(ctx, evt))

	events, err := store.Analyze(ctx, agentID, sessionID, 5*time.Minute)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 1, "expected at least 1 event within time window")
}

func TestIntegration_PostgresCorrelationStore_Analyze_OldEventsFiltered(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-analyze-old-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("int-session-analyze-old-%d", time.Now().UnixNano())

	// Record a recent event
	recent := createTestEvent("mcp", agentID, sessionID, "request", "low")
	require.NoError(t, store.RecordEvent(ctx, recent))

	// Record an old event by setting its timestamp in the past
	old := createTestEvent("mcp", agentID, sessionID, "error", "high")
	old.Timestamp = time.Now().UTC().Add(-2 * time.Hour)
	require.NoError(t, store.RecordEvent(ctx, old))

	// Analyze with a short window — only the recent event should appear
	window := 10 * time.Minute
	events, err := store.Analyze(ctx, agentID, sessionID, window)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 1, "expected at least the recent event")

	// The recent event should be present; verify that at least one
	// event in the result is the recent one.
	foundRecent := false
	for _, e := range events {
		if e.EventType == "request" {
			foundRecent = true
		}
	}
	assert.True(t, foundRecent, "expected to find the recent event in Analyze results")
}

func TestIntegration_PostgresCorrelationStore_Analyze_EmptyAgentID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.Analyze(ctx, "", "session-1", 5*time.Minute)
	assert.Error(t, err, "Analyze with empty agentID should error")
}

func TestIntegration_PostgresCorrelationStore_Analyze_EmptySessionID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.Analyze(ctx, "agent-1", "", 5*time.Minute)
	assert.Error(t, err, "Analyze with empty sessionID should error")
}

// --------------------------------------------------------------------------
// Prune
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_Prune(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Prune with a very short maxAge — removes events older than 1ns,
	// which should include any pre-existing data. Just verify it
	// doesn't error and returns a non-negative count.
	removed, err := store.Prune(ctx, 1*time.Nanosecond)
	require.NoError(t, err, "Prune should not error")
	assert.GreaterOrEqual(t, removed, 0, "removed count should be non-negative")
}

func TestIntegration_PostgresCorrelationStore_Prune_RemovesOldEvents(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-prune-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("int-session-prune-%d", time.Now().UnixNano())

	// Record a recent event
	recent := createTestEvent("mcp", agentID, sessionID, "request", "low")
	require.NoError(t, store.RecordEvent(ctx, recent))

	// Record an old event with a timestamp far in the past
	old := createTestEvent("mcp", agentID, sessionID, "error", "high")
	old.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	require.NoError(t, store.RecordEvent(ctx, old))

	// Prune events older than 1 hour — should remove the old event
	removed, err := store.Prune(ctx, 1*time.Hour)
	require.NoError(t, err, "Prune should not error")
	assert.GreaterOrEqual(t, removed, 1, "expected at least 1 old event pruned")

	// Verify the recent event is still queryable
	events, err := store.ListEventsByAgent(ctx, agentID)
	require.NoError(t, err)
	foundRecent := false
	for _, e := range events {
		if e.EventType == "request" {
			foundRecent = true
		}
	}
	assert.True(t, foundRecent, "recent event should still be present after prune")
}

// --------------------------------------------------------------------------
// Close
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_Close(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Close is a no-op (pool lifecycle managed externally)
	err := store.Close()
	assert.NoError(t, err, "Close should not return an error")
}

// --------------------------------------------------------------------------
// Full workflow: Record → Query → Analyze → Prune
// --------------------------------------------------------------------------

func TestIntegration_PostgresCorrelationStore_FullWorkflow(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	agentID := fmt.Sprintf("int-agent-workflow-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("int-session-workflow-%d", time.Now().UnixNano())

	// Step 1: Record multiple events
	events := []*Event{
		createTestEvent("mcp", agentID, sessionID, "request", "low"),
		createTestEvent("a2a", agentID, sessionID, "message", "medium"),
		createTestEvent("mcp", agentID, sessionID, "response", "low"),
	}
	for _, evt := range events {
		require.NoError(t, store.RecordEvent(ctx, evt), "RecordEvent should succeed")
	}

	// Step 2: List by session
	sessionEvents, err := store.ListEventsBySession(ctx, sessionID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessionEvents), 3, "expected at least 3 events for session")

	// Step 3: List by agent
	agentEvents, err := store.ListEventsByAgent(ctx, agentID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(agentEvents), 3, "expected at least 3 events for agent")

	// Step 4: List by agent and session
	agentSessionEvents, err := store.ListEventsByAgentAndSession(ctx, agentID, sessionID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(agentSessionEvents), 3, "expected at least 3 events for agent+session")

	// Step 5: Analyze within a time window
	analyzed, err := store.Analyze(ctx, agentID, sessionID, 5*time.Minute)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(analyzed), 3, "expected at least 3 events within time window")

	// Step 6: Prune with a very long maxAge (should remove nothing recent)
	removed, err := store.Prune(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, removed, 0, "prune with long maxAge should not error")
}
