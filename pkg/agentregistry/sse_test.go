// SPDX-License-Identifier: Apache-2.0
package agentregistry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSSELogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewEventBroadcaster(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	if b == nil {
		t.Fatal("NewEventBroadcaster returned nil")
	}
	if b.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount = %d; want 0", b.SubscriberCount())
	}
}

func TestEventBroadcaster_StartStop(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	b.Stop()
	// Stop should be idempotent.
	b.Stop()
}

func TestEventBroadcaster_SubscribeUnsubscribe(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("client-1")
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}
	if b.SubscriberCount() != 1 {
		t.Errorf("SubscriberCount = %d; want 1", b.SubscriberCount())
	}

	b.Unsubscribe("client-1")
	if b.SubscriberCount() != 0 {
		t.Errorf("After unsubscribe, SubscriberCount = %d; want 0", b.SubscriberCount())
	}
}

func TestEventBroadcaster_SubscribeReplacesExisting(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch1 := b.Subscribe("client-1")
	_ = ch1
	ch2 := b.Subscribe("client-2")
	_ = ch2

	if b.SubscriberCount() != 2 {
		t.Errorf("SubscriberCount = %d; want 2", b.SubscriberCount())
	}

	// Re-subscribe same client — should replace, not add.
	b.Subscribe("client-1")
	if b.SubscriberCount() != 2 {
		t.Errorf("After re-subscribe same client, SubscriberCount = %d; want 2", b.SubscriberCount())
	}
}

func TestEventBroadcaster_Unsubscribe_NotSubscribed(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	// Unsubscribing a non-existent client should not panic.
	b.Unsubscribe("never-subscribed")
}

func TestEventBroadcaster_Broadcast(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("client-1")

	b.Broadcast(SSEEventAgentLifecycle, map[string]string{"agent_id": "test-agent"})

	select {
	case received := <-ch:
		if received.Type != SSEEventAgentLifecycle {
			t.Errorf("Received type = %q; want %q", received.Type, SSEEventAgentLifecycle)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive broadcast event within 1s")
	}
}

func TestEventBroadcaster_Broadcast_DropsSlowSubscribers(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	// Subscribe but never read — channel buffer is 128.
	ch := b.Subscribe("client-slow")
	_ = ch

	// Send more than buffer size — should not block.
	for i := 0; i < 200; i++ {
		b.Broadcast(SSEEventAgentLifecycle, map[string]int{"i": i})
	}
	// If we get here, Broadcast didn't block on slow subscriber.
}

func TestEventBroadcaster_Broadcast_NoSubscribers(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	// Should not panic with no subscribers.
	b.Broadcast(SSEEventAgentLifecycle, map[string]string{"agent_id": "ghost"})
}

func TestEventBroadcaster_Broadcast_MultipleSubscribers(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch1 := b.Subscribe("client-1")
	ch2 := b.Subscribe("client-2")

	b.Broadcast(SSEEventAgentDormant, map[string]string{"agent_id": "multi-test"})

	// Both should receive.
	for _, ch := range []<-chan *SSEEvent{ch1, ch2} {
		select {
		case received := <-ch:
			if received.Type != SSEEventAgentDormant {
				t.Errorf("Received type = %q; want %q", received.Type, SSEEventAgentDormant)
			}
		case <-time.After(time.Second):
			t.Fatal("Did not receive broadcast event within 1s")
		}
	}
}

func TestEventBroadcaster_OnLifecycleEvent(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("client-1")

	evt := LifecycleEvent{
		AgentID:   "agent-123",
		OldStatus: StatusActive,
		NewStatus: StatusQuarantined,
		Reason:    "test-quarantine",
	}
	b.OnLifecycleEvent(evt)

	select {
	case received := <-ch:
		if received.Type != SSEEventAgentLifecycle {
			t.Errorf("Received type = %q; want %q", received.Type, SSEEventAgentLifecycle)
		}
		// Data should be the LifecycleEvent.
		dataMap, ok := received.Data.(LifecycleEvent)
		if !ok {
			t.Fatalf("Data is %T; want LifecycleEvent", received.Data)
		}
		if dataMap.AgentID != "agent-123" {
			t.Errorf("agent_id = %v; want agent-123", dataMap.AgentID)
		}
		if dataMap.Reason != "test-quarantine" {
			t.Errorf("reason = %v; want test-quarantine", dataMap.Reason)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive lifecycle event within 1s")
	}
}

func TestEventBroadcaster_OnLifecycleEvent_DormantMaps(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("client-1")

	b.OnLifecycleEvent(LifecycleEvent{
		AgentID:   "agent-d",
		OldStatus: StatusActive,
		NewStatus: StatusDormant,
	})

	select {
	case received := <-ch:
		if received.Type != SSEEventAgentDormant {
			t.Errorf("Dormant maps to %q; want %q", received.Type, SSEEventAgentDormant)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive dormant event")
	}
}

func TestEventBroadcaster_OnLifecycleEvent_RevokedMaps(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("client-1")

	b.OnLifecycleEvent(LifecycleEvent{
		AgentID:   "agent-r",
		OldStatus: StatusQuarantined,
		NewStatus: StatusRevoked,
	})

	select {
	case received := <-ch:
		if received.Type != SSEEventAgentRevoked {
			t.Errorf("Revoked maps to %q; want %q", received.Type, SSEEventAgentRevoked)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive revoked event")
	}
}

func TestEventBroadcaster_OnLifecycleEvent_NoSubscribers(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	// Should not panic with no subscribers.
	b.OnLifecycleEvent(LifecycleEvent{
		AgentID:   "agent-x",
		OldStatus: StatusActive,
		NewStatus: StatusRevoked,
	})
}

func TestEventBroadcaster_HandleSSE(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.HandleSSE(w, req)
		close(done)
	}()

	// Give the handler time to register as a subscriber.
	time.Sleep(50 * time.Millisecond)

	// Broadcast an event.
	b.Broadcast(SSEEventAgentLifecycle, map[string]string{"agent_id": "sse-test"})

	// Give time for the event to be written.
	time.Sleep(50 * time.Millisecond)

	// Cancel the request context to end the handler.
	cancel()
	<-done

	resp := w.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatal("SSE response body is empty")
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "event: agent_lifecycle") {
		t.Errorf("SSE body does not contain 'event: agent_lifecycle': %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "sse-test") {
		t.Errorf("SSE body does not contain 'sse-test': %s", bodyStr)
	}
}

func TestEventBroadcaster_HandleSSE_ContentType(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.HandleSSE(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	ct := w.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("Content-Type = %q; want %q", ct, "text/event-stream")
	}
}

func TestWriteAgentSSEEvent(t *testing.T) {
	w := httptest.NewRecorder()
	evt := &SSEEvent{
		Type:      SSEEventAgentLifecycle,
		Data:      map[string]string{"agent_id": "write-test"},
		ID:        "42",
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	writeAgentSSEEvent(w, w, evt)

	body := w.Body.String()
	if !strings.Contains(body, "event: agent_lifecycle") {
		t.Errorf("Missing event type: %s", body)
	}
	if !strings.Contains(body, "id: 42") {
		t.Errorf("Missing event ID: %s", body)
	}
	if !strings.Contains(body, "data: ") {
		t.Errorf("Missing data prefix: %s", body)
	}
	// Data should be valid JSON.
	lines := splitLines(body)
	for _, line := range lines {
		if len(line) > 6 && line[:6] == "data: " {
			var dataMap map[string]string
			if err := json.Unmarshal([]byte(line[6:]), &dataMap); err != nil {
				t.Errorf("Failed to unmarshal SSE data: %v (line: %s)", err, line)
			}
			if dataMap["agent_id"] != "write-test" {
				t.Errorf("agent_id = %q; want write-test", dataMap["agent_id"])
			}
			break
		}
	}
}

func TestWriteAgentSSEEvent_NilData(t *testing.T) {
	w := httptest.NewRecorder()
	evt := &SSEEvent{
		Type: SSEEventHeartbeat,
		Data: nil,
		ID:   "1",
	}
	writeAgentSSEEvent(w, w, evt)
	body := w.Body.String()
	if !strings.Contains(body, "event: agent_heartbeat") {
		t.Errorf("Missing heartbeat event: %s", body)
	}
}

func TestEventBroadcaster_ConcurrentSubscribeUnsubscribe(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ch := b.Subscribe(string(rune('A' + idx)))
			_ = ch
		}(i)
	}
	wg.Wait()

	if b.SubscriberCount() != 20 {
		t.Errorf("SubscriberCount = %d; want 20", b.SubscriberCount())
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			b.Unsubscribe(string(rune('A' + idx)))
		}(i)
	}
	wg.Wait()

	if b.SubscriberCount() != 0 {
		t.Errorf("After concurrent unsubscribe, SubscriberCount = %d; want 0", b.SubscriberCount())
	}
}

func TestEventBroadcaster_StopClearsSubscribers(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()

	b.Subscribe("c1")
	b.Subscribe("c2")
	b.Subscribe("c3")

	if b.SubscriberCount() != 3 {
		t.Fatalf("SubscriberCount = %d; want 3", b.SubscriberCount())
	}

	b.Stop()

	if b.SubscriberCount() != 0 {
		t.Errorf("After Stop, SubscriberCount = %d; want 0", b.SubscriberCount())
	}
}

// Helper: splitLines splits a string by newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// =====================================================================
// Edge case tests for NewEventBroadcaster and Broadcast
// =====================================================================

// TestNewEventBroadcaster_NilLogger verifies that nil logger is replaced.
func TestNewEventBroadcaster_NilLogger(t *testing.T) {
	b := NewEventBroadcaster(nil)
	if b == nil {
		t.Fatal("NewEventBroadcaster(nil) returned nil")
	}
	if b.logger == nil {
		t.Error("logger should not be nil after defaulting")
	}
}

// TestEventBroadcaster_Broadcast_NilData verifies broadcasting with nil data.
func TestEventBroadcaster_Broadcast_NilData(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ch := b.Subscribe("nil-data-client")
	b.Broadcast(SSEEventAgentLifecycle, nil)

	select {
	case evt := <-ch:
		if evt.Data != nil {
			t.Errorf("Data = %v, want nil", evt.Data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timed out waiting for broadcast event")
	}
}
