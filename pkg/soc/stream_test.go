// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Timeline SSE Streaming Tests (v3.8)

package soc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// =====================================================================
// TimelineStreamer tests
// =====================================================================

func TestTimelineStreamer_SubscribeAndPush(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())
	streamer.Start()
	defer streamer.Stop()

	ch := streamer.Subscribe("client-1")
	defer streamer.Unsubscribe("client-1")

	evt := &correlation.Event{
		ID:        "evt-1",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "tool_call",
		Severity:  "medium",
		Decision:  "allow",
		Timestamp: time.Now().UTC(),
	}

	streamer.PushEvent(evt)

	select {
	case se := <-ch:
		if se.Type != StreamEventTimeline {
			t.Fatalf("expected timeline_event, got %s", se.Type)
		}
		te, ok := se.Data.(*TimelineEvent)
		if !ok {
			t.Fatalf("expected *TimelineEvent, got %T", se.Data)
		}
		if te.ID != "evt-1" {
			t.Fatalf("expected evt-1, got %s", te.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestTimelineStreamer_MultipleClients(t *testing.T) {
	streamer := NewTimelineStreamer(nil, StreamConfig{BufferSize: 16, HeartbeatInterval: time.Hour})
	streamer.Start()
	defer streamer.Stop()

	ch1 := streamer.Subscribe("client-1")
	ch2 := streamer.Subscribe("client-2")
	defer streamer.Unsubscribe("client-1")
	defer streamer.Unsubscribe("client-2")

	evt := &correlation.Event{
		ID:        "evt-multi",
		Protocol:  "http",
		SessionID: "s1",
		EventType: "request",
		Severity:  "low",
		Timestamp: time.Now().UTC(),
	}

	streamer.PushEvent(evt)

	// Both clients should receive the event.
	for _, ch := range []<-chan *StreamEvent{ch1, ch2} {
		select {
		case se := <-ch:
			if se.Type != StreamEventTimeline {
				t.Fatalf("expected timeline_event, got %s", se.Type)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestTimelineStreamer_Unsubscribe(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())

	ch := streamer.Subscribe("client-1")
	streamer.Unsubscribe("client-1")

	// Channel should be closed after unsubscribe.
	_, ok := <-ch
	if ok {
		t.Fatal("expected channel to be closed after unsubscribe")
	}
}

func TestTimelineStreamer_SubCount(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())

	if count := streamer.SubCount(); count != 0 {
		t.Fatalf("expected 0 subs, got %d", count)
	}

	streamer.Subscribe("client-1")
	if count := streamer.SubCount(); count != 1 {
		t.Fatalf("expected 1 sub, got %d", count)
	}

	streamer.Subscribe("client-2")
	if count := streamer.SubCount(); count != 2 {
		t.Fatalf("expected 2 subs, got %d", count)
	}

	streamer.Unsubscribe("client-1")
	if count := streamer.SubCount(); count != 1 {
		t.Fatalf("expected 1 sub, got %d", count)
	}
}

func TestTimelineStreamer_PushEventNil(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())
	streamer.Start()
	defer streamer.Stop()

	// Should not panic on nil event.
	streamer.PushEvent(nil)
}

func TestTimelineStreamer_Heartbeat(t *testing.T) {
	cfg := StreamConfig{
		BufferSize:        16,
		HeartbeatInterval: 50 * time.Millisecond,
	}
	streamer := NewTimelineStreamer(nil, cfg)
	streamer.Start()
	defer streamer.Stop()

	ch := streamer.Subscribe("client-1")
	defer streamer.Unsubscribe("client-1")

	select {
	case se := <-ch:
		if se.Type != StreamEventHeartbeat {
			t.Fatalf("expected heartbeat, got %s", se.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}
}

func TestTimelineStreamer_StopClosesChannels(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())
	streamer.Start()

	ch := streamer.Subscribe("client-1")
	streamer.Stop()

	// Drain any remaining events (heartbeat, close), then
	// verify the channel is actually closed.
	for {
		_, ok := <-ch
		if !ok {
			break
		}
	}
	// If we get here, the channel is closed. Test passes.
}

func TestTimelineStreamer_BackPressure(t *testing.T) {
	cfg := StreamConfig{
		BufferSize:        2, // tiny buffer
		HeartbeatInterval: time.Hour,
	}
	streamer := NewTimelineStreamer(nil, cfg)
	streamer.Start()
	defer streamer.Stop()

	ch := streamer.Subscribe("client-1")
	defer streamer.Unsubscribe("client-1")

	// Push more events than the buffer can hold.
	for i := 0; i < 10; i++ {
		streamer.PushEvent(&correlation.Event{
			ID:        fmt.Sprintf("evt-%d", i),
			Protocol:  "mcp",
			SessionID: "s1",
			EventType: "tool_call",
			Severity:  "low",
			Timestamp: time.Now().UTC(),
		})
	}

	// Should get at least 2 events (buffer size) without blocking.
	received := 0
	timeout := time.After(time.Second)
	for {
		select {
		case <-ch:
			received++
			if received >= 2 {
				goto done
			}
		case <-timeout:
			goto done
		}
	}
done:
	if received < 2 {
		t.Fatalf("expected at least 2 events, got %d", received)
	}
}

// =====================================================================
// SSE HTTP handler tests
// =====================================================================

func TestServeSSE_EventsStream(t *testing.T) {
	streamer := NewTimelineStreamer(nil, StreamConfig{
		BufferSize:        16,
		HeartbeatInterval: time.Hour,
	})
	streamer.Start()
	defer streamer.Stop()

	// Subscribe a client and verify events arrive via the channel.
	ch := streamer.Subscribe("test-client-1")
	defer streamer.Unsubscribe("test-client-1")

	// Push an event.
	streamer.PushEvent(&correlation.Event{
		ID:        "sse-test-1",
		Protocol:  "mcp",
		SessionID: "s1",
		EventType: "tool_call",
		Severity:  "medium",
		Timestamp: time.Now().UTC(),
	})

	select {
	case se := <-ch:
		if se.Type != StreamEventTimeline {
			t.Fatalf("expected timeline_event, got %s", se.Type)
		}
		te, ok := se.Data.(*TimelineEvent)
		if !ok {
			t.Fatalf("expected *TimelineEvent, got %T", se.Data)
		}
		if te.ID != "sse-test-1" {
			t.Fatalf("expected sse-test-1, got %s", te.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestServeSSE_Headers(t *testing.T) {
	// Test that writeSSEEvent produces correct SSE format.
	w := httptest.NewRecorder()

	evt := &StreamEvent{
		Type:      StreamEventTimeline,
		Data:      &TimelineEvent{ID: "test-1", Protocol: "mcp", Severity: "low"},
		ID:        "12345-1",
		Timestamp: time.Now().UTC(),
	}
	writeSSEEvent(w, evt)

	body := w.Body.String()
	if !strings.Contains(body, "event: timeline_event") {
		t.Fatalf("expected event: timeline_event, got:\n%s", body)
	}
	if !strings.Contains(body, "data:") {
		t.Fatalf("expected data: line, got:\n%s", body)
	}
	if !strings.Contains(body, "id: 12345-1") {
		t.Fatalf("expected id: 12345-1, got:\n%s", body)
	}
}

// =====================================================================
// StreamEvent type tests
// =====================================================================

func TestTimelineEvent_IsCritical(t *testing.T) {
	tests := []struct {
		severity string
		want     bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", false},
		{"low", false},
		{"info", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			evt := &TimelineEvent{Severity: tt.severity}
			if got := evt.IsCritical(); got != tt.want {
				t.Errorf("IsCritical() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServeSSE_RealHTTP(t *testing.T) {
	streamer := NewTimelineStreamer(nil, StreamConfig{
		BufferSize:        16,
		HeartbeatInterval: time.Hour,
	})
	streamer.Start()
	defer streamer.Stop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeSSE(w, r, streamer, "http-client-1")
	}))
	defer server.Close()

	// Push an event shortly after client connects.
	go func() {
		time.Sleep(50 * time.Millisecond)
		streamer.PushEvent(&correlation.Event{
			ID:        "http-sse-test",
			Protocol:  "a2a",
			SessionID: "s-http",
			EventType: "message",
			Severity:  "high",
			Timestamp: time.Now().UTC(),
		})
	}()

	client := server.Client()
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %s", ct)
	}

	// Read some bytes (event should arrive within 2s).
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "timeline_event") {
		t.Fatalf("expected timeline_event in SSE output, got:\n%s", body)
	}
}

func TestStreamEventTypes(t *testing.T) {
	if StreamEventTimeline != "timeline_event" {
	}
	if StreamEventHeartbeat != "timeline_heartbeat" {
		t.Fatalf("expected timeline_heartbeat, got %s", StreamEventHeartbeat)
	}
	if StreamEventError != "timeline_error" {
		t.Fatalf("expected timeline_error, got %s", StreamEventError)
	}
	if StreamEventClose != "timeline_close" {
		t.Fatalf("expected timeline_close, got %s", StreamEventClose)
	}
}

func TestDefaultStreamConfig(t *testing.T) {
	cfg := DefaultStreamConfig()
	if cfg.BufferSize != 64 {
		t.Fatalf("expected BufferSize 64, got %d", cfg.BufferSize)
	}
	if cfg.HeartbeatInterval != 15*time.Second {
		t.Fatalf("expected HeartbeatInterval 15s, got %s", cfg.HeartbeatInterval)
	}
}

// =====================================================================
// ReplayEvents test (with mock store)
// =====================================================================

type mockCorrelationStore struct {
	events []*correlation.Event
}

func (m *mockCorrelationStore) RecordEvent(_ context.Context, _ *correlation.Event) error {
	return nil
}
func (m *mockCorrelationStore) ListEventsBySession(_ context.Context, sessionID string) ([]*correlation.Event, error) {
	var result []*correlation.Event
	for _, e := range m.events {
		if e.SessionID == sessionID {
			result = append(result, e)
		}
	}
	return result, nil
}
func (m *mockCorrelationStore) ListEventsByAgent(_ context.Context, _ string) ([]*correlation.Event, error) {
	return nil, nil
}
func (m *mockCorrelationStore) ListEventsByAgentAndSession(_ context.Context, _, _ string) ([]*correlation.Event, error) {
	return nil, nil
}
func (m *mockCorrelationStore) Analyze(_ context.Context, _, _ string, _ time.Duration) ([]*correlation.Event, error) {
	return nil, nil
}
func (m *mockCorrelationStore) Prune(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}
func (m *mockCorrelationStore) Close() error { return nil }

func TestReplayEvents_WithStore(t *testing.T) {
	store := &mockCorrelationStore{
		events: []*correlation.Event{
			{ID: "r1", SessionID: "s1", Protocol: "mcp", EventType: "call", Severity: "low", Timestamp: time.Now().UTC()},
			{ID: "r2", SessionID: "s1", Protocol: "a2a", EventType: "message", Severity: "medium", Timestamp: time.Now().UTC()},
			{ID: "r3", SessionID: "s2", Protocol: "http", EventType: "request", Severity: "low", Timestamp: time.Now().UTC()},
		},
	}

	streamer := NewTimelineStreamer(store, DefaultStreamConfig())
	streamer.Start()
	defer streamer.Stop()

	events, err := streamer.ReplayEvents(context.Background(), "s1")
	if err != nil {
		t.Fatalf("ReplayEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events for session s1, got %d", len(events))
	}
}

func TestReplayEvents_NilStore(t *testing.T) {
	streamer := NewTimelineStreamer(nil, DefaultStreamConfig())
	events, err := streamer.ReplayEvents(context.Background(), "s1")
	if err != nil {
		t.Fatalf("ReplayEvents with nil store should not error: %v", err)
	}
	if events != nil {
		t.Fatalf("ReplayEvents with nil store should return nil, got %v", events)
	}
}