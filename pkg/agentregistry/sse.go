// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry SSE Event Broadcasting (v5.0)
// =========================================================================
//
// sse.go provides a standalone Server-Sent Events broadcaster for
// agent lifecycle events. The broadcaster decouples event production
// (Registry lifecycle callbacks, policy enforcement) from event
// consumption (dashboard clients, SOC dashboards, external monitors).
//
// Architecture:
//
//   - EventBroadcaster maintains a set of subscribed SSE clients.
//   - Each client gets a dedicated buffered channel (128 events).
//   - Back-pressure: if a client's buffer is full, the oldest events
//     are dropped (better than blocking the producer).
//   - Heartbeat goroutine sends a keepalive every 15 seconds.
//   - The broadcaster is connected to the Registry via
//     SetLifecycleEventCallback; any lifecycle transition is
//     immediately pushed to all connected clients.
//
// SSE protocol:
//
//   - Content-Type: text/event-stream
//   - event: agent_lifecycle (status transitions)
//   - event: agent_discovered (new agent found)
//   - event: agent_dormant (dormancy threshold crossed)
//   - event: agent_revoked (credentials revoked)
//   - event: agent_drift (AIBOM reconciliation drift)
//   - event: agent_heartbeat (keepalive)
//   - id: <monotonic-sequence> (enables reconnection with Last-Event-ID)
//
// Tier gating: The SSE endpoint is mounted behind the same
// Professional-tier gate as the rest of the Agent Registry feature.
// Auth middleware ensures the caller is authenticated and has
// rbac.ResourceAgent:rbac.ActionRead permission.
//
// Air-gap compliance: SSE operates over HTTP within the platform
// process. No external network egress. The broadcaster is in-process
// only; there is no connection to any external message broker.
// =========================================================================

package agentregistry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// =====================================================================
// SSE Event Types
// =====================================================================

// SSEEventType identifies the type of agent registry SSE event.
// These mirror the StreamEventType constants in pkg/soc/stream.go
// but are defined locally to avoid a cross-package dependency.
type SSEEventType string

const (
	// SSEEventAgentLifecycle is sent when an agent's lifecycle
	// status transitions.
	SSEEventAgentLifecycle SSEEventType = "agent_lifecycle"

	// SSEEventAgentDiscovered is sent when discovery finds a new
	// agent not previously in the registry.
	SSEEventAgentDiscovered SSEEventType = "agent_discovered"

	// SSEEventAgentDormant is sent when an agent crosses the
	// dormancy threshold.
	SSEEventAgentDormant SSEEventType = "agent_dormant"

	// SSEEventAgentRevoked is sent when an agent's credentials
	// are revoked.
	SSEEventAgentRevoked SSEEventType = "agent_revoked"

	// SSEEventAgentDrift is sent when AIBOM-to-runtime
	// reconciliation detects drift.
	SSEEventAgentDrift SSEEventType = "agent_drift"

	// SSEEventHeartbeat is sent periodically to keep the
	// connection alive through proxies and load balancers.
	SSEEventHeartbeat SSEEventType = "agent_heartbeat"
)

// SSEEvent is a single SSE event sent to connected clients.
type SSEEvent struct {
	// Type is the SSE event type.
	Type SSEEventType `json:"type"`
	// Data is the event payload.
	Data interface{} `json:"data"`
	// ID is the SSE event ID for reconnection support.
	ID string `json:"id"`
	// Timestamp is when this event was generated.
	Timestamp time.Time `json:"timestamp"`
}

// =====================================================================
// EventBroadcaster
// =====================================================================

// EventBroadcaster manages SSE subscriptions and broadcasts agent
// registry events to all connected clients. It is safe for concurrent
// use.
type EventBroadcaster struct {
	mu       sync.RWMutex
	subs     map[string]chan *SSEEvent
	logger   *slog.Logger
	eventSeq atomic.Uint64
	stopCh   chan struct{}
	stopped  atomic.Bool
}

// NewEventBroadcaster creates a new EventBroadcaster. The broadcaster
// must be started with Start to enable heartbeats and stopped with
// Stop to release resources.
func NewEventBroadcaster(logger *slog.Logger) *EventBroadcaster {
	if logger == nil {
		logger = slog.Default().With("component", "agent-registry-sse")
	}
	return &EventBroadcaster{
		subs:   make(map[string]chan *SSEEvent),
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start launches the heartbeat goroutine. The heartbeat interval is
// 15 seconds. Call Stop to terminate the goroutine.
func (b *EventBroadcaster) Start() {
	go b.heartbeatLoop()
}

// Stop terminates the heartbeat goroutine and closes all subscriber
// channels. After Stop, the broadcaster should not be reused.
func (b *EventBroadcaster) Stop() {
	if !b.stopped.CompareAndSwap(false, true) {
		return
	}
	close(b.stopCh)

	b.mu.Lock()
	defer b.mu.Unlock()
	for id, ch := range b.subs {
		close(ch)
		delete(b.subs, id)
	}
}

// Subscribe registers a new SSE client and returns its event channel.
// The caller is responsible for reading from the channel; if the
// buffer fills, events are dropped for that client. The clientID must
// be unique; if it already exists, the previous subscription is
// replaced.
func (b *EventBroadcaster) Subscribe(clientID string) <-chan *SSEEvent {
	ch := make(chan *SSEEvent, 128)

	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.subs[clientID]; ok {
		close(old)
	}
	b.subs[clientID] = ch
	return ch
}

// Unsubscribe removes a client and closes its channel.
func (b *EventBroadcaster) Unsubscribe(clientID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[clientID]; ok {
		close(ch)
		delete(b.subs, clientID)
	}
}

// Broadcast pushes an event to all connected clients. If a client's
// buffer is full, the event is dropped for that client rather than
// blocking the producer.
func (b *EventBroadcaster) Broadcast(eventType SSEEventType, data interface{}) {
	if b.stopped.Load() {
		return
	}

	event := &SSEEvent{
		Type:      eventType,
		Data:      data,
		ID:        fmt.Sprintf("%d", b.eventSeq.Add(1)),
		Timestamp: time.Now().UTC(),
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for id, ch := range b.subs {
		select {
		case ch <- event:
		default:
			b.logger.Warn("sse event dropped for slow client", "client_id", id, "event_type", eventType)
		}
	}
}

// SubscriberCount returns the number of connected clients.
func (b *EventBroadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// HandleSSE is an http.HandlerFunc that streams agent registry events
// to the client via Server-Sent Events. It sets the appropriate
// headers, subscribes to the broadcaster, and writes events as they
// arrive. The handler blocks until the client disconnects or the
// broadcaster is stopped.
func (b *EventBroadcaster) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	clientID := fmt.Sprintf("sse-%d-%d", time.Now().UnixNano(), b.eventSeq.Add(1))
	ch := b.Subscribe(clientID)
	defer b.Unsubscribe(clientID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		case event, open := <-ch:
			if !open {
				return
			}
			writeAgentSSEEvent(w, flusher, event)
		}
	}
}

// OnLifecycleEvent is a callback function suitable for
// Registry.SetLifecycleEventCallback. It converts a LifecycleEvent
// into an SSE broadcast.
func (b *EventBroadcaster) OnLifecycleEvent(event LifecycleEvent) {
	eventType := SSEEventAgentLifecycle
	switch event.NewStatus {
	case StatusDormant:
		eventType = SSEEventAgentDormant
	case StatusRevoked:
		eventType = SSEEventAgentRevoked
	}
	b.Broadcast(eventType, event)
}

// =====================================================================
// Internal helpers
// =====================================================================

// heartbeatLoop sends a heartbeat event to all clients every 15
// seconds until the broadcaster is stopped.
func (b *EventBroadcaster) heartbeatLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.Broadcast(SSEEventHeartbeat, map[string]time.Time{
				"timestamp": time.Now().UTC(),
			})
		}
	}
}

// writeAgentSSEEvent writes a single SSE event to the response writer
// and flushes immediately.
func writeAgentSSEEvent(w http.ResponseWriter, flusher http.Flusher, event *SSEEvent) {
	data, err := json.Marshal(event.Data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\n", event.Type)
	fmt.Fprintf(w, "id: %s\n", event.ID)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}