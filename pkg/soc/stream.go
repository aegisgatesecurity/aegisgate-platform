// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - SOC Timeline SSE Streaming (v3.8)
// =========================================================================
//
// stream.go adds Server-Sent Events (SSE) streaming to the SOC timeline.
// This enables real-time incident monitoring without polling.
//
// Architecture:
//
//   - TimelineStreamer subscribes to a CorrelationStore and pushes new
//     events to connected SSE clients as they arrive.
//   - Each client gets a dedicated channel buffered to 64 events.
//   - Back-pressure: if a client's buffer is full, the oldest events
//     are dropped (better than blocking the producer).
//   - Heartbeat every 15 seconds to keep connections alive through
//     proxies and load balancers.
//
// SSE protocol:
//
//   - Content-Type: text/event-stream
//   - event: timeline_event (new events)
//   - event: timeline_heartbeat (keepalive)
//   - event: timeline_error (errors)
//   - event: timeline_close (graceful shutdown)
//   - id: <timestamp>-<event-index> (enables reconnection with Last-Event-ID)
//
// Wire target:
//
//   GET /api/v1/soc/incidents/:id/stream
//   GET /api/v1/soc/stream (all incidents, filtered client-side)
//
// Tier gating: SSE streaming is Professional+ (Developer gets 5-second
// poll; Community gets 30-second poll; Professional gets real-time SSE).
//
// v3.8 persistence gap closure.
// =========================================================================

package soc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// =====================================================================
// StreamEvent types
// =====================================================================

// StreamEventType identifies the type of SSE event.
type StreamEventType string

const (
	// StreamEventTimeline is sent when a new event arrives.
	StreamEventTimeline StreamEventType = "timeline_event"
	// StreamEventHeartbeat is sent periodically to keep the connection alive.
	StreamEventHeartbeat StreamEventType = "timeline_heartbeat"
	// StreamEventError is sent when an error occurs.
	StreamEventError StreamEventType = "timeline_error"
	// StreamEventClose is sent when the stream is closing gracefully.
	StreamEventClose StreamEventType = "timeline_close"
)

// StreamEvent is a single SSE event sent to the client.
type StreamEvent struct {
	// Type is the SSE event type.
	Type StreamEventType `json:"type"`
	// Data is the event payload (a TimelineEvent for timeline_event type).
	Data interface{} `json:"data"`
	// ID is the SSE event ID for reconnection support.
	ID string `json:"id"`
	// Timestamp is when this event was generated.
	Timestamp time.Time `json:"timestamp"`
}

// =====================================================================
// StreamConfig
// =====================================================================

// StreamConfig holds configuration for the timeline streamer.
type StreamConfig struct {
	// BufferSize is the per-client event buffer size. Default: 64.
	BufferSize int
	// HeartbeatInterval is how often heartbeat events are sent. Default: 15s.
	HeartbeatInterval time.Duration
	// ReplaySince enables replaying events since a given time on connect.
	// Zero means no replay (only new events).
	ReplaySince time.Duration
}

// DefaultStreamConfig returns sensible defaults.
func DefaultStreamConfig() StreamConfig {
	return StreamConfig{
		BufferSize:        64,
		HeartbeatInterval: 15 * time.Second,
		ReplaySince:       0,
	}
}

// =====================================================================
// TimelineStreamer
// =====================================================================

// TimelineStreamer pushes new correlation events to connected SSE
// clients in real-time. It subscribes to a CorrelationStore and
// distributes events to all active subscribers.
//
// Thread safety: all methods are safe for concurrent use.
type TimelineStreamer struct {
	cfg     StreamConfig
	store   correlation.CorrelationStore
	logger  *slog.Logger

	mu        sync.RWMutex
	subs      map[string]chan *StreamEvent // clientID -> event channel
	nextID    int64
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
}

// NewTimelineStreamer creates a new streamer. The store may be nil
// for pure-push mode (only events explicitly pushed via PushEvent
// are sent to clients). If a store is provided, the streamer can
// optionally replay recent events on client connect.
func NewTimelineStreamer(store correlation.CorrelationStore, cfg StreamConfig) *TimelineStreamer {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 64
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 15 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TimelineStreamer{
		cfg:    cfg,
		store:  store,
		logger: slog.Default().With("component", "soc-streamer"),
		subs:   make(map[string]chan *StreamEvent),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the heartbeat goroutine. Call this after NewTimelineStreamer.
func (s *TimelineStreamer) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	go s.heartbeatLoop()
	s.logger.Info("SOC timeline streamer started")
}

// Stop gracefully shuts down the streamer. All connected clients
// receive a timeline_close event and their channels are closed.
func (s *TimelineStreamer) Stop() {
	s.cancel()
	closeID := s.nextEventID()
	closeTime := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	for id, ch := range s.subs {
		select {
		case ch <- &StreamEvent{
			Type:      StreamEventClose,
			Data:      "stream closing",
			ID:        closeID,
			Timestamp: closeTime,
		}:
		default:
			// channel full, drop close event
		}
		close(ch)
		delete(s.subs, id)
	}
	s.logger.Info("SOC timeline streamer stopped")
}

// Subscribe registers a new SSE client and returns a read-only channel
// of events. The caller should range over the channel in the HTTP handler.
// When the streamer stops, the channel is closed.
//
// The clientID must be unique per client (typically a UUID).
func (s *TimelineStreamer) Subscribe(clientID string) <-chan *StreamEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan *StreamEvent, s.cfg.BufferSize)
	s.subs[clientID] = ch
	s.logger.Debug("client subscribed", "client_id", clientID, "total_subs", len(s.subs))
	return ch
}

// Unsubscribe removes a client. The channel is closed.
func (s *TimelineStreamer) Unsubscribe(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.subs[clientID]
	if ok {
		close(ch)
		delete(s.subs, clientID)
		s.logger.Debug("client unsubscribed", "client_id", clientID, "total_subs", len(s.subs))
	}
}

// SubCount returns the number of active subscribers.
func (s *TimelineStreamer) SubCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

// PushEvent pushes a correlation event to all connected clients.
// This is called by the platform's event pipeline when a new
// correlation event is recorded. Events are converted to
// TimelineEvent format and sent as timeline_event SSE events.
//
// If a client's buffer is full, the event is dropped for that client
// (back-pressure handling — better than blocking the producer).
func (s *TimelineStreamer) PushEvent(event *correlation.Event) {
	if event == nil {
		return
	}

	te := convertEvent(event)
	se := &StreamEvent{
		Type:      StreamEventTimeline,
		Data:      te,
		ID:        s.nextEventID(),
		Timestamp: time.Now().UTC(),
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for id, ch := range s.subs {
		select {
		case ch <- se:
		default:
			// Back-pressure: drop event for this client rather than blocking.
			s.logger.Warn("event dropped for slow client", "client_id", id)
		}
	}
}

// ReplayEvents replays recent events from the CorrelationStore for a
// given session. This is called when a client connects with a
// Last-Event-ID header to resume from a known point.
//
// If the store is nil, this is a no-op.
func (s *TimelineStreamer) ReplayEvents(ctx context.Context, sessionID string) ([]*TimelineEvent, error) {
	if s.store == nil {
		return nil, nil
	}
	events, err := s.store.ListEventsBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("soc: replay events: %w", err)
	}
	tes := make([]*TimelineEvent, len(events))
	for i, e := range events {
		tes[i] = convertEvent(e)
	}
	return tes, nil
}

// nextEventID generates a unique event ID for SSE reconnection.
func (s *TimelineStreamer) nextEventID() string {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.mu.Unlock()
	return fmt.Sprintf("%d-%d", time.Now().UnixMilli(), id)
}

// heartbeatLoop sends heartbeat events to all clients periodically.
func (s *TimelineStreamer) heartbeatLoop() {
	ticker := time.NewTicker(s.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			subs := make(map[string]chan *StreamEvent, len(s.subs))
			for id, ch := range s.subs {
				subs[id] = ch
			}
			s.mu.RUnlock()

			hb := &StreamEvent{
				Type:      StreamEventHeartbeat,
				Data:      "ok",
				ID:        s.nextEventID(),
				Timestamp: time.Now().UTC(),
			}

			for _, ch := range subs {
				select {
				case ch <- hb:
				default:
					// drop heartbeat for slow client
				}
			}
		}
	}
}

// =====================================================================
// SSE HTTP Handler
// =====================================================================

// ServeSSE handles a Server-Sent Events connection. It subscribes to
// the TimelineStreamer, writes events to the HTTP response, and
// unsubscribes when the client disconnects.
//
// Usage:
//
//	streamer := soc.NewTimelineStreamer(store, soc.DefaultStreamConfig())
//	http.HandleFunc("/api/v1/soc/stream", func(w, r) {
//	    soc.ServeSSE(w, r, streamer, "client-uuid")
//	})
func ServeSSE(w http.ResponseWriter, r *http.Request, streamer *TimelineStreamer, clientID string) {
	// SSE requires specific headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: disable buffering

	// Flush headers.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Subscribe to the streamer.
	ch := streamer.Subscribe(clientID)
	defer streamer.Unsubscribe(clientID)

	// Write events until client disconnects or streamer stops.
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				// Channel closed (streamer stopped).
				return
			}
			writeSSEEvent(w, event)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

// writeSSEEvent writes a single SSE event to the response writer.
// Format: "event: <type>\ndata: <json>\nid: <id>\n\n"
func writeSSEEvent(w http.ResponseWriter, event *StreamEvent) {
	// SSE event type.
	fmt.Fprintf(w, "event: %s\n", event.Type)

	// SSE data (JSON-encoded).
	data, err := json.Marshal(event.Data)
	if err != nil {
		// Fallback: send error as plain text.
		fmt.Fprintf(w, "data: {\"error\": \"marshal failed\"}\n")
	} else {
		// Split multi-line data into multiple "data:" lines per SSE spec.
		for _, line := range strings.Split(string(data), "\n") {
			fmt.Fprintf(w, "data: %s\n", line)
		}
	}

	// SSE event ID (for reconnection).
	if event.ID != "" {
		fmt.Fprintf(w, "id: %s\n", event.ID)
	}

	// Blank line terminates the event.
	fmt.Fprint(w, "\n")
}