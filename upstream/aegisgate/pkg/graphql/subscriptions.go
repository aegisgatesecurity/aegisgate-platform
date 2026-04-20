// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package graphql provides GraphQL subscription support
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SubscriptionManager manages GraphQL subscriptions
type SubscriptionManager struct {
	mu            sync.RWMutex
	subscriptions map[string]*Subscription
	handlers      map[string]EventHandler
	logger        *slog.Logger
}

// Subscription represents an active subscription
type Subscription struct {
	ID        string
	Query     string
	Variables map[string]interface{}
	Operation string
	Context   context.Context
	Cancel    context.CancelFunc
	Events    chan *SubscriptionEvent
	StartedAt time.Time
}

// SubscriptionEvent represents a subscription event
type SubscriptionEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
}

// EventHandler is a function that handles events
type EventHandler func(ctx context.Context, event *SubscriptionEvent)

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager() *SubscriptionManager {
	return &SubscriptionManager{
		subscriptions: make(map[string]*Subscription),
		handlers:      make(map[string]EventHandler),
		logger:        slog.Default(),
	}
}

// RegisterHandler registers an event handler for a subscription type
func (sm *SubscriptionManager) RegisterHandler(eventType string, handler EventHandler) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.handlers[eventType] = handler
}

// Subscribe creates a new subscription
func (sm *SubscriptionManager) Subscribe(ctx context.Context, query string, variables map[string]interface{}, operation string) (*Subscription, error) {
	id := uuid.New().String()
	ctx, cancel := context.WithCancel(ctx)

	sub := &Subscription{
		ID:        id,
		Query:     query,
		Variables: variables,
		Operation: operation,
		Context:   ctx,
		Cancel:    cancel,
		Events:    make(chan *SubscriptionEvent, 100),
		StartedAt: time.Now(),
	}

	sm.mu.Lock()
	sm.subscriptions[id] = sub
	sm.mu.Unlock()

	sm.logger.Info("subscription created", "id", id, "operation", operation)

	// Start event processor
	go sm.processEvents(sub)

	return sub, nil
}

// Unsubscribe removes a subscription
func (sm *SubscriptionManager) Unsubscribe(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sub, ok := sm.subscriptions[id]; ok {
		sub.Cancel()
		close(sub.Events)
		delete(sm.subscriptions, id)
		sm.logger.Info("subscription removed", "id", id)
	}
}

// Publish publishes an event to all matching subscriptions
func (sm *SubscriptionManager) Publish(eventType string, payload map[string]interface{}) {
	event := &SubscriptionEvent{
		ID:        uuid.New().String(),
		Type:      eventType,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, sub := range sm.subscriptions {
		select {
		case sub.Events <- event:
		default:
			// Channel full, skip
		}
	}
}

// processEvents processes subscription events
func (sm *SubscriptionManager) processEvents(sub *Subscription) {
	defer func() {
		sm.Unsubscribe(sub.ID)
	}()

	for {
		select {
		case <-sub.Context.Done():
			return
		case _, ok := <-sub.Events:
			if !ok {
				return
			}
			// Event processing happens in the WebSocket handler
		}
	}
}

// Cleanup removes all subscriptions
func (sm *SubscriptionManager) Cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, sub := range sm.subscriptions {
		sub.Cancel()
		close(sub.Events)
		delete(sm.subscriptions, id)
	}
}

// Count returns the number of active subscriptions
func (sm *SubscriptionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.subscriptions)
}

// WebSocketHandler handles GraphQL WebSocket connections
type WebSocketHandler struct {
	manager  *SubscriptionManager
	upgrader *WebSocketUpgrader
	authFunc func(http.Header) (context.Context, error)
	logger   *slog.Logger
}

// WebSocketUpgrader upgrades HTTP to WebSocket
type WebSocketUpgrader struct {
	ReadBufferSize  int
	WriteBufferSize int
	CheckOrigin     func(r *http.Request) bool
}

// DefaultUpgrader returns default WebSocket upgrader
func DefaultUpgrader() *WebSocketUpgrader {
	return &WebSocketUpgrader{
		ReadBufferSize:  512,
		WriteBufferSize: 512,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
}

// NewWebSocketHandler creates a new WebSocket handler
func NewWebSocketHandler(manager *SubscriptionManager) *WebSocketHandler {
	return &WebSocketHandler{
		manager:  manager,
		upgrader: DefaultUpgrader(),
		logger:   slog.Default(),
	}
}

// SetAuthFunc sets authentication function
func (wh *WebSocketHandler) SetAuthFunc(f func(http.Header) (context.Context, error)) {
	wh.authFunc = f
}

// HandleWebSocket handles WebSocket connection
func (wh *WebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Get context
	ctx := r.Context()
	if wh.authFunc != nil {
		var err error
		ctx, err = wh.authFunc(r.Header)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Note: In a real implementation, we would upgrade to WebSocket here
	// For this implementation, we simulate WebSocket with HTTP SSE

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Send initial connection event
	_, _ = fmt.Fprintf(w, "event: connection\ndata: {\"id\":\"%s\"}\n\n", uuid.New())
	w.(http.Flusher).Flush()

	// Handle incoming messages (subscription requests)
	msgChan := make(chan []byte)
	doneChan := make(chan struct{})

	// Read loop
	go func() {
		defer close(doneChan)
		for {
			var msg WebSocketMessage
			if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
				return
			}
			msgChan <- []byte(msg.Payload)
		}
	}()

	// Process messages
	for {
		select {
		case <-doneChan:
			return
		case msg := <-msgChan:
			wh.handleMessage(ctx, w, msg)
		}
	}
}

// handleMessage handles an incoming WebSocket message
func (wh *WebSocketHandler) handleMessage(ctx context.Context, w http.ResponseWriter, data []byte) {
	var msg WebSocketMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		wh.sendError(w, msg.ID, err.Error())
		return
	}

	switch msg.Type {
	case "connection_init":
		wh.sendMessage(w, msg.ID, "connection_ack", nil)

	case "start":
		wh.handleStart(ctx, w, msg)

	case "stop":
		if msg.ID != "" {
			wh.manager.Unsubscribe(msg.ID)
		}

	case "connection_terminate":
		wh.manager.Cleanup()
	}
}

// handleStart handles subscription start
func (wh *WebSocketHandler) handleStart(ctx context.Context, w http.ResponseWriter, msg WebSocketMessage) {
	var payload struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
		Operation string                 `json:"operationName"`
	}

	if err := json.Unmarshal([]byte(msg.Payload), &payload); err != nil {
		wh.sendError(w, msg.ID, err.Error())
		return
	}

	// Create subscription
	sub, err := wh.manager.Subscribe(ctx, payload.Query, payload.Variables, payload.Operation)
	if err != nil {
		wh.sendError(w, msg.ID, err.Error())
		return
	}

	// Send ack
	wh.sendMessage(w, msg.ID, "subscription_success", map[string]interface{}{
		"subscriptionId": sub.ID,
	})

	// Forward events to client
	go func() {
		for {
			select {
			case <-sub.Context.Done():
				wh.sendMessage(w, sub.ID, "subscription_end", nil)
				return
			case event := <-sub.Events:
				wh.sendMessage(w, sub.ID, "next", map[string]interface{}{
					"data": event.Payload,
				})
			}
		}
	}()
}

// sendMessage sends a WebSocket message
func (wh *WebSocketHandler) sendMessage(w http.ResponseWriter, id, msgType string, payload interface{}) {
	msg := WebSocketMessage{
		Type:    msgType,
		ID:      id,
		Payload: toJSON(payload),
	}
	data, _ := json.Marshal(msg)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	w.(http.Flusher).Flush()
}

// sendError sends an error message
func (wh *WebSocketHandler) sendError(w http.ResponseWriter, id, errMsg string) {
	wh.sendMessage(w, id, "error", map[string]interface{}{
		"message": errMsg,
	})
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Payload string `json:"payload,omitempty"`
}

func toJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// ============================================================
// SUBSCRIPTION ROUTES
// ============================================================

// RegisterSubscriptions registers default subscription handlers
func (sm *SubscriptionManager) RegisterSubscriptions() {
	// Violation subscription
	sm.RegisterHandler("violation", func(ctx context.Context, event *SubscriptionEvent) {
		// Handled by WebSocket forwarder
	})

	// SIEM event subscription
	sm.RegisterHandler("siem_event", func(ctx context.Context, event *SubscriptionEvent) {
		// Handled by WebSocket forwarder
	})

	// Security event subscription
	sm.RegisterHandler("security_event", func(ctx context.Context, event *SubscriptionEvent) {
		// Handled by WebSocket forwarder
	})

	// Metrics subscription
	sm.RegisterHandler("metrics", func(ctx context.Context, event *SubscriptionEvent) {
		// Handled by WebSocket forwarder
	})

	// Compliance subscription
	sm.RegisterHandler("compliance", func(ctx context.Context, event *SubscriptionEvent) {
		// Handled by WebSocket forwarder
	})
}

// ============================================================
// EVENT PUBLISHING HELPERS
// ============================================================

// PublishViolation publishes a violation event
func (sm *SubscriptionManager) PublishViolation(violation *Violation) {
	sm.Publish("violation", map[string]interface{}{
		"violation": violation,
	})
}

// PublishSIEMEvent publishes a SIEM event
func (sm *SubscriptionManager) PublishSIEMEvent(event *SIEMEvent) {
	sm.Publish("siem_event", map[string]interface{}{
		"event": event,
	})
}

// PublishSecurityEvent publishes a security event
func (sm *SubscriptionManager) PublishSecurityEvent(event *SecurityEvent) {
	sm.Publish("security_event", map[string]interface{}{
		"event": event,
	})
}

// PublishMetrics publishes metrics update
func (sm *SubscriptionManager) PublishMetrics(snapshot *MetricsSnapshot) {
	sm.Publish("metrics", map[string]interface{}{
		"snapshot": snapshot,
	})
}

// PublishCompliance publishes compliance result
func (sm *SubscriptionManager) PublishCompliance(result *ComplianceResult) {
	sm.Publish("compliance", map[string]interface{}{
		"result": result,
	})
}

// PublishHealth publishes health status change
func (sm *SubscriptionManager) PublishHealth(health *Health) {
	sm.Publish("health", map[string]interface{}{
		"health": health,
	})
}
