// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MessageType represents the type of SSE event
type MessageType string

const (
	MessageTypePing         MessageType = "ping"
	MessageTypePong         MessageType = "pong"
	MessageTypeSubscribe    MessageType = "subscribe"
	MessageTypeUnsubscribe  MessageType = "unsubscribe"
	MessageTypeMetrics      MessageType = "metrics"
	MessageTypeAlert        MessageType = "alert"
	MessageTypeError        MessageType = "error"
	MessageTypeConnected    MessageType = "connected"
	MessageTypeDisconnected MessageType = "disconnected"
	MessageTypeConfig       MessageType = "config"
	SSEContentType                      = "text/event-stream"
	DefaultPingInterval                 = 30 * time.Second
	DefaultRateLimit                    = 10
	DefaultBufferSize                   = 256
)

// Event represents a Server-Sent Event
type Event struct {
	ID    string      `json:"id,omitempty"`
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
	Retry int         `json:"retry,omitempty"`
}

// Message represents a structured message
type Message struct {
	Type      MessageType            `json:"type"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewMessage creates a new message with the current timestamp
func NewMessage(msgType MessageType, data map[string]interface{}) Message {
	return Message{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}
}

// SSEClient represents a connected SSE client
type SSEClient struct {
	id               string
	w                http.ResponseWriter
	flusher          http.Flusher
	done             chan struct{}
	send             chan Event
	rateLimiter      *RateLimiter
	subscribedEvents map[string]bool
	mu               sync.RWMutex
	connectedAt      time.Time
	lastActivity     atomic.Value
}

// Client accessors
func (c *SSEClient) ID() string      { return c.id }
func (c *SSEClient) UpdateActivity() { c.lastActivity.Store(time.Now()) }

func (c *SSEClient) LastActivity() time.Time {
	if v := c.lastActivity.Load(); v != nil {
		return v.(time.Time)
	}
	return c.connectedAt
}

func (c *SSEClient) String() string { return fmt.Sprintf("SSEClient[%s]", c.id) }

// IsSubscribed checks if client is subscribed to an event type
func (c *SSEClient) IsSubscribed(eventType string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.subscribedEvents[eventType] || c.subscribedEvents["*"]
}

// Subscribe adds an event type to subscription list
func (c *SSEClient) Subscribe(eventType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subscribedEvents[eventType] = true
}

// Unsubscribe removes an event type from subscription list
func (c *SSEClient) Unsubscribe(eventType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.subscribedEvents, eventType)
}

// IsAlive checks if client is still connected
func (c *SSEClient) IsAlive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	rate      int
	per       time.Duration
	allowance float64
	lastCheck time.Time
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, per time.Duration) *RateLimiter {
	return &RateLimiter{
		rate:      rate,
		per:       per,
		allowance: float64(rate),
		lastCheck: time.Now(),
	}
}

// Allow checks if an event can be sent (token bucket algorithm)
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.lastCheck)
	rl.lastCheck = now
	rl.allowance += elapsed.Seconds() * float64(rl.rate) / rl.per.Seconds()
	if rl.allowance > float64(rl.rate) {
		rl.allowance = float64(rl.rate)
	}
	if rl.allowance >= 1.0 {
		rl.allowance--
		return true
	}
	return false
}

// Config holds SSE server configuration
type Config struct {
	PingInterval       time.Duration
	RateLimit          int
	ClientBufferSize   int
	EnableRateLimiting bool
	EnablePing         bool
	AllowedOrigins     []string
	MetricsCallback    func(*Event)
	AlertCallback      func(*Event)
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		PingInterval:       DefaultPingInterval,
		RateLimit:          DefaultRateLimit,
		ClientBufferSize:   DefaultBufferSize,
		EnableRateLimiting: true,
		EnablePing:         true,
		AllowedOrigins:     []string{"*"},
	}
}

// SSEServer manages all SSE clients
type SSEServer struct {
	clients         map[string]*SSEClient
	mu              sync.RWMutex
	metricsCallback func(*Event)
	alertCallback   func(*Event)
	pingInterval    time.Duration
	rateLimit       int
	ctx             context.Context
	cancel          context.CancelFunc
	eventID         atomic.Uint64
	bufferPool      sync.Pool
	config          Config
}

// NewSSEServer creates a new SSE server with given configuration
func NewSSEServer(config Config) *SSEServer {
	ctx, cancel := context.WithCancel(context.Background())
	server := &SSEServer{
		clients:         make(map[string]*SSEClient),
		metricsCallback: config.MetricsCallback,
		alertCallback:   config.AlertCallback,
		pingInterval:    config.PingInterval,
		rateLimit:       config.RateLimit,
		ctx:             ctx,
		cancel:          cancel,
		config:          config,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 4096)
			},
		},
	}

	if config.EnablePing {
		go server.pingLoop()
	}

	return server
}

// NewDefaultSSEServer creates a server with default configuration
func NewDefaultSSEServer() *SSEServer {
	return NewSSEServer(DefaultConfig())
}

// RegisterClient registers a new SSE client from an HTTP request
func (s *SSEServer) RegisterClient(w http.ResponseWriter, r *http.Request) (*SSEClient, error) {
	// Set SSE headers
	w.Header().Set("Content-Type", SSEContentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Handle CORS
	origin := r.Header.Get("Origin")
	if s.isOriginAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	// Check for streaming support
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

	// Create client
	clientID := s.generateClientID()
	client := &SSEClient{
		id:               clientID,
		w:                w,
		flusher:          flusher,
		done:             make(chan struct{}),
		send:             make(chan Event, s.config.ClientBufferSize),
		subscribedEvents: make(map[string]bool),
		connectedAt:      time.Now(),
	}
	client.subscribedEvents["*"] = true

	if s.config.EnableRateLimiting {
		client.rateLimiter = NewRateLimiter(s.config.RateLimit, time.Second)
	}

	// Register in server
	s.mu.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.mu.Unlock()

	// Send connection event
	connectEvent := Event{
		Event: "connected",
		Data: map[string]interface{}{
			"client_id":  clientID,
			"client_num": clientCount,
			"timestamp":  time.Now().Unix(),
		},
	}
	s.sendEventToClient(client, connectEvent)

	log.Printf("SSE client registered: %s (active: %d)", clientID, clientCount)
	return client, nil
}

// RemoveClient removes a client from the server
func (s *SSEServer) RemoveClient(clientID string) {
	s.mu.Lock()
	client, exists := s.clients[clientID]
	if !exists {
		s.mu.Unlock()
		return
	}
	delete(s.clients, clientID)
	clientCount := len(s.clients)
	s.mu.Unlock()

	close(client.done)
	close(client.send)

	s.BroadcastEvent(s.ctx, Event{
		Event: "disconnected",
		Data: map[string]interface{}{
			"client_id": clientID,
			"remaining": clientCount,
		},
	})

	log.Printf("SSE client removed: %s (remaining: %d)", clientID, clientCount)
}

// GetClientCount returns the number of active clients
func (s *SSEServer) GetClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// GetClients returns list of active client IDs
func (s *SSEServer) GetClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.clients))
	for id := range s.clients {
		ids = append(ids, id)
	}
	return ids
}

// HandleSSE is the HTTP handler for SSE connections
func (s *SSEServer) HandleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.handleCORS(w, r)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client, err := s.RegisterClient(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle Last-Event-ID for reconnection
	lastEventID := r.Header.Get("Last-Event-ID")
	if lastEventID != "" {
		log.Printf("Client %s resuming from event ID: %s", client.ID(), lastEventID)
	}

	// Start event writer goroutine
	s.writeEvents(client)
}

// writeEvents handles sending events to a client
func (s *SSEServer) writeEvents(client *SSEClient) {
	defer s.RemoveClient(client.ID())
	for {
		select {
		case event, ok := <-client.send:
			if !ok {
				return
			}
			if err := s.writeEventToClient(client, event); err != nil {
				log.Printf("Error sending event to client %s: %v", client.ID(), err)
				return
			}
		case <-client.done:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

// writeEventToClient formats and sends an event to a specific client
func (s *SSEServer) writeEventToClient(client *SSEClient, event Event) error {
	if client.rateLimiter != nil && !client.rateLimiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Format SSE event
	var data []byte
	if event.ID != "" {
		data = append(data, fmt.Sprintf("id: %s\n", event.ID)...)
	} else {
		eventID := s.eventID.Add(1)
		data = append(data, fmt.Sprintf("id: %d\n", eventID)...)
	}

	if event.Event != "" {
		data = append(data, fmt.Sprintf("event: %s\n", event.Event)...)
	}

	if event.Retry > 0 {
		data = append(data, fmt.Sprintf("retry: %d\n", event.Retry)...)
	}

	if event.Data != nil {
		jsonData, err := json.Marshal(event.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal event data: %w", err)
		}
		data = append(data, fmt.Sprintf("data: %s\n", string(jsonData))...)
	}

	data = append(data, '\n')

	// Write to client
	if _, err := client.w.Write(data); err != nil {
		return err
	}
	client.flusher.Flush()
	client.UpdateActivity()
	return nil
}

// Broadcast sends an event to all connected clients
func (s *SSEServer) Broadcast(event Event) {
	s.BroadcastEvent(s.ctx, event)
}

// BroadcastEvent sends an event to all clients (with context for cancellation)
func (s *SSEServer) BroadcastEvent(ctx context.Context, event Event) {
	s.mu.RLock()
	clients := make([]*SSEClient, 0, len(s.clients))
	for _, client := range s.clients {
		if client.IsAlive() && client.IsSubscribed(event.Event) {
			clients = append(clients, client)
		}
	}
	s.mu.RUnlock()

	for _, client := range clients {
		select {
		case client.send <- event:
		case <-ctx.Done():
			return
		default:
			log.Printf("Client %s buffer full, dropping event", client.ID())
		}
	}
}

// BroadcastTo sends an event to a specific client
func (s *SSEServer) BroadcastTo(clientID string, event Event) bool {
	s.mu.RLock()
	client, exists := s.clients[clientID]
	s.mu.RUnlock()

	if !exists || !client.IsAlive() {
		return false
	}

	select {
	case client.send <- event:
		return true
	default:
		return false
	}
}

// BroadcastMetrics sends metrics data to all subscribed clients
func (s *SSEServer) BroadcastMetrics(metricsData interface{}) {
	event := Event{
		Event: string(MessageTypeMetrics),
		Data:  metricsData,
	}
	if s.metricsCallback != nil {
		s.metricsCallback(&event)
	}
	s.BroadcastEvent(s.ctx, event)
}

// BroadcastAlert sends an alert to all subscribed clients
func (s *SSEServer) BroadcastAlert(alertType, message, severity string) {
	alert := map[string]interface{}{
		"type":      alertType,
		"message":   message,
		"severity":  severity,
		"timestamp": time.Now().UTC(),
	}

	event := Event{
		Event: string(MessageTypeAlert),
		Data:  alert,
	}
	if s.alertCallback != nil {
		s.alertCallback(&event)
	}
	s.BroadcastEvent(s.ctx, event)
}

// SubscribeMetrics sets a callback for metrics events
func (s *SSEServer) SubscribeMetrics(callback func(*Event)) {
	s.metricsCallback = callback
}

// SubscribeAlerts sets a callback for alert events
func (s *SSEServer) SubscribeAlerts(callback func(*Event)) {
	s.alertCallback = callback
}

// HandleCommand handles client subscription commands
func (s *SSEServer) HandleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.handleCORS(w, r)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd struct {
		ClientID string   `json:"client_id"`
		Action   string   `json:"action"`
		Events   []string `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	client, exists := s.clients[cmd.ClientID]
	s.mu.RUnlock()
	if !exists {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	switch cmd.Action {
	case "subscribe":
		for _, eventType := range cmd.Events {
			client.Subscribe(eventType)
		}
		log.Printf("Client %s subscribed to events: %v", client.ID(), cmd.Events)
	case "unsubscribe":
		for _, eventType := range cmd.Events {
			client.Unsubscribe(eventType)
		}
		log.Printf("Client %s unsubscribed from events: %v", client.ID(), cmd.Events)
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"action": cmd.Action,
	})
}

// HandleConfig returns server configuration (HTTP endpoint)
func (s *SSEServer) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.handleCORS(w, r)
		return
	}

	response := map[string]interface{}{
		"ping_interval_ms": s.pingInterval.Milliseconds(),
		"rate_limit":       s.config.RateLimit,
		"client_buffer":    s.config.ClientBufferSize,
		"active_clients":   s.GetClientCount(),
		"supported_events": []string{
			"metrics",
			"alert",
			"connected",
			"disconnected",
			"ping",
			"config",
		},
	}
	_ = json.NewEncoder(w).Encode(response)
}

// Shutdown gracefully shuts down the server
func (s *SSEServer) Shutdown(ctx context.Context) error {
	s.cancel()

	s.mu.Lock()
	clients := make([]*SSEClient, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.clients = make(map[string]*SSEClient)
	s.mu.Unlock()

	disconnectEvent := Event{
		Event: "disconnected",
		Data: map[string]interface{}{
			"reason": "server_shutdown",
		},
	}

	for _, client := range clients {
		select {
		case client.send <- disconnectEvent:
			time.Sleep(100 * time.Millisecond)
		default:
		}
		close(client.done)
		close(client.send)
	}

	return nil
}

// pingLoop sends periodic keepalive pings
func (s *SSEServer) pingLoop() {
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.BroadcastEvent(s.ctx, Event{
				Event: string(MessageTypePing),
				Data: map[string]interface{}{
					"time": time.Now().Unix(),
				},
			})
		case <-s.ctx.Done():
			return
		}
	}
}

// sendEventToClient sends an event with timeout
func (s *SSEServer) sendEventToClient(client *SSEClient, event Event) {
	select {
	case client.send <- event:
	case <-time.After(time.Second):
		log.Printf("Timeout sending event to client %s", client.ID())
	}
}

// generateClientID generates a unique client identifier
func (s *SSEServer) generateClientID() string {
	return fmt.Sprintf("client_%d_%d", time.Now().UnixNano(), len(s.clients)+1)
}

// isOriginAllowed checks if an origin is allowed
func (s *SSEServer) isOriginAllowed(origin string) bool {
	if len(s.config.AllowedOrigins) == 0 {
		return true
	}
	for _, allowed := range s.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// handleCORS handles CORS preflight requests
func (s *SSEServer) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if s.isOriginAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Last-Event-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
	}
	w.WriteHeader(http.StatusNoContent)
}

// HealthCheck returns server health status
func (s *SSEServer) HealthCheck() map[string]interface{} {
	return map[string]interface{}{
		"status":         "healthy",
		"active_clients": s.GetClientCount(),
		"features": []string{
			"sse",
			"broadcast",
			"rate_limiting",
			"ping",
		},
	}
}
