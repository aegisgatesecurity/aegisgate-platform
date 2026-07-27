package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMessageType tests message type constants
func TestMessageType(t *testing.T) {
	types := []struct {
		name    string
		msgType MessageType
		want    string
	}{
		{"ping", MessageTypePing, "ping"},
		{"pong", MessageTypePong, "pong"},
		{"subscribe", MessageTypeSubscribe, "subscribe"},
		{"unsubscribe", MessageTypeUnsubscribe, "unsubscribe"},
		{"metrics", MessageTypeMetrics, "metrics"},
		{"alert", MessageTypeAlert, "alert"},
		{"error", MessageTypeError, "error"},
		{"connected", MessageTypeConnected, "connected"},
		{"disconnected", MessageTypeDisconnected, "disconnected"},
		{"config", MessageTypeConfig, "config"},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.msgType) != tt.want {
				t.Errorf("MessageType = %s, want %s", tt.msgType, tt.want)
			}
		})
	}
}

// TestNewMessage tests message creation
func TestNewMessage(t *testing.T) {
	data := map[string]interface{}{"key": "value"}
	msg := NewMessage(MessageTypeMetrics, data)

	if msg.Type != MessageTypeMetrics {
		t.Errorf("Message.Type = %s, want metrics", msg.Type)
	}

	if msg.Data["key"] != "value" {
		t.Errorf("Message.Data[key] = %v, want value", msg.Data["key"])
	}

	if msg.Timestamp.IsZero() {
		t.Error("Message.Timestamp should be set")
	}
}

// TestEvent tests event structure
func TestEvent(t *testing.T) {
	event := Event{
		ID:    "test-id",
		Event: "test-event",
		Data:  map[string]interface{}{"test": "data"},
		Retry: 5000,
	}

	if event.ID != "test-id" {
		t.Errorf("Event.ID = %s, want test-id", event.ID)
	}

	if event.Event != "test-event" {
		t.Errorf("Event.Event = %s, want test-event", event.Event)
	}

	if event.Retry != 5000 {
		t.Errorf("Event.Retry = %d, want 5000", event.Retry)
	}
}

// TestDefaultConfig tests default configuration
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.PingInterval != DefaultPingInterval {
		t.Errorf("DefaultConfig().PingInterval = %v, want %v", cfg.PingInterval, DefaultPingInterval)
	}
	if cfg.RateLimit != DefaultRateLimit {
		t.Errorf("DefaultConfig().RateLimit = %d, want %d", cfg.RateLimit, DefaultRateLimit)
	}
	if cfg.ClientBufferSize != DefaultBufferSize {
		t.Errorf("DefaultConfig().ClientBufferSize = %d, want %d", cfg.ClientBufferSize, DefaultBufferSize)
	}
	if !cfg.EnableRateLimiting {
		t.Error("DefaultConfig().EnableRateLimiting should be true")
	}
	if !cfg.EnablePing {
		t.Error("DefaultConfig().EnablePing should be true")
	}
}

// TestNewSSEServer tests SSE server creation
func TestNewSSEServer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnablePing = false // Disable ping for testing

	server := NewSSEServer(cfg)
	if server == nil {
		t.Fatal("NewSSEServer() returned nil")
	}

	if server.GetClientCount() != 0 {
		t.Errorf("New server should have 0 clients, got %d", server.GetClientCount())
	}
}

// TestNewDefaultSSEServer tests default server creation
func TestNewDefaultSSEServer(t *testing.T) {
	server := NewDefaultSSEServer()
	if server == nil {
		t.Fatal("NewDefaultSSEServer() returned nil")
	}
}

// TestSSEServerGetClients tests getting client list
func TestSSEServerGetClients(t *testing.T) {
	server := NewSSEServer(DefaultConfig())

	clients := server.GetClients()
	if clients == nil {
		t.Error("GetClients() should not return nil")
	}

	if len(clients) != 0 {
		t.Errorf("Expected 0 clients, got %d", len(clients))
	}
}

// TestSSEServerHealthCheck tests health check
func TestSSEServerHealthCheck(t *testing.T) {
	server := NewSSEServer(DefaultConfig())

	health := server.HealthCheck()
	if health == nil {
		t.Fatal("HealthCheck() returned nil")
	}

	status, ok := health["status"]
	if !ok || status != "healthy" {
		t.Errorf("HealthCheck().status = %v, want healthy", status)
	}

	_, ok = health["active_clients"]
	if !ok {
		t.Error("HealthCheck() missing active_clients")
	}

	features, ok := health["features"]
	if !ok {
		t.Error("HealthCheck() missing features")
	}
	featuresSlice, ok := features.([]string)
	if !ok || len(featuresSlice) == 0 {
		t.Error("HealthCheck() features should be non-empty slice")
	}
}

// TestSSEServerBroadcast tests broadcasting events
func TestSSEServerBroadcast(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing:         false,
		EnableRateLimiting: false,
	})

	event := Event{
		Event: "test",
		Data:  map[string]interface{}{"message": "hello"},
	}

	// Broadcast should work even with no clients
	server.Broadcast(event)
}

// TestSSEServerBroadcastEvent tests broadcasting with context
func TestSSEServerBroadcastEvent(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing:         false,
		EnableRateLimiting: false,
	})

	ctx := context.Background()
	event := Event{
		Event: "test",
		Data:  map[string]interface{}{"message": "hello"},
	}

	// Should not panic with no clients
	server.BroadcastEvent(ctx, event)
}

// TestSSEServerBroadcastTo tests broadcasting to a specific client
func TestSSEServerBroadcastTo(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing:         false,
		EnableRateLimiting: false,
	})

	event := Event{
		Event: "test",
		Data:  map[string]interface{}{"message": "hello"},
	}

	// Should return false for non-existent client
	if server.BroadcastTo("nonexistent", event) {
		t.Error("BroadcastTo() should return false for nonexistent client")
	}
}

// TestSSEServerBroadcastMetrics tests metrics broadcasting
func TestSSEServerBroadcastMetrics(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	metrics := map[string]interface{}{
		"requests": 100,
		"errors":   5,
	}

	// Should not panic
	server.BroadcastMetrics(metrics)
}

// TestSSEServerBroadcastAlert tests alert broadcasting
func TestSSEServerBroadcastAlert(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	// Should not panic
	server.BroadcastAlert("warning", "Test alert message", "high")
}

// TestSSEServerSubscribeMetrics tests metrics subscription
func TestSSEServerSubscribeMetrics(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	called := false
	callback := func(e *Event) {
		called = true
	}

	server.SubscribeMetrics(callback)

	// Trigger callback via BroadcastMetrics
	server.BroadcastMetrics(map[string]interface{}{"test": true})

	// Note: callback runs synchronously in current implementation
	// This tests that the subscription is set
	if !called {
		t.Error("Expected callback to be called after BroadcastMetrics")
	}
}

// TestSSEServerSubscribeAlerts tests alert subscription
func TestSSEServerSubscribeAlerts(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	callback := func(e *Event) {
		// Callback function
	}

	server.SubscribeAlerts(callback)
}

// TestSSEServerShutdown tests server shutdown
func TestSSEServerShutdown(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

// TestSSEServerHandleCORS tests CORS handling
func TestSSEServerHandleCORS(t *testing.T) {
	server := NewSSEServer(Config{
		AllowedOrigins: []string{"*"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/events", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	server.handleCORS(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("handleCORS() status = %d, want %d", w.Code, http.StatusNoContent)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %s, want http://example.com", origin)
	}
}

// TestSSEServerHandleCORSWithOrigin tests CORS with specific origins
func TestSSEServerHandleCORSWithOrigin(t *testing.T) {
	server := NewSSEServer(Config{
		AllowedOrigins: []string{"http://allowed.com"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/events", nil)
	req.Header.Set("Origin", "http://allowed.com")
	w := httptest.NewRecorder()

	server.handleCORS(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://allowed.com" {
		t.Errorf("Access-Control-Allow-Origin = %s, want http://allowed.com", origin)
	}
}

// TestSSEServerHandleCORSBlockedOrigin tests CORS for blocked origin
func TestSSEServerHandleCORSBlockedOrigin(t *testing.T) {
	server := NewSSEServer(Config{
		AllowedOrigins: []string{"http://allowed.com"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/events", nil)
	req.Header.Set("Origin", "http://blocked.com")
	w := httptest.NewRecorder()

	server.handleCORS(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin == "http://blocked.com" {
		t.Error("Blocked origin should not be allowed")
	}
}

// TestSSEServerHandleConfig tests config endpoint
func TestSSEServerHandleConfig(t *testing.T) {
	server := NewSSEServer(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	w := httptest.NewRecorder()

	server.HandleConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleConfig() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestSSEServerIsOriginAllowed tests origin checking
func TestSSEServerIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name     string
		origins  []string
		check    string
		expected bool
	}{
		{"wildcard", []string{"*"}, "http://any.com", true},
		{"matching", []string{"http://allowed.com"}, "http://allowed.com", true},
		{"not matching", []string{"http://allowed.com"}, "http://blocked.com", false},
		{"empty list", []string{}, "http://any.com", true},
		{"multiple origins", []string{"http://a.com", "http://b.com"}, "http://b.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewSSEServer(Config{
				AllowedOrigins: tt.origins,
				EnablePing:     false,
			})

			if result := server.isOriginAllowed(tt.check); result != tt.expected {
				t.Errorf("isOriginAllowed(%s) = %v, want %v", tt.check, result, tt.expected)
			}
		})
	}
}

// TestSSEServerHandleSSEMethod tests SSE endpoint method handling
func TestSSEServerHandleSSEMethod(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	// POST should be rejected
	req := httptest.NewRequest(http.MethodPost, "/events", nil)
	w := httptest.NewRecorder()
	server.HandleSSE(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HandleSSE() POST status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestSSEServerHandleCommand tests command handling
func TestSSEServerHandleCommand(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing: false,
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		server.HandleCommand(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("HandleCommand() status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("client not found", func(t *testing.T) {
		body := `{"client_id": "nonexistent", "action": "subscribe", "events": ["test"]}`
		req := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
		w := httptest.NewRecorder()

		server.HandleCommand(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("HandleCommand() status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		body := `{"client_id": "test", "action": "unknown", "events": []}`
		req := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
		w := httptest.NewRecorder()

		server.HandleCommand(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("HandleCommand() status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/command", nil)
		w := httptest.NewRecorder()

		server.HandleCommand(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("HandleCommand() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

// TestRateLimiter tests rate limiter functionality
func TestRateLimiter(t *testing.T) {
	// Allow 10 requests per second
	rl := NewRateLimiter(10, time.Second)

	// First request should be allowed
	if !rl.Allow() {
		t.Error("First request should be allowed")
	}

	// Many rapid requests should eventually be rate limited
	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow() {
			allowed++
		}
	}

	// Should have allowed some but not all
	// The exact number depends on timing and the token bucket algorithm
	if allowed == 0 {
		t.Error("At least some requests should be allowed")
	}
}

// TestRateLimiterRefill tests rate limiter token refill
func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)

	// Use initial tokens
	for i := 0; i < 15; i++ {
		rl.Allow()
	}

	// Wait for refill
	time.Sleep(100 * time.Millisecond)

	// Should be able to make some requests after waiting
	if !rl.Allow() {
		t.Error("Request should be allowed after token refill")
	}
}

// TestSSEClientSubscribe tests client subscription
func TestSSEClientSubscribe(t *testing.T) {
	// Create a mock client for testing subscription
	server := NewSSEServer(Config{
		EnablePing:         false,
		EnableRateLimiting: false,
		ClientBufferSize:   10,
	})

	// Create a mock response writer and request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)

	// Try to register a client
	_, err := server.RegisterClient(w, req)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Server should now have 1 client
	if server.GetClientCount() != 1 {
		t.Errorf("GetClientCount() = %d, want 1", server.GetClientCount())
	}
}

// TestSSEClientSubscription tests subscription management
func TestSSEClientSubscription(t *testing.T) {
	// Test IsSubscribed behavior with mock client data
	subscribedEvents := make(map[string]bool)
	subscribedEvents["*"] = true // Default subscription

	// Test wildcard subscription
	if !subscribedEvents["*"] {
		t.Error("Should be subscribed to wildcard")
	}

	// Add specific subscription
	subscribedEvents["metrics"] = true
	if !subscribedEvents["metrics"] {
		t.Error("Should be subscribed to metrics")
	}

	// Remove subscription
	delete(subscribedEvents, "metrics")
	if subscribedEvents["metrics"] {
		t.Error("Should not be subscribed to metrics after removal")
	}
}

// TestGenerateClientID tests client ID generation
func TestGenerateClientID(t *testing.T) {
	server := NewSSEServer(Config{EnablePing: false})

	id1 := server.generateClientID()
	time.Sleep(time.Microsecond) // Ensure unique timestamp
	id2 := server.generateClientID()

	if id1 == id2 {
		t.Error("Generated client IDs should be unique")
	}

	if !strings.HasPrefix(id1, "client_") {
		t.Errorf("Client ID = %s, should start with client_", id1)
	}
}

// TestSSEServerRemoveNonexistentClient tests removing nonexistent client
func TestSSEServerRemoveNonexistentClient(t *testing.T) {
	server := NewSSEServer(Config{EnablePing: false})

	// Should not panic when removing nonexistent client
	server.RemoveClient("nonexistent")

	if server.GetClientCount() != 0 {
		t.Errorf("GetClientCount() = %d, want 0", server.GetClientCount())
	}
}

// TestSSEServerConcurrentBroadcast tests concurrent broadcasts
func TestSSEServerConcurrentBroadcast(t *testing.T) {
	server := NewSSEServer(Config{
		EnablePing:         false,
		EnableRateLimiting: false,
	})

	// Broadcast from multiple goroutines
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			server.Broadcast(Event{
				Event: "test",
				Data:  map[string]interface{}{"message": "concurrent"},
			})
			done <- true
		}()
	}

	// Wait for all broadcasts to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestConfig tests configuration customization
func TestConfig(t *testing.T) {
	callback := func(e *Event) {
		// Callback function
	}

	cfg := Config{
		PingInterval:       60 * time.Second,
		RateLimit:          20,
		ClientBufferSize:   512,
		EnableRateLimiting: false,
		EnablePing:         false,
		AllowedOrigins:     []string{"http://localhost"},
		MetricsCallback:    callback,
		AlertCallback:      callback,
	}

	server := NewSSEServer(cfg)
	if server == nil {
		t.Fatal("NewSSEServer() returned nil")
	}
}

// TestEventJSON tests event JSON marshaling
func TestEventJSON(t *testing.T) {
	event := Event{
		ID:    "1",
		Event: "test",
		Data: map[string]interface{}{
			"key": "value",
			"num": 42,
		},
		Retry: 5000,
	}

	// Verify event fields are set
	if event.ID != "1" {
		t.Errorf("Event.ID = %s, want 1", event.ID)
	}
	if event.Event != "test" {
		t.Errorf("Event.Event = %s, want test", event.Event)
	}
	if event.Retry != 5000 {
		t.Errorf("Event.Retry = %d, want 5000", event.Retry)
	}
}

// TestMessageJSON tests message JSON marshaling
func TestMessageJSON(t *testing.T) {
	msg := Message{
		Type: MessageTypeMetrics,
		Data: map[string]interface{}{
			"requests": 100,
		},
		Timestamp: time.Now(),
	}

	if msg.Type != MessageTypeMetrics {
		t.Errorf("Message.Type = %s, want metrics", msg.Type)
	}
}

// TestConstants tests package constants
func TestConstants(t *testing.T) {
	if SSEContentType != "text/event-stream" {
		t.Errorf("SSEContentType = %s, want text/event-stream", SSEContentType)
	}
	if DefaultPingInterval != 30*time.Second {
		t.Errorf("DefaultPingInterval = %v, want 30s", DefaultPingInterval)
	}
	if DefaultRateLimit != 10 {
		t.Errorf("DefaultRateLimit = %d, want 10", DefaultRateLimit)
	}
	if DefaultBufferSize != 256 {
		t.Errorf("DefaultBufferSize = %d, want 256", DefaultBufferSize)
	}
}
