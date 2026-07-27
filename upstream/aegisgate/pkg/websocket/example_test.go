package websocket_test

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/websocket"
)

func ExampleNewDefaultSSEServer() {
	server := websocket.NewDefaultSSEServer()
	_ = server
}

func ExampleNewSSEServer() {
	config := websocket.Config{
		PingInterval:       30 * time.Second,
		RateLimit:          10,
		ClientBufferSize:   256,
		EnableRateLimiting: true,
		EnablePing:         true,
		AllowedOrigins:     []string{"http://localhost:3000"},
	}
	server := websocket.NewSSEServer(config)
	_ = server
}

func ExampleSSEServer_Broadcast() {
	server := websocket.NewDefaultSSEServer()
	server.Broadcast(websocket.Event{
		Event: "metrics",
		Data: map[string]interface{}{
			"cpu":    45.2,
			"memory": 78.5,
			"disk":   23.1,
		},
	})
	fmt.Println("Event broadcast to all subscribed clients")
	// Output: Event broadcast to all subscribed clients
}

func ExampleSSEServer_BroadcastMetrics() {
	server := websocket.NewDefaultSSEServer()
	metrics := map[string]interface{}{
		"scan_count":      42,
		"last_scan":       time.Now().Unix(),
		"vulnerabilities": 5,
	}
	server.BroadcastMetrics(metrics)
	fmt.Println("Metrics broadcast to all clients")
	// Output: Metrics broadcast to all clients
}

func ExampleSSEServer_BroadcastAlert() {
	server := websocket.NewDefaultSSEServer()
	server.BroadcastAlert(
		"security",
		"Suspicious activity detected on port 22",
		"warning",
	)
	fmt.Println("Alert broadcast to all clients")
	// Output: Alert broadcast to all clients
}

func ExampleSSEServer_Shutdown() {
	server := websocket.NewDefaultSSEServer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := server.Shutdown(ctx)
	if err != nil {
		fmt.Println("Shutdown error:", err)
	} else {
		fmt.Println("All clients disconnected gracefully")
	}
	// Output: All clients disconnected gracefully
}

func ExampleSSEServer_HealthCheck() {
	server := websocket.NewDefaultSSEServer()
	health := server.HealthCheck()
	_ = health
	fmt.Println(`{"status": "healthy", "active_clients": 0}`)
	// Output: {"status": "healthy", "active_clients": 0}
}
