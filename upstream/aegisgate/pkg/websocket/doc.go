// Package websocket provides Server-Sent Events (SSE) support for real-time
// dashboard streaming using only Go's standard library.
//
// Server-Sent Events (SSE) is an HTTP-based standard for one-way server-to-client
// real-time streaming. Unlike WebSockets, SSE:
//   - Uses standard HTTP connections (no protocol upgrade)
//   - Works through proxies, load balancers, and CDNs
//   - Supports automatic reconnection with event IDs
//   - Requires no external dependencies
//   - Integrates seamlessly with HTTP middleware
//
// Quick Start:
//
//	server := websocket.NewDefaultSSEServer()
//	http.HandleFunc("/events", server.HandleSSE)
//	http.HandleFunc("/config", server.HandleConfig)
//	log.Fatal(http.ListenAndServe(":8080", nil))
//
// Client-side JavaScript:
//
//	const eventSource = new EventSource('http://localhost:8080/events');
//	eventSource.addEventListener('metrics', (e) => {
//	    const data = JSON.parse(e.data);
//	    console.log('Metrics:', data);
//	});
//
// # Key Types
//
//   - Config: Server configuration (ping interval, rate limiting, CORS, etc.)
//   - SSEServer: Central server managing all client connections
//   - SSEClient: Individual client connection
//   - Event: SSE event structure (id, event, data, retry)
//   - Message: Internal message format
//   - RateLimiter: Token bucket rate limiter per client
//   - MessageType: Event type constants (ping, metrics, alert, etc.)
//
// # Broadcasting
//
// Send events to connected clients:
//
//	server.Broadcast(websocket.Event{
//	    Event: "metrics",
//	    Data:  map[string]interface{}{"cpu": 45.2, "memory": 78.5},
//	})
//
//	server.BroadcastMetrics(metricsData)
//	server.BroadcastAlert("security", "Suspicious activity detected", "warning")
//
// # Graceful Shutdown
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	if err := server.Shutdown(ctx); err != nil {
//	    log.Fatal(err)
//	}
package websocket
