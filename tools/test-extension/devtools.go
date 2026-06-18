// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Chrome DevTools Protocol Client
// =========================================================================
//
// devtools.go is a thin wrapper around the Chrome DevTools
// Protocol (CDP). CDP is JSON-RPC 2.0 over WebSocket. The
// wrapper exposes only the operations the Lens test harness
// needs:
//
//   - Connect to a running Chromium instance
//   - Navigate to a URL
//   - Evaluate JavaScript in the page context
//   - Wait for a Page event
//   - Subscribe to Network/Console events
//   - Send arbitrary CDP commands
//
// The wrapper handles:
//   - The WebSocket handshake (via gorilla/websocket)
//   - JSON-RPC request/response correlation (each request
//     has a unique ID; responses are matched by ID)
//   - Events from the server (not correlated with a request)
//   - Per-operation timeouts
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// devtoolsClient is a thin CDP client. It is NOT goroutine-safe
// for concurrent calls; the caller should serialize calls via
// the mutex if needed.
type devtoolsClient struct {
	url     string
	conn    *websocket.Conn
	mu      sync.Mutex
	nextID  int
	pending map[int]chan *cdpResponse
	events  chan cdpEvent
	closed  bool
}

// cdpResponse is a JSON-RPC 2.0 response.
type cdpResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpError       `json:"error,omitempty"`
}

// cdpError is a JSON-RPC 2.0 error.
type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *cdpError) Error() string {
	return fmt.Sprintf("CDP error %d: %s", e.Code, e.Message)
}

// cdpEvent is a JSON-RPC 2.0 event (notification).
type cdpEvent struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// connectCDP connects to a running Chromium instance and
// returns a CDP client. The Chromium process must already be
// running with --remote-debugging-port=<port>.
//
// The function reads the WebSocket URL from /json/version,
// which works for any port (including OS-assigned ports
// when the port argument was 0).
func connectCDP(cfg *Config) (*devtoolsClient, error) {
	// Step 1: GET /json/version to get the WebSocket URL.
	httpURL := fmt.Sprintf("http://127.0.0.1:%d/json/version", cfg.Port)
	resp, err := http.Get(httpURL) // #nosec G107 -- test harness, localhost only
	if err != nil {
		return nil, fmt.Errorf("GET /json/version: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /json/version: status %d", resp.StatusCode)
	}
	var versionInfo struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&versionInfo); err != nil {
		return nil, fmt.Errorf("decode /json/version: %w", err)
	}
	if versionInfo.WebSocketDebuggerURL == "" {
		return nil, fmt.Errorf("/json/version: no webSocketDebuggerUrl")
	}

	// Step 2: Open the WebSocket.
	dialer := websocket.Dialer{
		HandshakeTimeout: cfg.Timeout,
	}
	conn, _, err := dialer.Dial(versionInfo.WebSocketDebuggerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	client := &devtoolsClient{
		url:     versionInfo.WebSocketDebuggerURL,
		conn:    conn,
		nextID:  1,
		pending: make(map[int]chan *cdpResponse),
		events:  make(chan cdpEvent, 64),
	}

	// Step 3: Start the read loop in a goroutine. It
	// dispatches responses to the pending channel and
	// events to the events channel.
	go client.readLoop()

	return client, nil
}

// readLoop reads frames from the WebSocket and dispatches
// them to either a pending response channel (matched by ID)
// or the events channel.
func (c *devtoolsClient) readLoop() {
	defer func() {
		// Close the events channel so any goroutine waiting
		// on waitForEvent can exit. The pending channels
		// are drained by Close() (via the conn.Close()
		// triggering ReadMessage to return an error).
		close(c.events)
	}()
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			// Connection closed or error. Signal all
			// pending requests to fail.
			c.mu.Lock()
			for _, ch := range c.pending {
				close(ch)
			}
			c.pending = make(map[int]chan *cdpResponse)
			c.closed = true
			c.mu.Unlock()
			return
		}
		// Try to parse as a response (has an ID).
		var resp cdpResponse
		if err := json.Unmarshal(msg, &resp); err == nil && resp.ID != 0 {
			c.mu.Lock()
			ch, ok := c.pending[resp.ID]
			if ok {
				delete(c.pending, resp.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- &resp
			}
			continue
		}
		// Otherwise it's an event.
		var ev cdpEvent
		if err := json.Unmarshal(msg, &ev); err == nil && ev.Method != "" {
			select {
			case c.events <- ev:
			default:
				// Event channel full; drop the event.
				// (This is unlikely; the buffer is 64.)
			}
		}
	}
}

// Close closes the WebSocket connection.
func (c *devtoolsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// call sends a CDP command and waits for the response. The
// method is e.g. "Page.navigate". The params is the JSON
// object to pass as the command's parameters. Returns the
// raw JSON result or an error.
func (c *devtoolsClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("CDP client is closed")
	}
	id := c.nextID
	c.nextID++
	ch := make(chan *cdpResponse, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	// Build the JSON-RPC request.
	req := map[string]any{
		"id":     id,
		"method": method,
	}
	if params != nil {
		req["params"] = params
	}
	msg, err := json.Marshal(req)
	if err != nil {
		// Clean up the pending entry.
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Send the request.
	c.mu.Lock()
	if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("write: %w", err)
	}
	c.mu.Unlock()

	// Wait for the response (with context cancellation).
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("connection closed while waiting for %s", method)
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		// Clean up the pending entry.
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// navigate navigates the page to the given URL.
func (c *devtoolsClient) navigate(ctx context.Context, url string) error {
	_, err := c.call(ctx, "Page.navigate", map[string]any{"url": url})
	return err
}

// evaluate evaluates a JavaScript expression in the page's
// main frame and returns the result. The result is the raw
// JSON value; the caller is responsible for parsing it.
func (c *devtoolsClient) evaluate(ctx context.Context, expression string) (json.RawMessage, error) {
	result, err := c.call(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  true,
		"userGesture":   true,
	})
	if err != nil {
		return nil, err
	}
	// The result is wrapped in {"result": {"value": ...}, "exceptionDetails": ...}.
	// Parse and unwrap.
	var wrapper struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(result, &wrapper); err != nil {
		return nil, fmt.Errorf("decode evaluate result: %w", err)
	}
	if len(wrapper.ExceptionDetails) > 0 {
		return nil, fmt.Errorf("evaluate exception: %s", string(wrapper.ExceptionDetails))
	}
	return wrapper.Result.Value, nil
}

// addScriptToEvaluateOnNewDocument registers a script that
// will be evaluated on every new document. Used to inject
// the extension's content script (since we can't easily load
// the actual Chrome extension in headless mode without
// chrome.loadExtension()).
func (c *devtoolsClient) addScriptToEvaluateOnNewDocument(ctx context.Context, script string) error {
	_, err := c.call(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{
		"source": script,
	})
	return err
}

// enable enables a CDP domain. Required before using any
// commands/events in that domain.
func (c *devtoolsClient) enable(ctx context.Context, domain string) error {
	_, err := c.call(ctx, domain+".enable", nil)
	return err
}

// waitForEvent blocks until an event with the given method
// is received, or the context is cancelled. Useful for
// waiting for Page.loadEventFired.
func (c *devtoolsClient) waitForEvent(ctx context.Context, method string) (json.RawMessage, error) {
	for {
		select {
		case ev, ok := <-c.events:
			if !ok {
				return nil, fmt.Errorf("connection closed while waiting for %s", method)
			}
			if ev.Method == method {
				return ev.Params, nil
			}
			// Otherwise it's an event for a different method;
			// drop it and keep waiting.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// close closes the page.
func (c *devtoolsClient) close(ctx context.Context) error {
	_, err := c.call(ctx, "Page.close", nil)
	return err
}
