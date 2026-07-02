// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: CDP DevTools Client
// =========================================================================
//
// The test harness drives a real Chrome instance via the Chrome DevTools
// Protocol (CDP). This file implements the CDP client.
//
// CDP ARCHITECTURE (FIXED 2026-06-30)
// ------------------------------------
// The Chrome DevTools Protocol has a two-level architecture:
//
//   1. BROWSER-level WebSocket (ws://host:port/devtools/browser/<uuid>)
//      - Exposes the "Browser", "Target", "SystemInfo" domains
//      - Used for: listing targets, creating/attaching, browser-level ops
//      - Does NOT expose "Page", "Runtime", "DOM", etc.
//
//   2. PAGE-level WebSocket (ws://host:port/devtools/page/<targetId>)
//      - Exposes the "Page", "Runtime", "DOM", "Network", etc. domains
//      - One per target (tab, iframe, service worker, etc.)
//      - Page-level methods can ONLY be called here
//
//   3. SESSION-based multiplexing (CDP >= 1.3)
//      - Attach to a page target via Target.attachToTarget
//      - Receive a sessionId
//      - All commands on the BROWSER WebSocket can include {"sessionId": "..."}
//        to route to the attached page target
//      - This is the canonical pattern for "drive a real Chrome tab" from
//        a single Go client
//
// The OLD implementation (pre-fix) connected only to the browser WebSocket
// and tried to call Page.enable / Runtime.evaluate directly. Those methods
// don't exist on the browser WebSocket — the protocol returns -32601
// "method wasn't found". The harness then hung waiting for responses that
// never came.
//
// The FIX below uses Target.attachToTarget to get a sessionId, then
// includes that sessionId in every page-level command. This is the CDP
// best practice and the pattern used by Puppeteer, Playwright, and other
// production tools.
//
// References:
// - https://chromedevtools.github.io/devtools-protocol/tot/Target/
// - https://chromedevtools.github.io/devtools-protocol/tot/Page/
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// domainPageLevel is the set of CDP domains that are PAGE-level only.
// Commands in these domains require a sessionId (or a page-level WebSocket).
// Commands in other domains (Browser, Target, SystemInfo) work on the
// browser WebSocket without a sessionId.
var domainPageLevel = map[string]bool{
	"Page":                 true,
	"Runtime":              true,
	"DOM":                  true,
	"CSS":                  true,
	"Network":              true,
	"Debugger":             true,
	"Log":                  true,
	"Input":                true,
	"Emulation":            true,
	"HeadlessExperimental": true,
	"Tracing":              true,
	"ServiceWorker":        true,
	"Storage":              true,
	"Security":             true,
	"DOMSnapshot":          true,
	"DOMDebugger":          true,
	"Overlay":              true,
	"Performance":          true,
	"HeapProfiler":         true,
	"Profiler":             true,
}

// devtoolsClient is a stateful client to a single Chrome instance's
// DevTools Protocol. It uses a SINGLE browser-level WebSocket and
// multiplexes page-level commands via Target.attachToTarget sessions.
type devtoolsClient struct {
	url    string // browser-level WebSocket URL
	conn   *websocket.Conn
	nextID int
	mu     sync.Mutex
	// pending maps request ID to a channel that receives the response.
	pending map[int]chan *cdpResponse
	// events is a buffered channel for server-pushed events (Page.loadEventFired, etc.)
	events chan cdpEvent
	closed bool

	// pageSessionID is the sessionId for the attached page target. All
	// commands in page-level domains (Page, Runtime, DOM, etc.) are routed
	// to this session. Set by connectCDP after Target.attachToTarget.
	pageSessionID string
}

// cdpRequest is a JSON-RPC 2.0 request to CDP. The optional SessionID
// routes the command to a specific attached target session (set when the
// command is in a page-level domain).
type cdpRequest struct {
	ID        int                    `json:"id"`
	Method    string                 `json:"method"`
	Params    map[string]interface{} `json:"params,omitempty"`
	SessionID string                 `json:"sessionId,omitempty"`
}

// cdpResponse is a JSON-RPC 2.0 response from CDP.
type cdpResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpError       `json:"error,omitempty"`
	// SessionID is echoed by CDP for responses that came from a specific
	// session. It's the same sessionId we sent.
	SessionID string `json:"sessionId,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cdpEvent struct {
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	SessionID string          `json:"sessionId,omitempty"`
}

// connectCDP opens a browser-level WebSocket to Chrome, then attaches to
// a page target via Target.attachToTarget. The returned client is ready
// to issue page-level commands (the pageSessionID is set).
//
// Flow (matches the CDP canonical pattern):
//  1. GET /json/version → browser WebSocket URL
//  2. Open browser WebSocket
//  3. Browser-level: Target.setDiscoverTargets({discover: true})
//  4. Browser-level: Target.getTargets → find a "page" type target
//  5. Browser-level: Target.attachToTarget({targetId, flatten: true})
//     → returns {sessionId}
//  6. Set devtoolsClient.pageSessionID = sessionId
func connectCDP(cfg *Config) (*devtoolsClient, error) {
	// Step 1: GET /json/version
	httpURL := fmt.Sprintf("http://127.0.0.1:%d/json/version", cfg.Port)
	resp, err := http.Get(httpURL) // #nosec G107 G704 -- test harness, localhost only
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

	// Step 2: Open browser WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(versionInfo.WebSocketDebuggerURL, nil)
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
	go client.readLoop()

	// Step 3: Enable target discovery (so we can find pages)
	if _, err := client.call("Target.setDiscoverTargets", map[string]interface{}{
		"discover": true,
	}, ""); err != nil {
		return nil, fmt.Errorf("Target.setDiscoverTargets: %w", err)
	}

	// Step 4: Get a page target
	targets, err := client.getTargets()
	if err != nil {
		return nil, fmt.Errorf("Target.getTargets: %w", err)
	}
	var pageTarget *cdpTarget
	for i := range targets {
		if targets[i].Type == "page" {
			pageTarget = &targets[i]
			break
		}
	}
	if pageTarget == nil {
		return nil, fmt.Errorf("no page target found (Chrome may not have any tabs open)")
	}

	// Step 5: Attach to the page target
	sessionID, err := client.attachToTarget(pageTarget.TargetID)
	if err != nil {
		return nil, fmt.Errorf("Target.attachToTarget: %w", err)
	}
	client.pageSessionID = sessionID

	return client, nil
}

// cdpTarget is a subset of Target.getTargets response
type cdpTarget struct {
	TargetID             string `json:"targetId"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl,omitempty"`
}

// getTargets calls Target.getTargets and returns the list of targets.
func (c *devtoolsClient) getTargets() ([]cdpTarget, error) {
	res, err := c.call("Target.getTargets", nil, "")
	if err != nil {
		return nil, err
	}
	var result struct {
		TargetInfos []cdpTarget `json:"targetInfos"`
	}
	if err := json.Unmarshal(res.Result, &result); err != nil {
		return nil, err
	}
	return result.TargetInfos, nil
}

// attachToTarget calls Target.attachToTarget and returns the sessionId.
func (c *devtoolsClient) attachToTarget(targetID string) (string, error) {
	res, err := c.call("Target.attachToTarget", map[string]interface{}{
		"targetId": targetID,
		"flatten":  true,
	}, "")
	if err != nil {
		return "", err
	}
	var result struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(res.Result, &result); err != nil {
		return "", err
	}
	if result.SessionID == "" {
		return "", fmt.Errorf("Target.attachToTarget returned no sessionId")
	}
	return result.SessionID, nil
}

// call sends a JSON-RPC command. The sessionOverride parameter allows the
// caller to use a different sessionId than the default pageSessionID
// (e.g., for Browser-level commands that should NOT be routed).
func (c *devtoolsClient) call(method string, params map[string]interface{}, sessionOverride string) (*cdpResponse, error) {
	if c.closed {
		return nil, fmt.Errorf("CDP client is closed")
	}
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	ch := make(chan *cdpResponse, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	// Determine the sessionId: caller can override; otherwise use the
	// pageSessionID for page-level domains.
	sessionID := sessionOverride
	if sessionID == "" {
		domain := strings.SplitN(method, ".", 2)[0]
		if domainPageLevel[domain] && c.pageSessionID != "" {
			sessionID = c.pageSessionID
		}
	}

	req := cdpRequest{
		ID:        id,
		Method:    method,
		Params:    params,
		SessionID: sessionID,
	}
	msg, err := json.Marshal(req)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("send: %w", err)
	}
	select {
	case res := <-ch:
		if res.Error != nil {
			return nil, fmt.Errorf("%s: %s (code %d)", method, res.Error.Message, res.Error.Code)
		}
		return res, nil
	case <-time.After(30 * time.Second):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("%s: timeout", method)
	}
}

// =============================================================================
// HIGH-LEVEL HELPERS
// =============================================================================
// These methods are thin wrappers over call() that take a context.Context
// and return the raw result. They exist to keep the call sites readable
// (e.g., `cdp.navigate(ctx, url)` instead of `cdp.call("Page.navigate", ...)`)
// and to match the API the callers (loadExtension.go, runner.go, main.go)
// were written against.
//
// Each helper:
//   1. Calls call() with the appropriate CDP method
//   2. Returns the raw result
//   3. The caller parses the result if needed
//
// Note: The context is not currently used for cancellation (we have a
// 30-second timeout in call()), but we keep it for future use.
// =============================================================================

// rawCall is a convenience wrapper that takes a context and returns the
// raw result. It exists so the helper methods have a shorter signature.
func (c *devtoolsClient) rawCall(ctx context.Context, method string, params map[string]interface{}) (json.RawMessage, error) {
	res, err := c.call(method, params, "")
	if err != nil {
		return nil, err
	}
	return res.Result, nil
}

// navigate navigates the page to the given URL.
func (c *devtoolsClient) navigate(ctx context.Context, url string) error {
	_, err := c.call("Page.navigate", map[string]interface{}{"url": url}, "")
	return err
}

// evaluate evaluates a JavaScript expression in the page's
// main world and returns the result as a JSON value.
// The caller is responsible for parsing the result.
func (c *devtoolsClient) evaluate(ctx context.Context, expression string) (json.RawMessage, error) {
	return c.rawCall(ctx, "Runtime.evaluate", map[string]interface{}{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  true,
		"userGesture":   true,
	})
}

// addScriptToEvaluateOnNewDocument registers a script that
// will be evaluated on every new document. Used to inject
// the extension's content script (since we can't easily load
// an actual Chrome extension in headless mode without
// chrome.loadExtension()).
//
// v3.5.1+ (Bug C follow-up): no worldName specified, so the
// script runs in the main world (the default). This is
// required for the dist's ContentScript to attach input
// listeners that fire on the page's prompt textarea.
func (c *devtoolsClient) addScriptToEvaluateOnNewDocument(ctx context.Context, script string) error {
	_, err := c.call("Page.addScriptToEvaluateOnNewDocument", map[string]interface{}{
		"source": script,
	}, "")
	return err
}

// enable enables a CDP domain on the attached target session.
// For page-level domains, this routes through the page session.
func (c *devtoolsClient) enable(ctx context.Context, domain string) error {
	_, err := c.call(domain+".enable", nil, "")
	return err
}

// waitForEvent blocks until an event with the given method is
// received, or the context is cancelled. Useful for waiting for
// Page.loadEventFired.
func (c *devtoolsClient) waitForEvent(ctx context.Context, method string) (json.RawMessage, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case ev, ok := <-c.events:
			if !ok {
				return nil, fmt.Errorf("CDP client closed")
			}
			if ev.Method == method {
				return ev.Params, nil
			}
		}
	}
}

// readLoop reads frames from the WebSocket and dispatches to pending
// channels (for responses) or the events channel (for events).
func (c *devtoolsClient) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			close(c.events)
			return
		}
		var msg struct {
			ID        int             `json:"id,omitempty"`
			Method    string          `json:"method,omitempty"`
			Result    json.RawMessage `json:"result,omitempty"`
			Error     *cdpError       `json:"error,omitempty"`
			SessionID string          `json:"sessionId,omitempty"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		// Response (has ID)
		if msg.ID != 0 {
			c.mu.Lock()
			ch, ok := c.pending[msg.ID]
			if ok {
				delete(c.pending, msg.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- &cdpResponse{ID: msg.ID, Result: msg.Result, Error: msg.Error, SessionID: msg.SessionID}
			}
			continue
		}
		// Event (has Method, no ID)
		select {
		case c.events <- cdpEvent{Method: msg.Method, Params: msg.Result, SessionID: msg.SessionID}:
		default:
			// Drop events if buffer is full (don't block the read loop)
		}
	}
}

// Close closes the WebSocket connection. Exported (uppercase C) for
// the callers that use cdp.Close().
func (c *devtoolsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// close is the internal lowercase version, kept for backward compat
// with any code that might have used the old API.
func (c *devtoolsClient) close() error {
	return c.Close()
}
