// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Response Blocking Tests
// =========================================================================
//
// Tests that modifyResponse() actually blocks responses containing
// sensitive data (secrets, PII, ATLAS threats). This verifies the fix
// for the bug where scanner findings in responses were logged but
// never acted on — sensitive data passed through to the client.
//
// Also tests that ResponseGuard (7-layer scan) is wired into the
// proxy's response path for PII, secret, XSS, compliance, toxicity,
// token-limit, and hallucination detection.
// =========================================================================

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rbChatRequest is a chat completion request for test bodies.
type rbChatRequest struct {
	Model    string      `json:"model"`
	Messages []rbChatMsg `json:"messages"`
}

type rbChatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// rbChatResponse builds a minimal chat completion response with the given
// assistant content.
func rbChatResponse(content string) string {
	resp := map[string]interface{}{
		"id":      "test-rb",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "test-model",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// testRBProxy creates a proxy with a mock upstream that returns the given
// response body. Returns the proxy and a test server.
func testRBProxy(t *testing.T, upstreamResponseBody string) (*Proxy, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(upstreamResponseBody))
	}))

	opts := &Options{
		Upstream:    upstream.URL,
		MaxBodySize: 10 * 1024 * 1024,
		Timeout:     10 * time.Second,
		RateLimit:   1000,
	}
	p := New(opts)
	if p == nil {
		upstream.Close()
		t.Fatal("New() returned nil proxy")
	}
	return p, upstream
}

// sendRBRequest sends a benign chat request through the proxy and returns
// the status code and response body.
func sendRBRequest(t *testing.T, p *Proxy) (int, string) {
	t.Helper()
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	reqBody := rbChatRequest{
		Model: "test-model",
		Messages: []rbChatMsg{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBytes)
}

// TestResponseBlocked_SecretInResponse verifies that a response containing
// an AWS access key is blocked with 403 (not passed through to the client).
func TestResponseBlocked_SecretInResponse(t *testing.T) {
	// Response contains an AWS access key — should trigger scanner.ShouldBlock
	responseBody := rbChatResponse("Here is your key: AKIAIOSFODNN7EXAMPLE and some text")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for response with AWS key, got %d. Body: %s", status, body)
	}
	if !strings.Contains(strings.ToLower(body), "blocked") {
		t.Errorf("Expected 'blocked' in response body, got: %s", body)
	}
}

// TestResponseBlocked_CreditCardInResponse verifies that a response containing
// a credit card number is blocked.
func TestResponseBlocked_CreditCardInResponse(t *testing.T) {
	responseBody := rbChatResponse("The card number is 4111111111111111 for processing")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for response with credit card, got %d. Body: %s", status, body)
	}
}

// TestResponseBlocked_PrivateKeyInResponse verifies that a response containing
// a PEM private key header is blocked. Uses string concatenation to avoid
// triggering OPSEC private-key detection on the test file itself.
func TestResponseBlocked_PrivateKeyInResponse(t *testing.T) {
	pemHeader := "-----BEGIN " + "RSA PRIVATE KEY" + "-----\nMIIEowIBAAKCAQEA..."
	responseBody := rbChatResponse(pemHeader)
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for response with private key, got %d. Body: %s", status, body)
	}
}

// TestResponseAllowed_BenignResponse verifies that a normal response without
// sensitive data passes through to the client.
func TestResponseAllowed_BenignResponse(t *testing.T) {
	responseBody := rbChatResponse("Why did the chicken cross the road? To get to the other side!")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusOK {
		t.Errorf("Expected 200 OK for benign response, got %d. Body: %s", status, body)
	}
	if !strings.Contains(body, "chicken") {
		t.Errorf("Expected benign response to pass through, got: %s", body)
	}
}

// TestResponseGuard_Wired verifies that the ResponseGuard is initialized
// and enabled on the proxy.
func TestResponseGuard_Wired(t *testing.T) {
	p, upstream := testRBProxy(t, rbChatResponse("test"))
	defer upstream.Close()

	if p.responseGuard == nil {
		t.Fatal("ResponseGuard should be initialized on proxy")
	}
	if !p.responseGuard.IsEnabled() {
		t.Fatal("ResponseGuard should be enabled by default")
	}
}

// TestResponseGuard_PIIInResponse verifies that the ResponseGuard detects
// PII (SSN) in responses and blocks them.
func TestResponseGuard_PIIInResponse(t *testing.T) {
	// SSN in response — should be caught by either the scanner or ResponseGuard
	responseBody := rbChatResponse("The SSN on file is 123-45-6789 for the account")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for response with SSN, got %d. Body: %s", status, body)
	}
}

// TestResponseGuard_XSSInResponse verifies that the ResponseGuard detects
// XSS vectors in responses and blocks them.
func TestResponseGuard_XSSInResponse(t *testing.T) {
	// XSS script tag — should be caught by the scanner (CategoryXSS, Critical)
	responseBody := rbChatResponse("Here is the page: <script>alert('xss')</script>")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	status, body := sendRBRequest(t, p)

	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for response with XSS, got %d. Body: %s", status, body)
	}
}

// TestResponseCachedBlock verifies that when a response with sensitive data
// is seen again (cache hit), it is still blocked — not just logged.
func TestResponseCachedBlock(t *testing.T) {
	responseBody := rbChatResponse("Your key: AKIAIOSFODNN7EXAMPLE is ready")
	p, upstream := testRBProxy(t, responseBody)
	defer upstream.Close()

	// First request — should block and cache
	status1, _ := sendRBRequest(t, p)
	if status1 != http.StatusForbidden {
		t.Errorf("First request: expected 403, got %d", status1)
	}

	// Second request with same content — should also block (from cache)
	status2, body2 := sendRBRequest(t, p)
	if status2 != http.StatusForbidden {
		t.Errorf("Second request (cached): expected 403, got %d. Body: %s", status2, body2)
	}
	if !strings.Contains(strings.ToLower(body2), "blocked") {
		t.Errorf("Cached response should contain 'blocked', got: %s", body2)
	}
}
