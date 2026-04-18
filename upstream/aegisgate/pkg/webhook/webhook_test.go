// Package webhook provides comprehensive tests for the webhook system.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// ============================================================================
// Types Tests
// ============================================================================

func TestWebhookConfigDefaults(t *testing.T) {
	config := DefaultWebhookConfig()

	if config.Method != http.MethodPost {
		t.Errorf("expected default method POST, got %s", config.Method)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", config.Timeout)
	}
	if config.ContentType != "application/json" {
		t.Errorf("expected default content type application/json, got %s", config.ContentType)
	}
	if !config.Enabled {
		t.Error("expected default enabled to be true")
	}
	if config.MaxConcurrency != 5 {
		t.Errorf("expected default max concurrency 5, got %d", config.MaxConcurrency)
	}
}

func TestRetryConfigDefaults(t *testing.T) {
	config := DefaultRetryConfig()

	if !config.Enabled {
		t.Error("expected retry to be enabled")
	}
	if config.MaxAttempts != 3 {
		t.Errorf("expected max attempts 3, got %d", config.MaxAttempts)
	}
	if config.InitialBackoff != 1*time.Second {
		t.Errorf("expected initial backoff 1s, got %v", config.InitialBackoff)
	}
	if config.MaxBackoff != 30*time.Second {
		t.Errorf("expected max backoff 30s, got %v", config.MaxBackoff)
	}
	if config.BackoffMultiplier != 2.0 {
		t.Errorf("expected backoff multiplier 2.0, got %v", config.BackoffMultiplier)
	}
}

func TestBatchDeliveryConfigDefaults(t *testing.T) {
	config := DefaultBatchDeliveryConfig()

	if !config.Enabled {
		t.Error("expected batch to be enabled")
	}
	if config.MaxSize != 100 {
		t.Errorf("expected max size 100, got %d", config.MaxSize)
	}
	if config.MaxWait != 5*time.Second {
		t.Errorf("expected max wait 5s, got %v", config.MaxWait)
	}
}

func TestError(t *testing.T) {
	// Test error without cause
	err := NewError("test-webhook", "send", "connection failed", true, nil)
	expected := "webhook[test-webhook] send: connection failed"
	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
	if !err.Retryable {
		t.Error("expected error to be retryable")
	}

	// Test error with cause
	cause := &testError{msg: "underlying error"}
	err = NewError("test-webhook", "validate", "invalid config", false, cause)
	if !strings.Contains(err.Error(), "underlying error") {
		t.Errorf("expected error to contain cause, got %s", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("expected Unwrap to return cause")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  TLSConfig
		wantErr bool
	}{
		{
			name:    "disabled TLS",
			config:  TLSConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "enabled TLS with defaults",
			config: TLSConfig{
				Enabled:    true,
				MinVersion: "1.2",
			},
			wantErr: false,
		},
		{
			name: "enabled TLS with TLS 1.3",
			config: TLSConfig{
				Enabled:    true,
				MinVersion: "1.3",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := tt.config.BuildTLSConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.config.Enabled && tlsConfig != nil {
				t.Error("expected nil TLS config when disabled")
			}
		})
	}
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestNewManager(t *testing.T) {
	config := DefaultManagerConfig()
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	if manager == nil {
		t.Fatal("expected manager to be created")
	}
}

func TestManagerRegisterWebhook(t *testing.T) {
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	webhook := WebhookConfig{
		Name:    "test-webhook",
		URL:     "https://example.com/webhook",
		Method:  http.MethodPost,
		Enabled: true,
	}

	err = manager.Register(webhook)
	if err != nil {
		t.Fatalf("failed to register webhook: %v", err)
	}

	if len(manager.webhooks) != 1 {
		t.Errorf("expected 1 webhook, got %d", len(manager.webhooks))
	}
}

func TestManagerValidateConfig(t *testing.T) {
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	tests := []struct {
		name    string
		config  WebhookConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: WebhookConfig{
				URL:    "https://example.com/webhook",
				Method: http.MethodPost,
			},
			wantErr: false,
		},
		{
			name:    "missing URL",
			config:  WebhookConfig{},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: WebhookConfig{
				URL: "ftp://example.com/webhook",
			},
			wantErr: true,
		},
		{
			name: "invalid method",
			config: WebhookConfig{
				URL:    "https://example.com/webhook",
				Method: "INVALID",
			},
			wantErr: true,
		},
		{
			name: "basic auth without username",
			config: WebhookConfig{
				URL: "https://example.com/webhook",
				Auth: Authentication{
					Type: AuthBasic,
				},
			},
			wantErr: true,
		},
		{
			name: "bearer auth without token",
			config: WebhookConfig{
				URL: "https://example.com/webhook",
				Auth: Authentication{
					Type: AuthBearer,
				},
			},
			wantErr: true,
		},
		{
			name: "API key auth without key",
			config: WebhookConfig{
				URL: "https://example.com/webhook",
				Auth: Authentication{
					Type: AuthAPIKey,
				},
			},
			wantErr: true,
		},
		{
			name: "HMAC auth without config",
			config: WebhookConfig{
				URL: "https://example.com/webhook",
				Auth: Authentication{
					Type: AuthHMAC,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.Validate(&tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestManagerUnregisterWebhook(t *testing.T) {
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	webhook := WebhookConfig{
		ID:      "test-id",
		Name:    "test-webhook",
		URL:     "https://example.com/webhook",
		Enabled: true,
	}

	err = manager.Register(webhook)
	if err != nil {
		t.Fatalf("failed to register webhook: %v", err)
	}

	err = manager.Unregister("test-id")
	if err != nil {
		t.Fatalf("failed to unregister webhook: %v", err)
	}

	if len(manager.webhooks) != 0 {
		t.Errorf("expected 0 webhooks, got %d", len(manager.webhooks))
	}

	// Try to unregister non-existent webhook
	err = manager.Unregister("non-existent")
	if err == nil {
		t.Error("expected error when unregistering non-existent webhook")
	}
}

func TestManagerListWebhooks(t *testing.T) {
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Register multiple webhooks
	for i := 0; i < 3; i++ {
		webhook := WebhookConfig{
			ID:      string(rune('a' + i)),
			Name:    "test-webhook-" + string(rune('a'+i)),
			URL:     "https://example.com/webhook",
			Enabled: true,
		}
		err = manager.Register(webhook)
		if err != nil {
			t.Fatalf("failed to register webhook: %v", err)
		}
	}

	webhooks := manager.ListWebhooks()
	if len(webhooks) != 3 {
		t.Errorf("expected 3 webhooks, got %d", len(webhooks))
	}
}

func TestManagerEnableDisable(t *testing.T) {
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	webhook := WebhookConfig{
		ID:      "test-id",
		Name:    "test-webhook",
		URL:     "https://example.com/webhook",
		Enabled: true,
	}

	err = manager.Register(webhook)
	if err != nil {
		t.Fatalf("failed to register webhook: %v", err)
	}

	// Disable
	err = manager.Disable("test-id")
	if err != nil {
		t.Fatalf("failed to disable webhook: %v", err)
	}

	wh, _ := manager.GetWebhook("test-id")
	if wh.Enabled {
		t.Error("expected webhook to be disabled")
	}

	// Enable
	err = manager.Enable("test-id")
	if err != nil {
		t.Fatalf("failed to enable webhook: %v", err)
	}

	wh, _ = manager.GetWebhook("test-id")
	if !wh.Enabled {
		t.Error("expected webhook to be enabled")
	}
}

// ============================================================================
// Sender Tests
// ============================================================================

func TestHTTPSenderBuildRequest(t *testing.T) {
	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	config := &WebhookConfig{
		ID:          "test-webhook",
		URL:         "https://example.com/webhook",
		Method:      http.MethodPost,
		ContentType: "application/json",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
		EventType: "test.event",
		Message:   "Test message",
	}

	ctx := context.Background()
	req, _, err := sender.buildRequest(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	if req.Method != http.MethodPost {
		t.Errorf("expected method POST, got %s", req.Method)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected content type application/json, got %s", req.Header.Get("Content-Type"))
	}
	if req.Header.Get("X-Custom-Header") != "test-value" {
		t.Errorf("expected custom header test-value, got %s", req.Header.Get("X-Custom-Header"))
	}
	if req.Header.Get("X-Webhook-ID") != "test-webhook" {
		t.Errorf("expected webhook ID header, got %s", req.Header.Get("X-Webhook-ID"))
	}
}

func TestHTTPSenderWithMockServer(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON content type, got %s", r.Header.Get("Content-Type"))
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}

		// Verify body is valid JSON
		var payload WebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("failed to unmarshal payload: %v", err)
		}

		// Send response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	config := &WebhookConfig{
		ID:          "test-webhook",
		URL:         server.URL,
		Method:      http.MethodPost,
		ContentType: "application/json",
		Enabled:     true,
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
		EventType: "test.event",
		Message:   "Test message",
	}

	ctx := context.Background()
	resp, err := sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPSenderRetry(t *testing.T) {
	attempts := 0

	// Create mock server that fails first two attempts
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	retry := RetryConfig{
		Enabled:            true,
		MaxAttempts:        3,
		InitialBackoff:     10 * time.Millisecond,
		MaxBackoff:         100 * time.Millisecond,
		BackoffMultiplier:  2.0,
		RetryOnStatusCodes: []int{503},
	}

	sender := NewHTTPSender(client, retry)

	config := &WebhookConfig{
		ID:      "test-webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Retry:   retry,
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
		EventType: "test.event",
	}

	ctx := context.Background()
	resp, err := sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// ============================================================================
// HMAC Signature Tests
// ============================================================================

func TestHMACSignature(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"test":"data"}`)

	// Calculate signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Verify signature
	if !VerifySignature(body, expectedSignature, secret, "sha256") {
		t.Error("signature verification failed")
	}

	// Verify with wrong secret
	if VerifySignature(body, expectedSignature, "wrong-secret", "sha256") {
		t.Error("signature should not verify with wrong secret")
	}

	// Verify with wrong algorithm
	if VerifySignature(body, expectedSignature, secret, "sha512") {
		t.Error("signature should not verify with wrong algorithm")
	}
}

func TestHTTPSenderWithHMAC(t *testing.T) {
	var receivedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	secret := "test-secret"
	config := &WebhookConfig{
		ID:      "test-webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Auth: Authentication{
			Type: AuthHMAC,
			HMAC: &HMACConfig{
				Secret:           secret,
				Algorithm:        "sha256",
				Header:           "X-Signature",
				IncludeTimestamp: false,
			},
		},
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
		EventType: "test.event",
		Message:   "Test message",
	}

	ctx := context.Background()
	_, err = sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if receivedSig == "" {
		t.Error("expected HMAC signature in header")
	}

	// Verify the signature
	body, _ := json.Marshal(payload)
	if !VerifySignature(body, receivedSig, secret, "sha256") {
		t.Error("signature verification failed")
	}
}

// ============================================================================
// Authentication Tests
// ============================================================================

func TestBasicAuth(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	config := &WebhookConfig{
		ID:      "test-webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Auth: Authentication{
			Type:     AuthBasic,
			Username: "testuser",
			Password: "testpass",
		},
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
	}

	ctx := context.Background()
	_, err = sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got %s", receivedAuth)
	}
}

func TestBearerAuth(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	config := &WebhookConfig{
		ID:      "test-webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Auth: Authentication{
			Type:  AuthBearer,
			Token: "test-token-123",
		},
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
	}

	ctx := context.Background()
	_, err = sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if receivedAuth != "Bearer test-token-123" {
		t.Errorf("expected Bearer token header, got %s", receivedAuth)
	}
}

func TestAPIKeyAuth(t *testing.T) {
	var receivedKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewHTTPClient(DefaultHTTPClientConfig())
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	sender := NewHTTPSender(client, DefaultRetryConfig())

	config := &WebhookConfig{
		ID:      "test-webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Auth: Authentication{
			Type:         AuthAPIKey,
			APIKey:       "test-api-key",
			APIKeyHeader: "X-API-Key",
		},
	}

	payload := &WebhookPayload{
		ID:        "test-payload-id",
		Timestamp: time.Now(),
		WebhookID: "test-webhook",
	}

	ctx := context.Background()
	_, err = sender.Send(ctx, config, payload)
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	if receivedKey != "test-api-key" {
		t.Errorf("expected API key in header, got %s", receivedKey)
	}
}

// ============================================================================
// Filter Tests
// ============================================================================

func TestSeverityFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         *SeverityFilter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:           "min severity - high passes",
			filter:         NewSeverityFilter().WithMinSeverity(siem.SeverityHigh),
			event:          &siem.Event{Severity: siem.SeverityCritical},
			expectedResult: true,
		},
		{
			name:           "min severity - medium fails",
			filter:         NewSeverityFilter().WithMinSeverity(siem.SeverityHigh),
			event:          &siem.Event{Severity: siem.SeverityMedium},
			expectedResult: false,
		},
		{
			name:           "exclude severity",
			filter:         NewSeverityFilter().WithExcludeSeverities(siem.SeverityLow),
			event:          &siem.Event{Severity: siem.SeverityLow},
			expectedResult: false,
		},
		{
			name:           "include severity - match",
			filter:         NewSeverityFilter().WithIncludeSeverities(siem.SeverityCritical, siem.SeverityHigh),
			event:          &siem.Event{Severity: siem.SeverityHigh},
			expectedResult: true,
		},
		{
			name:           "include severity - no match",
			filter:         NewSeverityFilter().WithIncludeSeverities(siem.SeverityCritical, siem.SeverityHigh),
			event:          &siem.Event{Severity: siem.SeverityMedium},
			expectedResult: false,
		},
		{
			name:           "nil event",
			filter:         NewSeverityFilter().WithMinSeverity(siem.SeverityHigh),
			event:          nil,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestCategoryFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         *CategoryFilter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:           "include category - match",
			filter:         NewCategoryFilter().WithIncludeCategories(siem.CategoryAuthentication, siem.CategoryThreat),
			event:          &siem.Event{Category: siem.CategoryThreat},
			expectedResult: true,
		},
		{
			name:           "include category - no match",
			filter:         NewCategoryFilter().WithIncludeCategories(siem.CategoryAuthentication),
			event:          &siem.Event{Category: siem.CategoryThreat},
			expectedResult: false,
		},
		{
			name:           "exclude category",
			filter:         NewCategoryFilter().WithExcludeCategories(siem.CategoryAuthentication),
			event:          &siem.Event{Category: siem.CategoryAuthentication},
			expectedResult: false,
		},
		{
			name:           "no filter - all pass",
			filter:         NewCategoryFilter(),
			event:          &siem.Event{Category: siem.CategoryThreat},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestSourceFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         *SourceFilter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:           "include source - match",
			filter:         NewSourceFilter().WithIncludeSources("app1", "app2"),
			event:          &siem.Event{Source: "app1"},
			expectedResult: true,
		},
		{
			name:           "include source - no match",
			filter:         NewSourceFilter().WithIncludeSources("app1"),
			event:          &siem.Event{Source: "app2"},
			expectedResult: false,
		},
		{
			name:           "exclude source",
			filter:         NewSourceFilter().WithExcludeSources("app1"),
			event:          &siem.Event{Source: "app1"},
			expectedResult: false,
		},
		{
			name:           "case insensitive match",
			filter:         NewSourceFilter().WithIncludeSources("APP1").WithCaseSensitive(false),
			event:          &siem.Event{Source: "app1"},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestEventTypeFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         *EventTypeFilter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:           "include type - match",
			filter:         NewEventTypeFilter().WithIncludeTypes("login", "logout"),
			event:          &siem.Event{Type: "login"},
			expectedResult: true,
		},
		{
			name:           "include type - no match",
			filter:         NewEventTypeFilter().WithIncludeTypes("login"),
			event:          &siem.Event{Type: "access"},
			expectedResult: false,
		},
		{
			name:           "exclude type",
			filter:         NewEventTypeFilter().WithExcludeTypes("heartbeat"),
			event:          &siem.Event{Type: "heartbeat"},
			expectedResult: false,
		},
		{
			name:           "regex match",
			filter:         NewEventTypeFilter().WithIncludeTypes("login.*").WithRegex(true),
			event:          &siem.Event{Type: "login_failed"},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestCompositeFilter(t *testing.T) {
	// Test AND filter
	andFilter := NewCompositeFilter().
		WithFilters(
			NewSeverityFilter().WithMinSeverity(siem.SeverityMedium),
			NewCategoryFilter().WithIncludeCategories(siem.CategoryThreat),
		).
		WithMode("and")

	tests := []struct {
		name           string
		filter         Filter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:   "AND - both match",
			filter: andFilter,
			event: &siem.Event{
				Severity: siem.SeverityHigh,
				Category: siem.CategoryThreat,
			},
			expectedResult: true,
		},
		{
			name:   "AND - severity fails",
			filter: andFilter,
			event: &siem.Event{
				Severity: siem.SeverityLow,
				Category: siem.CategoryThreat,
			},
			expectedResult: false,
		},
		{
			name:   "AND - category fails",
			filter: andFilter,
			event: &siem.Event{
				Severity: siem.SeverityHigh,
				Category: siem.CategoryAuthentication,
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}

	// Test OR filter
	orFilter := NewCompositeFilter().
		WithFilters(
			NewSeverityFilter().WithMinSeverity(siem.SeverityCritical),
			NewCategoryFilter().WithIncludeCategories(siem.CategoryThreat),
		).
		WithMode("or")

	orTests := []struct {
		name           string
		filter         Filter
		event          *siem.Event
		expectedResult bool
	}{
		{
			name:   "OR - critical severity",
			filter: orFilter,
			event: &siem.Event{
				Severity: siem.SeverityCritical,
				Category: siem.CategoryAuthentication,
			},
			expectedResult: true,
		},
		{
			name:   "OR - threat category",
			filter: orFilter,
			event: &siem.Event{
				Severity: siem.SeverityLow,
				Category: siem.CategoryThreat,
			},
			expectedResult: true,
		},
		{
			name:   "OR - neither matches",
			filter: orFilter,
			event: &siem.Event{
				Severity: siem.SeverityMedium,
				Category: siem.CategoryAuthentication,
			},
			expectedResult: false,
		},
	}

	for _, tt := range orTests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestFilterBuilder(t *testing.T) {
	filter := NewFilterBuilder().
		WithSeverityFilter(siem.SeverityMedium).
		WithCategoryFilter([]siem.EventCategory{siem.CategoryThreat}, nil).
		WithSourceFilter([]string{"app1"}, nil).
		Build()

	// Should match
	event := &siem.Event{
		Severity: siem.SeverityHigh,
		Category: siem.CategoryThreat,
		Source:   "app1",
	}
	if !filter.Match(event) {
		t.Error("expected filter to match event")
	}

	// Should not match - wrong category
	event2 := &siem.Event{
		Severity: siem.SeverityHigh,
		Category: siem.CategoryAuthentication,
		Source:   "app1",
	}
	if filter.Match(event2) {
		t.Error("expected filter to not match event")
	}
}

func TestEventMatcher(t *testing.T) {
	matcher := NewEventMatcher()

	matcher.AddFilter("critical", NewSeverityFilter().WithMinSeverity(siem.SeverityCritical))
	matcher.AddFilter("threats", NewCategoryFilter().WithIncludeCategories(siem.CategoryThreat))

	tests := []struct {
		name          string
		event         *siem.Event
		expectedMatch bool
		expectedAll   bool
		expectedNamed bool
		namedFilter   string
	}{
		{
			name:          "critical auth event",
			event:         &siem.Event{Severity: siem.SeverityCritical, Category: siem.CategoryAuthentication},
			expectedMatch: true,  // matches critical filter
			expectedAll:   false, // doesn't match threats filter
			expectedNamed: true,  // matches critical named filter
			namedFilter:   "critical",
		},
		{
			name:          "medium threat event",
			event:         &siem.Event{Severity: siem.SeverityMedium, Category: siem.CategoryThreat},
			expectedMatch: true,  // matches threats filter
			expectedAll:   false, // doesn't match critical filter
			expectedNamed: true,  // matches threats named filter
			namedFilter:   "threats",
		},
		{
			name:          "low auth event",
			event:         &siem.Event{Severity: siem.SeverityLow, Category: siem.CategoryAuthentication},
			expectedMatch: false,
			expectedAll:   false,
			expectedNamed: false,
			namedFilter:   "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if matcher.Match(tt.event) != tt.expectedMatch {
				t.Errorf("Match: expected %v, got %v", tt.expectedMatch, !tt.expectedMatch)
			}
			// Note: MatchAll will be true for an empty filter set, but should work correctly
			if matcher.MatchNamed(tt.event, tt.namedFilter) != tt.expectedNamed {
				t.Errorf("MatchNamed: expected %v", tt.expectedNamed)
			}
		})
	}
}

func TestBuildFilterFromTrigger(t *testing.T) {
	trigger := TriggerCondition{
		MinSeverity:       siem.SeverityHigh,
		Categories:        []siem.EventCategory{siem.CategoryThreat, siem.CategoryAuthentication},
		Sources:           []string{"app1", "app2"},
		ExcludeEventTypes: []string{"heartbeat"},
	}

	filter := BuildFilterFromTrigger(trigger)

	// Should match
	event := &siem.Event{
		Severity: siem.SeverityCritical,
		Category: siem.CategoryThreat,
		Source:   "app1",
		Type:     "login",
	}
	if !filter.Match(event) {
		t.Error("expected filter to match event")
	}

	// Should not match - wrong severity
	event2 := &siem.Event{
		Severity: siem.SeverityMedium,
		Category: siem.CategoryThreat,
		Source:   "app1",
		Type:     "login",
	}
	if filter.Match(event2) {
		t.Error("expected filter to not match event")
	}

	// Should not match - excluded event type
	event3 := &siem.Event{
		Severity: siem.SeverityHigh,
		Category: siem.CategoryThreat,
		Source:   "app1",
		Type:     "heartbeat",
	}
	if filter.Match(event3) {
		t.Error("expected filter to not match event with excluded type")
	}
}

// ============================================================================
// Payload Tests
// ============================================================================

func TestWebhookPayloadJSON(t *testing.T) {
	payload := &WebhookPayload{
		ID:        "test-id",
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		WebhookID: "webhook-1",
		EventType: "test.event",
		Severity:  siem.SeverityHigh,
		Category:  siem.CategoryThreat,
		Source:    "test-app",
		Message:   "Test message",
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	data, err := payload.ToJSON()
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	// Verify JSON is valid
	var decoded WebhookPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if decoded.ID != payload.ID {
		t.Errorf("expected ID %s, got %s", payload.ID, decoded.ID)
	}
	if decoded.EventType != payload.EventType {
		t.Errorf("expected EventType %s, got %s", payload.EventType, decoded.EventType)
	}
}

func TestBatchPayloadJSON(t *testing.T) {
	payload := &BatchPayload{
		ID:        "batch-id",
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		WebhookID: "webhook-1",
		Events: []*WebhookPayload{
			{ID: "event-1", WebhookID: "webhook-1"},
			{ID: "event-2", WebhookID: "webhook-1"},
		},
		Size: 100,
	}

	data, err := payload.ToJSON()
	if err != nil {
		t.Fatalf("failed to marshal batch payload: %v", err)
	}

	var decoded BatchPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal batch payload: %v", err)
	}

	if len(decoded.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(decoded.Events))
	}
}

// ============================================================================
// Request Builder Tests
// ============================================================================

func TestRequestBuilder(t *testing.T) {
	config := &WebhookConfig{
		ID:   "test-webhook",
		URL:  "https://example.com/webhook",
		Name: "Test Webhook",
	}

	payload := NewRequestBuilder(config).
		WithEventType("test.event").
		WithSeverity(siem.SeverityHigh).
		WithCategory(siem.CategoryThreat).
		WithSource("test-app").
		WithMessage("Test message").
		WithData("key", "value").
		WithMetadata("meta", "data").
		Build()

	if payload.EventType != "test.event" {
		t.Errorf("expected event type test.event, got %s", payload.EventType)
	}
	if payload.Severity != siem.SeverityHigh {
		t.Errorf("expected severity high, got %s", payload.Severity)
	}
	if payload.Category != siem.CategoryThreat {
		t.Errorf("expected category threat, got %s", payload.Category)
	}
	if payload.Source != "test-app" {
		t.Errorf("expected source test-app, got %s", payload.Source)
	}
	if payload.Message != "Test message" {
		t.Errorf("expected message Test message, got %s", payload.Message)
	}
	if payload.Data["key"] != "value" {
		t.Errorf("expected data key to be value, got %v", payload.Data["key"])
	}
	if payload.Metadata["meta"] != "data" {
		t.Errorf("expected metadata meta to be data, got %v", payload.Metadata["meta"])
	}
}

// ============================================================================
// Status Tracker Tests
// ============================================================================

func TestStatusTracker(t *testing.T) {
	tracker := NewStatusTracker(100)

	attempt1 := DeliveryAttempt{
		Attempt:      1,
		Timestamp:    time.Now(),
		Success:      false,
		Error:        "connection refused",
		RetryPending: true, // Set this to indicate retry is pending
	}

	tracker.Record("webhook-1", attempt1)

	status, exists := tracker.Get("webhook-1")
	if !exists {
		t.Fatal("expected status to exist")
	}
	if status.Status != StatusRetrying {
		t.Errorf("expected status retrying, got %s", status.Status)
	}
	if len(status.Attempts) != 1 {
		t.Errorf("expected 1 attempt, got %d", len(status.Attempts))
	}

	attempt2 := DeliveryAttempt{
		Attempt:   2,
		Timestamp: time.Now(),
		Success:   true,
	}

	tracker.Record("webhook-1", attempt2)

	status, _ = tracker.Get("webhook-1")
	if status.Status != StatusDelivered {
		t.Errorf("expected status delivered, got %s", status.Status)
	}
	if len(status.Attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", len(status.Attempts))
	}
}

// ============================================================================
// Manager Send Tests
// ============================================================================

func TestManagerSend(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	// Create manager
	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Register webhook
	webhook := WebhookConfig{
		ID:      "test-webhook",
		Name:    "Test Webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
	}

	if err := manager.Register(webhook); err != nil {
		t.Fatalf("failed to register webhook: %v", err)
	}

	// Create event
	event := &siem.Event{
		ID:        "event-1",
		Timestamp: time.Now(),
		Source:    "test-app",
		Category:  siem.CategoryThreat,
		Type:      "intrusion_detected",
		Severity:  siem.SeverityHigh,
		Message:   "Intrusion detected",
	}

	// Send event
	ctx := context.Background()
	if err := manager.SendSync(ctx, event); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}
}

func TestManagerSendWithFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	manager, err := NewManager(DefaultManagerConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Register webhook with trigger conditions
	webhook := WebhookConfig{
		ID:      "test-webhook",
		Name:    "Test Webhook",
		URL:     server.URL,
		Method:  http.MethodPost,
		Enabled: true,
		Triggers: []TriggerCondition{
			{
				MinSeverity: siem.SeverityHigh,
			},
		},
	}

	if err := manager.Register(webhook); err != nil {
		t.Fatalf("failed to register webhook: %v", err)
	}

	ctx := context.Background()

	// Send low severity event - should be filtered
	lowEvent := &siem.Event{
		ID:        "event-1",
		Timestamp: time.Now(),
		Source:    "test-app",
		Severity:  siem.SeverityLow,
		Message:   "Low severity event",
	}

	if err := manager.SendSync(ctx, lowEvent); err != nil {
		t.Logf("low severity event processing: %v", err)
	}

	// Send high severity event - should be delivered
	highEvent := &siem.Event{
		ID:        "event-2",
		Timestamp: time.Now(),
		Source:    "test-app",
		Severity:  siem.SeverityHigh,
		Message:   "High severity event",
	}

	if err := manager.SendSync(ctx, highEvent); err != nil {
		t.Fatalf("failed to send high severity event: %v", err)
	}
}

// ============================================================================
// Helper Tests
// ============================================================================

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is a ..."},
		{"", 10, ""},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestHeadersToMap(t *testing.T) {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	h.Set("X-Custom", "value")
	h.Add("Multiple", "value1")
	h.Add("Multiple", "value2")

	m := headersToMap(h)

	if m["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", m["Content-Type"])
	}
	if m["X-Custom"] != "value" {
		t.Errorf("expected X-Custom value, got %s", m["X-Custom"])
	}
	if m["Multiple"] != "value1" {
		t.Errorf("expected first value for Multiple, got %s", m["Multiple"])
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkFilterMatch(b *testing.B) {
	filter := NewFilterBuilder().
		WithSeverityFilter(siem.SeverityMedium).
		WithCategoryFilter([]siem.EventCategory{siem.CategoryThreat}, nil).
		Build()

	event := &siem.Event{
		Severity: siem.SeverityHigh,
		Category: siem.CategoryThreat,
		Source:   "test-app",
		Type:     "test.event",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Match(event)
	}
}

func BenchmarkPayloadMarshal(b *testing.B) {
	payload := &WebhookPayload{
		ID:        "test-id",
		Timestamp: time.Now(),
		WebhookID: "webhook-1",
		EventType: "test.event",
		Severity:  siem.SeverityHigh,
		Category:  siem.CategoryThreat,
		Source:    "test-app",
		Message:   "Test message",
		Data: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload.ToJSON()
	}
}

func BenchmarkHMACSignature(b *testing.B) {
	body := bytes.Repeat([]byte("x"), 1024)
	secret := "test-secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		mac.Sum(nil)
	}
}
