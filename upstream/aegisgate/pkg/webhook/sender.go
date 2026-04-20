// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package webhook provides HTTP delivery functionality.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// ============================================================================
// Sender Interface
// ============================================================================

// Sender is the interface for webhook senders.
type Sender interface {
	// Send sends a webhook payload
	Send(ctx context.Context, config *WebhookConfig, payload Payload) (*DeliveryResponse, error)
	// SendWithRetry sends with custom retry settings
	SendWithRetry(ctx context.Context, config *WebhookConfig, payload Payload, retry RetryConfig) (*DeliveryResponse, error)
}

// Payload represents a payload that can be sent via webhook.
type Payload interface {
	// ToJSON returns the JSON representation
	ToJSON() ([]byte, error)
	// GetID returns the payload ID
	GetID() string
	// GetTimestamp returns the payload timestamp
	GetTimestamp() time.Time
}

// Ensure WebhookPayload and BatchPayload implement Payload
var _ Payload = (*WebhookPayload)(nil)
var _ Payload = (*BatchPayload)(nil)

// ToJSON returns the JSON representation of WebhookPayload.
func (p *WebhookPayload) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// GetID returns the payload ID.
func (p *WebhookPayload) GetID() string {
	return p.ID
}

// GetTimestamp returns the payload timestamp.
func (p *WebhookPayload) GetTimestamp() time.Time {
	return p.Timestamp
}

// ToJSON returns the JSON representation of BatchPayload.
func (p *BatchPayload) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// GetID returns the batch ID.
func (p *BatchPayload) GetID() string {
	return p.ID
}

// GetTimestamp returns the batch timestamp.
func (p *BatchPayload) GetTimestamp() time.Time {
	return p.Timestamp
}

// ============================================================================
// HTTP Client
// ============================================================================

// HTTPClient wraps http.Client with webhook-specific functionality.
type HTTPClient struct {
	*http.Client
	config *HTTPClientConfig
}

// NewHTTPClient creates a new HTTP client for webhook delivery.
func NewHTTPClient(config *HTTPClientConfig) (*HTTPClient, error) {
	if config == nil {
		config = DefaultHTTPClientConfig()
	}

	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableKeepAlives:   config.DisableKeepAlives,
		DisableCompression:  config.DisableCompression,
	}

	// Configure TLS
	if config.TLS != nil && config.TLS.Enabled {
		tlsConf, err := config.TLS.BuildTLSConfig()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConf
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// Set response header timeout
	if config.ResponseHeaderTimeout > 0 {
		transport.ResponseHeaderTimeout = config.ResponseHeaderTimeout
	}

	// Set expect continue timeout
	if config.ExpectContinueTimeout > 0 {
		transport.ExpectContinueTimeout = config.ExpectContinueTimeout
	}

	return &HTTPClient{
		Client: client,
		config: config,
	}, nil
}

// ============================================================================
// HTTP Sender
// ============================================================================

// HTTPSender implements Sender using HTTP.
type HTTPSender struct {
	client  *HTTPClient
	retry   RetryConfig
	tokenMu sync.RWMutex
}

// NewHTTPSender creates a new HTTP sender.
func NewHTTPSender(client *HTTPClient, retry RetryConfig) *HTTPSender {
	return &HTTPSender{
		client: client,
		retry:  retry,
	}
}

// Send sends a webhook payload.
func (s *HTTPSender) Send(ctx context.Context, config *WebhookConfig, payload Payload) (*DeliveryResponse, error) {
	retry := config.Retry
	if !retry.Enabled {
		retry = s.retry
	}
	return s.SendWithRetry(ctx, config, payload, retry)
}

// SendWithRetry sends a webhook payload with custom retry settings.
func (s *HTTPSender) SendWithRetry(ctx context.Context, config *WebhookConfig, payload Payload, retry RetryConfig) (*DeliveryResponse, error) {
	var lastResp *DeliveryResponse
	var lastErr error

	maxAttempts := 1
	if retry.Enabled {
		maxAttempts = retry.MaxAttempts
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Check context
		select {
		case <-ctx.Done():
			return nil, NewError(config.ID, "send", "context cancelled", false, ctx.Err())
		default:
		}

		// Build request
		req, bodyData, err := s.buildRequest(ctx, config, payload)
		if err != nil {
			return nil, err
		}

		// Add signature if HMAC is configured
		if config.Auth.Type == AuthHMAC && config.Auth.HMAC != nil {
			s.signPayload(req, bodyData, config.Auth.HMAC, payload)
		}

		// Add authentication headers
		if err := s.addAuthHeaders(req, config); err != nil {
			return nil, err
		}

		// Execute request
		start := time.Now()
		resp, err := s.client.Do(req)
		duration := time.Since(start)

		if err != nil {
			lastErr = NewError(config.ID, "send", "request failed: "+err.Error(), true, err)

			// Check if we should retry
			if attempt < maxAttempts && s.shouldRetryOnError(err, retry) {
				s.backoff(attempt, retry)
				continue
			}
			return nil, lastErr
		}

		// Read response
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		lastResp = &DeliveryResponse{
			StatusCode:  resp.StatusCode,
			Body:        truncateString(string(respBody), 10240), // Truncate to 10KB
			Headers:     headersToMap(resp.Header),
			ContentType: resp.Header.Get("Content-Type"),
		}

		// Check if successful
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return lastResp, nil
		}

		// Check if we should retry on status code
		if attempt < maxAttempts && s.shouldRetryOnStatus(resp.StatusCode, retry) {
			lastErr = NewError(config.ID, "send", fmt.Sprintf("status %d after %v", resp.StatusCode, duration), true, nil)
			s.backoff(attempt, retry)
			continue
		}

		// Non-retryable error
		return lastResp, NewError(config.ID, "send", fmt.Sprintf("status %d: %s", resp.StatusCode, truncateString(string(respBody), 200)), false, nil)
	}

	return lastResp, lastErr
}

// buildRequest constructs an HTTP request for the webhook.
func (s *HTTPSender) buildRequest(ctx context.Context, config *WebhookConfig, payload Payload) (*http.Request, []byte, error) {
	// Serialize payload
	bodyData, err := payload.ToJSON()
	if err != nil {
		return nil, nil, NewError(config.ID, "build_request", "failed to marshal payload", false, err)
	}

	// Create request
	method := config.Method
	if method == "" {
		method = http.MethodPost
	}

	req, err := http.NewRequestWithContext(ctx, method, config.URL, bytes.NewReader(bodyData))
	if err != nil {
		return nil, nil, NewError(config.ID, "build_request", "failed to create request", false, err)
	}

	// Set content type
	contentType := config.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)

	// Set custom headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// Add standard headers
	req.Header.Set("User-Agent", "AegisGate-Webhook/1.0")
	req.Header.Set("X-Webhook-ID", config.ID)
	req.Header.Set("X-Payload-ID", payload.GetID())
	req.Header.Set("X-Payload-Timestamp", payload.GetTimestamp().Format(time.RFC3339))

	return req, bodyData, nil
}

// signPayload adds HMAC signature to the request.
func (s *HTTPSender) signPayload(req *http.Request, body []byte, hmacConfig *HMACConfig, payload Payload) {
	if hmacConfig == nil || hmacConfig.Secret == "" {
		return
	}

	// Calculate signature
	var mac hash.Hash
	algorithm := strings.ToLower(hmacConfig.Algorithm)
	switch algorithm {
	case "sha384":
		mac = hmac.New(sha512.New384, []byte(hmacConfig.Secret))
	case "sha512":
		mac = hmac.New(sha512.New, []byte(hmacConfig.Secret))
	default: // sha256
		mac = hmac.New(sha256.New, []byte(hmacConfig.Secret))
	}

	// Include timestamp if configured
	var signature string
	if hmacConfig.IncludeTimestamp {
		ts := time.Now()
		tsHeader := hmacConfig.TimestampHeader
		if tsHeader == "" {
			tsHeader = "X-Timestamp"
		}
		req.Header.Set(tsHeader, ts.Format(time.RFC3339))

		// Include timestamp in signature
		mac.Write([]byte(ts.Format(time.RFC3339)))
		mac.Write(body)
	} else {
		mac.Write(body)
	}

	// Encode signature
	sig := mac.Sum(nil)
	switch algorithm {
	case "sha384", "sha512":
		signature = hex.EncodeToString(sig)
	default:
		signature = hex.EncodeToString(sig)
	}

	// Add prefix if configured
	if hmacConfig.SignaturePrefix != "" {
		signature = hmacConfig.SignaturePrefix + signature
	}

	// Set header
	header := hmacConfig.Header
	if header == "" {
		header = "X-Signature"
	}
	req.Header.Set(header, signature)
}

// addAuthHeaders adds authentication headers to the request.
func (s *HTTPSender) addAuthHeaders(req *http.Request, config *WebhookConfig) error {
	switch config.Auth.Type {
	case AuthNone:
		// No authentication

	case AuthBasic:
		auth := config.Auth.Username + ":" + config.Auth.Password
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+config.Auth.Token)

	case AuthAPIKey:
		header := config.Auth.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, config.Auth.APIKey)

	case AuthOAuth2:
		return s.addOAuth2Token(req, config)

	case AuthHMAC:
		// HMAC is handled separately in signPayload
	}

	return nil
}

// addOAuth2Token adds OAuth2 bearer token to the request.
func (s *HTTPSender) addOAuth2Token(req *http.Request, config *WebhookConfig) error {
	if config.Auth.OAuth2 == nil {
		return NewError(config.ID, "auth", "OAuth2 config missing", false, nil)
	}

	// Check if we need a new token
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()

	oauth2 := config.Auth.OAuth2

	// Return existing token if valid
	if oauth2.AccessToken != "" && time.Now().Before(oauth2.TokenExpiry.Add(-time.Minute)) {
		req.Header.Set("Authorization", "Bearer "+oauth2.AccessToken)
		return nil
	}

	// Request new token
	token, expiry, err := s.fetchOAuth2Token(req.Context(), oauth2)
	if err != nil {
		return NewError(config.ID, "auth", "failed to fetch OAuth2 token", true, err)
	}

	oauth2.AccessToken = token
	oauth2.TokenExpiry = expiry

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// fetchOAuth2Token fetches a new OAuth2 token using client credentials flow.
func (s *HTTPSender) fetchOAuth2Token(ctx context.Context, config *OAuth2Config) (string, time.Time, error) {
	// Build token request
	reqBody := "grant_type=client_credentials"
	if len(config.Scopes) > 0 {
		reqBody += "&scope=" + strings.Join(config.Scopes, " ")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(reqBody))
	if err != nil {
		return "", time.Time{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("token request failed: %s", string(body))
	}

	// Parse token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", time.Time{}, err
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return tokenResp.AccessToken, expiry, nil
}

// shouldRetryOnStatus checks if we should retry based on status code.
func (s *HTTPSender) shouldRetryOnStatus(statusCode int, retry RetryConfig) bool {
	for _, code := range retry.RetryOnStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// shouldRetryOnError checks if we should retry based on error.
func (s *HTTPSender) shouldRetryOnError(err error, retry RetryConfig) bool {
	if retry.RetryOnNetworkError {
		return true
	}

	// Check for timeout
	if retry.RetryOnTimeout {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			return true
		}
	}

	return false
}

// backoff performs exponential backoff with optional jitter.
func (s *HTTPSender) backoff(attempt int, retry RetryConfig) {
	backoff := retry.InitialBackoff
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * retry.BackoffMultiplier)
		if backoff > retry.MaxBackoff {
			backoff = retry.MaxBackoff
			break
		}
	}

	// Add jitter if enabled
	if retry.Jitter {
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		backoff += jitter
	}

	time.Sleep(backoff)
}

// ============================================================================
// Helper Functions
// ============================================================================

// headersToMap converts http.Header to map[string]string.
func headersToMap(h http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range h {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// truncateString truncates a string to a maximum length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// VerifySignature verifies an HMAC signature.
func VerifySignature(body []byte, signature string, secret string, algorithm string) bool {
	var mac hash.Hash
	switch strings.ToLower(algorithm) {
	case "sha384":
		mac = hmac.New(sha512.New384, []byte(secret))
	case "sha512":
		mac = hmac.New(sha512.New, []byte(secret))
	default:
		mac = hmac.New(sha256.New, []byte(secret))
	}

	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSig := hex.EncodeToString(expectedMAC)

	// Remove prefix if present
	sig := signature
	if idx := strings.Index(signature, "="); idx >= 0 {
		sig = signature[idx+1:]
	}

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// ============================================================================
// Request Builder
// ============================================================================

// RequestBuilder provides a fluent interface for building webhook requests.
type RequestBuilder struct {
	config  *WebhookConfig
	payload *WebhookPayload
}

// NewRequestBuilder creates a new request builder.
func NewRequestBuilder(config *WebhookConfig) *RequestBuilder {
	return &RequestBuilder{
		config: config,
		payload: &WebhookPayload{
			ID:        generateID(),
			Timestamp: time.Now(),
			WebhookID: config.ID,
			Data:      make(map[string]interface{}),
			Metadata:  make(map[string]string),
		},
	}
}

// WithEventType sets the event type.
func (b *RequestBuilder) WithEventType(eventType string) *RequestBuilder {
	b.payload.EventType = eventType
	return b
}

// WithSeverity sets the severity.
func (b *RequestBuilder) WithSeverity(severity siem.Severity) *RequestBuilder {
	b.payload.Severity = severity
	return b
}

// WithCategory sets the category.
func (b *RequestBuilder) WithCategory(category siem.EventCategory) *RequestBuilder {
	b.payload.Category = category
	return b
}

// WithSource sets the source.
func (b *RequestBuilder) WithSource(source string) *RequestBuilder {
	b.payload.Source = source
	return b
}

// WithMessage sets the message.
func (b *RequestBuilder) WithMessage(message string) *RequestBuilder {
	b.payload.Message = message
	return b
}

// WithEvent sets the SIEM event.
func (b *RequestBuilder) WithEvent(event *siem.Event) *RequestBuilder {
	b.payload.Event = event
	return b
}

// WithData adds data to the payload.
func (b *RequestBuilder) WithData(key string, value interface{}) *RequestBuilder {
	b.payload.Data[key] = value
	return b
}

// WithMetadata adds metadata to the payload.
func (b *RequestBuilder) WithMetadata(key, value string) *RequestBuilder {
	b.payload.Metadata[key] = value
	return b
}

// Build returns the configured payload.
func (b *RequestBuilder) Build() *WebhookPayload {
	return b.payload
}

// ============================================================================
// Delivery Status Tracker
// ============================================================================

// StatusTracker tracks delivery status for webhooks.
type StatusTracker struct {
	mu       sync.RWMutex
	statuses map[string]*DeliveryStatus
	maxSize  int
}

// NewStatusTracker creates a new status tracker.
func NewStatusTracker(maxSize int) *StatusTracker {
	return &StatusTracker{
		statuses: make(map[string]*DeliveryStatus),
		maxSize:  maxSize,
	}
}

// Record records a delivery attempt.
func (t *StatusTracker) Record(webhookID string, attempt DeliveryAttempt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	status, exists := t.statuses[webhookID]
	if !exists {
		status = &DeliveryStatus{
			WebhookID: webhookID,
			Status:    StatusPending,
			CreatedAt: time.Now(),
		}
		t.statuses[webhookID] = status
	}

	status.Attempts = append(status.Attempts, attempt)
	status.TotalAttempts = len(status.Attempts)
	status.LastAttempt = attempt.Timestamp

	// Update status
	if attempt.Success {
		status.Status = StatusDelivered
		status.LastSuccess = attempt.Timestamp
	} else if attempt.RetryPending {
		status.Status = StatusRetrying
	} else {
		status.Status = StatusFailed
	}

	// Trim history if needed
	if t.maxSize > 0 && len(status.Attempts) > t.maxSize {
		status.Attempts = status.Attempts[len(status.Attempts)-t.maxSize:]
	}
}

// Get retrieves the delivery status for a webhook.
func (t *StatusTracker) Get(webhookID string) (*DeliveryStatus, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	status, exists := t.statuses[webhookID]
	return status, exists
}

// GetAll retrieves all delivery statuses.
func (t *StatusTracker) GetAll() map[string]*DeliveryStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]*DeliveryStatus, len(t.statuses))
	for k, v := range t.statuses {
		result[k] = v
	}
	return result
}

// Clear clears the status history for a webhook.
func (t *StatusTracker) Clear(webhookID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.statuses, webhookID)
}
