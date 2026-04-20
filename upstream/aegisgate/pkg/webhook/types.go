// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package webhook provides webhook alerting functionality for the AegisGate AI
// Security Gateway. It supports configurable webhooks with retry logic,
// authentication, event filtering, and delivery tracking.
//
// Features:
//   - Multiple authentication methods (Basic, Bearer, API Key, HMAC)
//   - Configurable retry with exponential backoff
//   - Event filtering by severity, category, and source
//   - HMAC signature generation for payload integrity
//   - TLS/SSL support with certificate verification
//   - Delivery status tracking and history
//   - Batch delivery support
//   - Concurrent webhook delivery with worker pools
package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// ============================================================================
// Authentication Types
// ============================================================================

// AuthenticationType represents the type of authentication for a webhook.
type AuthenticationType string

const (
	AuthNone   AuthenticationType = "none"    // No authentication
	AuthBasic  AuthenticationType = "basic"   // HTTP Basic authentication
	AuthBearer AuthenticationType = "bearer"  // Bearer token authentication
	AuthAPIKey AuthenticationType = "api_key" // API key authentication
	AuthHMAC   AuthenticationType = "hmac"    // HMAC signature authentication
	AuthOAuth2 AuthenticationType = "oauth2"  // OAuth2 authentication
)

// Authentication contains authentication settings for a webhook.
type Authentication struct {
	// Type of authentication
	Type AuthenticationType `json:"type"`
	// Username for basic auth
	Username string `json:"username,omitempty"`
	// Password for basic auth
	Password string `json:"password,omitempty"`
	// Token for bearer auth
	Token string `json:"token,omitempty"`
	// API key for api_key auth
	APIKey string `json:"api_key,omitempty"`
	// Header name for API key (default: X-API-Key)
	APIKeyHeader string `json:"api_key_header,omitempty"`
	// HMAC configuration for hmac auth
	HMAC *HMACConfig `json:"hmac,omitempty"`
	// OAuth2 configuration
	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`
}

// HMACConfig contains HMAC signature settings.
type HMACConfig struct {
	// Secret key for signing
	Secret string `json:"secret"`
	// Algorithm (sha256, sha384, sha512)
	Algorithm string `json:"algorithm"`
	// Header name for signature (default: X-Signature)
	Header string `json:"header"`
	// Include timestamp in signature
	IncludeTimestamp bool `json:"include_timestamp"`
	// Timestamp header name (default: X-Timestamp)
	TimestampHeader string `json:"timestamp_header"`
	// Signature prefix (e.g., "sha256=")
	SignaturePrefix string `json:"signature_prefix"`
}

// OAuth2Config contains OAuth2 client credentials flow settings.
type OAuth2Config struct {
	// Token endpoint URL
	TokenURL string `json:"token_url"`
	// Client ID
	ClientID string `json:"client_id"`
	// Client secret
	ClientSecret string `json:"client_secret"`
	// OAuth scopes
	Scopes []string `json:"scopes,omitempty"`
	// Cached access token
	AccessToken string `json:"-"`
	// Token expiration
	TokenExpiry time.Time `json:"-"`
}

// ============================================================================
// TLS Configuration
// ============================================================================

// TLSConfig contains TLS settings for webhook connections.
type TLSConfig struct {
	// Enable TLS (default: true for HTTPS URLs)
	Enabled bool `json:"enabled"`
	// Skip certificate verification (insecure)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// CA certificate file path
	CAFile string `json:"ca_file,omitempty"`
	// CA certificate PEM data
	CAData []byte `json:"ca_data,omitempty"`
	// Client certificate file path
	CertFile string `json:"cert_file,omitempty"`
	// Client certificate PEM data
	CertData []byte `json:"cert_data,omitempty"`
	// Client key file path
	KeyFile string `json:"key_file,omitempty"`
	// Client key PEM data
	KeyData []byte `json:"key_data,omitempty"`
	// Server name for SNI
	ServerName string `json:"server_name,omitempty"`
	// Minimum TLS version (1.2, 1.3)
	MinVersion string `json:"min_version,omitempty"`
	// Maximum TLS version
	MaxVersion string `json:"max_version,omitempty"`
	// Cipher suites (nil for default)
	CipherSuites []string `json:"cipher_suites,omitempty"`
}

// ============================================================================
// Retry Configuration
// ============================================================================

// RetryConfig contains retry settings for webhook delivery.
type RetryConfig struct {
	// Enable retry on failure
	Enabled bool `json:"enabled"`
	// Maximum retry attempts
	MaxAttempts int `json:"max_attempts"`
	// Initial backoff duration
	InitialBackoff time.Duration `json:"initial_backoff"`
	// Maximum backoff duration
	MaxBackoff time.Duration `json:"max_backoff"`
	// Backoff multiplier (default: 2.0)
	BackoffMultiplier float64 `json:"backoff_multiplier"`
	// Add jitter to backoff
	Jitter bool `json:"jitter"`
	// Retry on these HTTP status codes
	RetryOnStatusCodes []int `json:"retry_on_status_codes,omitempty"`
	// Retry on network errors
	RetryOnNetworkError bool `json:"retry_on_network_error"`
	// Retry on timeout
	RetryOnTimeout bool `json:"retry_on_timeout"`
	// Maximum total retry duration
	MaxTotalDuration time.Duration `json:"max_total_duration"`
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Enabled:             true,
		MaxAttempts:         3,
		InitialBackoff:      1 * time.Second,
		MaxBackoff:          30 * time.Second,
		BackoffMultiplier:   2.0,
		Jitter:              true,
		RetryOnStatusCodes:  []int{429, 500, 502, 503, 504},
		RetryOnNetworkError: true,
		RetryOnTimeout:      true,
		MaxTotalDuration:    5 * time.Minute,
	}
}

// ============================================================================
// Webhook Configuration
// ============================================================================

// WebhookConfig contains the complete configuration for a webhook endpoint.
type WebhookConfig struct {
	// Unique identifier for this webhook
	ID string `json:"id"`
	// Human-readable name
	Name string `json:"name"`
	// Description of the webhook
	Description string `json:"description,omitempty"`
	// Webhook endpoint URL
	URL string `json:"url"`
	// HTTP method (POST, PUT, PATCH)
	Method string `json:"method"`
	// Custom headers to include in requests
	Headers map[string]string `json:"headers,omitempty"`
	// Authentication configuration
	Auth Authentication `json:"auth"`
	// TLS configuration
	TLS TLSConfig `json:"tls"`
	// Request timeout
	Timeout time.Duration `json:"timeout"`
	// Retry configuration
	Retry RetryConfig `json:"retry"`
	// Trigger conditions for when to send webhooks
	Triggers []TriggerCondition `json:"triggers,omitempty"`
	// Enable/disable this webhook
	Enabled bool `json:"enabled"`
	// Maximum concurrent deliveries
	MaxConcurrency int `json:"max_concurrency"`
	// Content type for request body
	ContentType string `json:"content_type"`
	// Custom template for payload formatting
	PayloadTemplate string `json:"payload_template,omitempty"`
	// Include full event details in payload
	IncludeEventDetails bool `json:"include_event_details"`
	// Created timestamp
	CreatedAt time.Time `json:"created_at"`
	// Last updated timestamp
	UpdatedAt time.Time `json:"updated_at"`
	// Tags for organization
	Tags []string `json:"tags,omitempty"`
}

// DefaultWebhookConfig returns a webhook configuration with sensible defaults.
func DefaultWebhookConfig() WebhookConfig {
	return WebhookConfig{
		Method:              http.MethodPost,
		Headers:             make(map[string]string),
		Timeout:             30 * time.Second,
		Retry:               DefaultRetryConfig(),
		Enabled:             true,
		MaxConcurrency:      5,
		ContentType:         "application/json",
		IncludeEventDetails: true,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
}

// ============================================================================
// Trigger Conditions
// ============================================================================

// TriggerCondition defines when a webhook should be triggered.
type TriggerCondition struct {
	// Minimum severity level to trigger
	MinSeverity siem.Severity `json:"min_severity,omitempty"`
	// Event categories to trigger on (empty = all)
	Categories []siem.EventCategory `json:"categories,omitempty"`
	// Event sources to trigger on (empty = all)
	Sources []string `json:"sources,omitempty"`
	// Event types to trigger on (empty = all)
	EventTypes []string `json:"event_types,omitempty"`
	// Custom filter expression
	CustomFilter string `json:"custom_filter,omitempty"`
	// Exclude these severities
	ExcludeSeverities []siem.Severity `json:"exclude_severities,omitempty"`
	// Exclude these categories
	ExcludeCategories []siem.EventCategory `json:"exclude_categories,omitempty"`
	// Exclude these sources
	ExcludeSources []string `json:"exclude_sources,omitempty"`
	// Exclude these event types
	ExcludeEventTypes []string `json:"exclude_event_types,omitempty"`
	// Time window for triggering (rate limiting)
	RateLimit *RateLimitConfig `json:"rate_limit,omitempty"`
}

// MatchCondition defines a condition for matching events.
type MatchCondition struct {
	// Field to match against
	Field string `json:"field"`
	// Operator (eq, ne, contains, regex, gt, lt, gte, lte)
	Operator string `json:"operator"`
	// Value to compare
	Value interface{} `json:"value"`
	// Case-sensitive matching
	CaseSensitive bool `json:"case_sensitive"`
}

// RateLimitConfig defines rate limiting for webhook triggers.
type RateLimitConfig struct {
	// Maximum number of triggers per window
	MaxTriggers int `json:"max_triggers"`
	// Time window for rate limiting
	Window time.Duration `json:"window"`
	// Burst allowance
	Burst int `json:"burst"`
}

// ============================================================================
// Webhook Payload
// ============================================================================

// WebhookPayload contains the data sent in a webhook request.
type WebhookPayload struct {
	// Unique identifier for this payload
	ID string `json:"id"`
	// Timestamp when the payload was created
	Timestamp time.Time `json:"timestamp"`
	// Webhook that generated this payload
	WebhookID string `json:"webhook_id"`
	// Event type that triggered this webhook
	EventType string `json:"event_type"`
	// Event severity
	Severity siem.Severity `json:"severity"`
	// Event category
	Category siem.EventCategory `json:"category"`
	// Event source
	Source string `json:"source"`
	// Human-readable message
	Message string `json:"message"`
	// The original event data
	Event *siem.Event `json:"event,omitempty"`
	// Custom data payload
	Data map[string]interface{} `json:"data,omitempty"`
	// HMAC signature (if configured)
	Signature string `json:"signature,omitempty"`
	// Signature timestamp
	SignatureTimestamp time.Time `json:"signature_timestamp,omitempty"`
	// Additional metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ============================================================================
// Delivery Status
// ============================================================================

// WebhookStatus represents the status of a webhook delivery.
type WebhookStatus string

const (
	StatusPending   WebhookStatus = "pending"
	StatusDelivered WebhookStatus = "delivered"
	StatusFailed    WebhookStatus = "failed"
	StatusRetrying  WebhookStatus = "retrying"
	StatusCancelled WebhookStatus = "cancelled"
	StatusTimeout   WebhookStatus = "timeout"
	StatusDisabled  WebhookStatus = "disabled"
)

// DeliveryAttempt represents a single delivery attempt.
type DeliveryAttempt struct {
	// Attempt number
	Attempt int `json:"attempt"`
	// Timestamp of the attempt
	Timestamp time.Time `json:"timestamp"`
	// HTTP status code received
	StatusCode int `json:"status_code,omitempty"`
	// Response body (truncated if too long)
	ResponseBody string `json:"response_body,omitempty"`
	// Response headers
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	// Error message if failed
	Error string `json:"error,omitempty"`
	// Duration of the attempt
	Duration time.Duration `json:"duration"`
	// Whether this was the final successful attempt
	Success bool `json:"success"`
	// Whether a retry is pending
	RetryPending bool `json:"retry_pending"`
	// Next retry time if retry pending
	NextRetry time.Time `json:"next_retry,omitempty"`
}

// DeliveryStatus tracks the delivery status of a webhook.
type DeliveryStatus struct {
	// Webhook ID
	WebhookID string `json:"webhook_id"`
	// Payload ID
	PayloadID string `json:"payload_id"`
	// Current status
	Status WebhookStatus `json:"status"`
	// All delivery attempts
	Attempts []DeliveryAttempt `json:"attempts"`
	// Total attempts made
	TotalAttempts int `json:"total_attempts"`
	// Last attempt timestamp
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	// Last successful delivery
	LastSuccess time.Time `json:"last_success,omitempty"`
	// Created timestamp
	CreatedAt time.Time `json:"created_at"`
	// Final response (after success or max retries)
	FinalResponse *DeliveryResponse `json:"final_response,omitempty"`
}

// DeliveryResponse contains the final response details.
type DeliveryResponse struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// ============================================================================
// Webhook Statistics
// ============================================================================

// WebhookStats contains statistics for a webhook.
type WebhookStats struct {
	// Total deliveries attempted
	TotalDeliveries int64 `json:"total_deliveries"`
	// Successful deliveries
	SuccessCount int64 `json:"success_count"`
	// Failed deliveries
	FailureCount int64 `json:"failure_count"`
	// Currently pending deliveries
	PendingCount int64 `json:"pending_count"`
	// Average delivery time
	AvgDeliveryTime time.Duration `json:"avg_delivery_time"`
	// Last successful delivery
	LastSuccess time.Time `json:"last_success,omitempty"`
	// Last failed delivery
	LastFailure time.Time `json:"last_failure,omitempty"`
	// Consecutive failures
	ConsecutiveFailures int `json:"consecutive_failures"`
	// Last error message
	LastError string `json:"last_error,omitempty"`
	// Events sent (events delivered)
	EventsSent int64 `json:"events_sent"`
	// Events dropped (due to filtering or errors)
	EventsDropped int64 `json:"events_dropped"`
}

// ManagerStats contains statistics for the webhook manager.
type ManagerStats struct {
	mu sync.RWMutex

	// Total webhooks registered
	TotalWebhooks int `json:"total_webhooks"`
	// Enabled webhooks
	EnabledWebhooks int `json:"enabled_webhooks"`
	// Total deliveries across all webhooks
	TotalDeliveries int64 `json:"total_deliveries"`
	// Successful deliveries
	SuccessCount int64 `json:"success_count"`
	// Failed deliveries
	FailureCount int64 `json:"failure_count"`
	// Events filtered out
	EventsFiltered int64 `json:"events_filtered"`
	// Per-webhook statistics
	WebhookStats map[string]*WebhookStats `json:"webhook_stats"`
}

// ============================================================================
// Error Types
// ============================================================================

// Error represents a webhook delivery error.
type Error struct {
	WebhookID string    `json:"webhook_id"`
	Operation string    `json:"operation"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
	Cause     error     `json:"cause,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return "webhook[" + e.WebhookID + "] " + e.Operation + ": " + e.Message + ": " + e.Cause.Error()
	}
	return "webhook[" + e.WebhookID + "] " + e.Operation + ": " + e.Message
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new webhook error.
func NewError(webhookID, operation, message string, retryable bool, cause error) *Error {
	return &Error{
		WebhookID: webhookID,
		Operation: operation,
		Message:   message,
		Retryable: retryable,
		Cause:     cause,
		Timestamp: time.Now(),
	}
}

// ============================================================================
// HTTP Client Configuration
// ============================================================================

// HTTPClientConfig contains HTTP client settings.
type HTTPClientConfig struct {
	// TLS configuration
	TLS *TLSConfig
	// Request timeout
	Timeout time.Duration
	// Maximum idle connections
	MaxIdleConns int
	// Maximum idle connections per host
	MaxIdleConnsPerHost int
	// Idle connection timeout
	IdleConnTimeout time.Duration
	// Response header timeout
	ResponseHeaderTimeout time.Duration
	// Expect continue timeout
	ExpectContinueTimeout time.Duration
	// Disable keep-alive
	DisableKeepAlives bool
	// Disable compression
	DisableCompression bool
}

// DefaultHTTPClientConfig returns default HTTP client configuration.
func DefaultHTTPClientConfig() *HTTPClientConfig {
	return &HTTPClientConfig{
		Timeout:               30 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// BuildTLSConfig builds a crypto/tls.Config from TLSConfig.
func (t *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	if !t.Enabled {
		return nil, nil
	}

	config := &tls.Config{
		InsecureSkipVerify: t.InsecureSkipVerify,
		ServerName:         t.ServerName,
	}

	// Set minimum version
	if t.MinVersion != "" {
		switch t.MinVersion {
		case "1.2":
			config.MinVersion = tls.VersionTLS12
		case "1.3":
			config.MinVersion = tls.VersionTLS13
		}
	}

	// Set maximum version
	if t.MaxVersion != "" {
		switch t.MaxVersion {
		case "1.2":
			config.MaxVersion = tls.VersionTLS12
		case "1.3":
			config.MaxVersion = tls.VersionTLS13
		}
	}

	// Load CA certificate
	if t.CAFile != "" || len(t.CAData) > 0 {
		caCertPool := x509.NewCertPool()
		if t.CAFile != "" {
			caCert, err := os.ReadFile(t.CAFile)
			if err != nil {
				return nil, NewError("", "tls", "failed to read CA certificate", false, err)
			}
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, NewError("", "tls", "failed to parse CA certificate", false, nil)
			}
		} else if len(t.CAData) > 0 {
			if !caCertPool.AppendCertsFromPEM(t.CAData) {
				return nil, NewError("", "tls", "failed to parse CA certificate data", false, nil)
			}
		}
		config.RootCAs = caCertPool
	}

	// Load client certificate
	if t.CertFile != "" || len(t.CertData) > 0 {
		var cert tls.Certificate
		var err error
		if t.CertFile != "" {
			if t.KeyFile == "" {
				return nil, NewError("", "tls", "key file required with cert file", false, nil)
			}
			cert, err = tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		} else {
			if len(t.KeyData) == 0 {
				return nil, NewError("", "tls", "key data required with cert data", false, nil)
			}
			cert, err = tls.X509KeyPair(t.CertData, t.KeyData)
		}
		if err != nil {
			return nil, NewError("", "tls", "failed to load client certificate", false, err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

// ============================================================================
// Batch Delivery
// ============================================================================

// BatchDeliveryConfig contains settings for batch delivery.
type BatchDeliveryConfig struct {
	// Enable batch delivery
	Enabled bool `json:"enabled"`
	// Maximum batch size (number of events)
	MaxSize int `json:"max_size"`
	// Maximum batch wait time
	MaxWait time.Duration `json:"max_wait"`
	// Maximum batch size in bytes
	MaxBytes int `json:"max_bytes"`
	// Batch events by webhook
	BatchByWebhook bool `json:"batch_by_webhook"`
}

// DefaultBatchDeliveryConfig returns default batch delivery configuration.
func DefaultBatchDeliveryConfig() BatchDeliveryConfig {
	return BatchDeliveryConfig{
		Enabled:        true,
		MaxSize:        100,
		MaxWait:        5 * time.Second,
		MaxBytes:       1048576, // 1MB
		BatchByWebhook: true,
	}
}

// BatchPayload contains multiple events in a single payload.
type BatchPayload struct {
	// Batch ID
	ID string `json:"id"`
	// Timestamp
	Timestamp time.Time `json:"timestamp"`
	// Webhook ID
	WebhookID string `json:"webhook_id"`
	// Events in this batch
	Events []*WebhookPayload `json:"events"`
	// Batch size in bytes
	Size int `json:"size"`
	// Signature for the batch
	Signature string `json:"signature,omitempty"`
}

// ============================================================================
// Worker Pool
// ============================================================================

// WorkerPoolConfig contains settings for the worker pool.
type WorkerPoolConfig struct {
	// Number of workers
	Workers int `json:"workers"`
	// Queue size for pending deliveries
	QueueSize int `json:"queue_size"`
	// Shutdown timeout
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
}

// DefaultWorkerPoolConfig returns default worker pool configuration.
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	return WorkerPoolConfig{
		Workers:         10,
		QueueSize:       1000,
		ShutdownTimeout: 30 * time.Second,
	}
}
