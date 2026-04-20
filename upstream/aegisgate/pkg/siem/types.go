// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package siem provides Security Information and Event Management integration
// for the AegisGate AI Security Gateway. It supports multiple SIEM platforms
// including Splunk, Elasticsearch, QRadar, Sentinel, and more.
//
// Features:
//   - Multiple output formats (CEF, LEEF, JSON, Syslog)
//   - Push and pull integration modes
//   - Event buffering and batching
//   - Retry with exponential backoff
//   - TLS/SSL support
//   - OAuth2 and API key authentication
//   - Real-time event streaming
//   - Audit log compliance
package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Core Types
// ============================================================================

// Platform represents a SIEM platform type.
type Platform string

const (
	PlatformSplunk        Platform = "splunk"
	PlatformElasticsearch Platform = "elasticsearch"
	PlatformQRadar        Platform = "qradar"
	PlatformSentinel      Platform = "sentinel"
	PlatformSumoLogic     Platform = "sumologic"
	PlatformLogRhythm     Platform = "logrhythm"
	PlatformCloudWatch    Platform = "cloudwatch"
	PlatformSecurityHub   Platform = "securityhub"
	PlatformArcSight      Platform = "arcsight"
	PlatformSyslog        Platform = "syslog"
	PlatformCustom        Platform = "custom"
)

// Format represents the log output format.
type Format string

const (
	FormatJSON   Format = "json"
	FormatCEF    Format = "cef"    // Common Event Format (ArcSight)
	FormatLEEF   Format = "leef"   // Log Event Extended Format (QRadar)
	FormatSyslog Format = "syslog" // RFC 5424
	FormatCSV    Format = "csv"
)

// Severity maps to common SIEM severity levels.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// EventCategory classifies security events.
type EventCategory string

const (
	CategoryAuthentication EventCategory = "authentication"
	CategoryAuthorization  EventCategory = "authorization"
	CategoryAccess         EventCategory = "access"
	CategoryThreat         EventCategory = "threat"
	CategoryVulnerability  EventCategory = "vulnerability"
	CategoryCompliance     EventCategory = "compliance"
	CategoryAudit          EventCategory = "audit"
	CategoryNetwork        EventCategory = "network"
	CategoryApplication    EventCategory = "application"
	CategoryDataLoss       EventCategory = "data_loss"
	CategoryMalware        EventCategory = "malware"
	CategoryPolicy         EventCategory = "policy"
)

// Event represents a security event to be sent to a SIEM.
type Event struct {
	// Unique identifier for this event
	ID string `json:"id"`
	// Timestamp when the event occurred
	Timestamp time.Time `json:"timestamp"`
	// Platform that generated the event
	Source string `json:"source"`
	// Event category
	Category EventCategory `json:"category"`
	// Event type (e.g., "blocked_request", "authentication_failure")
	Type string `json:"type"`
	// Action taken (block, allow, drop, throttle, etc.) - for RFC 5424
	Action string `json:"action,omitempty"`
	// Severity level
	Severity Severity `json:"severity"`
	// Human-readable message
	Message string `json:"message"`
	// Source IP address - for RFC 5424
	SourceIP string `json:"sourceIP,omitempty"`
	// Destination address - for RFC 5424
	Destination string `json:"destination,omitempty"`
	// User identifier - for RFC 5424
	User string `json:"user,omitempty"`
	// Client ID - for RFC 5424
	ClientID string `json:"clientID,omitempty"`
	// Threat type - for RFC 5424
	ThreatType string `json:"threatType,omitempty"`
	// Threat level - for RFC 5424
	ThreatLevel string `json:"threatLevel,omitempty"`
	// Pattern matched - for RFC 5424
	Pattern string `json:"pattern,omitempty"`
	// Raw event data
	Raw map[string]interface{} `json:"raw,omitempty"`
	// Additional attributes
	Attributes map[string]string `json:"attributes,omitempty"`
	// Related entities (users, IPs, hosts)
	Entities []Entity `json:"entities,omitempty"`
	// MITRE ATT&CK mapping
	MITRE *MITREMapping `json:"mitre,omitempty"`
	// Compliance framework mapping
	Compliance []ComplianceMapping `json:"compliance,omitempty"`
	// Compliance framework name - for RFC 5424
	ComplianceFramework string `json:"complianceFramework,omitempty"`
	// Compliance control ID - for RFC 5424
	ComplianceControl string `json:"complianceControl,omitempty"`
}

// Entity represents a related entity in an event.
type Entity struct {
	Type  string `json:"type"` // user, host, ip, application, etc.
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// MITREMapping maps events to MITRE ATT&CK framework.
type MITREMapping struct {
	Tactic       string   `json:"tactic,omitempty"`
	Technique    string   `json:"technique,omitempty"`
	SubTechnique string   `json:"sub_technique,omitempty"`
	Tactics      []string `json:"tactics,omitempty"`
	Techniques   []string `json:"techniques,omitempty"`
}

// ComplianceMapping maps events to compliance frameworks.
type ComplianceMapping struct {
	Framework string `json:"framework"` // SOC2, PCI-DSS, HIPAA, NIST, etc.
	Control   string `json:"control"`
	Section   string `json:"section,omitempty"`
}

// ============================================================================
// Configuration
// ============================================================================

// Config contains SIEM integration configuration.
type Config struct {
	// Enabled platforms
	Platforms []PlatformConfig `json:"platforms"`
	// Global settings
	Global GlobalConfig `json:"global"`
	// Event filtering
	Filter FilterConfig `json:"filter"`
	// Buffering settings
	Buffer BufferConfig `json:"buffer"`
}

// PlatformConfig contains platform-specific configuration.
type PlatformConfig struct {
	// Platform type
	Platform Platform `json:"platform"`
	// Enable/disable this platform
	Enabled bool `json:"enabled"`
	// Output format
	Format Format `json:"format"`
	// Endpoint URL (for HTTP-based platforms)
	Endpoint string `json:"endpoint,omitempty"`
	// Authentication configuration
	Auth AuthConfig `json:"auth"`
	// TLS configuration
	TLS TLSConfig `json:"tls"`
	// Platform-specific settings
	Settings map[string]interface{} `json:"settings,omitempty"`
	// Retry configuration
	Retry RetryConfig `json:"retry"`
	// Batch configuration
	Batch BatchConfig `json:"batch"`
}

// AuthConfig contains authentication settings.
type AuthConfig struct {
	// Authentication type: api_key, oauth2, basic, certificate
	Type string `json:"type"`
	// API key (for api_key auth)
	APIKey string `json:"api_key,omitempty"`
	// API key header name
	APIKeyHeader string `json:"api_key_header,omitempty"`
	// Username (for basic auth)
	Username string `json:"username,omitempty"`
	// Password (for basic auth)
	Password string `json:"password,omitempty"`
	// OAuth2 token URL
	TokenURL string `json:"token_url,omitempty"`
	// OAuth2 client ID
	ClientID string `json:"client_id,omitempty"`
	// OAuth2 client secret
	ClientSecret string `json:"client_secret,omitempty"`
	// OAuth2 scopes
	Scopes []string `json:"scopes,omitempty"`
	// Certificate file path (for certificate auth)
	CertFile string `json:"cert_file,omitempty"`
	// Key file path (for certificate auth)
	KeyFile string `json:"key_file,omitempty"`
}

// TLSConfig contains TLS settings.
type TLSConfig struct {
	// Enable TLS
	Enabled bool `json:"enabled"`
	// Skip certificate verification (insecure)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// CA certificate file
	CAFile string `json:"ca_file,omitempty"`
	// Server name for SNI
	ServerName string `json:"server_name,omitempty"`
	// Minimum TLS version
	MinVersion string `json:"min_version,omitempty"`
}

// RetryConfig contains retry settings.
type RetryConfig struct {
	// Enable retries
	Enabled bool `json:"enabled"`
	// Maximum retry attempts
	MaxAttempts int `json:"max_attempts"`
	// Initial backoff duration
	InitialBackoff time.Duration `json:"initial_backoff"`
	// Maximum backoff duration
	MaxBackoff time.Duration `json:"max_backoff"`
	// Backoff multiplier
	BackoffMultiplier float64 `json:"backoff_multiplier"`
	// Retry on these HTTP status codes
	RetryOnStatusCodes []int `json:"retry_on_status_codes,omitempty"`
}

// BatchConfig contains batching settings.
type BatchConfig struct {
	// Enable batching
	Enabled bool `json:"enabled"`
	// Maximum batch size (events)
	MaxSize int `json:"max_size"`
	// Maximum batch wait time
	MaxWait time.Duration `json:"max_wait"`
	// Maximum batch size in bytes
	MaxBytes int `json:"max_bytes,omitempty"`
}

// GlobalConfig contains global SIEM settings.
type GlobalConfig struct {
	// Application name/identifier
	AppName string `json:"app_name"`
	// Environment (production, staging, development)
	Environment string `json:"environment"`
	// Default severity for unmapped events
	DefaultSeverity Severity `json:"default_severity"`
	// Include raw event data
	IncludeRaw bool `json:"include_raw"`
	// Add hostname to events
	AddHostname bool `json:"add_hostname"`
	// Hostname override
	Hostname string `json:"hostname,omitempty"`
}

// FilterConfig contains event filtering settings.
type FilterConfig struct {
	// Minimum severity to forward
	MinSeverity Severity `json:"min_severity"`
	// Include these categories only
	IncludeCategories []EventCategory `json:"include_categories,omitempty"`
	// Exclude these categories
	ExcludeCategories []EventCategory `json:"exclude_categories,omitempty"`
	// Include these event types only
	IncludeTypes []string `json:"include_types,omitempty"`
	// Exclude these event types
	ExcludeTypes []string `json:"exclude_types,omitempty"`
	// Custom filter expression
	CustomFilter string `json:"custom_filter,omitempty"`
}

// BufferConfig contains event buffering settings.
type BufferConfig struct {
	// Enable buffering
	Enabled bool `json:"enabled"`
	// Maximum buffer size (events)
	MaxSize int `json:"max_size"`
	// Buffer flush interval
	FlushInterval time.Duration `json:"flush_interval"`
	// Persist buffer to disk
	Persist bool `json:"persist"`
	// Persist directory
	PersistDir string `json:"persist_dir,omitempty"`
}

// DefaultConfig returns the default SIEM configuration.
func DefaultConfig() Config {
	return Config{
		Global: GlobalConfig{
			AppName:         "aegisgate",
			Environment:     "production",
			DefaultSeverity: SeverityInfo,
			IncludeRaw:      true,
			AddHostname:     true,
		},
		Filter: FilterConfig{
			MinSeverity: SeverityInfo,
		},
		Buffer: BufferConfig{
			Enabled:       true,
			MaxSize:       10000,
			FlushInterval: 5 * time.Second,
			Persist:       false,
		},
	}
}

// DefaultPlatformConfig returns default configuration for a platform.
func DefaultPlatformConfig(platform Platform) PlatformConfig {
	base := PlatformConfig{
		Platform: platform,
		Enabled:  true,
		Format:   FormatJSON,
		Retry: RetryConfig{
			Enabled:            true,
			MaxAttempts:        3,
			InitialBackoff:     1 * time.Second,
			MaxBackoff:         30 * time.Second,
			BackoffMultiplier:  2.0,
			RetryOnStatusCodes: []int{429, 500, 502, 503, 504},
		},
		Batch: BatchConfig{
			Enabled:  true,
			MaxSize:  100,
			MaxWait:  5 * time.Second,
			MaxBytes: 1048576, // 1MB
		},
		TLS: TLSConfig{
			Enabled: true,
		},
	}

	// Platform-specific defaults
	switch platform {
	case PlatformSplunk:
		base.Format = FormatJSON
		base.Auth.APIKeyHeader = "Authorization"
	case PlatformElasticsearch:
		base.Format = FormatJSON
	case PlatformQRadar:
		base.Format = FormatLEEF
	case PlatformArcSight:
		base.Format = FormatCEF
	case PlatformSyslog:
		base.Format = FormatSyslog
	}

	return base
}

// ============================================================================
// Error Types
// ============================================================================

// Error represents a SIEM integration error.
type Error struct {
	Platform  Platform
	Operation string
	Message   string
	Retryable bool
	Cause     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("siem [%s] %s: %s: %v", e.Platform, e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("siem [%s] %s: %s", e.Platform, e.Operation, e.Message)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new SIEM error.
func NewError(platform Platform, operation, message string, retryable bool, cause error) *Error {
	return &Error{
		Platform:  platform,
		Operation: operation,
		Message:   message,
		Retryable: retryable,
		Cause:     cause,
	}
}

// ============================================================================
// HTTP Client with TLS
// ============================================================================

// HTTPClient wraps http.Client with SIEM-specific configuration.
type HTTPClient struct {
	*http.Client
	platform Platform
}

// NewHTTPClient creates a new HTTP client for SIEM integration.
func NewHTTPClient(platform Platform, tlsConfig TLSConfig) (*HTTPClient, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if tlsConfig.Enabled {
		tlsConf := &tls.Config{
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         tlsConfig.ServerName,
		}

		// Load CA certificate if provided
		if tlsConfig.CAFile != "" {
			caCert, err := os.ReadFile(tlsConfig.CAFile)
			if err != nil {
				return nil, NewError(platform, "tls_config", "failed to load CA certificate", false, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, NewError(platform, "tls_config", "failed to parse CA certificate", false, nil)
			}
			tlsConf.RootCAs = caCertPool
		}

		// Set minimum TLS version
		if tlsConfig.MinVersion != "" {
			switch tlsConfig.MinVersion {
			case "1.2":
				tlsConf.MinVersion = tls.VersionTLS12
			case "1.3":
				tlsConf.MinVersion = tls.VersionTLS13
			}
		}

		transport.TLSClientConfig = tlsConf
	}

	return &HTTPClient{
		Client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		platform: platform,
	}, nil
}

// DoRequest performs an HTTP request with retry logic.
func (c *HTTPClient) DoRequest(ctx context.Context, req *http.Request, retryCfg RetryConfig) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < retryCfg.MaxAttempts || !retryCfg.Enabled; attempt++ {
		if attempt > 0 {
			// Calculate backoff
			backoff := retryCfg.InitialBackoff
			for i := 0; i < attempt-1; i++ {
				backoff = time.Duration(float64(backoff) * retryCfg.BackoffMultiplier)
				if backoff > retryCfg.MaxBackoff {
					backoff = retryCfg.MaxBackoff
					break
				}
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.Client.Do(req.WithContext(ctx))
		if err != nil {
			lastErr = NewError(c.platform, "http_request", "request failed", true, err)
			continue
		}

		// Check if we should retry
		if retryCfg.Enabled && c.shouldRetry(resp.StatusCode, retryCfg.RetryOnStatusCodes) {
			resp.Body.Close()
			lastErr = NewError(c.platform, "http_request", fmt.Sprintf("status code %d", resp.StatusCode), true, nil)
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

// shouldRetry determines if a status code should trigger a retry.
func (c *HTTPClient) shouldRetry(statusCode int, retryCodes []int) bool {
	for _, code := range retryCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// ============================================================================
// Event Buffer
// ============================================================================

// EventBuffer provides event buffering and batching.
type EventBuffer struct {
	mu       sync.RWMutex
	events   []*Event
	maxSize  int
	platform Platform
}

// NewEventBuffer creates a new event buffer.
func NewEventBuffer(platform Platform, maxSize int) *EventBuffer {
	return &EventBuffer{
		events:   make([]*Event, 0, maxSize),
		maxSize:  maxSize,
		platform: platform,
	}
}

// Add adds an event to the buffer.
func (b *EventBuffer) Add(event *Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) >= b.maxSize {
		return NewError(b.platform, "buffer", "buffer full", false, nil)
	}

	b.events = append(b.events, event)
	return nil
}

// AddBatch adds multiple events to the buffer.
func (b *EventBuffer) AddBatch(events []*Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events)+len(events) > b.maxSize {
		return NewError(b.platform, "buffer", "buffer would overflow", false, nil)
	}

	b.events = append(b.events, events...)
	return nil
}

// Flush returns all events and clears the buffer.
func (b *EventBuffer) Flush() []*Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	events := b.events
	b.events = make([]*Event, 0, b.maxSize)
	return events
}

// Size returns the current buffer size.
func (b *EventBuffer) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.events)
}

// IsFull returns true if the buffer is full.
func (b *EventBuffer) IsFull() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.events) >= b.maxSize
}

// ============================================================================
// Event Formatter
// ============================================================================

// Formatter formats events for different SIEM platforms.
type Formatter interface {
	// Format formats a single event
	Format(event *Event) ([]byte, error)
	// FormatBatch formats multiple events
	FormatBatch(events []*Event) ([]byte, error)
	// ContentType returns the content type for the format
	ContentType() string
	// FileExtension returns the file extension for the format
	FileExtension() string
}

// JSONFormatter formats events as JSON.
type JSONFormatter struct {
	platform Platform
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(platform Platform) *JSONFormatter {
	return &JSONFormatter{platform: platform}
}

// Format formats a single event as JSON.
func (f *JSONFormatter) Format(event *Event) ([]byte, error) {
	return json.Marshal(event)
}

// FormatBatch formats multiple events as JSON lines.
func (f *JSONFormatter) FormatBatch(events []*Event) ([]byte, error) {
	var buf strings.Builder
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return nil, NewError(f.platform, "format", "failed to marshal event", false, err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	return []byte(buf.String()), nil
}

// ContentType returns the content type.
func (f *JSONFormatter) ContentType() string {
	return "application/json"
}

// FileExtension returns the file extension.
func (f *JSONFormatter) FileExtension() string {
	return ".json"
}

// ============================================================================
// Reader Utilities
// ============================================================================

// ReadCloser wraps a reader with a closer.
type ReadCloser struct {
	io.Reader
	CloseFunc func() error
}

// Close implements io.Closer.
func (r *ReadCloser) Close() error {
	if r.CloseFunc != nil {
		return r.CloseFunc()
	}
	return nil
}

// NewReadCloser creates a new ReadCloser.
func NewReadCloser(r io.Reader, closeFunc func() error) *ReadCloser {
	return &ReadCloser{
		Reader:    r,
		CloseFunc: closeFunc,
	}
}
