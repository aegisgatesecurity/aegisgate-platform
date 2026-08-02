// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — Configuration
// =========================================================================
//
// config.go defines the Config struct, functional option helpers, and the
// DefaultConfig constructor used by NewClient and NewClientFromEnv.
// =========================================================================

package aegisgate

import (
	"crypto/tls"
	"net/http"
	"time"
)

// DefaultBaseURL is the default AegisGate platform endpoint.
const DefaultBaseURL = "http://localhost:8080"

// DefaultTimeout is the default HTTP request timeout.
const DefaultTimeout = 30 * time.Second

// DefaultMaxRetries is the default number of retry attempts for transient
// failures (5xx and network errors).
const DefaultMaxRetries = 3

// Config holds all configuration for an AegisGate client.
type Config struct {
	// BaseURL is the root URL of the AegisGate platform (required).
	BaseURL string

	// APIKey authenticates requests via the X-API-Key header.
	// Lower precedence than Token.
	APIKey string

	// Token authenticates requests via the Authorization: Bearer header.
	// Takes precedence over APIKey when both are set.
	Token string

	// Timeout is the HTTP client request timeout. Defaults to 30s.
	Timeout time.Duration

	// MaxRetries controls how many times transient failures are retried.
	MaxRetries int

	// HTTPClient is an optional pre-configured *http.Client. When set, the
	// SDK uses this client directly and ignores Timeout and TLSConfig.
	HTTPClient *http.Client

	// TLSConfig is applied to the default transport when HTTPClient is nil.
	TLSConfig *tls.Config
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		BaseURL:    DefaultBaseURL,
		Timeout:    DefaultTimeout,
		MaxRetries: DefaultMaxRetries,
	}
}

// Option is a functional option that mutates a Config.
type Option func(*Config)

// WithBaseURL sets the platform base URL.
func WithBaseURL(url string) Option {
	return func(cfg *Config) { cfg.BaseURL = url }
}

// WithAPIKey sets the API key for X-API-Key authentication.
func WithAPIKey(key string) Option {
	return func(cfg *Config) { cfg.APIKey = key }
}

// WithToken sets the bearer token for Authorization header authentication.
func WithToken(token string) Option {
	return func(cfg *Config) { cfg.Token = token }
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) Option {
	return func(cfg *Config) { cfg.Timeout = d }
}

// WithMaxRetries sets the maximum number of retry attempts.
func WithMaxRetries(n int) Option {
	return func(cfg *Config) { cfg.MaxRetries = n }
}

// WithHTTPClient sets a pre-configured HTTP client. When provided, Timeout
// and TLSConfig on the Config are ignored.
func WithHTTPClient(hc *http.Client) Option {
	return func(cfg *Config) { cfg.HTTPClient = hc }
}

// WithTLS sets the TLS configuration on the default transport.
func WithTLS(tlsCfg *tls.Config) Option {
	return func(cfg *Config) { cfg.TLSConfig = tlsCfg }
}

// NewConfig creates a Config from functional options, starting from defaults.
func NewConfig(opts ...Option) *Config {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
