// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Unified Telemetry Receiver — Configuration

package telemetry

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the runtime configuration for the unified telemetry receiver.
// All fields have safe defaults — the receiver runs with zero configuration.
type Config struct {
	// Port is the TCP port the HTTP server listens on.
	// Default: 9091 (one above lensbackend's 9090 for easy co-location)
	Port int

	// TLSCert is the path to the PEM-encoded TLS certificate.
	// If empty, the server runs plaintext HTTP (for reverse-proxy termination).
	TLSCert string

	// TLSKey is the path to the PEM-encoded TLS private key.
	TLSKey string

	// APIKey is the required bearer token for all endpoints except /healthz.
	// If empty, authenticated endpoints return 503 Service Unavailable.
	// This is the single auth mechanism for ALL products (lens, rampart,
	// scanner, mcp). Each product's config has a platform_api_key field.
	APIKey string

	// EventRetentionDays is how long to retain raw events.
	// Default: 90 (same as lensbackend)
	EventRetentionDays int

	// StorePath is the directory for the event store.
	// Default: /var/lib/aegisgate/telemetry
	StorePath string

	// RateLimitPerMin is the server-side global events/min cap.
	// Default: 10000 (same as lensbackend)
	RateLimitPerMin int

	// HMACKeyPath is the path to a 32-byte HMAC key file used to derive
	// per-installation rate-limit tokens. Default: empty (IP-based rate limiting).
	HMACKeyPath string

	// LogPath is the path to the structured log file.
	// Default: stdout
	LogPath string

	// PatternsVersion is the current version label for the pattern set
	// served by the pull endpoint. Updated when patterns are pushed to Platform.
	PatternsVersion string

	// PatternsUpdatedAt is the RFC3339 timestamp of the last pattern update.
	// Returned in pull endpoint responses for client-side cache decisions.
	PatternsUpdatedAt string
}

// LoadConfig reads configuration from environment variables.
// All variables are prefixed with TELEMETRY_ to avoid collisions with
// LENS_ prefixed variables from lensbackend.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:               getenvInt("TELEMETRY_PORT", 9091),
		TLSCert:            os.Getenv("TELEMETRY_TLS_CERT"),
		TLSKey:             os.Getenv("TELEMETRY_TLS_KEY"),
		APIKey:             os.Getenv("TELEMETRY_API_KEY"),
		EventRetentionDays: getenvInt("TELEMETRY_EVENT_RETENTION_DAYS", 90),
		StorePath:          getenvStr("TELEMETRY_STORE_PATH", "/var/lib/aegisgate/telemetry"),
		RateLimitPerMin:    getenvInt("TELEMETRY_RATE_LIMIT_PER_MIN", 10000),
		HMACKeyPath:        os.Getenv("TELEMETRY_HMAC_KEY"),
		LogPath:            os.Getenv("TELEMETRY_LOG_PATH"),
		PatternsVersion:    getenvStr("TELEMETRY_PATTERNS_VERSION", "v1"),
		PatternsUpdatedAt:  os.Getenv("TELEMETRY_PATTERNS_UPDATED_AT"),
	}
	return cfg, nil
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvStr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// Validate returns an error if the config is invalid.
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if c.EventRetentionDays < 1 {
		return fmt.Errorf("invalid retention days: %d", c.EventRetentionDays)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("TLS cert and key must both be set or both be empty")
	}
	return nil
}
