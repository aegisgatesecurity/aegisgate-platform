// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Configuration
// =========================================================================
//
// config.go reads runtime configuration from environment variables.
// We deliberately use os.Getenv (and a hand-written parser) rather
// than a third-party config library (viper, koanf, etc.) to honor
// the Platform's stdlib-or-first-party-only constraint.
//
// All fields have safe defaults. The backend runs with no
// configuration at all (zero-config, like the rest of the Platform)
// using the Community-tier defaults.
//
// Environment variables:
//
//   LENS_PORT                    TCP port to listen on (default 9090)
//   LENS_TLS_CERT                Path to PEM-encoded TLS certificate
//                                (default: empty, meaning HTTP not started)
//   LENS_TLS_KEY                 Path to PEM-encoded TLS private key
//   LENS_BEARER_TOKEN            Required bearer token for the 4 endpoints
//                                (default: empty, meaning /healthz is open
//                                and the other endpoints return 503)
//   LENS_EVENT_RETENTION_DAYS    How long to retain raw events (default 90)
//   LENS_IOC_STORE_PATH          Directory for the IOC store (default /var/lib/aegisgate/lens)
//   LENS_RATE_LIMIT_PER_MIN      Server-side events/min cap (default 10000)
//   LENS_HMAC_KEY                Path to a 32-byte HMAC key file used to
//                                derive per-installation rate-limit tokens
//                                (default: empty, meaning rate limiting
//                                uses IP address only)
//   LENS_LOG_PATH                Path to the structured log file
//                                (default: stdout)
//   LENS_PUBLIC_URL              The public URL the Lens extension uses
//                                to reach this backend (used in CORS
//                                allowlist; default: empty, meaning
//                                the Access-Control-Allow-Origin header
//                                is not set)
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the runtime configuration for the Lens backend.
// All fields are populated from environment variables by LoadConfig.
type Config struct {
	// Port is the TCP port the HTTP(S) server listens on.
	Port int

	// TLSCert is the path to the PEM-encoded TLS certificate.
	// If empty, the server does not start TLS.
	TLSCert string

	// TLSKey is the path to the PEM-encoded TLS private key.
	TLSKey string

	// BearerToken is the shared secret the Lens extension includes
	// in the Authorization: Bearer header. If empty, only /healthz
	// is reachable; the other endpoints return 503.
	BearerToken string

	// EventRetention is how long raw events are retained before
	// being purged by retention.go. Defaults to 90 days.
	EventRetention time.Duration

	// IOCStorePath is the on-disk location of the IOC store.
	// Defaults to /var/lib/aegisgate/lens. The directory is
	// created on startup if it does not exist.
	IOCStorePath string

	// RateLimitPerMin is the server-side cap on events per
	// minute across all installations. Defaults to 10000.
	RateLimitPerMin int

	// HMACKeyPath is the path to a 32-byte HMAC key file used
	// to derive per-installation rate-limit tokens. If empty,
	// the rate limiter keys on client IP only.
	HMACKeyPath string

	// LogPath is the path to the structured log file. If empty,
	// logs go to stdout.
	LogPath string

	// PublicURL is the public URL the Lens extension uses to
	// reach this backend. Used in the CORS allowlist. If empty,
	// the Access-Control-Allow-Origin header is not set (the
	// server is same-origin only).
	PublicURL string
}

// LoadConfig reads the configuration from environment variables.
// Returns a Config with safe defaults applied to any field that
// is not set in the environment. Returns an error only if a value
// is present but malformed (e.g., LENS_PORT="abc").
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:            9090,
		EventRetention:  90 * 24 * time.Hour,
		IOCStorePath:    "/var/lib/aegisgate/lens",
		RateLimitPerMin: 10000,
	}

	if v := os.Getenv("LENS_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("LENS_PORT must be an integer: %w", err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("LENS_PORT must be 1..65535, got %d", p)
		}
		cfg.Port = p
	}

	if v := os.Getenv("LENS_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("LENS_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("LENS_BEARER_TOKEN"); v != "" {
		cfg.BearerToken = v
	}
	if v := os.Getenv("LENS_IOC_STORE_PATH"); v != "" {
		cfg.IOCStorePath = v
	}
	if v := os.Getenv("LENS_HMAC_KEY"); v != "" {
		cfg.HMACKeyPath = v
	}
	if v := os.Getenv("LENS_LOG_PATH"); v != "" {
		cfg.LogPath = v
	}
	if v := os.Getenv("LENS_PUBLIC_URL"); v != "" {
		cfg.PublicURL = v
	}

	if v := os.Getenv("LENS_EVENT_RETENTION_DAYS"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("LENS_EVENT_RETENTION_DAYS must be an integer: %w", err)
		}
		if d < 1 || d > 3650 {
			return nil, fmt.Errorf("LENS_EVENT_RETENTION_DAYS must be 1..3650, got %d", d)
		}
		cfg.EventRetention = time.Duration(d) * 24 * time.Hour
	}

	if v := os.Getenv("LENS_RATE_LIMIT_PER_MIN"); v != "" {
		r, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("LENS_RATE_LIMIT_PER_MIN must be an integer: %w", err)
		}
		if r < 1 || r > 10_000_000 {
			return nil, fmt.Errorf("LENS_RATE_LIMIT_PER_MIN must be 1..10000000, got %d", r)
		}
		cfg.RateLimitPerMin = r
	}

	return cfg, nil
}
