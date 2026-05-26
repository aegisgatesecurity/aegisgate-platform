// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Guard Configuration
// =========================================================================

package acp

import (
	"log/slog"
	"time"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ACPGuardConfig holds configuration for the ACP guard
type ACPGuardConfig struct {
	// Base response guard configuration
	ResponseGuardConfig *responseguard.ResponseGuardConfig

	// ACP-specific settings
	EnableHMAC            bool     `json:"enableHMAC"`
	HMACSecret            string   `json:"hmacSecret,omitempty"`
	EnableRateLimiting    bool     `json:"enableRateLimiting"`
	RateLimitPerMinute    int      `json:"rateLimitPerMinute"`
	RateLimitBurst        int      `json:"rateLimitBurst"`
	EnableCapabilityEnf   bool     `json:"enableCapabilityEnforcement"`
	AllowedCapabilities   []string `json:"allowedCapabilities,omitempty"`
	BlockedMethods        []string `json:"blockedMethods,omitempty"`
	EnableInputValidation bool     `json:"enableInputValidation"`

	// Timeout settings
	ScanTimeout time.Duration `json:"scanTimeout"`
	AuthTimeout time.Duration `json:"authTimeout"`

	// Logger
	Logger *slog.Logger `json:"-"`
}

// DefaultACPGuardConfig returns the default configuration
func DefaultACPGuardConfig() *ACPGuardConfig {
	return &ACPGuardConfig{
		ResponseGuardConfig:   responseguard.DefaultResponseGuardConfig(),
		EnableHMAC:            true,
		EnableRateLimiting:    true,
		RateLimitPerMinute:    60,
		RateLimitBurst:        10,
		EnableCapabilityEnf:   true,
		EnableInputValidation: true,
		ScanTimeout:           5 * time.Second,
		AuthTimeout:           30 * time.Second,
		Logger:                slog.Default().With("component", "acp-guard"),
	}
}

// Validate validates the configuration
func (c *ACPGuardConfig) Validate() error {
	if c.ScanTimeout <= 0 {
		c.ScanTimeout = 5 * time.Second
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 30 * time.Second
	}
	if c.RateLimitPerMinute <= 0 {
		c.RateLimitPerMinute = 60
	}
	if c.RateLimitBurst <= 0 {
		c.RateLimitBurst = 10
	}
	return nil
}
