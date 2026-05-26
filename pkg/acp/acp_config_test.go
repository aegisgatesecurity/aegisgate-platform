// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP Config Tests

package acp

import (
	"testing"
)

func TestValidateConfigDefaults(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.HMACSecret = "valid-secret-key-32-bytes-long!!!!"
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected valid config, got error: %v", err)
	}
}

func TestValidateConfigZeroTimeout(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.ScanTimeout = 0
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected zero timeout to be set to default, got error: %v", err)
	}
	if cfg.ScanTimeout != 5*1e9 { // 5 seconds in nanoseconds
		t.Errorf("Expected ScanTimeout to be 5s, got %v", cfg.ScanTimeout)
	}
}

func TestValidateConfigZeroAuthTimeout(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.AuthTimeout = 0
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected zero auth timeout to be set to default, got error: %v", err)
	}
}

func TestValidateConfigNegativeRateLimit(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.RateLimitPerMinute = -1
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected negative rate limit to be set to default, got error: %v", err)
	}
}

func TestValidateRateLimitDefaults(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.RateLimitPerMinute = 0
	cfg.RateLimitBurst = 0
	cfg.Validate()
	if cfg.RateLimitPerMinute <= 0 || cfg.RateLimitBurst <= 0 {
		t.Error("Expected positive rate limit defaults")
	}
}
