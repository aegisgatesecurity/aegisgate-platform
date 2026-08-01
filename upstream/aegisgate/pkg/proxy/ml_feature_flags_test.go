// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate - ML Threat Detection Feature Flag Wiring Tests
// =========================================================================
//
// Tests that verify:
//   - When MLThreatDetectionEnabled=true, proxy creates ThreatDetector with Enabled=true
//   - When MLShadowMode=false, proxy creates ThreatDetector with ShadowMode=false
//   - Default options leave ThreatDetector disabled (cold-start safety)
//
// =========================================================================

package proxy

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/ml"
)

// TestProxy_MLThreatDetectionDisabledByDefault verifies that the default
// proxy options leave the ThreatDetector disabled (cold-start safety).
func TestProxy_MLThreatDetectionDisabledByDefault(t *testing.T) {
	opts := &Options{
		BindAddress: "127.0.0.1:0",
		Upstream:    "http://127.0.0.1:9999",
		MaxBodySize: 1024,
		Timeout:     5 * time.Second,
		RateLimit:   100,
	}

	p := New(opts)
	if p.threatDetector == nil {
		t.Fatal("threatDetector should not be nil")
	}

	if p.threatDetector.IsEnabled() {
		t.Error("ThreatDetector should be disabled by default (cold-start safety)")
	}

	stats := p.threatDetector.GetStats()
	if stats["enabled"].(bool) {
		t.Error("ThreatDetector Enabled should be false by default")
	}
}

// TestProxy_MLThreatDetectionEnabled verifies that when
// MLThreatDetectionEnabled=true, the ThreatDetector is created with
// Enabled=true.
func TestProxy_MLThreatDetectionEnabled(t *testing.T) {
	opts := &Options{
		BindAddress:              "127.0.0.1:0",
		Upstream:                 "http://127.0.0.1:9999",
		MaxBodySize:              1024,
		Timeout:                  5 * time.Second,
		RateLimit:                100,
		MLThreatDetectionEnabled: true,
		MLShadowMode:             true,
	}

	p := New(opts)
	if p.threatDetector == nil {
		t.Fatal("threatDetector should not be nil")
	}

	if !p.threatDetector.IsEnabled() {
		t.Error("ThreatDetector should be enabled when MLThreatDetectionEnabled=true")
	}

	stats := p.threatDetector.GetStats()
	if !stats["enabled"].(bool) {
		t.Error("ThreatDetector Enabled should be true")
	}
	if !stats["shadow_mode"].(bool) {
		t.Error("ThreatDetector ShadowMode should be true (default)")
	}
}

// TestProxy_MLShadowModeDisabled verifies that when MLShadowMode=false,
// the ThreatDetector is created with ShadowMode=false.
func TestProxy_MLShadowModeDisabled(t *testing.T) {
	opts := &Options{
		BindAddress:              "127.0.0.1:0",
		Upstream:                 "http://127.0.0.1:9999",
		MaxBodySize:              1024,
		Timeout:                  5 * time.Second,
		RateLimit:                100,
		MLThreatDetectionEnabled: true,
		MLShadowMode:             false,
	}

	p := New(opts)
	if p.threatDetector == nil {
		t.Fatal("threatDetector should not be nil")
	}

	stats := p.threatDetector.GetStats()
	if !stats["enabled"].(bool) {
		t.Error("ThreatDetector should be enabled")
	}
	if stats["shadow_mode"].(bool) {
		t.Error("ThreatDetector ShadowMode should be false when MLShadowMode=false")
	}
}

// TestProxy_MLFeatureFlags_ColdStartDefaults verifies that default
// DetectorConfig matches the cold-start safety requirements:
// Enabled=false, ShadowMode=true.
func TestProxy_MLFeatureFlags_ColdStartDefaults(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()

	if cfg.Enabled {
		t.Error("DefaultDetectorConfig.Enabled should be false (cold-start safety)")
	}
	if !cfg.ShadowMode {
		t.Error("DefaultDetectorConfig.ShadowMode should be true (safe deployment)")
	}
}

// TestProxy_MLFeatureFlags_EnabledWithoutShadow verifies the full blocking
// configuration: detection enabled with shadow mode off. This should only
// be used after 7-day shadow validation with 0% FPR.
func TestProxy_MLFeatureFlags_EnabledWithoutShadow(t *testing.T) {
	opts := &Options{
		BindAddress:              "127.0.0.1:0",
		Upstream:                 "http://127.0.0.1:9999",
		MaxBodySize:              1024,
		Timeout:                  5 * time.Second,
		RateLimit:                100,
		MLThreatDetectionEnabled: true,
		MLShadowMode:             false,
	}

	p := New(opts)

	stats := p.threatDetector.GetStats()
	if !stats["enabled"].(bool) {
		t.Error("ThreatDetector should be enabled")
	}
	if stats["shadow_mode"].(bool) {
		t.Error("ThreatDetector ShadowMode should be false")
	}
}
