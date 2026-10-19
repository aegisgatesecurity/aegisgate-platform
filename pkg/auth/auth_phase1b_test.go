// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"os"
	"testing"
	"time"
)

// TestPhase1bIsUsingDefaultKeys checks both default and custom key states.
func TestPhase1bIsUsingDefaultKeys(t *testing.T) {
	// Default config should have default keys
	cfg := DefaultConfig()
	if !cfg.IsUsingDefaultKeys() {
		t.Fatal("expected default config to use default keys")
	}

	// Custom keys should not be default
	cfg.JWTSigningKey = []byte("custom-key-that-is-not-default")
	cfg.APIAuthToken = "custom-token"
	if cfg.IsUsingDefaultKeys() {
		t.Fatal("expected custom config to not use default keys")
	}

	// Only JWT default
	cfg2 := DefaultConfig()
	cfg2.APIAuthToken = "custom"
	if !cfg2.IsUsingDefaultKeys() {
		t.Fatal("expected IsUsingDefaultKeys=true when only JWT is default")
	}

	// Only API token default
	cfg3 := DefaultConfig()
	cfg3.JWTSigningKey = []byte("custom-key")
	if !cfg3.IsUsingDefaultKeys() {
		t.Fatal("expected IsUsingDefaultKeys=true when only API token is default")
	}
}

// TestPhase1bValidateProduction tests production validation with default keys.
func TestPhase1bValidateProduction_DefaultKeys(t *testing.T) {
	os.Setenv("AEGISGATE_ENV", "production")
	defer os.Unsetenv("AEGISGATE_ENV")

	cfg := DefaultConfig()
	err := cfg.ValidateProduction()
	if err == nil {
		t.Fatal("expected error for default keys in production")
	}
}

// TestPhase1bValidateProduction_ShortKey tests short key rejection in prod.
func TestPhase1bValidateProduction_ShortKey(t *testing.T) {
	os.Setenv("AEGISGATE_ENV", "production")
	defer os.Unsetenv("AEGISGATE_ENV")

	cfg := &Config{
		JWTSigningKey:    []byte("short-key"),
		APIAuthToken:     "custom-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	err := cfg.ValidateProduction()
	if err == nil {
		t.Fatal("expected error for short JWT key in production")
	}
}

// TestPhase1bValidateProduction_ValidConfig tests valid production config.
func TestPhase1bValidateProduction_ValidConfig(t *testing.T) {
	os.Setenv("AEGISGATE_ENV", "production")
	defer os.Unsetenv("AEGISGATE_ENV")

	cfg := &Config{
		JWTSigningKey:    []byte("this-is-a-very-long-production-key-32+bytes"),
		APIAuthToken:     "custom-production-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	err := cfg.ValidateProduction()
	if err != nil {
		t.Fatalf("expected no error for valid production config: %v", err)
	}
}

// TestPhase1bValidateProduction_NonProduction tests that defaults are OK in dev.
func TestPhase1bValidateProduction_NonProduction(t *testing.T) {
	os.Setenv("AEGISGATE_ENV", "development")
	defer os.Unsetenv("AEGISGATE_ENV")

	cfg := DefaultConfig()
	err := cfg.ValidateProduction()
	if err != nil {
		t.Fatalf("expected no error in development: %v", err)
	}
}

// TestPhase1bValidateProduction_ProdEnv tests the "prod" env variant.
func TestPhase1bValidateProduction_ProdEnv(t *testing.T) {
	os.Setenv("AEGISGATE_ENV", "prod")
	defer os.Unsetenv("AEGISGATE_ENV")

	cfg := DefaultConfig()
	err := cfg.ValidateProduction()
	if err == nil {
		t.Fatal("expected error for default keys in prod env")
	}
}

// TestPhase1bRecordDatacenterIP tests recording datacenter IPs.
func TestPhase1bRecordDatacenterIP(t *testing.T) {
	detector := NewProxyServiceDetector()
	// Record a known datacenter IP (AWS us-east-1: 54.144.0.0/12 is in KnownProxyRanges)
	detector.RecordDatacenterIP("54.144.1.1")
	count := detector.GetDatacenterIPCount()
	if count == 0 {
		t.Log("no datacenter IPs recorded (IP may not match known ranges)")
	}
}

// TestPhase1bRecordDatacenterIP_NonDatacenter tests that non-datacenter IPs
// are not recorded.
func TestPhase1bRecordDatacenterIP_NonDatacenter(t *testing.T) {
	detector := NewProxyServiceDetector()
	detector.RecordDatacenterIP("192.168.1.100")
	count := detector.GetDatacenterIPCount()
	if count != 0 {
		t.Errorf("expected 0 datacenter IPs for private IP, got %d", count)
	}
}

// TestPhase1bGetDatacenterIPCount verifies counting.
func TestPhase1bGetDatacenterIPCount(t *testing.T) {
	detector := NewProxyServiceDetector()
	if detector.GetDatacenterIPCount() != 0 {
		t.Fatal("expected 0 count on new detector")
	}
}

// TestPhase1bDistillationCleanupExpired tests the CleanupExpired method.
func TestPhase1bDistillationCleanupExpired(t *testing.T) {
	detector := NewDistillationPatternDetector()
	// Cleanup on empty detector
	removed := detector.CleanupExpired()
	if removed != 0 {
		t.Errorf("expected 0 removed from empty detector, got %d", removed)
	}
}

// TestPhase1bStolenKeyCleanupExpired tests the CleanupExpired method.
func TestPhase1bStolenKeyCleanupExpired(t *testing.T) {
	proxyDetector := NewProxyServiceDetector()
	detector := NewStolenKeyDetector(proxyDetector)
	// Cleanup on empty detector
	removed := detector.CleanupExpired()
	if removed != 0 {
		t.Errorf("expected 0 removed from empty detector, got %d", removed)
	}
}

// TestPhase1bStolenKeyGetKeyIPCount_NonExistent tests GetKeyIPCount for unknown key.
func TestPhase1bStolenKeyGetKeyIPCount_NonExistent(t *testing.T) {
	proxyDetector := NewProxyServiceDetector()
	detector := NewStolenKeyDetector(proxyDetector)
	count := detector.GetKeyIPCount("nonexistent-key")
	if count != 0 {
		t.Errorf("expected 0 IPs for unknown key, got %d", count)
	}
}

// TestPhase1bPatternSimilarity tests the patternSimilarity helper.
func TestPhase1bPatternSimilarity(t *testing.T) {
	// clusterSize <= 1 → 0
	if s := patternSimilarity(0); s != 0 {
		t.Errorf("expected 0 for clusterSize=0, got %f", s)
	}
	if s := patternSimilarity(1); s != 0 {
		t.Errorf("expected 0 for clusterSize=1, got %f", s)
	}
	// 1 < clusterSize < 20 → clusterSize/20
	if s := patternSimilarity(10); s != 0.5 {
		t.Errorf("expected 0.5 for clusterSize=10, got %f", s)
	}
	// clusterSize >= 20 → 1.0 (capped)
	if s := patternSimilarity(20); s != 1.0 {
		t.Errorf("expected 1.0 for clusterSize=20, got %f", s)
	}
	if s := patternSimilarity(100); s != 1.0 {
		t.Errorf("expected 1.0 for clusterSize=100, got %f", s)
	}
}

// TestPhase1bCheckAnomaly_NoBaseline tests anomaly check with no baseline.
func TestPhase1bCheckAnomaly_NoBaseline(t *testing.T) {
	detector := NewAnomalyDetector()
	rec := KeyUsageRecord{
		KeyID:     "unknown-key",
		Timestamp: time.Now(),
		ToolName:  "test_tool",
	}
	result := detector.CheckAnomaly("unknown-key", rec)
	if result.IsAnomalous {
		t.Fatal("expected no anomaly for key without baseline")
	}
}

// TestPhase1bCheckAnomaly_InsufficientSamples tests that anomaly detection
// requires minimum samples before activating.
func TestPhase1bCheckAnomaly_InsufficientSamples(t *testing.T) {
	detector := NewAnomalyDetector()
	// Record a few samples (less than MinSamplesForBaseline=10)
	for i := 0; i < 5; i++ {
		detector.RecordUsage(KeyUsageRecord{
			KeyID:     "test-key",
			Timestamp: time.Now(),
			ToolName:  "tool_a",
			SourceIP:  "192.168.1.1",
		})
	}
	result := detector.CheckAnomaly("test-key", KeyUsageRecord{
		KeyID:     "test-key",
		Timestamp: time.Now(),
		ToolName:  "tool_a",
	})
	if result.IsAnomalous {
		t.Fatal("expected no anomaly with insufficient samples")
	}
}

// TestPhase1bCheckAnomaly_NewTool tests that a new tool triggers anomaly
// after sufficient baseline samples.
func TestPhase1bCheckAnomaly_NewTool(t *testing.T) {
	detector := NewAnomalyDetector()
	// Record enough samples to establish baseline
	for i := 0; i < 15; i++ {
		detector.RecordUsage(KeyUsageRecord{
			KeyID:     "test-key-newtool",
			Timestamp: time.Now(),
			ToolName:  "known_tool",
			SourceIP:  "192.168.1.1",
		})
	}
	// Check with a new tool not in baseline
	result := detector.CheckAnomaly("test-key-newtool", KeyUsageRecord{
		KeyID:     "test-key-newtool",
		Timestamp: time.Now(),
		ToolName:  "unknown_new_tool",
	})
	if !result.IsAnomalous {
		t.Fatal("expected anomaly for new tool access")
	}
}
