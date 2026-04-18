package proxy

import (
	"testing"
	"time"
)

// TestNewProxy tests proxy creation with various options
func TestNewProxy(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &Options{},
		},
		{
			name: "full options",
			opts: &Options{
				BindAddress: ":8443",
				Upstream:    "http://localhost:8080",
				MaxBodySize: 1024 * 1024,
				Timeout:     30 * time.Second,
				RateLimit:   100,
			},
		},
		{
			name: "with ML enabled",
			opts: &Options{
				BindAddress:       ":8443",
				Upstream:          "http://localhost:8080",
				EnableMLDetection: true,
				MLSensitivity:     "medium",
				MLSampleRate:      100,
			},
		},
		{
			name: "with ML high sensitivity",
			opts: &Options{
				BindAddress:               ":8443",
				Upstream:                  "http://localhost:8080",
				EnableMLDetection:         true,
				MLSensitivity:             "high",
				MLBlockOnCriticalSeverity: true,
				MLBlockOnHighSeverity:     true,
				MLMinScoreToBlock:         2.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.opts)
			if p == nil {
				t.Fatal("New() returned nil")
			}

			// Verify defaults applied
			if p.options.MaxBodySize == 0 {
				t.Error("MaxBodySize should have a default")
			}
			if p.options.Timeout == 0 {
				t.Error("Timeout should have a default")
			}
			if p.options.RateLimit == 0 {
				t.Error("RateLimit should have a default")
			}
		})
	}
}

// TestProxyOptionsWithML tests ML-specific options
func TestProxyOptionsWithML(t *testing.T) {
	opts := &Options{
		BindAddress:                    ":8443",
		Upstream:                       "http://localhost:8080",
		EnableMLDetection:              true,
		MLSensitivity:                  "paranoid",
		MLBlockOnCriticalSeverity:      true,
		MLBlockOnHighSeverity:          true,
		MLMinScoreToBlock:              1.5,
		MLSampleRate:                   100,
		MLExcludedPaths:                []string{"/health", "/ready"},
		MLExcludedMethods:              []string{"OPTIONS", "HEAD"},
		EnablePromptInjectionDetection: true,
		PromptInjectionSensitivity:     90,
		EnableContentAnalysis:          true,
		EnableBehavioralAnalysis:       true,
	}

	p := New(opts)
	if p == nil {
		t.Fatal("New() returned nil")
	}

	// Check ML middleware was created
	if p.mlMiddleware == nil {
		t.Error("ML middleware should be created when EnableMLDetection is true")
	}

	// Verify ML config
	if p.mlMiddleware != nil {
		cfg := p.mlMiddleware.Config()
		if cfg.Sensitivity != "paranoid" {
			t.Errorf("Expected sensitivity 'paranoid', got '%s'", cfg.Sensitivity)
		}
		if !cfg.BlockOnCriticalSeverity {
			t.Error("BlockOnCriticalSeverity should be true")
		}
		if !cfg.BlockOnHighSeverity {
			t.Error("BlockOnHighSeverity should be true")
		}
		if cfg.MinScoreToBlock != 1.5 {
			t.Errorf("Expected MinScoreToBlock 1.5, got %f", cfg.MinScoreToBlock)
		}
	}
}

// TestProxyGetStats tests statistics retrieval
func TestProxyGetStats(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
		RateLimit:   100,
	})

	// Get stats before any requests
	stats := p.GetStats()
	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}

	enabled, ok := stats["enabled"].(bool)
	if !ok {
		t.Error("enabled should be a boolean")
	}
	if enabled {
		t.Error("proxy should not be enabled before Start()")
	}

	// Check ML stats when ML is disabled
	_, hasML := stats["ml"]
	if hasML {
		t.Error("ml stats should not be present when ML is disabled")
	}
}

// TestProxyGetStatsWithML tests statistics with ML enabled
func TestProxyGetStatsWithML(t *testing.T) {
	p := New(&Options{
		BindAddress:       ":8443",
		Upstream:          "http://localhost:8080",
		RateLimit:         100,
		EnableMLDetection: true,
		MLSensitivity:     "medium",
	})

	stats := p.GetStats()
	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}

	// Check ML stats are present
	mlStats, ok := stats["ml"].(map[string]interface{})
	if !ok {
		t.Fatal("ml stats should be present when ML is enabled")
	}

	if mlStats["total_requests"] == nil {
		t.Error("ml total_requests should be present")
	}
	if mlStats["analyzed_requests"] == nil {
		t.Error("ml analyzed_requests should be present")
	}
	if mlStats["blocked_requests"] == nil {
		t.Error("ml blocked_requests should be present")
	}
}

// TestProxyGetHealth tests health check
func TestProxyGetHealth(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
	})

	health := p.GetHealth()
	if health == nil {
		t.Fatal("GetHealth() returned nil")
	}

	// Check basic health fields
	if health["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%v'", health["status"])
	}
	if health["bind_address"] != ":8443" {
		t.Errorf("Expected bind_address ':8443', got '%v'", health["bind_address"])
	}
	if health["upstream"] != "http://localhost:8080" {
		t.Errorf("Expected upstream 'http://localhost:8080', got '%v'", health["upstream"])
	}
}

// TestRateLimiter tests rate limiting functionality
func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10) // 10 requests per minute

	// Should allow initial burst
	for i := 0; i < 10; i++ {
		if !rl.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 11th request should be blocked
	if rl.Allow() {
		t.Error("11th request should be blocked")
	}

	rl.Stop()
}

// TestRateLimiterEmptyBucket tests rate limiter with empty bucket
func TestRateLimiterEmptyBucket(t *testing.T) {
	rl := NewRateLimiter(1)

	// Consume the one token
	if !rl.Allow() {
		t.Error("First request should be allowed")
	}

	// Next request should be blocked
	if rl.Allow() {
		t.Error("Second request should be blocked")
	}

	rl.Stop()
}

// TestProxyIsEnabled tests enabled state
func TestProxyIsEnabled(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
	})

	// Before Start(), proxy is not enabled
	if p.IsEnabled() {
		t.Error("Proxy should not be enabled before Start()")
	}
}

// TestProxyGetScanner tests scanner access
func TestProxyGetScanner(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
	})

	scanner := p.GetScanner()
	if scanner == nil {
		t.Error("GetScanner() should not return nil")
	}
}

// TestProxySetScanner tests scanner assignment
func TestProxySetScanner(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
	})

	// Should not panic with nil
	p.SetScanner(nil)

	// Set a new scanner
	// p.SetScanner(scanner.New(nil)) // This would require importing scanner
}

// TestProxyGetMLMiddleware tests ML middleware access
func TestProxyGetMLMiddleware(t *testing.T) {
	// Test without ML
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
	})

	ml := p.GetMLMiddleware()
	if ml != nil {
		t.Error("ML middleware should be nil when disabled")
	}

	// Test with ML
	p2 := New(&Options{
		BindAddress:       ":8443",
		Upstream:          "http://localhost:8080",
		EnableMLDetection: true,
		MLSensitivity:     "medium",
	})

	ml2 := p2.GetMLMiddleware()
	if ml2 == nil {
		t.Error("ML middleware should not be nil when enabled")
	}
}

// TestProxyGetStatsStruct tests structured stats
func TestProxyGetStatsStruct(t *testing.T) {
	p := New(&Options{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
		RateLimit:   100,
	})

	stats := p.GetStatsStruct()
	if stats == nil {
		t.Fatal("GetStatsStruct() returned nil")
	}

	if stats.RequestsTotal != 0 {
		t.Errorf("Expected 0 initial requests, got %d", stats.RequestsTotal)
	}
}
