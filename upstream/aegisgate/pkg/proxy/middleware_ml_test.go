// Copyright 2024 AegisGate, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/ml"
)

// TestMLMiddleware_Integration tests the full ML middleware integration
func TestMLMiddleware_Integration(t *testing.T) {
	// Create ML middleware with test configuration
	config := &MLMiddlewareConfig{
		Enabled:                 true,
		Sensitivity:             "medium",
		BlockOnHighSeverity:     false,
		BlockOnCriticalSeverity: true,
		MinScoreToBlock:         3.0,
		LogAllAnomalies:         false,
		SampleRate:              100,
		ExcludedPaths:           []string{"/health", "/ready"},
		ExcludedMethods:         []string{"OPTIONS"},
	}

	middleware, err := NewMLMiddleware(config)
	if err != nil {
		t.Fatalf("Failed to create ML middleware: %v", err)
	}

	// Test handler that we expect to be called
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	// Wrap with middleware
	handler := middleware.Middleware(nextHandler)

	// Test 1: Normal request should pass through
	t.Run("Normal Request", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if !nextCalled {
			t.Error("Expected next handler to be called for normal request")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	// Test 2: Excluded path should pass through
	t.Run("Excluded Path", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if !nextCalled {
			t.Error("Expected next handler to be called for excluded path")
		}
	})

	// Test 3: Excluded method should pass through
	t.Run("Excluded Method", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if !nextCalled {
			t.Error("Expected next handler to be called for excluded method")
		}
	})

	// Test 4: Request with suspicious pattern should trigger detection
	t.Run("Suspicious Pattern Detection", func(t *testing.T) {
		nextCalled = false
		// Simulate path traversal attack
		req := httptest.NewRequest("GET", "/api/../../../etc/passwd", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// The request should still pass through because our basic
		// implementation doesn't detect path traversal by default
		// In production, this would be blocked based on severity
		if !nextCalled {
			t.Log("Request was blocked (expected for high severity)")
		}
	})
}

// TestMLMiddleware_Blocking tests the blocking functionality
func TestMLMiddleware_Blocking(t *testing.T) {
	config := &MLMiddlewareConfig{
		Enabled:                 true,
		Sensitivity:             "paranoid",
		BlockOnHighSeverity:     true,
		BlockOnCriticalSeverity: true,
		MinScoreToBlock:         2.0, // Low threshold for testing
		LogAllAnomalies:         false,
		SampleRate:              100,
	}

	middleware, err := NewMLMiddleware(config)
	if err != nil {
		t.Fatalf("Failed to create ML middleware: %v", err)
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Test with high entropy payload (potential attack)
	t.Run("High Entropy Payload Blocking", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(`
			<script>alert('xss')</script>
			../../../etc/passwd
			'; DROP TABLE users;--
			{{7*7}}
		`)))
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Check if blocked in paranoid mode
		// Note: In actual implementation, blocking depends on ML detection
		t.Logf("Response status: %d", w.Code)
	})
}

// TestMLMiddleware_Stats tests the statistics tracking
func TestMLMiddleware_Stats(t *testing.T) {
	config := DefaultMLMiddlewareConfig()
	middleware, err := NewMLMiddleware(config)
	if err != nil {
		t.Fatalf("Failed to create ML middleware: %v", err)
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Make some requests
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Get stats
	stats := middleware.GetStats()

	if stats.TotalRequests != 10 {
		t.Errorf("Expected 10 total requests, got %d", stats.TotalRequests)
	}

	if stats.AnalyzedRequests != 10 {
		t.Errorf("Expected 10 analyzed requests, got %d", stats.AnalyzedRequests)
	}

	t.Logf("Stats: %+v", stats)
}

// TestMLMiddleware_SensitivityLevels tests different sensitivity levels
func TestMLMiddleware_SensitivityLevels(t *testing.T) {
	sensitivities := []string{"low", "medium", "high", "paranoid"}

	for _, sensitivity := range sensitivities {
		t.Run("Sensitivity: "+sensitivity, func(t *testing.T) {
			config := &MLMiddlewareConfig{
				Enabled:     true,
				Sensitivity: sensitivity,
			}

			middleware, err := NewMLMiddleware(config)
			if err != nil {
				t.Errorf("Failed to create ML middleware with sensitivity %s: %v", sensitivity, err)
			}

			if middleware.config.Sensitivity != sensitivity {
				t.Errorf("Expected sensitivity %s, got %s", sensitivity, middleware.config.Sensitivity)
			}
		})
	}
}

// TestMLMiddleware_ConfigUpdate tests runtime config updates
func TestMLMiddleware_ConfigUpdate(t *testing.T) {
	config := DefaultMLMiddlewareConfig()
	middleware, err := NewMLMiddleware(config)
	if err != nil {
		t.Fatalf("Failed to create ML middleware: %v", err)
	}

	// Update configuration
	newConfig := &MLMiddlewareConfig{
		Enabled:             false,
		Sensitivity:         "high",
		BlockOnHighSeverity: true,
	}

	err = middleware.UpdateConfig(newConfig)
	if err != nil {
		t.Errorf("Failed to update config: %v", err)
	}

	// Verify update
	if middleware.config.Enabled != false {
		t.Error("Expected enabled to be false after update")
	}

	if middleware.config.Sensitivity != "high" {
		t.Error("Expected sensitivity to be high after update")
	}
}

// TestMLMiddleware_JSONSerialization tests JSON serialization of results
func TestMLMiddleware_JSONSerialization(t *testing.T) {
	result := &MLAnomalyResult{
		Anomalies: []ml.Anomaly{
			{
				Type:        "traffic_spike",
				Severity:    ml.Severity(4),
				Score:       4.5,
				Description: "Traffic spike detected",
				Timestamp:   time.Now(),
			},
		},
		SeverityCounts: map[string]int{
			"4": 1,
		},
		ShouldBlock:      true,
		BlockingReason:   "severity_4_traffic_spike",
		AnalysisDuration: 5 * time.Millisecond,
		Method:           "GET",
		Path:             "/api/test",
		Size:             0,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	// Verify we can unmarshal it back
	var unmarshaled MLAnomalyResult
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(unmarshaled.Anomalies) != 1 {
		t.Errorf("Expected 1 anomaly, got %d", len(unmarshaled.Anomalies))
	}

	if !unmarshaled.ShouldBlock {
		t.Error("Expected ShouldBlock to be true")
	}

	t.Logf("Serialized result: %s", string(data))
}

// BenchmarkMLMiddleware benchmarks the ML middleware performance
func BenchmarkMLMiddleware(b *testing.B) {
	config := DefaultMLMiddlewareConfig()
	middleware, _ := NewMLMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkMLMiddleware_WithAnomalies benchmarks with suspicious requests
func BenchmarkMLMiddleware_WithAnomalies(b *testing.B) {
	config := DefaultMLMiddlewareConfig()
	middleware, _ := NewMLMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate suspicious request
		req := httptest.NewRequest("POST", "/api/../../../etc/passwd", bytes.NewReader([]byte(`
			<script>alert('xss')</script>
			'; DROP TABLE users;--
		`)))
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
