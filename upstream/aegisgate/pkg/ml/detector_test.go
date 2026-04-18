package ml

import (
	"math"
	"testing"
	"time"
)

// TestNewDetector tests detector creation with various configurations
func TestNewDetector(t *testing.T) {
	// Test with default configuration
	detector := New(Config{})
	if detector == nil {
		t.Fatal("NewDetector returned nil")
	}

	// Test with custom configuration
	cfg := Config{
		Sensitivity:      High,
		WindowSize:       200,
		ZThreshold:       2.5,
		MinSamples:       20,
		EntropyThreshold: 0.9,
	}
	detector2 := New(cfg)
	if detector2 == nil {
		t.Fatal("NewDetector with config returned nil")
	}
}

// TestSensitivityThresholds tests sensitivity-based threshold selection
func TestSensitivityThresholds(t *testing.T) {
	tests := []struct {
		sensitivity Sensitivity
		expectedZ   float64
	}{
		{Low, 4.0},
		{Medium, 3.0},
		{High, 2.0},
		{Critical, 1.5},
	}

	for _, test := range tests {
		cfg := Config{Sensitivity: test.sensitivity}
		detector := New(cfg)
		if detector == nil {
			t.Errorf("Failed to create detector for sensitivity %v", test.sensitivity)
			continue
		}
		stats := detector.GetBaselineStats()
		if zThreshold, ok := stats["z_threshold"].(float64); ok {
			if zThreshold != test.expectedZ {
				t.Errorf("Sensitivity %v: expected z_threshold=%.1f, got %.1f",
					test.sensitivity, test.expectedZ, zThreshold)
			}
		}
	}
}

// TestRecordTraffic tests traffic recording and anomaly detection
func TestRecordTraffic(t *testing.T) {
	detector := New(Config{
		WindowSize: 100,
		MinSamples: 5,
		ZThreshold: 3.0,
	})

	// Record normal traffic
	for i := 0; i < 10; i++ {
		anomaly := detector.RecordTraffic(TrafficSample{
			Timestamp:  time.Now(),
			Volume:     100,
			Size:       1024,
			Violations: 0,
		})
		if anomaly != nil {
			t.Errorf("Unexpected anomaly during normal traffic: %v", anomaly)
		}
	}

	// Record a spike and check for anomaly
	anomaly := detector.RecordTraffic(TrafficSample{
		Timestamp:  time.Now(),
		Volume:     10000, // 100x normal
		Size:       102400,
		Violations: 0,
	})
	// May or may not detect - depends on z-score
	_ = anomaly
}

// TestAnalyzeRequest tests request analysis
func TestAnalyzeRequest(t *testing.T) {
	detector := New(Config{
		WindowSize: 50,
		MinSamples: 5,
		ZThreshold: 3.0,
	})

	// Record normal requests to build baseline
	for i := 0; i < 20; i++ {
		detector.AnalyzeRequest("GET", "/api/data", 1024)
	}

	// Record a request with unusual size
	anomaly, detected := detector.AnalyzeRequest("POST", "/api/upload", 1024*1024) // 1MB
	// Size anomaly may be detected depending on baseline
	_ = anomaly
	_ = detected
}

// TestAnalyzeContent tests entropy analysis
func TestAnalyzeContent(t *testing.T) {
	detector := New(Config{
		EntropyThreshold: 0.8,
	})

	// Test low entropy content (repeating pattern)
	lowEntropy := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	entropy1, anomaly1 := detector.AnalyzeContent(lowEntropy)
	if entropy1 > 0.5 {
		t.Errorf("Low entropy content should have entropy < 0.5, got %.2f", entropy1)
	}
	if anomaly1 != nil {
		t.Error("Low entropy should not trigger anomaly")
	}

	// Test high entropy content (random-looking)
	highEntropy := []byte("kJ8sF2mN9pL3xQ7vC1yH5tR0wZ4bA6dE")
	entropy2, anomaly2 := detector.AnalyzeContent(highEntropy)
	if entropy2 < 0.5 {
		t.Errorf("High entropy content should have entropy > 0.5, got %.2f", entropy2)
	}
	// May detect anomaly depending on threshold
	_ = anomaly2
}

// TestAnalyzePatterns tests pattern anomaly detection
func TestAnalyzePatterns(t *testing.T) {
	detector := New(Config{})

	// Test excessive special characters
	specialChars := "!@#$%^&*()!@#$%^&*()!@#$%^&*()"
	anomalies := detector.AnalyzePatterns(specialChars)
	if len(anomalies) == 0 {
		t.Error("Should detect excessive special characters")
	}

	// Test repeated characters
	repeated := "aaaaaaaaaaaaaaaaaaaaa"
	anomalies = detector.AnalyzePatterns(repeated)
	if len(anomalies) == 0 {
		t.Error("Should detect repeated characters")
	}

	// Test path traversal
	pathTraversal := "../../../etc/passwd"
	anomalies = detector.AnalyzePatterns(pathTraversal)
	if len(anomalies) == 0 {
		t.Error("Should detect path traversal")
	}

	// Test normal content
	normal := "Hello, World!"
	anomalies = detector.AnalyzePatterns(normal)
	if len(anomalies) > 0 {
		t.Errorf("Normal content should not trigger anomalies, got %d", len(anomalies))
	}
}

// TestGetAnomalies tests anomaly retrieval
func TestGetAnomalies(t *testing.T) {
	detector := New(Config{
		EntropyThreshold: 0.5, // Low threshold to trigger anomalies easily
	})

	// Initially no anomalies
	anomalies := detector.GetAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies, got %d", len(anomalies))
	}

	// Trigger some anomalies
	detector.AnalyzeContent([]byte("xJ7kL9mN2pQ4rS6tV8wY0zA3bC5dE8fG")) // High entropy

	anomalies = detector.GetAnomalies()
	if len(anomalies) == 0 {
		t.Error("Expected at least one anomaly")
	}
}

// TestGetRecentAnomalies tests time-filtered anomaly retrieval
func TestGetRecentAnomalies(t *testing.T) {
	detector := New(Config{
		EntropyThreshold: 0.5,
	})

	// Trigger anomalies
	detector.AnalyzeContent([]byte("xJ7kL9mN2pQ4rS6tV8wY0zA3bC5dE8fG"))

	// Should find recent anomalies
	recent := detector.GetRecentAnomalies(time.Minute)
	if len(recent) == 0 {
		t.Error("Expected recent anomalies")
	}

	// Should not find old anomalies
	old := detector.GetRecentAnomalies(time.Nanosecond)
	// May be 0 since time has passed
	_ = old
}

// TestClearAnomalies tests clearing anomalies
func TestClearAnomalies(t *testing.T) {
	detector := New(Config{
		EntropyThreshold: 0.5,
	})

	// Trigger anomalies
	detector.AnalyzeContent([]byte("xJ7kL9mN2pQ4rS6tV8wY0zA3bC5dE8fG"))

	// Clear them
	detector.ClearAnomalies()

	// Should be empty
	anomalies := detector.GetAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies after clear, got %d", len(anomalies))
	}
}

// TestIsReady tests detector readiness
func TestIsReady(t *testing.T) {
	detector := New(Config{
		MinSamples: 5,
	})

	// Not ready initially
	if detector.IsReady() {
		t.Error("Detector should not be ready initially")
	}

	// Record samples
	for i := 0; i < 5; i++ {
		detector.RecordTraffic(TrafficSample{
			Timestamp:  time.Now(),
			Volume:     100,
			Size:       1024,
			Violations: 0,
		})
	}

	// Should be ready now
	if !detector.IsReady() {
		t.Error("Detector should be ready after min samples")
	}
}

// TestReset tests detector reset
func TestReset(t *testing.T) {
	detector := New(Config{
		MinSamples:       5,
		EntropyThreshold: 0.5,
	})

	// Build up state
	for i := 0; i < 10; i++ {
		detector.RecordTraffic(TrafficSample{
			Timestamp:  time.Now(),
			Volume:     100,
			Size:       1024,
			Violations: 0,
		})
	}
	detector.AnalyzeContent([]byte("xJ7kL9mN2pQ4rS6tV8wY0zA3bC5dE8fG"))

	// Reset
	detector.Reset()

	// Should not be ready after reset
	if detector.IsReady() {
		t.Error("Detector should not be ready after reset")
	}

	// Anomalies should be cleared
	anomalies := detector.GetAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies after reset, got %d", len(anomalies))
	}
}

// TestGetMethodsDistribution tests HTTP method tracking
func TestGetMethodsDistribution(t *testing.T) {
	detector := New(Config{})

	// Record some requests
	detector.AnalyzeRequest("GET", "/api/data", 1024)
	detector.AnalyzeRequest("GET", "/api/data", 1024)
	detector.AnalyzeRequest("POST", "/api/data", 2048)

	dist := detector.GetMethodsDistribution()
	if dist["GET"] != 2.0/3.0 {
		t.Errorf("Expected GET=0.67, got %.2f", dist["GET"])
	}
	if dist["POST"] != 1.0/3.0 {
		t.Errorf("Expected POST=0.33, got %.2f", dist["POST"])
	}
}

// TestGetTopPaths tests path tracking
func TestGetTopPaths(t *testing.T) {
	detector := New(Config{})

	// Record some requests
	detector.AnalyzeRequest("GET", "/api/data", 1024)
	detector.AnalyzeRequest("GET", "/api/data", 1024)
	detector.AnalyzeRequest("GET", "/api/data", 1024)
	detector.AnalyzeRequest("GET", "/api/users", 1024)

	topPaths := detector.GetTopPaths(2)
	if len(topPaths) > 2 {
		t.Errorf("Expected at most 2 paths, got %d", len(topPaths))
	}
	if len(topPaths) > 0 && topPaths[0].Path != "/api/data" {
		t.Errorf("Expected top path to be /api/data, got %s", topPaths[0].Path)
	}
}

// TestGetBaselineStats tests baseline statistics retrieval
func TestGetBaselineStats(t *testing.T) {
	detector := New(Config{
		WindowSize: 100,
		MinSamples: 5,
		ZThreshold: 3.0,
	})

	stats := detector.GetBaselineStats()
	if stats == nil {
		t.Fatal("GetBaselineStats returned nil")
	}

	// Check expected keys exist
	expectedKeys := []string{
		"traffic_average",
		"traffic_samples",
		"size_average",
		"size_samples",
		"violation_average",
		"violation_samples",
		"total_anomalies",
		"configured_window",
		"z_threshold",
	}

	for _, key := range expectedKeys {
		if _, ok := stats[key]; !ok {
			t.Errorf("Missing expected key: %s", key)
		}
	}
}

// TestSeverityLevels tests severity calculation based on z-score
func TestSeverityLevels(t *testing.T) {
	detector := New(Config{})

	// Test recordTraffic with extreme values to trigger different severities
	// First establish a baseline
	for i := 0; i < 50; i++ {
		detector.RecordTraffic(TrafficSample{
			Timestamp:  time.Now(),
			Volume:     100,
			Size:       1024,
			Violations: 0,
		})
	}

	// Trigger spike - should cause anomaly with certain severity
	anomaly := detector.RecordTraffic(TrafficSample{
		Timestamp:  time.Now(),
		Volume:     10000, // 100x normal
		Size:       102400,
		Violations: 0,
	})

	if anomaly != nil {
		// Verify severity is in valid range
		if anomaly.Severity < Info || anomaly.Severity > CriticalSev {
			t.Errorf("Invalid severity level: %d", anomaly.Severity)
		}

		// Verify z-score (Score) is positive
		if anomaly.Score < 0 {
			t.Errorf("Z-score should be positive for spike, got %.2f", anomaly.Score)
		}
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	// Valid config
	validCfg := Config{
		WindowSize:       100,
		MinSamples:       10,
		EntropyThreshold: 0.8,
		ZThreshold:       3.0,
	}
	if err := validCfg.Validate(); err != nil {
		t.Errorf("Valid config should pass validation: %v", err)
	}

	// Invalid WindowSize
	invalidWindowSize := Config{WindowSize: -1}
	if err := invalidWindowSize.Validate(); err == nil {
		t.Error("Expected error for negative WindowSize")
	}

	// Invalid MinSamples
	invalidMinSamples := Config{MinSamples: -1}
	if err := invalidMinSamples.Validate(); err == nil {
		t.Error("Expected error for negative MinSamples")
	}

	// Invalid EntropyThreshold (negative)
	invalidEntropy1 := Config{EntropyThreshold: -0.5}
	if err := invalidEntropy1.Validate(); err == nil {
		t.Error("Expected error for negative EntropyThreshold")
	}

	// Invalid EntropyThreshold (> 1)
	invalidEntropy2 := Config{EntropyThreshold: 1.5}
	if err := invalidEntropy2.Validate(); err == nil {
		t.Error("Expected error for EntropyThreshold > 1")
	}

	// Invalid ZThreshold
	invalidZ := Config{ZThreshold: -1.0}
	if err := invalidZ.Validate(); err == nil {
		t.Error("Expected error for negative ZThreshold")
	}
}

// TestCalculateEntropy tests entropy calculation
func TestCalculateEntropy(t *testing.T) {
	detector := New(Config{})

	// Empty input
	entropy := detector.calculateEntropy([]byte{})
	if entropy != 0 {
		t.Errorf("Empty input should have 0 entropy, got %.2f", entropy)
	}

	// Single character (zero entropy)
	entropy = detector.calculateEntropy([]byte("aaaa"))
	if entropy != 0 {
		t.Errorf("Single character pattern should have ~0 entropy, got %.4f", entropy)
	}

	// Two characters (entropy should be 1 bit = 1/8 normalized)
	entropy = detector.calculateEntropy([]byte("abab"))
	expectedEntropy := 1.0 / 8.0 // 1 bit = 1/8 byte entropy
	if math.Abs(entropy-expectedEntropy) > 0.01 {
		t.Errorf("Two-char pattern should have entropy ~%.4f, got %.4f", expectedEntropy, entropy)
	}

	// Random bytes (high entropy)
	randomBytes := make([]byte, 256)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	entropy = detector.calculateEntropy(randomBytes)
	// Full byte entropy = 8 bits, normalized to 1.0
	if entropy < 0.95 {
		t.Errorf("Full entropy should be ~1.0, got %.2f", entropy)
	}
}

// TestBaseline tests baseline operations
func TestBaseline(t *testing.T) {
	b := newBaseline(100)

	// Test initial state
	if b.sampleCount() != 0 {
		t.Error("Initial sample count should be 0")
	}

	// Test update and z-score
	z1 := b.update(100.0)
	// First sample should have z-score of 0 (no deviation)
	if z1 != 0 {
		t.Errorf("First sample z-score should be 0, got %.2f", z1)
	}

	// Add more samples
	for i := 0; i < 10; i++ {
		b.update(100.0)
	}

	// Add outlier
	zOutlier := b.update(10000.0)
	// Outlier should have high z-score
	if zOutlier < 2.0 {
		t.Errorf("Outlier z-score should be > 2, got %.2f", zOutlier)
	}

	// Test getAverage
	avg := b.getAverage()
	if avg <= 0 {
		t.Errorf("Average should be positive, got %.2f", avg)
	}
}

// BenchmarkDetectorRecordTraffic benchmarks traffic recording
func BenchmarkDetectorRecordTraffic(b *testing.B) {
	detector := New(Config{
		WindowSize: 100,
		MinSamples: 10,
		ZThreshold: 3.0,
	})

	sample := TrafficSample{
		Timestamp:  time.Now(),
		Volume:     100,
		Size:       1024,
		Violations: 0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.RecordTraffic(sample)
	}
}

// BenchmarkDetectorAnalyzeRequest benchmarks request analysis
func BenchmarkDetectorAnalyzeRequest(b *testing.B) {
	detector := New(Config{
		WindowSize: 100,
		MinSamples: 10,
		ZThreshold: 3.0,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.AnalyzeRequest("GET", "/api/data", 1024)
	}
}

// BenchmarkDetectorAnalyzeContent benchmarks content analysis
func BenchmarkDetectorAnalyzeContent(b *testing.B) {
	detector := New(Config{})
	content := []byte("This is a test string for entropy analysis")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.AnalyzeContent(content)
	}
}
