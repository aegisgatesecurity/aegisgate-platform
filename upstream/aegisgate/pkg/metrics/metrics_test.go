package metrics

import (
	"sync"
	"testing"
	"time"
)

// TestMetricTypeString tests MetricType string representation
func TestMetricTypeString(t *testing.T) {
	tests := []struct {
		mt       MetricType
		expected string
	}{
		{MetricRequest, "request"},
		{MetricResponse, "response"},
		{MetricBlocked, "blocked"},
		{MetricViolation, "violation"},
		{MetricError, "error"},
		{MetricScanDuration, "scan_duration"},
		{MetricProxyLatency, "proxy_latency"},
		{MetricType(999), "unknown"},
	}

	for _, test := range tests {
		if got := test.mt.String(); got != test.expected {
			t.Errorf("MetricType(%d).String() = %q, want %q", test.mt, got, test.expected)
		}
	}
}

// TestSeverityString tests Severity string representation
func TestSeverityString(t *testing.T) {
	tests := []struct {
		s        Severity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(999), "unknown"},
	}

	for _, test := range tests {
		if got := test.s.String(); got != test.expected {
			t.Errorf("Severity(%d).String() = %q, want %q", test.s, got, test.expected)
		}
	}
}

// TestSeverityCount tests SeverityCount operations
func TestSeverityCount(t *testing.T) {
	sc := SeverityCount{}

	sc.Increment(SeverityCritical)
	if sc.Critical != 1 {
		t.Errorf("Expected Critical=1, got %d", sc.Critical)
	}

	sc.Increment(SeverityHigh)
	if sc.High != 1 {
		t.Errorf("Expected High=1, got %d", sc.High)
	}

	sc.Increment(SeverityMedium)
	if sc.Medium != 1 {
		t.Errorf("Expected Medium=1, got %d", sc.Medium)
	}

	sc.Increment(SeverityLow)
	if sc.Low != 1 {
		t.Errorf("Expected Low=1, got %d", sc.Low)
	}

	sc.Increment(SeverityInfo)
	if sc.Info != 1 {
		t.Errorf("Expected Info=1, got %d", sc.Info)
	}

	if total := sc.Total(); total != 5 {
		t.Errorf("Expected Total=5, got %d", total)
	}

	snapshot := sc.Get()
	if snapshot.Critical != 1 || snapshot.High != 1 || snapshot.Medium != 1 || snapshot.Low != 1 || snapshot.Info != 1 {
		t.Errorf("Get() snapshot incorrect: %+v", snapshot)
	}
}

// TestPatternMatch tests PatternMatch operations
func TestPatternMatch(t *testing.T) {
	pm := &PatternMatch{
		PatternName: "test-pattern",
		Category:    "sql_injection",
	}

	pm.Increment()
	if count := pm.GetCount(); count != 1 {
		t.Errorf("Expected count=1, got %d", count)
	}

	pm.Increment()
	if count := pm.GetCount(); count != 2 {
		t.Errorf("Expected count=2, got %d", count)
	}
}

// TestRealtimeMetrics tests RealtimeMetrics creation
func TestRealtimeMetrics(t *testing.T) {
	rm := NewRealtimeMetrics()

	if rm.PatternMatches == nil {
		t.Error("PatternMatches should be initialized")
	}
	if rm.CategoryCounts == nil {
		t.Error("CategoryCounts should be initialized")
	}
}

// TestTimeSeries tests TimeSeries operations
func TestTimeSeries(t *testing.T) {
	ts := NewTimeSeries(5)

	if ts.Len() != 0 {
		t.Errorf("Expected Len=0, got %d", ts.Len())
	}
	if ts.Capacity() != 5 {
		t.Errorf("Expected Capacity=5, got %d", ts.Capacity())
	}

	now := time.Now()
	for i := 0; i < 3; i++ {
		ts.Add(TimeSeriesPoint{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Value:     float64(i),
		})
	}

	if ts.Len() != 3 {
		t.Errorf("Expected Len=3, got %d", ts.Len())
	}

	points := ts.GetPoints()
	if len(points) != 3 {
		t.Errorf("Expected 3 points, got %d", len(points))
	}

	// Test ring buffer overflow
	for i := 3; i < 7; i++ {
		ts.Add(TimeSeriesPoint{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Value:     float64(i),
		})
	}

	if ts.Len() != 5 {
		t.Errorf("Expected Len=5 after overflow, got %d", ts.Len())
	}
}

// TestMetricEvent tests MetricEvent creation
func TestMetricEvent(t *testing.T) {
	msg := NewMessage(MetricRequest, map[string]interface{}{"key": "value"})
	if msg.Type != MetricRequest {
		t.Errorf("Expected type MetricRequest, got %v", msg.Type)
	}
	if msg.Data == nil {
		t.Error("Data should not be nil")
	}
	if msg.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

// TestMetricsCollector tests MetricsCollector creation
func TestMetricsCollector(t *testing.T) {
	mc := NewCollector(nil)
	defer mc.Stop()

	if mc == nil {
		t.Fatal("NewCollector returned nil")
	}

	opts := &CollectorOptions{
		RequestHistoryMinutes: 30,
		ViolationHistoryHours: 12,
		LatencyHistorySize:    50,
		AggregationInterval:   time.Second * 30,
	}
	mc2 := NewCollector(opts)
	defer mc2.Stop()

	if mc2 == nil {
		t.Fatal("NewCollector with options returned nil")
	}
}

// TestMetricsCollectorRecord tests recording metrics
func TestMetricsCollectorRecord(t *testing.T) {
	mc := NewCollector(nil)
	defer mc.Stop()

	mc.RecordRequest(time.Millisecond * 10)
	mc.RecordResponse(200, 1024)
	mc.RecordBlocked("sql_injection", []string{"pattern1", "pattern2"})
	mc.RecordViolation("xss_pattern", "xss", SeverityHigh)
	mc.RecordError("connection_failed")
	mc.RecordScanDuration(time.Millisecond * 5)

	time.Sleep(time.Millisecond * 100)

	stats := mc.GetRealtimeMetrics()
	if stats.RequestCount != 1 {
		t.Errorf("Expected RequestCount=1, got %d", stats.RequestCount)
	}
	if stats.ResponseCount != 1 {
		t.Errorf("Expected ResponseCount=1, got %d", stats.ResponseCount)
	}
	if stats.BlockedCount != 1 {
		t.Errorf("Expected BlockedCount=1, got %d", stats.BlockedCount)
	}
	if stats.ViolationCount != 1 {
		t.Errorf("Expected ViolationCount=1, got %d", stats.ViolationCount)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("Expected ErrorCount=1, got %d", stats.ErrorCount)
	}
}

// TestMetricsCollectorGetStats tests stats retrieval
func TestMetricsCollectorGetStats(t *testing.T) {
	mc := NewCollector(nil)
	defer mc.Stop()

	mc.RecordRequest(time.Millisecond * 10)
	mc.RecordResponse(200, 1024)
	mc.RecordBlocked("test", []string{"pattern"})
	mc.RecordViolation("test_pattern", "test_category", SeverityMedium)

	time.Sleep(time.Millisecond * 100)

	stats := mc.GetStats()

	if stats.Requests != 1 {
		t.Errorf("Expected Requests=1, got %d", stats.Requests)
	}
	if stats.Responses != 1 {
		t.Errorf("Expected Responses=1, got %d", stats.Responses)
	}
	if stats.Blocked != 1 {
		t.Errorf("Expected Blocked=1, got %d", stats.Blocked)
	}
	if stats.Violations != 1 {
		t.Errorf("Expected Violations=1, got %d", stats.Violations)
	}
}

// TestMetricsCollectorSeverity tests severity tracking
func TestMetricsCollectorSeverity(t *testing.T) {
	mc := NewCollector(nil)
	defer mc.Stop()

	mc.RecordViolation("p1", "cat1", SeverityCritical)
	mc.RecordViolation("p2", "cat2", SeverityHigh)
	mc.RecordViolation("p3", "cat3", SeverityMedium)
	mc.RecordViolation("p4", "cat4", SeverityLow)
	mc.RecordViolation("p5", "cat5", SeverityInfo)

	time.Sleep(time.Millisecond * 100)

	sc := mc.GetSeverityCounts()
	if sc.Critical != 1 {
		t.Errorf("Expected Critical=1, got %d", sc.Critical)
	}
	if sc.High != 1 {
		t.Errorf("Expected High=1, got %d", sc.High)
	}
	if sc.Medium != 1 {
		t.Errorf("Expected Medium=1, got %d", sc.Medium)
	}
	if sc.Low != 1 {
		t.Errorf("Expected Low=1, got %d", sc.Low)
	}
	if sc.Info != 1 {
		t.Errorf("Expected Info=1, got %d", sc.Info)
	}
}

// TestGlobalCollector tests global collector functions
func TestGlobalCollector(t *testing.T) {
	ResetGlobalCollector()

	gc := GlobalCollector()
	if gc == nil {
		t.Fatal("GlobalCollector returned nil")
	}

	RecordRequestGlobal(time.Millisecond * 5)
	RecordResponseGlobal(200, 512)
	RecordBlockedGlobal("test", nil)
	RecordViolationGlobal("test", "test", SeverityMedium)
	RecordErrorGlobal("test_error")
	RecordScanDurationGlobal(time.Millisecond * 10)

	ResetGlobalCollector()
}

// TestConcurrentMetrics tests concurrent metric recording
func TestConcurrentMetrics(t *testing.T) {
	mc := NewCollector(nil)
	defer mc.Stop()

	var wg sync.WaitGroup
	numGoroutines := 5
	numOperations := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				mc.RecordRequest(time.Millisecond)
				mc.RecordResponse(200, 100)
				mc.RecordViolation("test", "test", SeverityMedium)
			}
		}()
	}

	wg.Wait()
	time.Sleep(time.Millisecond * 500) // Wait for async processing

	stats := mc.GetRealtimeMetrics()
	expected := int64(numGoroutines * numOperations)

	// Due to asynchronous event processing with buffered channel and non-blocking sends,
	// some events may be dropped when the channel is full. The test verifies thread safety
	// and that a reasonable percentage of events are recorded.
	minExpected := int64(float64(expected) * 0.4) // At least 40% should be recorded (non-blocking design)

	if stats.RequestCount < minExpected {
		t.Errorf("Expected RequestCount >= %d, got %d (sent %d)", minExpected, stats.RequestCount, expected)
	}
}

// TestDefaultCollectorOptions tests default options
func TestDefaultCollectorOptions(t *testing.T) {
	opts := DefaultCollectorOptions()

	if opts.RequestHistoryMinutes != 60 {
		t.Errorf("Expected RequestHistoryMinutes=60, got %d", opts.RequestHistoryMinutes)
	}
	if opts.ViolationHistoryHours != 24 {
		t.Errorf("Expected ViolationHistoryHours=24, got %d", opts.ViolationHistoryHours)
	}
	if opts.LatencyHistorySize != 100 {
		t.Errorf("Expected LatencyHistorySize=100, got %d", opts.LatencyHistorySize)
	}
	if opts.AggregationInterval != time.Minute {
		t.Errorf("Expected AggregationInterval=1m, got %v", opts.AggregationInterval)
	}
}

// BenchmarkMetricRecording benchmarks metric recording performance
func BenchmarkMetricRecording(b *testing.B) {
	mc := NewCollector(nil)
	defer mc.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mc.RecordRequest(time.Millisecond)
		mc.RecordResponse(200, 100)
	}
}

// BenchmarkConcurrentMetrics benchmarks concurrent metric recording
func BenchmarkConcurrentMetrics(b *testing.B) {
	mc := NewCollector(nil)
	defer mc.Stop()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mc.RecordRequest(time.Millisecond)
			mc.RecordResponse(200, 100)
		}
	})
}
