// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package metrics provides real-time metrics collection and time-series data storage
// for the AegisGate WAF. It uses atomic operations for thread safety and event-driven
// architecture for real-time streaming capabilities.
//
// The package supports:
//   - Atomic counters for thread-safe metric tracking
//   - Ring buffers for efficient time-series data storage
//   - Event channels for real-time metric streaming
//   - Pattern match tracking with category and severity information
//   - Performance metrics for scan duration and proxy latency
package metrics

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the type of metric being recorded.
// Used to categorize different events in the WAF processing pipeline.
type MetricType int32

const (
	// MetricRequest tracks incoming HTTP requests
	MetricRequest MetricType = iota
	// MetricResponse tracks outgoing HTTP responses
	MetricResponse
	// MetricBlocked tracks requests that were blocked
	MetricBlocked
	// MetricViolation tracks security violations detected
	MetricViolation
	// MetricError tracks system errors
	MetricError
	// MetricScanDuration tracks WAF scan processing time
	MetricScanDuration
	// MetricProxyLatency tracks proxy forwarding latency
	MetricProxyLatency
)

// String returns the string representation of a MetricType.
func (m MetricType) String() string {
	switch m {
	case MetricRequest:
		return "request"
	case MetricResponse:
		return "response"
	case MetricBlocked:
		return "blocked"
	case MetricViolation:
		return "violation"
	case MetricError:
		return "error"
	case MetricScanDuration:
		return "scan_duration"
	case MetricProxyLatency:
		return "proxy_latency"
	default:
		return "unknown"
	}
}

// Severity represents the severity level of a security violation.
type Severity int32

const (
	// SeverityInfo represents informational severity
	SeverityInfo Severity = iota
	// SeverityLow represents low severity
	SeverityLow
	// SeverityMedium represents medium severity
	SeverityMedium
	// SeverityHigh represents high severity
	SeverityHigh
	// SeverityCritical represents critical severity
	SeverityCritical
)

// String returns the string representation of a Severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SeverityCount tracks the count of violations by severity level.
// Uses atomic operations for thread-safe updates.
type SeverityCount struct {
	// Critical is the count of critical severity violations
	Critical int64
	// High is the count of high severity violations
	High int64
	// Medium is the count of medium severity violations
	Medium int64
	// Low is the count of low severity violations
	Low int64
	// Info is the count of informational severity violations
	Info int64
}

// Increment increments the counter for the specified severity level atomically.
func (sc *SeverityCount) Increment(severity Severity) {
	switch severity {
	case SeverityCritical:
		atomic.AddInt64(&sc.Critical, 1)
	case SeverityHigh:
		atomic.AddInt64(&sc.High, 1)
	case SeverityMedium:
		atomic.AddInt64(&sc.Medium, 1)
	case SeverityLow:
		atomic.AddInt64(&sc.Low, 1)
	case SeverityInfo:
		atomic.AddInt64(&sc.Info, 1)
	}
}

// Get returns a snapshot of current severity counts.
func (sc *SeverityCount) Get() SeverityCount {
	return SeverityCount{
		Critical: atomic.LoadInt64(&sc.Critical),
		High:     atomic.LoadInt64(&sc.High),
		Medium:   atomic.LoadInt64(&sc.Medium),
		Low:      atomic.LoadInt64(&sc.Low),
		Info:     atomic.LoadInt64(&sc.Info),
	}
}

// Total returns the total count of all severity levels.
func (sc *SeverityCount) Total() int64 {
	return atomic.LoadInt64(&sc.Critical) +
		atomic.LoadInt64(&sc.High) +
		atomic.LoadInt64(&sc.Medium) +
		atomic.LoadInt64(&sc.Low) +
		atomic.LoadInt64(&sc.Info)
}

// PatternMatch tracks pattern detection statistics.
// Updated atomically when patterns are matched during request processing.
type PatternMatch struct {
	// PatternName is the unique identifier of the matched pattern
	PatternName string
	// Category is the classification of the pattern (e.g., "sql_injection", "xss")
	Category string
	// Count is the number of times this pattern has been matched (atomic)
	Count int64
	// LastSeen is the timestamp of the most recent match
	LastSeen time.Time
}

// Increment atomically increments the pattern match count.
func (pm *PatternMatch) Increment() {
	atomic.AddInt64(&pm.Count, 1)
	// Note: LastSeen is updated non-atomically; callers should hold lock
}

// GetCount returns the current match count atomically.
func (pm *PatternMatch) GetCount() int64 {
	return atomic.LoadInt64(&pm.Count)
}

// RealtimeMetrics holds all real-time counters and maps.
// All fields use atomic operations or are protected by the embedded mutex.
type RealtimeMetrics struct {
	mu sync.RWMutex

	// RequestCount is the total number of requests processed
	RequestCount int64

	// ResponseCount is the total number of responses sent
	ResponseCount int64

	// BlockedCount is the total number of blocked requests
	BlockedCount int64

	// ViolationCount is the total number of violations detected
	ViolationCount int64

	// ErrorCount is the total number of system errors
	ErrorCount int64

	// SeverityCounts tracks violations by severity level
	SeverityCounts SeverityCount

	// PatternMatches tracks statistics for each pattern
	PatternMatches map[string]*PatternMatch

	// CategoryCounts tracks violation counts by category
	CategoryCounts map[string]int64

	// ScanDurationTotal is the cumulative scan duration in microseconds
	ScanDurationTotal int64

	// ScanDurationCount is the number of scan duration samples
	ScanDurationCount int64

	// ProxyLatencyTotal is the cumulative proxy latency in microseconds
	ProxyLatencyTotal int64

	// ProxyLatencyCount is the number of proxy latency samples
	ProxyLatencyCount int64
}

// NewRealtimeMetrics creates a new RealtimeMetrics instance.
func NewRealtimeMetrics() *RealtimeMetrics {
	return &RealtimeMetrics{
		PatternMatches: make(map[string]*PatternMatch),
		CategoryCounts: make(map[string]int64),
	}
}

// TimeSeriesPoint represents a single data point in a time series.
type TimeSeriesPoint struct {
	// Timestamp is when the data point was recorded
	Timestamp time.Time
	// Value is the numeric value of the metric
	Value float64
	// Labels contains optional metadata tags
	Labels map[string]string
}

// TimeSeries is a thread-safe ring buffer for time-series data.
// It maintains a fixed-size circular buffer of data points.
type TimeSeries struct {
	mu     sync.RWMutex
	points []TimeSeriesPoint
	size   int
	head   int
	count  int
}

// NewTimeSeries creates a new time series with the specified capacity.
func NewTimeSeries(capacity int) *TimeSeries {
	return &TimeSeries{
		points: make([]TimeSeriesPoint, capacity),
		size:   capacity,
		head:   0,
		count:  0,
	}
}

// Add inserts a new data point into the time series.
// If the buffer is full, the oldest point is overwritten.
func (ts *TimeSeries) Add(point TimeSeriesPoint) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.points[ts.head] = point
	ts.head = (ts.head + 1) % ts.size
	if ts.count < ts.size {
		ts.count++
	}
}

// GetPoints returns a copy of all current data points in chronological order.
func (ts *TimeSeries) GetPoints() []TimeSeriesPoint {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]TimeSeriesPoint, ts.count)
	if ts.count == 0 {
		return result
	}

	// Calculate start index (oldest point)
	start := (ts.head - ts.count + ts.size) % ts.size
	for i := 0; i < ts.count; i++ {
		idx := (start + i) % ts.size
		result[i] = ts.points[idx]
	}

	return result
}

// Len returns the current number of points in the series.
func (ts *TimeSeries) Len() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.count
}

// Capacity returns the maximum capacity of the time series.
func (ts *TimeSeries) Capacity() int {
	return ts.size
}

// MetricEvent represents a metrics event for real-time streaming.
type MetricEvent struct {
	// Type is the type of metric event
	Type MetricType
	// Timestamp is when the event occurred
	Timestamp time.Time
	// Data contains event-specific data
	Data map[string]interface{}
}

// NewMessage creates a new MetricEvent with the current timestamp.
func NewMessage(msgType MetricType, data map[string]interface{}) MetricEvent {
	return MetricEvent{
		Type:      msgType,
		Timestamp: time.Now(),
		Data:      data,
	}
}

// MetricsCollector is the main metrics collection and distribution engine.
// It manages real-time counters, time-series storage, and event broadcasting.
type MetricsCollector struct {
	mu sync.RWMutex

	// realtime holds the current real-time metrics
	realtime *RealtimeMetrics

	// requestHistory stores request metrics for the last 60 minutes
	requestHistory *TimeSeries

	// violationHistory stores violation metrics for the last 24 hours
	violationHistory *TimeSeries

	// latencyHistory stores latency samples for the last 100 requests
	latencyHistory *TimeSeries

	// listeners holds channels subscribed to metric events
	listeners map[chan MetricEvent]bool

	// eventCh is the internal channel for processing events
	eventCh chan MetricEvent

	// ctx and cancel manage the background processor lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// ticker controls periodic aggregation of time-series data
	ticker *time.Ticker
}

// CollectorOptions provides configuration options for the metrics collector.
type CollectorOptions struct {
	// RequestHistoryMinutes is the duration in minutes to retain request history (default: 60)
	RequestHistoryMinutes int
	// ViolationHistoryHours is the duration in hours to retain violation history (default: 24)
	ViolationHistoryHours int
	// LatencyHistorySize is the number of latency samples to retain (default: 100)
	LatencyHistorySize int
	// AggregationInterval is the interval for aggregating time-series data (default: 1 minute)
	AggregationInterval time.Duration
}

// DefaultCollectorOptions returns the default collector options.
func DefaultCollectorOptions() CollectorOptions {
	return CollectorOptions{
		RequestHistoryMinutes: 60,
		ViolationHistoryHours: 24,
		LatencyHistorySize:    100,
		AggregationInterval:   time.Minute,
	}
}

// NewCollector creates a new MetricsCollector with the specified options.
// It starts the background processor and returns an initialized collector.
// If opts is nil, default options are used.
func NewCollector(opts *CollectorOptions) *MetricsCollector {
	if opts == nil {
		defaultOpts := DefaultCollectorOptions()
		opts = &defaultOpts
	}

	ctx, cancel := context.WithCancel(context.Background())

	mc := &MetricsCollector{
		realtime:         NewRealtimeMetrics(),
		requestHistory:   NewTimeSeries(opts.RequestHistoryMinutes),
		violationHistory: NewTimeSeries(opts.ViolationHistoryHours),
		latencyHistory:   NewTimeSeries(opts.LatencyHistorySize),
		listeners:        make(map[chan MetricEvent]bool),
		eventCh:          make(chan MetricEvent, 1000),
		ctx:              ctx,
		cancel:           cancel,
		ticker:           time.NewTicker(opts.AggregationInterval),
	}

	// Start background processor
	mc.wg.Add(1)
	go mc.processEvents()

	return mc
}

// processEvents is the background goroutine that processes metric events.
func (mc *MetricsCollector) processEvents() {
	defer mc.wg.Done()

	for {
		select {
		case event := <-mc.eventCh:
			mc.handleEvent(event)
		case <-mc.ticker.C:
			mc.aggregateTimeSeries()
		case <-mc.ctx.Done():
			return
		}
	}
}

// handleEvent processes a single metric event.
func (mc *MetricsCollector) handleEvent(event MetricEvent) {
	// Update realtime metrics based on event type
	switch event.Type {
	case MetricRequest:
		atomic.AddInt64(&mc.realtime.RequestCount, 1)
	case MetricResponse:
		if statusCode, ok := event.Data["status_code"].(int); ok {
			mc.recordResponseMetrics(statusCode)
		}
	case MetricBlocked:
		atomic.AddInt64(&mc.realtime.BlockedCount, 1)
		if reason, ok := event.Data["reason"].(string); ok {
			mc.recordBlockedDetails(reason, event.Data["patterns"])
		}
	case MetricViolation:
		atomic.AddInt64(&mc.realtime.ViolationCount, 1)
		if patternName, ok := event.Data["pattern_name"].(string); ok {
			category, _ := event.Data["category"].(string)
			severity, _ := event.Data["severity"].(Severity)
			mc.recordViolationDetails(patternName, category, severity)
		}
	case MetricError:
		atomic.AddInt64(&mc.realtime.ErrorCount, 1)
	case MetricScanDuration:
		if duration, ok := event.Data["duration"].(time.Duration); ok {
			mc.recordScanDuration(duration)
		}
	case MetricProxyLatency:
		if latency, ok := event.Data["latency"].(time.Duration); ok {
			mc.recordProxyLatency(latency)
		}
	}

	// Broadcast to listeners
	mc.broadcastEvent(event)
}

// recordResponseMetrics updates response-related counters.
func (mc *MetricsCollector) recordResponseMetrics(statusCode int) {
	atomic.AddInt64(&mc.realtime.ResponseCount, 1)
}

// recordBlockedDetails updates blocked request statistics.
func (mc *MetricsCollector) recordBlockedDetails(reason string, patterns interface{}) {
	// Store patterns matches if provided
	if patternList, ok := patterns.([]string); ok {
		mc.realtime.mu.Lock()
		for _, patternName := range patternList {
			if pm, exists := mc.realtime.PatternMatches[patternName]; exists {
				pm.Increment()
				pm.LastSeen = time.Now()
			} else {
				mc.realtime.PatternMatches[patternName] = &PatternMatch{
					PatternName: patternName,
					Count:       1,
					LastSeen:    time.Now(),
				}
			}
		}
		mc.realtime.mu.Unlock()
	}
}

// recordViolationDetails updates violation statistics with pattern information.
func (mc *MetricsCollector) recordViolationDetails(patternName, category string, severity Severity) {
	mc.realtime.SeverityCounts.Increment(severity)

	mc.realtime.mu.Lock()
	defer mc.realtime.mu.Unlock()

	// Update pattern match count
	if pm, exists := mc.realtime.PatternMatches[patternName]; exists {
		pm.Increment()
		pm.LastSeen = time.Now()
		if category != "" && pm.Category == "" {
			pm.Category = category
		}
	} else {
		mc.realtime.PatternMatches[patternName] = &PatternMatch{
			PatternName: patternName,
			Category:    category,
			Count:       1,
			LastSeen:    time.Now(),
		}
	}

	// Update category count
	if category != "" {
		mc.realtime.CategoryCounts[category]++
	}
}

// recordScanDuration updates scan duration statistics.
func (mc *MetricsCollector) recordScanDuration(duration time.Duration) {
	microseconds := duration.Microseconds()
	atomic.AddInt64(&mc.realtime.ScanDurationTotal, microseconds)
	atomic.AddInt64(&mc.realtime.ScanDurationCount, 1)

	// Add to latency history
	mc.latencyHistory.Add(TimeSeriesPoint{
		Timestamp: time.Now(),
		Value:     float64(duration.Milliseconds()),
		Labels:    map[string]string{"type": "scan"},
	})
}

// recordProxyLatency updates proxy latency statistics.
func (mc *MetricsCollector) recordProxyLatency(latency time.Duration) {
	microseconds := latency.Microseconds()
	atomic.AddInt64(&mc.realtime.ProxyLatencyTotal, microseconds)
	atomic.AddInt64(&mc.realtime.ProxyLatencyCount, 1)

	// Add to latency history
	mc.latencyHistory.Add(TimeSeriesPoint{
		Timestamp: time.Now(),
		Value:     float64(latency.Milliseconds()),
		Labels:    map[string]string{"type": "proxy"},
	})
}

// aggregateTimeSeries aggregates realtime metrics into time-series storage.
func (mc *MetricsCollector) aggregateTimeSeries() {
	now := time.Now()

	// Aggregate request count
	reqCount := atomic.LoadInt64(&mc.realtime.RequestCount)
	mc.requestHistory.Add(TimeSeriesPoint{
		Timestamp: now,
		Value:     float64(reqCount),
		Labels:    map[string]string{"metric": "requests"},
	})

	// Aggregate violation count
	violCount := atomic.LoadInt64(&mc.realtime.ViolationCount)
	mc.violationHistory.Add(TimeSeriesPoint{
		Timestamp: now,
		Value:     float64(violCount),
		Labels:    map[string]string{"metric": "violations"},
	})
}

// broadcastEvent sends the event to all subscribed listeners.
func (mc *MetricsCollector) broadcastEvent(event MetricEvent) {
	mc.mu.RLock()
	listeners := make([]chan MetricEvent, 0, len(mc.listeners))
	for ch := range mc.listeners {
		listeners = append(listeners, ch)
	}
	mc.mu.RUnlock()

	// Send to all listeners (non-blocking)
	for _, ch := range listeners {
		select {
		case ch <- event:
		default:
			// Channel is full, skip this listener
		}
	}
}

// RecordRequest records a request metric with the given duration.
func (mc *MetricsCollector) RecordRequest(duration time.Duration) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricRequest,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"duration": duration,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// RecordResponse records a response metric with status code and size.
func (mc *MetricsCollector) RecordResponse(statusCode int, size int64) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricResponse,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"status_code": statusCode,
			"size":        size,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// RecordBlocked records a blocked request with the reason and matched patterns.
func (mc *MetricsCollector) RecordBlocked(reason string, patterns []string) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricBlocked,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"reason":   reason,
			"patterns": patterns,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// RecordViolation records a security violation with pattern details.
func (mc *MetricsCollector) RecordViolation(patternName, category string, severity Severity) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricViolation,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"pattern_name": patternName,
			"category":     category,
			"severity":     severity,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// RecordError records a system error of the specified type.
func (mc *MetricsCollector) RecordError(errorType string) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricError,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"error_type": errorType,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// RecordScanDuration records the scan processing duration.
func (mc *MetricsCollector) RecordScanDuration(duration time.Duration) {
	select {
	case mc.eventCh <- MetricEvent{
		Type:      MetricScanDuration,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"duration": duration,
		},
	}:
	default:
		// Channel is full, drop the event
	}
}

// Subscribe creates a new event channel and registers it as a listener.
// The returned channel receives all metric events.
// The buffer size determines how many events can be queued per subscriber.
func (mc *MetricsCollector) Subscribe(bufferSize int) <-chan MetricEvent {
	ch := make(chan MetricEvent, bufferSize)

	mc.mu.Lock()
	mc.listeners[ch] = true
	mc.mu.Unlock()

	return ch
}

// Unsubscribe removes the specified channel from the listener list.
// The channel is closed as part of unsubscription.
func (mc *MetricsCollector) Unsubscribe(ch <-chan MetricEvent) {
	mc.mu.Lock()
	// Convert back to send channel for map lookup
	for listener := range mc.listeners {
		if listener == ch {
			delete(mc.listeners, listener)
			close(listener)
			break
		}
	}
	mc.mu.Unlock()
}

// GetRealtimeMetrics returns a copy of the current realtime metrics snapshot.
func (mc *MetricsCollector) GetRealtimeMetrics() *RealtimeMetrics {
	mc.realtime.mu.RLock()
	defer mc.realtime.mu.RUnlock()

	snapshot := RealtimeMetrics{
		RequestCount:      atomic.LoadInt64(&mc.realtime.RequestCount),
		ResponseCount:     atomic.LoadInt64(&mc.realtime.ResponseCount),
		BlockedCount:      atomic.LoadInt64(&mc.realtime.BlockedCount),
		ViolationCount:    atomic.LoadInt64(&mc.realtime.ViolationCount),
		ErrorCount:        atomic.LoadInt64(&mc.realtime.ErrorCount),
		SeverityCounts:    mc.realtime.SeverityCounts.Get(),
		PatternMatches:    make(map[string]*PatternMatch),
		CategoryCounts:    make(map[string]int64),
		ScanDurationTotal: atomic.LoadInt64(&mc.realtime.ScanDurationTotal),
		ScanDurationCount: atomic.LoadInt64(&mc.realtime.ScanDurationCount),
		ProxyLatencyTotal: atomic.LoadInt64(&mc.realtime.ProxyLatencyTotal),
		ProxyLatencyCount: atomic.LoadInt64(&mc.realtime.ProxyLatencyCount),
	}

	// Copy pattern matches
	for k, v := range mc.realtime.PatternMatches {
		snapshot.PatternMatches[k] = &PatternMatch{
			PatternName: v.PatternName,
			Category:    v.Category,
			Count:       v.GetCount(),
			LastSeen:    v.LastSeen,
		}
	}

	// Copy category counts
	for k, v := range mc.realtime.CategoryCounts {
		snapshot.CategoryCounts[k] = v
	}

	return &snapshot
}

// GetRequestHistory returns the time series data for request metrics.
func (mc *MetricsCollector) GetRequestHistory() []TimeSeriesPoint {
	return mc.requestHistory.GetPoints()
}

// GetViolationHistory returns the time series data for violation metrics.
func (mc *MetricsCollector) GetViolationHistory() []TimeSeriesPoint {
	return mc.violationHistory.GetPoints()
}

// GetLatencyHistory returns the time series data for latency metrics.
func (mc *MetricsCollector) GetLatencyHistory() []TimeSeriesPoint {
	return mc.latencyHistory.GetPoints()
}

// GetAverageScanDuration returns the average scan duration in milliseconds.
func (mc *MetricsCollector) GetAverageScanDuration() float64 {
	total := atomic.LoadInt64(&mc.realtime.ScanDurationTotal)
	count := atomic.LoadInt64(&mc.realtime.ScanDurationCount)
	if count == 0 {
		return 0
	}
	// Convert microseconds to milliseconds
	return float64(total) / float64(count) / 1000.0
}

// GetAverageProxyLatency returns the average proxy latency in milliseconds.
func (mc *MetricsCollector) GetAverageProxyLatency() float64 {
	total := atomic.LoadInt64(&mc.realtime.ProxyLatencyTotal)
	count := atomic.LoadInt64(&mc.realtime.ProxyLatencyCount)
	if count == 0 {
		return 0
	}
	// Convert microseconds to milliseconds
	return float64(total) / float64(count) / 1000.0
}

// GetPatternMatches returns a copy of all pattern match statistics.
func (mc *MetricsCollector) GetPatternMatches() map[string]*PatternMatch {
	mc.realtime.mu.RLock()
	defer mc.realtime.mu.RUnlock()

	result := make(map[string]*PatternMatch)
	for k, v := range mc.realtime.PatternMatches {
		result[k] = &PatternMatch{
			PatternName: v.PatternName,
			Category:    v.Category,
			Count:       v.GetCount(),
			LastSeen:    v.LastSeen,
		}
	}
	return result
}

// GetSeverityCounts returns the current severity count snapshot.
func (mc *MetricsCollector) GetSeverityCounts() SeverityCount {
	return mc.realtime.SeverityCounts.Get()
}

// Stop gracefully shuts down the metrics collector.
// It stops the background processor and closes all listener channels.
func (mc *MetricsCollector) Stop() {
	// Stop the ticker
	mc.ticker.Stop()

	// Cancel context to stop background goroutines
	mc.cancel()

	// Wait for background processor to finish
	mc.wg.Wait()

	// Close event channel
	close(mc.eventCh)

	// Close all listener channels
	mc.mu.Lock()
	for ch := range mc.listeners {
		close(ch)
	}
	mc.listeners = make(map[chan MetricEvent]bool)
	mc.mu.Unlock()
}

// globalCollector holds the singleton collector instance.
var (
	globalCollector     *MetricsCollector
	globalCollectorOnce sync.Once
	globalCollectorMu   sync.RWMutex
)

// GlobalCollector returns the singleton metrics collector instance.
// If the collector doesn't exist, it creates one with default options.
func GlobalCollector() *MetricsCollector {
	globalCollectorOnce.Do(func() {
		globalCollector = NewCollector(nil)
	})
	return globalCollector
}

// SetGlobalCollector sets the global collector instance.
// This is useful for testing or when custom configuration is needed.
func SetGlobalCollector(mc *MetricsCollector) {
	globalCollectorMu.Lock()
	defer globalCollectorMu.Unlock()
	globalCollector = mc
}

// ResetGlobalCollector resets the global collector to a new instance with default options.
// This stops the existing global collector if it exists.
func ResetGlobalCollector() {
	globalCollectorMu.Lock()
	defer globalCollectorMu.Unlock()

	if globalCollector != nil {
		globalCollector.Stop()
	}

	globalCollectorOnce = sync.Once{}
	globalCollector = nil
}

// Convenience functions for global collector access

// RecordRequestGlobal records a request using the global collector.
func RecordRequestGlobal(duration time.Duration) {
	GlobalCollector().RecordRequest(duration)
}

// RecordResponseGlobal records a response using the global collector.
func RecordResponseGlobal(statusCode int, size int64) {
	GlobalCollector().RecordResponse(statusCode, size)
}

// RecordBlockedGlobal records a blocked request using the global collector.
func RecordBlockedGlobal(reason string, patterns []string) {
	GlobalCollector().RecordBlocked(reason, patterns)
}

// RecordViolationGlobal records a violation using the global collector.
func RecordViolationGlobal(patternName, category string, severity Severity) {
	GlobalCollector().RecordViolation(patternName, category, severity)
}

// RecordErrorGlobal records an error using the global collector.
func RecordErrorGlobal(errorType string) {
	GlobalCollector().RecordError(errorType)
}

// RecordScanDurationGlobal records scan duration using the global collector.
func RecordScanDurationGlobal(duration time.Duration) {
	GlobalCollector().RecordScanDuration(duration)
}

// RecordProxyLatencyGlobal records proxy latency using the global collector.
func RecordProxyLatencyGlobal(latency time.Duration) {
	GlobalCollector().RecordScanDuration(latency)
}

// Stats provides a human-readable summary of collector statistics.
type Stats struct {
	Requests        int64
	Responses       int64
	Blocked         int64
	Violations      int64
	Errors          int64
	AvgScanDuration float64
	AvgProxyLatency float64
	SeverityCounts  SeverityCount
	TopPatterns     []PatternStat
}

// PatternStat represents a pattern and its match count.
type PatternStat struct {
	PatternName string
	Category    string
	Count       int64
	LastSeen    time.Time
}

// GetStats returns a formatted statistics summary.
func (mc *MetricsCollector) GetStats() Stats {
	realtime := mc.GetRealtimeMetrics()

	stats := Stats{
		Requests:        realtime.RequestCount,
		Responses:       realtime.ResponseCount,
		Blocked:         realtime.BlockedCount,
		Violations:      realtime.ViolationCount,
		Errors:          realtime.ErrorCount,
		AvgScanDuration: mc.GetAverageScanDuration(),
		AvgProxyLatency: mc.GetAverageProxyLatency(),
		SeverityCounts:  realtime.SeverityCounts.Get(),
		TopPatterns:     make([]PatternStat, 0, len(realtime.PatternMatches)),
	}

	for _, pm := range realtime.PatternMatches {
		stats.TopPatterns = append(stats.TopPatterns, PatternStat{
			PatternName: pm.PatternName,
			Category:    pm.Category,
			Count:       pm.GetCount(),
			LastSeen:    pm.LastSeen,
		})
	}

	return stats
}

// String returns a formatted string representation of Stats.
func (s Stats) String() string {
	return fmt.Sprintf(
		"Metrics Stats:\n"+
			"  Requests: %d\n"+
			"  Responses: %d\n"+
			"  Blocked: %d\n"+
			"  Violations: %d\n"+
			"  Errors: %d\n"+
			"  Avg Scan Duration: %.2f ms\n"+
			"  Avg Proxy Latency: %.2f ms\n"+
			"  Severity: Critical=%d High=%d Medium=%d Low=%d Info=%d",
		s.Requests,
		s.Responses,
		s.Blocked,
		s.Violations,
		s.Errors,
		s.AvgScanDuration,
		s.AvgProxyLatency,
		s.SeverityCounts.Critical,
		s.SeverityCounts.High,
		s.SeverityCounts.Medium,
		s.SeverityCounts.Low,
		s.SeverityCounts.Info,
	)
}
