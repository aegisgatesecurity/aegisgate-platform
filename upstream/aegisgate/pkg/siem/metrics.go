// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package siem provides integration with the metrics and reporting packages.
package siem

import (
	"sync"
	"time"
)

// ============================================================================
// Metrics Integration
// ============================================================================

// SIEMMetrics provides metrics collection for SIEM operations.
type SIEMMetrics struct {
	mu sync.RWMutex

	// Event counters by platform
	EventsSent     map[Platform]int64
	EventsFailed   map[Platform]int64
	EventsFiltered map[Platform]int64
	EventsDropped  map[Platform]int64

	// Latency tracking
	LatencyTotal map[Platform]time.Duration
	LatencyCount map[Platform]int64
	LatencyMax   map[Platform]time.Duration

	// Error tracking
	ErrorsByType map[Platform]map[string]int64

	// Buffer tracking
	BufferSize     map[Platform]int
	BufferCapacity map[Platform]int

	// Retry tracking
	Retries map[Platform]int64

	// Platform health status
	PlatformHealth map[Platform]HealthStatus

	// Last activity timestamps
	LastSendTime  map[Platform]time.Time
	LastErrorTime map[Platform]time.Time
	LastError     map[Platform]string
}

// HealthStatus represents the health status of a SIEM platform.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// NewSIEMMetrics creates a new SIEM metrics instance.
func NewSIEMMetrics() *SIEMMetrics {
	return &SIEMMetrics{
		EventsSent:     make(map[Platform]int64),
		EventsFailed:   make(map[Platform]int64),
		EventsFiltered: make(map[Platform]int64),
		EventsDropped:  make(map[Platform]int64),
		LatencyTotal:   make(map[Platform]time.Duration),
		LatencyCount:   make(map[Platform]int64),
		LatencyMax:     make(map[Platform]time.Duration),
		ErrorsByType:   make(map[Platform]map[string]int64),
		BufferSize:     make(map[Platform]int),
		BufferCapacity: make(map[Platform]int),
		Retries:        make(map[Platform]int64),
		PlatformHealth: make(map[Platform]HealthStatus),
		LastSendTime:   make(map[Platform]time.Time),
		LastErrorTime:  make(map[Platform]time.Time),
		LastError:      make(map[Platform]string),
	}
}

// RecordEvent records a successfully sent event.
func (m *SIEMMetrics) RecordEvent(platform Platform) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsSent[platform]++
	m.LastSendTime[platform] = time.Now()
	m.PlatformHealth[platform] = HealthStatusHealthy
}

// RecordFailure records a failed event send.
func (m *SIEMMetrics) RecordFailure(platform Platform, errType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsFailed[platform]++
	m.LastErrorTime[platform] = time.Now()
	m.LastError[platform] = errType

	// Initialize error type map if needed
	if m.ErrorsByType[platform] == nil {
		m.ErrorsByType[platform] = make(map[string]int64)
	}
	m.ErrorsByType[platform][errType]++

	// Update health status based on failure rate
	sent := m.EventsSent[platform]
	failed := m.EventsFailed[platform]
	if sent > 0 {
		failureRate := float64(failed) / float64(sent+failed)
		if failureRate > 0.5 {
			m.PlatformHealth[platform] = HealthStatusUnhealthy
		} else if failureRate > 0.1 {
			m.PlatformHealth[platform] = HealthStatusDegraded
		}
	}
}

// RecordFiltered records a filtered event.
func (m *SIEMMetrics) RecordFiltered(platform Platform) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsFiltered[platform]++
}

// RecordDropped records a dropped event.
func (m *SIEMMetrics) RecordDropped(platform Platform) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsDropped[platform]++
}

// RecordLatency records operation latency.
func (m *SIEMMetrics) RecordLatency(platform Platform, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LatencyTotal[platform] += duration
	m.LatencyCount[platform]++
	if duration > m.LatencyMax[platform] {
		m.LatencyMax[platform] = duration
	}
}

// RecordBufferStatus updates buffer tracking.
func (m *SIEMMetrics) RecordBufferStatus(platform Platform, size, capacity int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BufferSize[platform] = size
	m.BufferCapacity[platform] = capacity
}

// RecordRetry records a retry attempt.
func (m *SIEMMetrics) RecordRetry(platform Platform) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Retries[platform]++
}

// GetAverageLatency returns the average latency for a platform.
func (m *SIEMMetrics) GetAverageLatency(platform Platform) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := m.LatencyTotal[platform]
	count := m.LatencyCount[platform]
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// GetStats returns a snapshot of all metrics.
func (m *SIEMMetrics) GetStats() map[Platform]PlatformMetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[Platform]PlatformMetricsSnapshot)
	for platform := range m.EventsSent {
		result[platform] = PlatformMetricsSnapshot{
			EventsSent:     m.EventsSent[platform],
			EventsFailed:   m.EventsFailed[platform],
			EventsFiltered: m.EventsFiltered[platform],
			EventsDropped:  m.EventsDropped[platform],
			AvgLatency:     m.GetAverageLatency(platform),
			MaxLatency:     m.LatencyMax[platform],
			BufferSize:     m.BufferSize[platform],
			BufferCapacity: m.BufferCapacity[platform],
			Retries:        m.Retries[platform],
			HealthStatus:   m.PlatformHealth[platform],
			LastSendTime:   m.LastSendTime[platform],
			LastErrorTime:  m.LastErrorTime[platform],
			LastError:      m.LastError[platform],
		}
	}
	return result
}

// PlatformMetricsSnapshot is a point-in-time snapshot of platform metrics.
type PlatformMetricsSnapshot struct {
	EventsSent     int64
	EventsFailed   int64
	EventsFiltered int64
	EventsDropped  int64
	AvgLatency     time.Duration
	MaxLatency     time.Duration
	BufferSize     int
	BufferCapacity int
	Retries        int64
	HealthStatus   HealthStatus
	LastSendTime   time.Time
	LastErrorTime  time.Time
	LastError      string
}

// ============================================================================
// Reporting Integration
// ============================================================================

// SIEMReportGenerator generates SIEM-specific reports.
type SIEMReportGenerator struct {
	metrics *SIEMMetrics
	manager *Manager
}

// NewSIEMReportGenerator creates a new report generator.
func NewSIEMReportGenerator(metrics *SIEMMetrics, manager *Manager) *SIEMReportGenerator {
	return &SIEMReportGenerator{
		metrics: metrics,
		manager: manager,
	}
}

// GenerateSummaryReport generates a SIEM activity summary.
func (g *SIEMReportGenerator) GenerateSummaryReport(startTime, endTime time.Time) *SIEMSummaryReport {
	stats := g.metrics.GetStats()

	report := &SIEMSummaryReport{
		StartTime: startTime,
		EndTime:   endTime,
		Generated: time.Now(),
		Platforms: make(map[Platform]PlatformSummary),
	}

	var totalSent, totalFailed, totalDropped int64
	var totalLatency time.Duration
	var platformCount int

	for platform, snap := range stats {
		totalSent += snap.EventsSent
		totalFailed += snap.EventsFailed
		totalDropped += snap.EventsDropped
		totalLatency += snap.AvgLatency
		platformCount++

		report.Platforms[platform] = PlatformSummary{
			EventsSent:     snap.EventsSent,
			EventsFailed:   snap.EventsFailed,
			EventsFiltered: snap.EventsFiltered,
			EventsDropped:  snap.EventsDropped,
			AvgLatencyMs:   snap.AvgLatency.Milliseconds(),
			MaxLatencyMs:   snap.MaxLatency.Milliseconds(),
			HealthStatus:   string(snap.HealthStatus),
			LastSendTime:   snap.LastSendTime,
		}
	}

	report.TotalEvents = totalSent + totalFailed + totalDropped
	report.EventsSent = totalSent
	report.EventsFailed = totalFailed
	report.EventsDropped = totalDropped

	if platformCount > 0 {
		report.AvgLatencyMs = (totalLatency / time.Duration(platformCount)).Milliseconds()
	}

	if totalSent > 0 {
		report.SuccessRate = float64(totalSent) / float64(totalSent+totalFailed) * 100
	}

	return report
}

// SIEMSummaryReport represents a SIEM activity summary.
type SIEMSummaryReport struct {
	StartTime     time.Time                    `json:"start_time"`
	EndTime       time.Time                    `json:"end_time"`
	Generated     time.Time                    `json:"generated"`
	TotalEvents   int64                        `json:"total_events"`
	EventsSent    int64                        `json:"events_sent"`
	EventsFailed  int64                        `json:"events_failed"`
	EventsDropped int64                        `json:"events_dropped"`
	SuccessRate   float64                      `json:"success_rate"`
	AvgLatencyMs  int64                        `json:"avg_latency_ms"`
	Platforms     map[Platform]PlatformSummary `json:"platforms"`
}

// PlatformSummary is per-platform summary data.
type PlatformSummary struct {
	EventsSent     int64     `json:"events_sent"`
	EventsFailed   int64     `json:"events_failed"`
	EventsFiltered int64     `json:"events_filtered"`
	EventsDropped  int64     `json:"events_dropped"`
	AvgLatencyMs   int64     `json:"avg_latency_ms"`
	MaxLatencyMs   int64     `json:"max_latency_ms"`
	HealthStatus   string    `json:"health_status"`
	LastSendTime   time.Time `json:"last_send_time"`
}

// ============================================================================
// Global Metrics Instance
// ============================================================================

var (
	globalMetrics     *SIEMMetrics
	globalMetricsOnce sync.Once
)

// GlobalSIEMMetrics returns the global SIEM metrics instance.
func GlobalSIEMMetrics() *SIEMMetrics {
	globalMetricsOnce.Do(func() {
		globalMetrics = NewSIEMMetrics()
	})
	return globalMetrics
}

// SetGlobalSIEMMetrics sets the global SIEM metrics instance.
func SetGlobalSIEMMetrics(m *SIEMMetrics) {
	globalMetrics = m
}

// ============================================================================
// Metrics Hook for Manager
// ============================================================================

// MetricsHook provides hooks to record metrics during SIEM operations.
type MetricsHook struct {
	metrics *SIEMMetrics
}

// NewMetricsHook creates a new metrics hook.
func NewMetricsHook(metrics *SIEMMetrics) *MetricsHook {
	return &MetricsHook{metrics: metrics}
}

// OnEventSent is called when an event is successfully sent.
func (h *MetricsHook) OnEventSent(platform Platform, duration time.Duration) {
	h.metrics.RecordEvent(platform)
	h.metrics.RecordLatency(platform, duration)
}

// OnEventFailed is called when an event fails to send.
func (h *MetricsHook) OnEventFailed(platform Platform, err error) {
	errorType := "unknown"
	if siemErr, ok := err.(*Error); ok {
		errorType = siemErr.Operation
	}
	h.metrics.RecordFailure(platform, errorType)
}

// OnEventFiltered is called when an event is filtered.
func (h *MetricsHook) OnEventFiltered(platform Platform) {
	h.metrics.RecordFiltered(platform)
}

// OnEventDropped is called when an event is dropped.
func (h *MetricsHook) OnEventDropped(platform Platform) {
	h.metrics.RecordDropped(platform)
}

// OnRetry is called when a retry is attempted.
func (h *MetricsHook) OnRetry(platform Platform) {
	h.metrics.RecordRetry(platform)
}

// OnBufferUpdate is called when buffer status changes.
func (h *MetricsHook) OnBufferUpdate(platform Platform, size, capacity int) {
	h.metrics.RecordBufferStatus(platform, size, capacity)
}
