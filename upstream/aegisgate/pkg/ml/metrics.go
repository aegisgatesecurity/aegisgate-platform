// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

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

package ml

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricsExporter exports ML metrics to Prometheus
type MetricsExporter struct {
	mu sync.RWMutex

	// Middleware metrics
	totalRequests     prometheus.Counter
	analyzedRequests  prometheus.Counter
	blockedRequests   prometheus.Counter
	anomalyDetections *prometheus.CounterVec

	// Prompt injection metrics
	piScanned    prometheus.Counter
	piDetections prometheus.Counter
	piBlocks     prometheus.Counter
	piByPattern  *prometheus.CounterVec

	// Content analysis metrics
	contentAnalyzed   prometheus.Counter
	contentViolations prometheus.Counter
	contentByType     *prometheus.CounterVec

	// Behavioral metrics
	behaviorClients   prometheus.Gauge
	behaviorAnomalies prometheus.Counter
	behaviorByType    *prometheus.CounterVec

	// Latency metrics
	analysisDuration *prometheus.HistogramVec

	// Configuration
	sensitivity string
}

// NewMetricsExporter creates a new ML metrics exporter
func NewMetricsExporter(sensitivity string) *MetricsExporter {
	e := &MetricsExporter{
		sensitivity: sensitivity,
	}

	// Middleware metrics
	e.totalRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_total_requests_total",
		Help: "Total number of requests processed by ML middleware",
	})

	e.analyzedRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_analyzed_requests_total",
		Help: "Total number of requests analyzed by ML middleware",
	})

	e.blockedRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_blocked_requests_total",
		Help: "Total number of requests blocked by ML middleware",
	})

	e.anomalyDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_anomaly_detections_total",
			Help: "Total number of anomaly detections by type",
		},
		[]string{"type", "severity"},
	)

	// Prompt injection metrics
	e.piScanned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_prompt_injection_scanned_total",
		Help: "Total number of prompts scanned for injection",
	})

	e.piDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_prompt_injection_detections_total",
		Help: "Total number of prompt injection detections",
	})

	e.piBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_prompt_injection_blocked_total",
		Help: "Total number of prompt injection attempts blocked",
	})

	e.piByPattern = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_prompt_injection_by_pattern_total",
			Help: "Prompt injection detections by pattern",
		},
		[]string{"pattern"},
	)

	// Content analysis metrics
	e.contentAnalyzed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_content_analyzed_total",
		Help: "Total number of content items analyzed",
	})

	e.contentViolations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_content_violations_total",
		Help: "Total number of content policy violations",
	})

	e.contentByType = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_content_violations_by_type_total",
			Help: "Content violations by type (PII, secrets, etc)",
		},
		[]string{"type"},
	)

	// Behavioral metrics
	e.behaviorClients = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aegisgate_ml_behavioral_clients_active",
		Help: "Number of active clients being tracked",
	})

	e.behaviorAnomalies = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_ml_behavioral_anomalies_total",
		Help: "Total number of behavioral anomalies detected",
	})

	e.behaviorByType = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_behavioral_anomalies_by_type_total",
			Help: "Behavioral anomalies by type",
		},
		[]string{"type"},
	)

	// Latency metrics
	e.analysisDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_ml_analysis_duration_seconds",
			Help:    "Time spent on ML analysis",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"type"},
	)

	return e
}

// RecordRequest records a request processed by ML middleware
func (e *MetricsExporter) RecordRequest(analyzed, blocked bool) {
	e.totalRequests.Inc()
	if analyzed {
		e.analyzedRequests.Inc()
	}
	if blocked {
		e.blockedRequests.Inc()
	}
}

// RecordAnomaly records an anomaly detection
func (e *MetricsExporter) RecordAnomaly(anomalyType string, severity int) {
	e.anomalyDetections.WithLabelValues(anomalyType, strconv.Itoa(severity)).Inc()
}

// RecordPromptInjection records a prompt injection detection
func (e *MetricsExporter) RecordPromptInjection(detection *DetectionResult, blocked bool) {
	e.piScanned.Inc()
	if detection.IsInjection {
		e.piDetections.Inc()
		for _, pattern := range detection.MatchedPatterns {
			e.piByPattern.WithLabelValues(pattern).Inc()
		}
		if blocked {
			e.piBlocks.Inc()
		}
	}
}

// RecordContentAnalysis records content analysis results
func (e *MetricsExporter) RecordContentAnalysis(result *AnalysisResult) {
	e.contentAnalyzed.Inc()
	if result.IsViolation {
		e.contentViolations.Inc()
		for _, vtype := range result.ViolationTypes {
			e.contentByType.WithLabelValues(vtype).Inc()
		}
	}
}

// RecordBehavioralAnalysis records behavioral analysis results
func (e *MetricsExporter) RecordBehavioralAnalysis(result *BehavioralResult, activeClients int) {
	e.behaviorClients.Set(float64(activeClients))
	if result.IsAnomaly {
		e.behaviorAnomalies.Inc()
		e.behaviorByType.WithLabelValues(result.AnomalyType).Inc()
	}
}

// RecordAnalysisDuration records the duration of ML analysis
func (e *MetricsExporter) RecordAnalysisDuration(analysisType string, duration time.Duration) {
	e.analysisDuration.WithLabelValues(analysisType).Observe(duration.Seconds())
}

// UpdateFromStats updates metrics from stats
func (e *MetricsExporter) UpdateFromStats(stats map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Update middleware stats
	if ms, ok := stats["middleware"].(map[string]interface{}); ok {
		if v, ok := ms["total_requests"].(int64); ok {
			e.totalRequests.Add(float64(v))
		}
		if v, ok := ms["analyzed_requests"].(int64); ok {
			e.analyzedRequests.Add(float64(v))
		}
		if v, ok := ms["blocked_requests"].(int64); ok {
			e.blockedRequests.Add(float64(v))
		}
	}

	// Update prompt injection stats
	if pis, ok := stats["prompt_injection"].(map[string]interface{}); ok {
		if v, ok := pis["total_scanned"].(int64); ok {
			e.piScanned.Add(float64(v))
		}
		if v, ok := pis["threats_detected"].(int64); ok {
			e.piDetections.Add(float64(v))
		}
		if v, ok := pis["by_pattern"].(map[string]int64); ok {
			for pattern, count := range v {
				e.piByPattern.WithLabelValues(pattern).Add(float64(count))
			}
		}
	}

	// Update content analysis stats
	if cas, ok := stats["content_analysis"].(map[string]interface{}); ok {
		if v, ok := cas["total_analyzed"].(int64); ok {
			e.contentAnalyzed.Add(float64(v))
		}
		if v, ok := cas["violations_found"].(int64); ok {
			e.contentViolations.Add(float64(v))
		}
		if v, ok := cas["by_type"].(map[string]int64); ok {
			for vtype, count := range v {
				e.contentByType.WithLabelValues(vtype).Add(float64(count))
			}
		}
	}

	// Update behavioral stats
	if bas, ok := stats["behavioral_analysis"].(map[string]interface{}); ok {
		if v, ok := bas["active_clients"].(int); ok {
			e.behaviorClients.Set(float64(v))
		}
		if v, ok := bas["total_anomalies"].(int64); ok {
			e.behaviorAnomalies.Add(float64(v))
		}
	}
}

// SetSensitivity updates the sensitivity label
func (e *MetricsExporter) SetSensitivity(sensitivity string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sensitivity = sensitivity
}

// PrometheusMetrics returns all ML-related Prometheus metrics
var (
	// Middleware metrics
	MLTotalRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_total_requests_total",
			Help: "Total number of requests processed by ML middleware",
		},
		[]string{"sensitivity"},
	)

	MLAnalyzedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_analyzed_requests_total",
			Help: "Total number of requests analyzed by ML middleware",
		},
		[]string{"sensitivity"},
	)

	MLBlockedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_blocked_requests_total",
			Help: "Total number of requests blocked by ML middleware",
		},
		[]string{"sensitivity", "reason"},
	)

	MLAnomalyDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_anomaly_detections_total",
			Help: "Total number of anomaly detections",
		},
		[]string{"type", "severity", "blocked"},
	)

	// Prompt injection metrics
	MLPromptInjectionScanned = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_prompt_injection_scanned_total",
			Help: "Total number of prompts scanned for injection",
		},
		[]string{"sensitivity"},
	)

	MLPromptInjectionDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_prompt_injection_detections_total",
			Help: "Total number of prompt injection detections",
		},
		[]string{"sensitivity", "pattern", "severity"},
	)

	// Content analysis metrics
	MLContentAnalyzed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_content_analyzed_total",
			Help: "Total number of content items analyzed",
		},
		[]string{"sensitivity"},
	)

	MLContentViolations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_content_violations_total",
			Help: "Total number of content policy violations",
		},
		[]string{"sensitivity", "type"},
	)

	// Behavioral metrics
	MLBehavioralClients = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aegisgate_ml_behavioral_clients_active",
			Help: "Number of active clients being tracked",
		},
		[]string{},
	)

	MLBehavioralAnomalies = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_ml_behavioral_anomalies_total",
			Help: "Total number of behavioral anomalies",
		},
		[]string{"type", "client"},
	)

	// Latency metrics
	MLAnalysisDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_ml_analysis_duration_seconds",
			Help:    "Time spent on ML analysis",
			Buckets: []float64{.0001, .0005, .001, .005, .01, .05, .1, .5, 1},
		},
		[]string{"type"},
	)
)

// RecordMLMetrics records metrics for a single ML analysis
func RecordMLMetrics(metricsType, sensitivity string, duration time.Duration, blocked bool) {
	MLAnalyzedRequests.WithLabelValues(sensitivity).Inc()
	if blocked {
		MLBlockedRequests.WithLabelValues(sensitivity, metricsType).Inc()
	}

	MLAnalysisDuration.WithLabelValues(metricsType).Observe(duration.Seconds())
}

// RecordPromptInjectionMetrics records prompt injection specific metrics
func RecordPromptInjectionMetrics(detection *DetectionResult, sensitivity string, duration time.Duration) {
	MLPromptInjectionScanned.WithLabelValues(sensitivity).Inc()

	if detection.IsInjection {
		for _, pattern := range detection.MatchedPatterns {
			MLPromptInjectionDetections.WithLabelValues(
				sensitivity,
				pattern,
				fmt.Sprintf("%d", detection.Severity),
			).Inc()
		}
	}

	MLAnalysisDuration.WithLabelValues("prompt_injection").Observe(duration.Seconds())
}

// RecordContentMetrics records content analysis metrics
func RecordContentMetrics(result *AnalysisResult, sensitivity string, duration time.Duration) {
	MLContentAnalyzed.WithLabelValues(sensitivity).Inc()

	if result.IsViolation {
		for _, vtype := range result.ViolationTypes {
			MLContentViolations.WithLabelValues(sensitivity, vtype).Inc()
		}
	}

	MLAnalysisDuration.WithLabelValues("content_analysis").Observe(duration.Seconds())
}

// RecordBehavioralMetrics records behavioral analysis metrics
func RecordBehavioralMetrics(result *BehavioralResult, clientID string, duration time.Duration) {
	if result.IsAnomaly {
		MLBehavioralAnomalies.WithLabelValues(result.AnomalyType, clientID).Inc()
	}

	MLAnalysisDuration.WithLabelValues("behavioral_analysis").Observe(duration.Seconds())
}
