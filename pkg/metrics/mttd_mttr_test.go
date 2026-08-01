// SPDX-License-Identifier: Apache-2.0
// MTTD/MTTR Metrics Tests

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewMTTDRecorder(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)
	if r == nil {
		t.Fatal("NewMTTDRecorder returned nil")
	}
	if !r.registered {
		t.Error("expected registered to be true")
	}
}

func TestNewMTTDRecorder_NilRegisterer(t *testing.T) {
	r := NewMTTDRecorder(nil)
	if r == nil {
		t.Fatal("NewMTTDRecorder with nil registerer returned nil")
	}
	if r.registered {
		t.Error("expected registered to be false with nil registerer")
	}
}

func TestRecordDetection(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)

	r.RecordDetection("ATLAS", "T1535", "critical", 150*time.Millisecond)

	count := testutil.CollectAndCount(r.mttd)
	if count != 1 {
		t.Errorf("expected 1 mttd observation, got %d", count)
	}
}

func TestRecordResponse(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)

	r.RecordResponse("ATLAS", "T1535", "critical", 500*time.Millisecond)

	count := testutil.CollectAndCount(r.mttr)
	if count != 1 {
		t.Errorf("expected 1 mttr observation, got %d", count)
	}
}

func TestRecordIncident(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)

	r.RecordIncident("ATLAS", "T1535", "critical", "blocked")
	r.RecordIncident("ATLAS", "T1535", "critical", "blocked")
	r.RecordIncident("OWASP", "LLM01", "high", "detected")

	blocked := testutil.ToFloat64(r.incidents.WithLabelValues("ATLAS", "T1535", "critical", "blocked"))
	if blocked != 2 {
		t.Errorf("expected 2 blocked incidents, got %v", blocked)
	}

	detected := testutil.ToFloat64(r.incidents.WithLabelValues("OWASP", "LLM01", "high", "detected"))
	if detected != 1 {
		t.Errorf("expected 1 detected incident, got %v", detected)
	}
}

func TestRecordDetectionLatency(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)

	r.RecordDetectionLatency("ATLAS", "regex", 5*time.Millisecond)
	r.RecordDetectionLatency("ATLAS", "ml", 25*time.Millisecond)

	count := testutil.CollectAndCount(r.detectLat)
	if count != 2 {
		t.Errorf("expected 2 detection latency observations, got %d", count)
	}
}

func TestRecord_NoPanicWhenUnregistered(t *testing.T) {
	r := NewMTTDRecorder(nil)

	// Should not panic
	r.RecordDetection("ATLAS", "T1535", "critical", 100*time.Millisecond)
	r.RecordResponse("ATLAS", "T1535", "critical", 200*time.Millisecond)
	r.RecordIncident("ATLAS", "T1535", "critical", "blocked")
	r.RecordDetectionLatency("ATLAS", "regex", 5*time.Millisecond)
}

func TestMultipleDetections(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewMTTDRecorder(reg)

	for i := 0; i < 10; i++ {
		r.RecordDetection("ATLAS", "T1535", "critical", time.Duration(i+1)*10*time.Millisecond)
	}

	// Verify that observations were recorded by checking the histogram count
	metricCh := make(chan prometheus.Metric, 10)
	r.mttd.Collect(metricCh)
	close(metricCh)

	// Should have 1 metric series (one label combination)
	count := 0
	for range metricCh {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 metric series, got %d", count)
	}
}