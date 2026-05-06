//go:build !race

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// --------------------------------------------------------------------------
// A2A metric recording functions
// --------------------------------------------------------------------------

func TestA2ALicenseFailure(t *testing.T) {
	before := counterValue(t, a2aLicenseFailures, "test-license-agent")
	RecordA2ALicenseFailure("test-license-agent")
	after := counterValue(t, a2aLicenseFailures, "test-license-agent")
	if after != before+1 {
		t.Errorf("A2ALicenseFailure: expected counter to increment by 1, got before=%v after=%v", before, after)
	}
}

func TestA2ACapabilityDenial(t *testing.T) {
	before := counterValueTwoLabels(t, a2aCapabilityDenials, "test-cap-agent", "scan")
	RecordA2ACapabilityDenial("test-cap-agent", "scan")
	after := counterValueTwoLabels(t, a2aCapabilityDenials, "test-cap-agent", "scan")
	if after != before+1 {
		t.Errorf("A2ACapabilityDenial: expected counter to increment by 1, got before=%v after=%v", before, after)
	}
}

func TestA2AAuthFailure(t *testing.T) {
	before := counterValue(t, a2aAuthFailures, "test-auth-agent")
	RecordA2AAuthFailure("test-auth-agent")
	after := counterValue(t, a2aAuthFailures, "test-auth-agent")
	if after != before+1 {
		t.Errorf("A2AAuthFailure: expected counter to increment by 1, got before=%v after=%v", before, after)
	}
}

func TestA2AIntegrityFailure(t *testing.T) {
	before := counterValue(t, a2aIntegrityFailures, "test-integrity-agent")
	RecordA2AIntegrityFailure("test-integrity-agent")
	after := counterValue(t, a2aIntegrityFailures, "test-integrity-agent")
	if after != before+1 {
		t.Errorf("A2AIntegrityFailure: expected counter to increment by 1, got before=%v after=%v", before, after)
	}
}

// --------------------------------------------------------------------------
// Registry.Gather()
// --------------------------------------------------------------------------

func TestGather(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_gather_total",
		Help: "Test counter for Gather",
	})
	reg.MustRegister(counter)
	counter.Inc()

	result, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("Gather() returned empty result, expected at least one metric family")
	}

	// Verify result elements are *dto.MetricFamily
	for _, item := range result {
		mf, ok := item.(*dto.MetricFamily)
		if !ok {
			t.Errorf("Gather() returned %T, expected *dto.MetricFamily", item)
			continue
		}
		if mf.GetName() == "" {
			t.Error("Gather() returned MetricFamily with empty name")
		}
	}
}

func TestGather_ReturnsInterfaceSlice(t *testing.T) {
	reg := NewRegistry()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_gather_gauge",
		Help: "Test gauge for Gather return type",
	})
	reg.MustRegister(gauge)
	gauge.Set(42.0)

	result, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned unexpected error: %v", err)
	}

	// Confirm each element satisfies the interface{} type wrapping *dto.MetricFamily
	var found bool
	for _, item := range result {
		if mf, ok := item.(*dto.MetricFamily); ok && mf.GetName() == "test_gather_gauge" {
			found = true
			if len(mf.GetMetric()) != 1 {
				t.Errorf("expected 1 metric sample, got %d", len(mf.GetMetric()))
			}
		}
	}
	if !found {
		t.Error("Gather() result did not contain expected metric family 'test_gather_gauge'")
	}
}

// --------------------------------------------------------------------------
// Helpers: read counter values via Prometheus gather/parse
// --------------------------------------------------------------------------

// counterValue reads the current float64 value of a single-label CounterVec.
// This avoids racing with other tests by capturing before/after deltas.
func counterValue(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	var m prometheus.Metric = vec.WithLabelValues(label)
	ch := make(chan prometheus.Metric, 1)
	go func() {
		ch <- m
	}()
	metric := <-ch
	var pm dto.Metric
	if err := metric.Write(&pm); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	return pm.GetCounter().GetValue()
}

// counterValueTwoLabels reads the current float64 value of a two-label CounterVec.
func counterValueTwoLabels(t *testing.T, vec *prometheus.CounterVec, label1, label2 string) float64 {
	t.Helper()
	var m prometheus.Metric = vec.WithLabelValues(label1, label2)
	ch := make(chan prometheus.Metric, 1)
	go func() {
		ch <- m
	}()
	metric := <-ch
	var pm dto.Metric
	if err := metric.Write(&pm); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	return pm.GetCounter().GetValue()
}
