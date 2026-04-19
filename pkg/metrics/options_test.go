package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRegisterCollector(t *testing.T) {
	reg := NewRegistry()
	opts := &Options{Registry: reg}

	// Create a test collector
	summary := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "test_summary",
		Help: "Test summary",
	})

	// This should not panic
	opts.registerCollector(summary)
}
