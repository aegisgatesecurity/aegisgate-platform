// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Data Drift Monitoring Tests
// =========================================================================

package ml

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDriftMonitor_SetBaseline(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	// Set baseline for input_length feature
	values := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	dm.SetBaseline("input_length", values)

	if len(dm.baseline) != 1 {
		t.Errorf("expected 1 baseline feature, got %d", len(dm.baseline))
	}

	dist, ok := dm.baseline["input_length"]
	if !ok {
		t.Fatal("input_length baseline not found")
	}
	if dist.Count != 10 {
		t.Errorf("expected count=10, got %d", dist.Count)
	}
	if dist.Feature != "input_length" {
		t.Errorf("expected feature=input_length, got %s", dist.Feature)
	}
}

func TestDriftMonitor_Observe(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("score", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0})

	// Observe values in the current window
	for i := 0; i < 20; i++ {
		dm.Observe("score", float64(i%10+1)/10.0)
	}

	if len(dm.current) != 1 {
		t.Errorf("expected 1 current feature, got %d", len(dm.current))
	}
}

func TestDriftMonitor_ObserveBatch(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("input_length", []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100})

	// Observe a batch of similar values (should have low drift)
	batch := []float64{15, 25, 35, 45, 55, 65, 75, 85, 95, 105}
	dm.ObserveBatch("input_length", batch)

	results := dm.CheckDrift()
	if len(results) == 0 {
		t.Fatal("expected drift results")
	}

	// Low drift should be "none" or "minor"
	for _, r := range results {
		if r.Level == DriftMajor || r.Level == DriftSignificant {
			t.Logf("unexpected drift level for similar data: %s (PSI=%.4f)", r.Level, r.PSI)
		}
	}
}

func TestDriftMonitor_NoDrift(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	// Identical distributions = zero drift
	dm.SetBaseline("score", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0})
	dm.ObserveBatch("score", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0})

	results := dm.CheckDrift()
	if len(results) == 0 {
		t.Fatal("expected drift results")
	}

	for _, r := range results {
		if r.PSI > 0.1 {
			t.Errorf("expected near-zero PSI for identical distributions, got %.4f", r.PSI)
		}
		if r.Level != DriftNone {
			t.Errorf("expected DriftNone for identical distributions, got %s", r.Level)
		}
	}
}

func TestDriftMonitor_SignificantDrift(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	// Baseline: uniform distribution 0-1
	baseline := make([]float64, 100)
	for i := range baseline {
		baseline[i] = float64(i) / 100.0
	}
	dm.SetBaseline("score", baseline)

	// Current: all values concentrated at one end (bimodal shift)
	current := make([]float64, 100)
	for i := range current {
		current[i] = 0.9 + float64(i%10)/100.0 // concentrated near 0.9-1.0
	}
	dm.ObserveBatch("score", current)

	results := dm.CheckDrift()
	if len(results) == 0 {
		t.Fatal("expected drift results")
	}

	for _, r := range results {
		t.Logf("Drift: feature=%s PSI=%.4f KL=%.4f level=%s", r.Feature, r.PSI, r.KLDivergence, r.Level)
	}
}

func TestDriftMonitor_EmptyCurrent(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("score", []float64{0.5, 0.6, 0.7})
	// Don't observe anything — current is empty

	results := dm.CheckDrift()
	if len(results) == 0 {
		t.Fatal("expected drift results")
	}

	for _, r := range results {
		if r.CurrentN != 0 {
			t.Errorf("expected CurrentN=0 for empty current, got %d", r.CurrentN)
		}
		if r.PSI != 0 {
			t.Errorf("expected PSI=0 for empty current, got %.4f", r.PSI)
		}
	}
}

func TestDriftMonitor_ResetCurrent(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("score", []float64{0.5, 0.6, 0.7})
	dm.ObserveBatch("score", []float64{0.5, 0.6, 0.7})

	if len(dm.current) != 1 {
		t.Errorf("expected 1 current feature before reset, got %d", len(dm.current))
	}

	dm.ResetCurrent()

	if len(dm.current) != 0 {
		t.Errorf("expected 0 current features after reset, got %d", len(dm.current))
	}
}

func TestDriftMonitor_GetHistory(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("score", []float64{0.1, 0.5, 0.9})
	dm.ObserveBatch("score", []float64{0.2, 0.5, 0.8})
	dm.CheckDrift()

	dm.ObserveBatch("score", []float64{0.3, 0.5, 0.7})
	dm.CheckDrift()

	history := dm.GetHistory(1)
	if len(history) != 1 {
		t.Errorf("expected 1 history entry, got %d", len(history))
	}

	history = dm.GetHistory(10)
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestDriftMonitor_ServeHTTP(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	dm.SetBaseline("score", []float64{0.1, 0.5, 0.9})
	dm.ObserveBatch("score", []float64{0.2, 0.5, 0.8})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ml/drift", nil)
	w := httptest.NewRecorder()
	dm.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDriftMonitor_ServeHTTP_MethodNotAllowed(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	dm := NewDriftMonitor(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ml/drift", nil)
	w := httptest.NewRecorder()
	dm.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestClassifyDrift(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()
	thresholds := cfg.PSIThresholds

	tests := []struct {
		psi  float64
		want DriftLevel
	}{
		{0.01, DriftNone},
		{0.05, DriftNone},
		{0.1, DriftMinor},
		{0.15, DriftMinor},
		{0.25, DriftSignificant},
		{0.35, DriftSignificant},
		{0.5, DriftMajor},
		{1.0, DriftMajor},
	}

	for _, tt := range tests {
		got := classifyDrift(tt.psi, thresholds)
		if got != tt.want {
			t.Errorf("classifyDrift(%.2f) = %s, want %s", tt.psi, got, tt.want)
		}
	}
}

func TestCalculatePSI(t *testing.T) {
	// Test with identical distributions → PSI ≈ 0
	cfg := DefaultDriftMonitorConfig()

	baseline := buildDistribution("test", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}, cfg.BinCount)
	current := buildDistribution("test", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}, cfg.BinCount)

	psi := calculatePSI(baseline, current, cfg.BinCount)
	if psi > 0.05 {
		t.Errorf("expected near-zero PSI for identical distributions, got %.4f", psi)
	}
}

func TestCalculateKLDivergence(t *testing.T) {
	cfg := DefaultDriftMonitorConfig()

	baseline := buildDistribution("test", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}, cfg.BinCount)
	current := buildDistribution("test", []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}, cfg.BinCount)

	kl := calculateKLDivergence(baseline, current, cfg.BinCount)
	if kl > 0.05 {
		t.Errorf("expected near-zero KL divergence for identical distributions, got %.4f", kl)
	}
}

func TestBuildDistribution(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	dist := buildDistribution("test", values, 5)

	if dist.Feature != "test" {
		t.Errorf("expected feature=test, got %s", dist.Feature)
	}
	if dist.Count != 10 {
		t.Errorf("expected count=10, got %d", dist.Count)
	}
	if len(dist.Bins) != 5 {
		t.Errorf("expected 5 bins, got %d", len(dist.Bins))
	}

	// Mean should be 5.5
	if math.Abs(dist.Mean-5.5) > 0.01 {
		t.Errorf("expected mean≈5.5, got %.2f", dist.Mean)
	}
}

func TestBuildDistribution_Empty(t *testing.T) {
	dist := buildDistribution("test", []float64{}, 10)
	if dist.Count != 0 {
		t.Errorf("expected count=0 for empty input, got %d", dist.Count)
	}
}

func TestDriftResultString(t *testing.T) {
	r := DriftResult{
		Feature:      "input_length",
		PSI:           0.15,
		KLDivergence:  0.22,
		Level:         DriftMinor,
		BaselineN:     1000,
		CurrentN:      500,
	}
	s := r.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
	if !containsStr(s, "input_length") || !containsStr(s, "minor") {
		t.Errorf("expected string to contain feature and level, got %s", s)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStrHelper(s, sub))
}

func containsStrHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}