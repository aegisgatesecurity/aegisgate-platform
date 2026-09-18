// =========================================================================
// Test stub for anomaly_detect.go (P4: API Key Anomaly Detection)
// =========================================================================

package auth

import (
	"testing"
	"time"
)

func TestNewAnomalyDetector(t *testing.T) {
	ad := NewAnomalyDetector()
	if ad == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}
	if ad.threshold != AnomalyThreshold {
		t.Errorf("expected threshold=%.1f, got %.1f", AnomalyThreshold, ad.threshold)
	}
	if ad.minSamples != MinSamplesForBaseline {
		t.Errorf("expected minSamples=%d, got %d", MinSamplesForBaseline, ad.minSamples)
	}
}

func TestRecordUsage_CreatesBaseline(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.RecordUsage(KeyUsageRecord{
		KeyID:    "key-1",
		ToolName: "read_file",
		SourceIP: "10.0.0.1",
	})

	ad.mu.RLock()
	_, ok := ad.baselines["key-1"]
	ad.mu.RUnlock()
	if !ok {
		t.Fatal("baseline not created after RecordUsage")
	}
}

func TestRecordUsage_IncrementsCounts(t *testing.T) {
	ad := NewAnomalyDetector()
	ts := time.Date(2026, 9, 18, 14, 0, 0, 0, time.UTC)
	ad.RecordUsage(KeyUsageRecord{
		KeyID:     "key-1",
		Timestamp: ts,
		ToolName:  "read_file",
		SourceIP:  "10.0.0.1",
	})

	baseline, ok := ad.GetBaseline("key-1")
	if !ok {
		t.Fatal("baseline not found")
	}
	if baseline.RequestCount != 1 {
		t.Errorf("expected requestCount=1, got %d", baseline.RequestCount)
	}
	if baseline.HourlyCounts[14] != 1 {
		t.Errorf("expected hourlyCounts[14]=1, got %d", baseline.HourlyCounts[14])
	}
}

func TestCheckAnomaly_InsufficientSamples(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.minSamples = 10

	for i := 0; i < 5; i++ {
		ad.RecordUsage(KeyUsageRecord{
			KeyID:    "key-low",
			ToolName: "read_file",
		})
	}

	result := ad.CheckAnomaly("key-low", KeyUsageRecord{ToolName: "read_file"})
	if result.IsAnomalous {
		t.Error("should not flag anomaly with insufficient samples")
	}
}

func TestCheckAnomaly_NewTool(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.minSamples = 3

	for i := 0; i < 5; i++ {
		ad.RecordUsage(KeyUsageRecord{
			KeyID:    "key-newtool",
			ToolName: "read_file",
		})
	}

	result := ad.CheckAnomaly("key-newtool", KeyUsageRecord{ToolName: "delete_file"})
	if !result.IsAnomalous {
		t.Error("expected anomaly for new tool")
	}
	found := false
	for _, at := range result.Types {
		if at == AnomalyNewTool {
			found = true
		}
	}
	if !found {
		t.Error("expected AnomalyNewTool in types")
	}
}

func TestCheckAnomaly_NewIP(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.minSamples = 3

	for i := 0; i < 5; i++ {
		ad.RecordUsage(KeyUsageRecord{
			KeyID:    "key-ip",
			ToolName: "read_file",
			SourceIP: "10.0.0.1",
		})
	}

	result := ad.CheckAnomaly("key-ip", KeyUsageRecord{
		ToolName: "read_file",
		SourceIP: "192.168.1.99",
	})
	if !result.IsAnomalous {
		t.Error("expected anomaly for new IP")
	}
}

func TestCheckAnomaly_NoAnomaly(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.minSamples = 3

	for i := 0; i < 10; i++ {
		ad.RecordUsage(KeyUsageRecord{
			KeyID:    "key-normal",
			ToolName: "read_file",
			SourceIP: "10.0.0.1",
		})
	}

	result := ad.CheckAnomaly("key-normal", KeyUsageRecord{
		ToolName: "read_file",
		SourceIP: "10.0.0.1",
	})
	if result.IsAnomalous {
		t.Error("expected no anomaly for normal usage")
	}
}

func TestCheckAnomaly_NoBaseline(t *testing.T) {
	ad := NewAnomalyDetector()
	result := ad.CheckAnomaly("unknown", KeyUsageRecord{})
	if result.IsAnomalous {
		t.Error("expected no anomaly for unknown key")
	}
}

func TestComputeHourlyStats_Empty(t *testing.T) {
	ad := NewAnomalyDetector()
	baseline := &KeyBaseline{}
	mean, stddev := ad.computeHourlyStats(baseline)
	if mean != 0 || stddev != 0 {
		t.Errorf("expected 0,0 for empty baseline, got %.2f,%.2f", mean, stddev)
	}
}

func TestGetBaseline_NotFound(t *testing.T) {
	ad := NewAnomalyDetector()
	_, ok := ad.GetBaseline("unknown")
	if ok {
		t.Error("expected not found for unknown key")
	}
}

func TestCleanupExpired(t *testing.T) {
	ad := NewAnomalyDetector()
	ad.window = 50 * time.Millisecond

	ad.RecordUsage(KeyUsageRecord{KeyID: "key-old"})
	time.Sleep(100 * time.Millisecond)
	ad.RecordUsage(KeyUsageRecord{KeyID: "key-new"})

	removed := ad.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
}
