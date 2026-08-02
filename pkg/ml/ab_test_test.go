// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// A/B Testing Module - Tests
// =========================================================================

package ml_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ml"
)

func TestNewABTestManager(t *testing.T) {
	manager := ml.NewABTestManager()
	assert.NotNil(t, manager)
}

func TestCreateTest_Valid(t *testing.T) {
	manager := ml.NewABTestManager()

	config := ml.ABTestConfig{
		Name:                "Challenger Test v2",
		ChampionModelPath:   "/models/threat_v1.onnx",
		ChallengerModelPath: "/models/threat_v2.onnx",
		ChampionVersion:     "v1.0.0",
		ChallengerVersion:   "v2.0.0",
		TrafficSplitPct:     10,
		MinSampleSize:       500,
		ConfidenceLevel:     0.95,
		Duration:            7 * 24 * time.Hour,
		MetricThresholds: ml.ABTestThresholds{
			MaxFPRIncrease:        0.01,
			MinTPRImprovement:     0.05,
			MaxLatencyIncreasePct: 10,
			MaxDriftIncrease:      0.1,
		},
	}

	created, err := manager.CreateTest(config)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, config.Name, created.Name)
	assert.Equal(t, 10.0, created.TrafficSplitPct)
	assert.Equal(t, 500, created.MinSampleSize)
	assert.Equal(t, 0.95, created.ConfidenceLevel)
}

func TestCreateTest_InvalidTrafficSplit(t *testing.T) {
	manager := ml.NewABTestManager()

	tests := []struct {
		name   string
		split  float64
		errMsg string
	}{
		{"zero split", 0, "traffic split must be between"},
		{"negative split", -5, "traffic split must be between"},
		{"100% split", 100, "traffic split must be between"},
		{"over 99%", 99.5, "traffic split must be between"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := validABTestConfig()
			config.TrafficSplitPct = tc.split
			_, err := manager.CreateTest(config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestCreateTest_InvalidMinSampleSize(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 0
	_, err := manager.CreateTest(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum sample size must be >= 1")
}

func TestCreateTest_InvalidConfidence(t *testing.T) {
	manager := ml.NewABTestManager()

	tests := []struct {
		name       string
		confidence float64
	}{
		{"too low", 0.5},
		{"too high", 1.0},
		{"just below", 0.79},
		{"just above", 0.991},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := validABTestConfig()
			config.ConfidenceLevel = tc.confidence
			_, err := manager.CreateTest(config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "confidence level must be between")
		})
	}
}

func TestCreateTest_MissingModelPaths(t *testing.T) {
	manager := ml.NewABTestManager()

	t.Run("missing champion path", func(t *testing.T) {
		config := validABTestConfig()
		config.ChampionModelPath = ""
		_, err := manager.CreateTest(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "champion model path is required")
	})

	t.Run("missing challenger path", func(t *testing.T) {
		config := validABTestConfig()
		config.ChallengerModelPath = ""
		_, err := manager.CreateTest(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "challenger model path is required")
	})
}

func TestStartTest_Draft(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	status, err := manager.GetTestStatus(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestRunning, status)
}

func TestStartTest_AlreadyRunning(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStartTest_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	err := manager.StartTest("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRecordPrediction(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	prediction := ml.ABPrediction{
		TestID:           created.ID,
		InputHash:        "abc123",
		ChampionScore:    0.85,
		ChallengerScore:  0.92,
		ChampionThreat:   true,
		ChallengerThreat: true,
		GroundTruth:      true,
		RoutedTo:         "champion",
		LatencyMs:        2.5,
	}

	err = manager.RecordPrediction(prediction)
	require.NoError(t, err)
}

func TestRecordPrediction_Routing(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.TrafficSplitPct = 10 // 10% to challenger
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Record predictions with explicit routing.
	championPred := ml.ABPrediction{
		TestID:           created.ID,
		InputHash:        "input1",
		ChampionScore:    0.85,
		ChallengerScore:  0.90,
		ChampionThreat:   true,
		ChallengerThreat: true,
		GroundTruth:      true,
		RoutedTo:         "champion",
		LatencyMs:        2.5,
	}

	err = manager.RecordPrediction(championPred)
	require.NoError(t, err)
	assert.Equal(t, "champion", championPred.RoutedTo)
}

func TestRecordPrediction_TestNotFound(t *testing.T) {
	manager := ml.NewABTestManager()

	prediction := ml.ABPrediction{
		TestID:    "nonexistent",
		InputHash: "abc123",
	}
	err := manager.RecordPrediction(prediction)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetTestStatus(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	// Initially draft.
	status, err := manager.GetTestStatus(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestDraft, status)

	// After starting, should be running.
	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	status, err = manager.GetTestStatus(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestRunning, status)
}

func TestGetTestStatus_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	_, err := manager.GetTestStatus("nonexistent")
	assert.Error(t, err)
}

func TestGetTestMetrics(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 3
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Record predictions with known outcomes.
	predictions := []ml.ABPrediction{
		{
			TestID:           created.ID,
			InputHash:        "input1",
			ChampionScore:    0.85,
			ChallengerScore:  0.92,
			ChampionThreat:   true,
			ChallengerThreat: true,
			GroundTruth:      true,
			LatencyMs:        2.0,
		},
		{
			TestID:           created.ID,
			InputHash:        "input2",
			ChampionScore:    0.30,
			ChallengerScore:  0.25,
			ChampionThreat:   false,
			ChallengerThreat: false,
			GroundTruth:      false,
			LatencyMs:        1.5,
		},
		{
			TestID:           created.ID,
			InputHash:        "input3",
			ChampionScore:    0.70,
			ChallengerScore:  0.88,
			ChampionThreat:   false,
			ChallengerThreat: true,
			GroundTruth:      true,
			LatencyMs:        3.0,
		},
	}

	for _, p := range predictions {
		err := manager.RecordPrediction(p)
		require.NoError(t, err)
	}

	champion, challenger, err := manager.GetTestMetrics(created.ID)
	require.NoError(t, err)

	assert.Equal(t, 3, champion.TotalPredictions)
	assert.Equal(t, 3, challenger.TotalPredictions)

	// Champion: TP=1, TN=1, FP=0, FN=1 (missed ground-truth threat on input3)
	assert.Equal(t, 1, champion.TruePositives)
	assert.Equal(t, 1, champion.TrueNegatives)
	assert.Equal(t, 0, champion.FalsePositives)
	assert.Equal(t, 1, champion.FalseNegatives)

	// Challenger: TP=2, TN=1, FP=0, FN=0
	assert.Equal(t, 2, challenger.TruePositives)
	assert.Equal(t, 1, challenger.TrueNegatives)
	assert.Equal(t, 0, challenger.FalsePositives)
	assert.Equal(t, 0, challenger.FalseNegatives)

	// Verify derived metrics.
	assert.Greater(t, challenger.TPR, champion.TPR)
}

func TestGetTestMetrics_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	_, _, err := manager.GetTestMetrics("nonexistent")
	assert.Error(t, err)
}

func TestEvaluateTest_ChallengerWins(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 100
	config.ConfidenceLevel = 0.90
	config.MetricThresholds = ml.ABTestThresholds{
		MaxFPRIncrease:        0.02,
		MinTPRImprovement:     0.01,
		MaxLatencyIncreasePct: 50,
		MaxDriftIncrease:      0.5,
	}
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Record 100 predictions where challenger clearly outperforms.
	for i := 0; i < 100; i++ {
		// Challenger catches all threats, champion misses some.
		championThreat := i%10 != 0 // champion misses 10% of threats
		challengerThreat := true    // challenger catches all
		groundTruth := true

		prediction := ml.ABPrediction{
			TestID:           created.ID,
			InputHash:        "input",
			ChampionScore:    0.7,
			ChallengerScore:  0.95,
			ChampionThreat:   championThreat,
			ChallengerThreat: challengerThreat,
			GroundTruth:      groundTruth,
			LatencyMs:        2.0,
		}
		err := manager.RecordPrediction(prediction)
		require.NoError(t, err)
	}

	result, err := manager.EvaluateTest(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestCompleted, result.Status)
	assert.Equal(t, "challenger", result.Winner)
	assert.Less(t, result.ConfidencePValue, 0.10) // significant at 90% confidence
}

func TestEvaluateTest_ChampionRetains(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 100
	config.ConfidenceLevel = 0.80
	config.MetricThresholds = ml.ABTestThresholds{
		MaxFPRIncrease:        0.005, // very strict FPR threshold
		MinTPRImprovement:     0.05,
		MaxLatencyIncreasePct: 5,
		MaxDriftIncrease:      0.05,
	}
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Record 100 predictions where champion is clearly better:
	// Champion: TPR=0.857 (60/70), FPR=0.033 (1/30)
	// Challenger: TPR=0.714 (50/70), FPR=0.333 (10/30) — much worse
	for i := 0; i < 100; i++ {
		var championThreat, challengerThreat, groundTruth bool
		if i < 70 {
			// 70 true threats
			groundTruth = true
			championThreat = i < 60   // 60/70 TPR
			challengerThreat = i < 50 // 50/70 TPR (worse)
		} else {
			// 30 benign
			groundTruth = false
			championThreat = i < 71   // 1/30 FPR (better)
			challengerThreat = i < 80 // 10/30 FPR (worse)
		}

		prediction := ml.ABPrediction{
			TestID:           created.ID,
			InputHash:        "input",
			ChampionScore:    0.7,
			ChallengerScore:  0.75,
			ChampionThreat:   championThreat,
			ChallengerThreat: challengerThreat,
			GroundTruth:      groundTruth,
			LatencyMs:        2.0,
		}
		err := manager.RecordPrediction(prediction)
		require.NoError(t, err)
	}

	result, err := manager.EvaluateTest(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestCompleted, result.Status)
	assert.Equal(t, "champion", result.Winner)
}

func TestEvaluateTest_NoSignificantDifference(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 1000 // high min sample size
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Record only a few predictions (insufficient data).
	for i := 0; i < 10; i++ {
		prediction := ml.ABPrediction{
			TestID:           created.ID,
			InputHash:        "input",
			ChampionScore:    0.7,
			ChallengerScore:  0.75,
			ChampionThreat:   true,
			ChallengerThreat: true,
			GroundTruth:      true,
			LatencyMs:        2.0,
		}
		err := manager.RecordPrediction(prediction)
		require.NoError(t, err)
	}

	result, err := manager.EvaluateTest(created.ID)
	require.NoError(t, err)
	assert.Equal(t, "no_significant_difference", result.Winner)
	assert.Contains(t, result.Recommendation, "Insufficient data")
}

func TestEvaluateTest_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	_, err := manager.EvaluateTest("nonexistent")
	assert.Error(t, err)
}

func TestCancelTest(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	err = manager.CancelTest(created.ID)
	require.NoError(t, err)

	status, err := manager.GetTestStatus(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestCancelled, status)
}

func TestCancelTest_AlreadyCompleted(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 3
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	// Add minimum predictions.
	for i := 0; i < 3; i++ {
		prediction := ml.ABPrediction{
			TestID:           created.ID,
			InputHash:        "input",
			ChampionScore:    0.7,
			ChallengerScore:  0.75,
			ChampionThreat:   true,
			ChallengerThreat: true,
			GroundTruth:      true,
			LatencyMs:        2.0,
		}
		err := manager.RecordPrediction(prediction)
		require.NoError(t, err)
	}

	_, err = manager.EvaluateTest(created.ID)
	require.NoError(t, err)

	err = manager.CancelTest(created.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already completed")
}

func TestCancelTest_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	err := manager.CancelTest("nonexistent")
	assert.Error(t, err)
}

func TestListTests_ByStatus(t *testing.T) {
	manager := ml.NewABTestManager()

	// Create two tests.
	config1 := validABTestConfig()
	config1.Name = "Test 1"
	created1, err := manager.CreateTest(config1)
	require.NoError(t, err)

	config2 := validABTestConfig()
	config2.Name = "Test 2"
	created2, err := manager.CreateTest(config2)
	require.NoError(t, err)

	// Both should be in draft status.
	draftTests := manager.ListTests(ml.ABTestDraft)
	assert.Len(t, draftTests, 2)

	// Start one.
	err = manager.StartTest(created1.ID)
	require.NoError(t, err)

	runningTests := manager.ListTests(ml.ABTestRunning)
	assert.Len(t, runningTests, 1)
	assert.Equal(t, created1.ID, runningTests[0].ID)

	draftTests = manager.ListTests(ml.ABTestDraft)
	assert.Len(t, draftTests, 1)
	assert.Equal(t, created2.ID, draftTests[0].ID)
}

func TestListTests_All(t *testing.T) {
	manager := ml.NewABTestManager()

	config1 := validABTestConfig()
	config1.Name = "Test 1"
	_, err := manager.CreateTest(config1)
	require.NoError(t, err)

	config2 := validABTestConfig()
	config2.Name = "Test 2"
	_, err = manager.CreateTest(config2)
	require.NoError(t, err)

	allTests := manager.ListTests("")
	assert.Len(t, allTests, 2)
}

func TestGetResult(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 3
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		prediction := ml.ABPrediction{
			TestID:           created.ID,
			InputHash:        "input",
			ChampionScore:    0.7,
			ChallengerScore:  0.75,
			ChampionThreat:   true,
			ChallengerThreat: true,
			GroundTruth:      true,
			LatencyMs:        2.0,
		}
		err := manager.RecordPrediction(prediction)
		require.NoError(t, err)
	}

	_, err = manager.EvaluateTest(created.ID)
	require.NoError(t, err)

	result, err := manager.GetResult(created.ID)
	require.NoError(t, err)
	assert.Equal(t, ml.ABTestCompleted, result.Status)
	assert.NotEmpty(t, result.Winner)
	assert.Greater(t, result.SampleSize, 0)
}

func TestGetResult_NotFound(t *testing.T) {
	manager := ml.NewABTestManager()
	_, err := manager.GetResult("nonexistent")
	assert.Error(t, err)
}

func TestDefaultABTestConfig(t *testing.T) {
	config := ml.DefaultABTestConfig()
	assert.Equal(t, "Default A/B Test", config.Name)
	assert.Equal(t, 10.0, config.TrafficSplitPct)
	assert.Equal(t, 1000, config.MinSampleSize)
	assert.Equal(t, 0.95, config.ConfidenceLevel)
	assert.Equal(t, 7*24*time.Hour, config.Duration)
	assert.Equal(t, 0.01, config.MetricThresholds.MaxFPRIncrease)
	assert.Equal(t, 0.05, config.MetricThresholds.MinTPRImprovement)
	assert.Equal(t, 10.0, config.MetricThresholds.MaxLatencyIncreasePct)
	assert.Equal(t, 0.1, config.MetricThresholds.MaxDriftIncrease)
}

func TestABModelMetrics_Calculation(t *testing.T) {
	metrics := ml.ABModelMetrics{
		ModelVersion:     "v1.0",
		TotalPredictions: 100,
		TruePositives:    70,
		TrueNegatives:    20,
		FalsePositives:   5,
		FalseNegatives:   5,
	}

	ml.ComputeDerivedMetrics(&metrics)

	// TPR = TP / (TP + FN) = 70 / 75 = 0.9333...
	assert.InDelta(t, 0.9333, metrics.TPR, 0.01)

	// FPR = FP / (FP + TN) = 5 / 25 = 0.2
	assert.InDelta(t, 0.2, metrics.FPR, 0.01)

	// Precision = TP / (TP + FP) = 70 / 75 = 0.9333...
	assert.InDelta(t, 0.9333, metrics.Precision, 0.01)

	// F1 = 2 * P * R / (P + R) ≈ 0.9333
	assert.InDelta(t, 0.9333, metrics.F1Score, 0.01)
}

func TestABModelMetrics_ZeroDivision(t *testing.T) {
	// Test with zero counts to avoid division by zero.
	metrics := ml.ABModelMetrics{
		ModelVersion:     "v0.0",
		TotalPredictions: 0,
		TruePositives:    0,
		TrueNegatives:    0,
		FalsePositives:   0,
		FalseNegatives:   0,
	}

	ml.ComputeDerivedMetrics(&metrics)

	assert.Equal(t, 0.0, metrics.TPR)
	assert.Equal(t, 0.0, metrics.FPR)
	assert.Equal(t, 0.0, metrics.Precision)
	assert.Equal(t, 0.0, metrics.F1Score)
}

func TestABPrediction_Recording(t *testing.T) {
	manager := ml.NewABTestManager()

	config := validABTestConfig()
	config.MinSampleSize = 2
	created, err := manager.CreateTest(config)
	require.NoError(t, err)

	err = manager.StartTest(created.ID)
	require.NoError(t, err)

	now := time.Now().UTC()
	p1 := ml.ABPrediction{
		TestID:           created.ID,
		InputHash:        "hash1",
		Timestamp:        now,
		ChampionScore:    0.85,
		ChallengerScore:  0.92,
		ChampionThreat:   true,
		ChallengerThreat: true,
		GroundTruth:      true,
		RoutedTo:         "champion",
		LatencyMs:        2.5,
	}
	p2 := ml.ABPrediction{
		TestID:           created.ID,
		InputHash:        "hash2",
		Timestamp:        now.Add(time.Second),
		ChampionScore:    0.30,
		ChallengerScore:  0.25,
		ChampionThreat:   false,
		ChallengerThreat: false,
		GroundTruth:      false,
		RoutedTo:         "champion",
		LatencyMs:        1.8,
	}

	err = manager.RecordPrediction(p1)
	require.NoError(t, err)

	err = manager.RecordPrediction(p2)
	require.NoError(t, err)

	champion, challenger, err := manager.GetTestMetrics(created.ID)
	require.NoError(t, err)

	// Both models see the same predictions.
	assert.Equal(t, 2, champion.TotalPredictions)
	assert.Equal(t, 2, challenger.TotalPredictions)

	// Champion: TP=1, TN=1, FP=0, FN=0
	assert.Equal(t, 1, champion.TruePositives)
	assert.Equal(t, 1, champion.TrueNegatives)
	assert.Equal(t, 0, champion.FalsePositives)
	assert.Equal(t, 0, champion.FalseNegatives)

	// Challenger: TP=1, TN=1, FP=0, FN=0
	assert.Equal(t, 1, challenger.TruePositives)
	assert.Equal(t, 1, challenger.TrueNegatives)
	assert.Equal(t, 0, challenger.FalsePositives)
	assert.Equal(t, 0, challenger.FalseNegatives)
}

// validABTestConfig returns a valid A/B test configuration for testing.
func validABTestConfig() ml.ABTestConfig {
	return ml.ABTestConfig{
		Name:                "Test A/B",
		ChampionModelPath:   "/models/champion_v1.onnx",
		ChallengerModelPath: "/models/challenger_v2.onnx",
		ChampionVersion:     "v1.0.0",
		ChallengerVersion:   "v2.0.0",
		TrafficSplitPct:     10,
		MinSampleSize:       500,
		ConfidenceLevel:     0.95,
		Duration:            7 * 24 * time.Hour,
		MetricThresholds: ml.ABTestThresholds{
			MaxFPRIncrease:        0.01,
			MinTPRImprovement:     0.05,
			MaxLatencyIncreasePct: 10,
			MaxDriftIncrease:      0.1,
		},
	}
}
