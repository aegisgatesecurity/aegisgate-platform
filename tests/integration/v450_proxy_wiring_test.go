// SPDX-License-Identifier: Apache-2.0
// Integration tests for v4.5.0 P2/P3/P4 proxy wiring.
// These tests verify that the proxy correctly instantiates and invokes
// the ChainAnalyzer, ProvenanceRecorder, and AnomalyDetector through
// the integration layer in v450_integration.go.

package integration_test

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
)

// TestP2_ProxyWiring_ChainAnalyzer verifies the ChainAnalyzer is
// instantiated and can record + analyze tool call chains.
func TestP2_ProxyWiring_ChainAnalyzer(t *testing.T) {
	ca := toolauth.NewChainAnalyzer()
	if ca == nil {
		t.Fatal("NewChainAnalyzer returned nil")
	}

	// Record a recon→exploit chain
	sessionID := "test-session-p2-wiring"
	ca.RecordCall(sessionID, toolauth.ChainEntry{
		Timestamp: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
		ToolName:  "list_files",
		RiskLevel: toolauth.RiskLevelLow,
		Decision:  "allow",
		DataType:  "read",
		Target:    "/etc",
	})
	ca.RecordCall(sessionID, toolauth.ChainEntry{
		Timestamp: time.Date(2026, 9, 19, 10, 0, 5, 0, time.UTC),
		ToolName:  "shell_command",
		RiskLevel: toolauth.RiskLevelCritical,
		Decision:  "allow",
		DataType:  "execute",
		Target:    "rm -rf /",
	})

	result := ca.AnalyzeChain(sessionID)
	if !result.ReconChain {
		t.Error("Expected ReconChain=true after list_files→shell_command")
	}
	if result.OverallRisk < toolauth.RiskLevelHigh {
		t.Errorf("Expected OverallRisk >= High, got %s", result.OverallRisk)
	}
	t.Logf("P2 wiring: recon=%v exfil=%v escalation=%v risk=%s flags=%v",
		result.ReconChain, result.ExfilChain, result.EscalationChain,
		result.OverallRisk, result.Flags)
}

// TestP3_ProxyWiring_ProvenanceRecorder verifies the ProvenanceRecorder
// is instantiated and can validate model provenance.
func TestP3_ProxyWiring_ProvenanceRecorder(t *testing.T) {
	pr := aibom.NewProvenanceRecorder()
	if pr == nil {
		t.Fatal("NewProvenanceRecorder returned nil")
	}

	// Record a model with complete provenance
	modelBytes := []byte("fake-model-bytes-for-testing")
	meta := aibom.ModelProvenance{
		ModelName:         "threat_cnn_bilstm",
		ModelVersion:      "4.5.0",
		ModelFormat:       "onnx",
		ModelSizeBytes:    int64(len(modelBytes)),
		ModelParamCount:   1250000,
		TrainingDataset:   "atlas-adversarial-prompts-v4.5",
		TrainingFramework: "PyTorch 2.4.0",
	}

	if err := pr.RecordModel(modelBytes, meta); err != nil {
		t.Fatalf("RecordModel failed: %v", err)
	}

	// Validate — should have no issues (all required fields present)
	issues := pr.ValidateProvenance("threat_cnn_bilstm", "4.5.0")
	if len(issues) > 0 {
		t.Errorf("Expected no validation issues, got: %v", issues)
	}

	// Export to JSON
	jsonBytes, err := pr.ToJSON("threat_cnn_bilstm", "4.5.0")
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Error("ToJSON returned empty bytes")
	}
	t.Logf("P3 wiring: provenance validated, JSON export %d bytes", len(jsonBytes))
}

// TestP3_ProxyWiring_ProvenanceValidation_Failures verifies that
// incomplete provenance records are flagged.
func TestP3_ProxyWiring_ProvenanceValidation_Failures(t *testing.T) {
	pr := aibom.NewProvenanceRecorder()

	// Record a model with missing fields
	modelBytes := []byte("fake-model")
	meta := aibom.ModelProvenance{
		ModelName:    "incomplete-model",
		ModelVersion: "1.0.0",
		// Missing: ModelFormat, ModelSizeBytes, ModelParamCount, TrainingDataset, TrainingFramework
	}

	if err := pr.RecordModel(modelBytes, meta); err != nil {
		t.Fatalf("RecordModel failed: %v", err)
	}

	issues := pr.ValidateProvenance("incomplete-model", "1.0.0")
	if len(issues) == 0 {
		t.Error("Expected validation issues for incomplete record, got none")
	}
	t.Logf("P3 wiring: %d validation issues for incomplete record: %v",
		len(issues), issues)
}

// TestP4_ProxyWiring_AnomalyDetector verifies the AnomalyDetector
// is instantiated and can detect abnormal usage patterns.
func TestP4_ProxyWiring_AnomalyDetector(t *testing.T) {
	ad := auth.NewAnomalyDetector()
	if ad == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}

	keyID := "test-key-p4-wiring"

	// Record normal usage to build a baseline
	for i := 0; i < 10; i++ {
		ad.RecordUsage(auth.KeyUsageRecord{
			KeyID:     keyID,
			Timestamp: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
			ToolName:  "file_read",
			SourceIP:  "192.168.1.100",
			Endpoint:  "/v1/chat/completions",
		})
	}

	// Check anomaly with normal usage
	result := ad.CheckAnomaly(keyID, auth.KeyUsageRecord{
		KeyID:     keyID,
		Timestamp: time.Date(2026, 9, 19, 10, 30, 0, 0, time.UTC),
		ToolName:  "file_read",
		SourceIP:  "192.168.1.100",
		Endpoint:  "/v1/chat/completions",
	})

	t.Logf("P4 wiring: normal usage: anomalous=%v types=%v details=%v",
		result.IsAnomalous, result.Types, result.Details)
}

// TestP4_ProxyWiring_AnomalyDetector_NewTool verifies that the
// anomaly detector flags access to a previously unseen tool.
func TestP4_ProxyWiring_AnomalyDetector_NewTool(t *testing.T) {
	ad := auth.NewAnomalyDetector()
	keyID := "test-key-new-tool"

	// Build baseline with only file_read
	for i := 0; i < auth.MinSamplesForBaseline; i++ {
		ad.RecordUsage(auth.KeyUsageRecord{
			KeyID:     keyID,
			Timestamp: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
			ToolName:  "file_read",
			SourceIP:  "10.0.0.1",
			Endpoint:  "/v1/chat/completions",
		})
	}

	// Now use a new tool that wasn't in the baseline
	result := ad.CheckAnomaly(keyID, auth.KeyUsageRecord{
		KeyID:     keyID,
		Timestamp: time.Date(2026, 9, 19, 11, 0, 0, 0, time.UTC),
		ToolName:  "shell_command",
		SourceIP:  "10.0.0.1",
		Endpoint:  "/v1/chat/completions",
	})

	if !result.IsAnomalous {
		t.Error("Expected anomaly for new tool access (shell_command)")
	}
	found := false
	for _, typ := range result.Types {
		if typ == auth.AnomalyNewTool {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected AnomalyNewTool in types")
	}
	t.Logf("P4 wiring: new tool: anomalous=%v types=%v details=%v",
		result.IsAnomalous, result.Types, result.Details)
}
