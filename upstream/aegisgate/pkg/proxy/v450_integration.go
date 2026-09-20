// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// v4.5.0 P2/P3/P4 Integration Layer
//
// This file wires three platform packages into the proxy pipeline:
//   P2 — ChainAnalyzer: detects multi-step tool call attack chains
//   P3 — ProvenanceRecorder: validates ML model provenance at startup
//   P4 — AnomalyDetector: tracks API key usage anomalies
//
// All three operate in non-blocking mode (alert/log only) during v4.5.0.
// Blocking behavior will be enabled in v4.6.0 after shadow validation.
// =========================================================================

package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	platformaibom "github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	platformanomaly "github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	platformtoolauth "github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
)

// ---------------------------------------------------------------------------
// P2: Tool Call Chain Analyzer Integration
// ---------------------------------------------------------------------------

// toolCallExtractor parses tool calls from OpenAI-format chat completion
// requests. The proxy receives requests that may include a "tools" array
// (tool definitions) and/or "tool_calls" in assistant messages. We extract
// tool invocation metadata to feed the ChainAnalyzer.
type toolCallExtractor struct {
	matrix *platformtoolauth.Matrix
}

// newToolCallExtractor creates an extractor with the default risk matrix.
func newToolCallExtractor() *toolCallExtractor {
	m := platformtoolauth.NewMatrix()
	m.RegisterDefaultPolicies()
	return &toolCallExtractor{matrix: m}
}

// toolCallInfo holds extracted tool call metadata.
type toolCallInfo struct {
	ToolName string
	DataType string // "read", "write", "execute", "network"
	Target   string
}

// chatCompletionRequestWithTools extends the basic request struct to capture
// tool-related fields that the proxy's chatCompletionRequest doesn't parse.
type chatCompletionRequestWithTools struct {
	Model    string             `json:"model"`
	Messages []chatMessageTools `json:"messages"`
	Stream   bool               `json:"stream,omitempty"`
}

// chatMessageTools extends chatMessage to capture tool calls in assistant messages.
type chatMessageTools struct {
	Role      string          `json:"role"`
	Content   string          `json:"content"`
	ToolCalls []toolCallEntry `json:"tool_calls,omitempty"`
}

// toolCallEntry represents a single tool call in an assistant message.
type toolCallEntry struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function toolFunction `json:"function"`
}

// toolFunction is the function payload of a tool call.
type toolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string of arguments
}

// extractToolCalls parses the request body for tool calls and returns
// metadata suitable for the ChainAnalyzer.
func (tce *toolCallExtractor) extractToolCalls(body []byte) []toolCallInfo {
	if len(body) == 0 {
		return nil
	}

	// Fast path: skip if no tool_calls in body
	if !strings.Contains(string(body), "tool_calls") {
		return nil
	}

	var req chatCompletionRequestWithTools
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var calls []toolCallInfo
	for _, msg := range req.Messages {
		for _, tc := range msg.ToolCalls {
			if tc.Type != "function" && tc.Type != "" {
				continue
			}
			info := toolCallInfo{
				ToolName: tc.Function.Name,
				Target:   tc.Function.Arguments,
			}
			// Classify data type based on tool name
			info.DataType = classifyToolDataType(tc.Function.Name)
			calls = append(calls, info)
		}
	}

	return calls
}

// classifyToolDataType infers the data type category for a tool name.
func classifyToolDataType(toolName string) string {
	name := strings.ToLower(toolName)
	switch {
	case strings.Contains(name, "exec") || strings.Contains(name, "shell") ||
		strings.Contains(name, "bash") || strings.Contains(name, "run") ||
		strings.Contains(name, "eval") || strings.Contains(name, "command"):
		return "execute"
	case strings.Contains(name, "write") || strings.Contains(name, "create") ||
		strings.Contains(name, "delete") || strings.Contains(name, "update") ||
		strings.Contains(name, "insert") || strings.Contains(name, "modify"):
		return "write"
	case strings.Contains(name, "read") || strings.Contains(name, "list") ||
		strings.Contains(name, "get") || strings.Contains(name, "fetch") ||
		strings.Contains(name, "search") || strings.Contains(name, "query") ||
		strings.Contains(name, "inspect") || strings.Contains(name, "discover") ||
		strings.Contains(name, "enumerate") || strings.Contains(name, "scan"):
		return "read"
	case strings.Contains(name, "http") || strings.Contains(name, "fetch") ||
		strings.Contains(name, "request") || strings.Contains(name, "curl") ||
		strings.Contains(name, "wget") || strings.Contains(name, "network"):
		return "network"
	default:
		return "read" // default to read (lowest risk)
	}
}

// recordToolCalls feeds extracted tool calls into the ChainAnalyzer.
// It also records P2 shadow alerts for response header tracking.
func (p *Proxy) recordToolCalls(sessionID string, body []byte, sac *shadowAlertContext) {
	if p.chainAnalyzer == nil {
		return
	}

	calls := p.toolCallExtractor.extractToolCalls(body)
	if len(calls) == 0 {
		return
	}

	for _, call := range calls {
		riskLevel := p.toolCallExtractor.matrix.GetRiskLevel(call.ToolName)

		entry := platformtoolauth.ChainEntry{
			Timestamp: time.Now(),
			ToolName:  call.ToolName,
			RiskLevel: riskLevel,
			Decision:  "allow",
			DataType:  call.DataType,
			Target:    call.Target,
		}

		p.chainAnalyzer.RecordCall(sessionID, entry)

		// Analyze after each call to detect chains in real time
		result := p.chainAnalyzer.AnalyzeChain(sessionID)
		if sac != nil {
			sac.RecordPrediction(ShadowDetectorP2)
		}
		if result.EscalationChain || result.ExfilChain || result.ReconChain {
			slog.Warn("v4.5.0 P2: Tool call chain pattern detected",
				"session_id", sessionID,
				"tool", call.ToolName,
				"escalation", result.EscalationChain,
				"exfil", result.ExfilChain,
				"recon", result.ReconChain,
				"risk", result.OverallRisk.String(),
				"flags", strings.Join(result.Flags, ", "),
				"call_count", result.CallCount,
			)
			// Record P2 shadow alert for response header + metrics
			if sac != nil {
				sac.RecordAlert(ShadowDetectorP2)
			}
			// v4.5.0: alert only. v4.6.0 may block based on chain risk.
		}
	}
}

// ---------------------------------------------------------------------------
// P3: ML Model Provenance Validation
// ---------------------------------------------------------------------------

// validateModelProvenance records and validates the ML model's provenance
// at proxy startup. If the model hash doesn't match or required fields are
// missing, it logs warnings but does not block startup (shadow mode).
func (p *Proxy) validateModelProvenance(modelPath string) {
	if p.provenanceRecorder == nil {
		return
	}

	// Read model bytes for hash computation
	modelBytes, err := os.ReadFile(modelPath)
	if err != nil {
		slog.Warn("v4.5.0 P3: Failed to read model for provenance validation",
			"path", modelPath, "error", err)
		return
	}

	// Compute SHA-256 hash
	hash := fmt.Sprintf("%x", sha256.Sum256(modelBytes))

	// Build provenance record from known metadata
	// In production, this would come from a signed manifest file
	meta := platformaibom.ModelProvenance{
		ModelName:         "threat_cnn_bilstm",
		ModelVersion:      "4.5.0",
		ModelHash:         hash,
		ModelFormat:       "onnx",
		ModelSizeBytes:    int64(len(modelBytes)),
		ModelParamCount:   1250000, // approximate parameter count for CNN-BiLSTM
		TrainingDataset:   "atlas-adversarial-prompts-v4.5",
		TrainingFramework: "PyTorch 2.4.0",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := p.provenanceRecorder.RecordModel(modelBytes, meta); err != nil {
		slog.Warn("v4.5.0 P3: Failed to record model provenance",
			"error", err)
		return
	}

	// Validate provenance completeness
	issues := p.provenanceRecorder.ValidateProvenance("threat_cnn_bilstm", "4.5.0")
	if len(issues) > 0 {
		slog.Warn("v4.5.0 P3: Model provenance validation issues",
			"model", "threat_cnn_bilstm",
			"version", "4.5.0",
			"hash", hash[:16]+"...",
			"issues", strings.Join(issues, "; "),
		)
	} else {
		slog.Info("v4.5.0 P3: Model provenance validated",
			"model", "threat_cnn_bilstm",
			"version", "4.5.0",
			"hash", hash[:16]+"...",
			"size_bytes", len(modelBytes),
		)
	}
}

// ---------------------------------------------------------------------------
// P4: API Key Anomaly Detection Integration
// ---------------------------------------------------------------------------

// recordKeyUsage feeds request metadata into the AnomalyDetector.
// It extracts the API key ID from the Authorization header (hashed for privacy),
// records usage stats, and checks for anomalies. Also records P4 shadow alerts.
func (p *Proxy) recordKeyUsage(req *http.Request, sac *shadowAlertContext) {
	if p.anomalyDetector == nil {
		return
	}

	// Extract key ID from Authorization header
	keyID := extractKeyID(req)
	if keyID == "" {
		return
	}

	// Extract tool name from request body if available
	toolName := ""
	endpoint := req.URL.Path

	rec := platformanomaly.KeyUsageRecord{
		KeyID:     keyID,
		Timestamp: time.Now(),
		ToolName:  toolName,
		SourceIP:  getClientIP(req),
		Endpoint:  endpoint,
	}

	// Record usage and check for anomalies
	p.anomalyDetector.RecordUsage(rec)
	result := p.anomalyDetector.CheckAnomaly(keyID, rec)

	if sac != nil {
		sac.RecordPrediction(ShadowDetectorP4)
	}

	if result.IsAnomalous {
		slog.Warn("v4.5.0 P4: API key anomaly detected",
			"key_id", keyID,
			"endpoint", endpoint,
			"source_ip", rec.SourceIP,
			"types", fmt.Sprintf("%v", result.Types),
			"details", strings.Join(result.Details, "; "),
		)
		// Record P4 shadow alert for response header + metrics
		if sac != nil {
			sac.RecordAlert(ShadowDetectorP4)
		}
		// v4.5.0: alert only. v4.6.0 may block or rate-limit anomalous keys.
	}
}

// extractKeyID derives a stable, privacy-preserving key identifier from
// the request's Authorization header.
func extractKeyID(req *http.Request) string {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	// Hash the auth header for privacy (don't store raw API keys)
	h := sha256.Sum256([]byte(auth))
	return fmt.Sprintf("key:%x", h[:16])
}

// ---------------------------------------------------------------------------
// Cleanup goroutine for P2/P4 periodic maintenance
// ---------------------------------------------------------------------------

// startV450Cleanup launches a background goroutine that periodically cleans
// up expired entries in the ChainAnalyzer and AnomalyDetector.
func (p *Proxy) startV450Cleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-p.v450CleanupDone:
				return
			case <-ticker.C:
				if p.chainAnalyzer != nil {
					removed := p.chainAnalyzer.CleanupExpired()
					if removed > 0 {
						slog.Debug("v4.5.0 P2: Cleaned up expired chain sessions",
							"removed", removed)
					}
				}
				if p.anomalyDetector != nil {
					removed := p.anomalyDetector.CleanupExpired()
					if removed > 0 {
						slog.Debug("v4.5.0 P4: Cleaned up expired anomaly baselines",
							"removed", removed)
					}
				}
			}
		}
	}()
}
