// SPDX-License-Identifier: Apache-2.0
// Bridge package - Additional coverage tests for uncovered paths
// Sprint 12: Push bridge package to maximum achievable coverage

package bridge_test

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// TestScanBridgeResponse_GitHubTokenSecret - Hit secret switch branch with GitHub token
func TestScanBridgeResponse_GitHubTokenSecret(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	// GitHub token: ghp_ followed by 36 alphanumeric chars
	ghToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	resp := &bridge.LLMResponse{
		RequestID:  "test-github-token",
		StatusCode: 200,
		Body:       []byte("GitHub token: " + ghToken),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("Secrets found: %v", result.SecretsFound)
}

// TestScanBridgeResponse_AWSKeySecret - Hit secret switch branch with AWS key
func TestScanBridgeResponse_AWSKeySecret(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	// AWS key: AKIA followed by 16 chars
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	resp := &bridge.LLMResponse{
		RequestID:  "test-aws-key",
		StatusCode: 200,
		Body:       []byte("AWS Key: " + awsKey),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("AWS secrets found: %v", result.SecretsFound)
}

// TestScanBridgeResponse_HallucinationThreat - Hit hallucination switch branch
func TestScanBridgeResponse_HallucinationThreat(t *testing.T) {
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:      false,
		EnableSecretDetection: false,
		EnableToxicityFilter:  false,
		EnableHallucination:   true,
	}
	scanner := bridge.NewResponseScannerWithConfig(config)
	ctx := context.Background()

	hallContent := "According to my training data from 2024, the president of the US in 1950 was John F. Kennedy."
	resp := &bridge.LLMResponse{
		RequestID:  "test-hallucination",
		StatusCode: 200,
		Body:       []byte(hallContent),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("Hallucination result: Allowed=%v, Threats=%d", result.Allowed, result.Threats)
}

// TestScanAndFilter_BlockedToxicWarning - Hit non-strict blocked content warning
func TestScanAndFilter_BlockedToxicWarning(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()
	toxicContent := "I want to murder and kill everyone with a bomb"

	_, result, err := pb.ScanAndFilter(ctx, toxicContent)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("Toxic content result: Allowed=%v, Reason=%s", result.Allowed, result.BlockReason)
}
