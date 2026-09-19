// SPDX-License-Identifier: Apache-2.0
// Integration tests for v4.5.0 P5: Egress Exfiltration Scoring wired into
// ResponseGuard. Verifies that exfiltration patterns are detected during
// ScanWithContext and that the ExfilResult is populated on the scan result.

package response

import (
	"encoding/base64"
	"testing"
)

func TestScanWithContext_ExfilDetected_AggregationAndEncoding(t *testing.T) {
	rg := NewResponseGuard()
	// Create a response with 5+ sensitive findings + encoded content
	// aggregation (0.3) + encoded (0.25) = 0.55, below 0.6 threshold.
	// Use HasIngressAlert by setting it via the ExfilDetector directly
	// to push the score over threshold: 0.3 + 0.25 + 0.2 = 0.75
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	response := "SSN: 123-45-6789. SSN: 111-22-3333. SSN: 234-56-7890. SSN: 345-67-8901. SSN: 456-78-9012. SSN: 567-89-0123.\n" + encoded

	scanCtx := &ScanContext{
		ClientID: "sess-exfil-integration",
	}

	// Manually pre-register an ingress alert to simulate the proxy
	// passing ingress context. In production, the proxy will set
	// HasIngressAlert when the corresponding request was flagged.
	// For testing, we trigger the exfil detector directly first
	// to get a repeated attempt, then scan.
	rg.exfilDetector.Analyze(ExfilInput{
		SessionID:       "sess-exfil-integration",
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})

	result, err := rg.ScanWithContext(nil, response, scanCtx)
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	// Should have exfil result populated
	if result.ExfilResult == nil {
		t.Fatal("expected ExfilResult to be populated")
	}
	if !result.ExfilResult.IsExfil {
		t.Errorf("expected IsExfil=true, got score=%.2f, flags=%v",
			result.ExfilResult.Score, result.ExfilResult.Flags)
	}
}

func TestScanWithContext_ExfilNotDetected_BenignResponse(t *testing.T) {
	rg := NewResponseGuard()
	response := "This is a normal AI response with no sensitive data or encoding."

	result, err := rg.ScanWithContext(nil, response, &ScanContext{ClientID: "sess-benign"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	// ExfilResult should either be nil or IsExfil=false
	if result.ExfilResult != nil && result.ExfilResult.IsExfil {
		t.Errorf("expected no exfil for benign response, got score=%.2f",
			result.ExfilResult.Score)
	}
}

func TestScanWithContext_ExfilThreatAdded(t *testing.T) {
	rg := NewResponseGuard()
	rg.exfilDetector.threshold = 0.5 // lower for testing
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	response := "SSN: 123-45-6789. SSN: 111-22-3333. SSN: 234-56-7890. SSN: 345-67-8901. SSN: 456-78-9012. SSN: 567-89-0123.\n" + encoded

	result, err := rg.ScanWithContext(nil, response, &ScanContext{ClientID: "sess-exfil-threat"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	// Should have an exfiltration threat
	found := false
	for _, threat := range result.Threats {
		if threat.Type == "exfiltration" {
			found = true
		}
	}
	if !found {
		t.Error("expected exfiltration threat in result.Threats")
	}
}

func TestScanWithContext_ExfilStrictMode_BlocksResponse(t *testing.T) {
	cfg := DefaultResponseGuardConfig()
	cfg.StrictMode = true
	rg := NewResponseGuardWithConfig(cfg)
	rg.exfilDetector.threshold = 0.5 // lower for testing

	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	response := "SSN: 123-45-6789. SSN: 111-22-3333. SSN: 234-56-7890. SSN: 345-67-8901. SSN: 456-78-9012. SSN: 567-89-0123.\n" + encoded

	result, err := rg.ScanWithContext(nil, response, &ScanContext{ClientID: "sess-strict"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	if result.Allowed {
		t.Error("expected response to be blocked in strict mode with exfil detected")
	}
}

func TestScanWithContext_ExfilResultHasFlags(t *testing.T) {
	rg := NewResponseGuard()
	rg.exfilDetector.threshold = 0.5 // lower for testing
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	response := "SSN: 123-45-6789. SSN: 111-22-3333. SSN: 234-56-7890. SSN: 345-67-8901. SSN: 456-78-9012. SSN: 567-89-0123.\n" + encoded

	result, err := rg.ScanWithContext(nil, response, &ScanContext{ClientID: "sess-flags"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	if result.ExfilResult == nil {
		t.Fatal("expected ExfilResult")
	}
	if len(result.ExfilResult.Flags) == 0 {
		t.Error("expected flags in ExfilResult")
	}
	// Should have at least sensitive_data_aggregation and encoded_content
	hasAggregation := false
	hasEncoded := false
	for _, f := range result.ExfilResult.Flags {
		if f == "sensitive_data_aggregation" {
			hasAggregation = true
		}
		if f == "encoded_content" {
			hasEncoded = true
		}
	}
	if !hasAggregation {
		t.Error("expected sensitive_data_aggregation flag")
	}
	if !hasEncoded {
		t.Error("expected encoded_content flag")
	}
}

func TestExfilDetector_WiredInResponseGuard(t *testing.T) {
	rg := NewResponseGuard()
	if rg.exfilDetector == nil {
		t.Fatal("exfilDetector should be initialized in NewResponseGuard")
	}
}
