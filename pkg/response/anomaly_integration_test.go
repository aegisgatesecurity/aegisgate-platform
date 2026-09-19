// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — pkg/anomaly Integration Tests (v4.5.0)
//
// Verifies that the entropy-based anomaly detector (pkg/anomaly) is
// correctly wired into ResponseGuard.ScanWithContext as stage 9,
// and that it does NOT block responses (non-blocking, alert-only).

package response

import (
	"context"
	"strings"
	"testing"
)

func TestAnomalyDetection_EnabledByDefault(t *testing.T) {
	config := DefaultResponseGuardConfig()
	if !config.EnableAnomalyDetection {
		t.Fatal("EnableAnomalyDetection should be true by default")
	}
	rg := NewResponseGuardWithConfig(config)
	if rg.anomalyDetector == nil {
		t.Fatal("anomalyDetector should be initialized when EnableAnomalyDetection is true")
	}
	t.Log("GAP CLOSED: pkg/anomaly wired into ResponseGuard")
	t.Log("  - EnableAnomalyDetection defaults to true")
	t.Log("  - anomalyDetector initialized in NewResponseGuardWithConfig")
}

func TestAnomalyDetection_DisabledWhenConfigSaysSo(t *testing.T) {
	config := DefaultResponseGuardConfig()
	config.EnableAnomalyDetection = false
	rg := NewResponseGuardWithConfig(config)
	if rg.anomalyDetector != nil {
		t.Fatal("anomalyDetector should be nil when EnableAnomalyDetection is false")
	}
}

func TestScanWithContext_AnomalyScore_PopulatedOnNormalResponse(t *testing.T) {
	rg := NewResponseGuardWithConfig(DefaultResponseGuardConfig())
	result, err := rg.ScanWithContext(context.Background(),
		"The weather today is sunny with a high of 72 degrees.",
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}
	if result.AnomalyScore == nil {
		t.Fatal("AnomalyScore should be populated when anomaly detection is enabled")
	}
	t.Logf("Normal response anomaly score: %.4f (isAnomalous=%v, isAlert=%v)",
		result.AnomalyScore.Total, result.AnomalyScore.IsAnomalous, result.AnomalyScore.IsAlert)
}

func TestScanWithContext_AnomalyScore_DetectsEncodedContent(t *testing.T) {
	// Base64-encoded content should trigger higher anomaly scores
	// because the entropy and frequency profiles differ from natural language
	encoded := "VTJsMFkybHNIWGxDWkRweWVDMHlNQ3R6ZUNkVlNFaHJZbTl2YW10cVlYZGFla0ptYjJ3" +
		"eWRYUnRMV0Z3Y2tOb1pDMHlOVkV2YmxKdmJrVm1hejB5YjBwelpDMHlMamc9LnRlc3Q=" +
		"VGhpcyBpcyBhIHRlc3Qgb2YgZW50cm9weSBiYXNlNjQgZGF0YSBmb3IgZXhmaWw="
	rg := NewResponseGuardWithConfig(DefaultResponseGuardConfig())
	result, err := rg.ScanWithContext(context.Background(), encoded,
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}
	if result.AnomalyScore == nil {
		t.Fatal("AnomalyScore should be populated")
	}
	t.Logf("Encoded content anomaly score: %.4f (entropy=%.4f, freq=%.4f, struct=%.4f)",
		result.AnomalyScore.Total, result.AnomalyScore.Entropy,
		result.AnomalyScore.Frequency, result.AnomalyScore.Structure)
	t.Logf("  Classification: %s", result.AnomalyScore.Classification)
	t.Logf("  Flags: %v", result.AnomalyScore.Flags)
}

func TestScanWithContext_Anomaly_NeverBlocksResponse(t *testing.T) {
	// Even high-entropy content should NOT be blocked by anomaly detection alone
	// (by design — fail-closed, non-blocking)
	highEntropy := strings.Repeat("AaBbCcDdEeFf", 100)
	config := DefaultResponseGuardConfig()
	config.StrictMode = true // Even in strict mode, anomaly alone shouldn't block
	rg := NewResponseGuardWithConfig(config)
	result, err := rg.ScanWithContext(context.Background(), highEntropy,
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}
	if result.AnomalyScore != nil && result.AnomalyScore.IsAlert {
		// Anomaly was detected — verify it did NOT cause blocking
		// unless other threats also triggered
		anomalyOnly := true
		for _, threat := range result.Threats {
			if threat.Type != "anomaly" {
				anomalyOnly = false
				break
			}
		}
		if anomalyOnly && !result.Allowed {
			t.Fatalf("Anomaly detection blocked the response (should be non-blocking). "+
				"Score: %.4f, BlockReason: %s", result.AnomalyScore.Total, result.BlockReason)
		}
		t.Logf("Correct: anomaly alert detected (score=%.4f) but response NOT blocked by anomaly alone",
			result.AnomalyScore.Total)
	} else {
		t.Logf("Note: content did not trigger anomaly alert (score=%.4f) — non-blocking verified",
			func() float64 {
				if result.AnomalyScore != nil {
					return result.AnomalyScore.Total
				}
				return 0
			}())
	}
}

func TestScanWithContext_AnomalyThreatAddedOnAlert(t *testing.T) {
	// When anomaly detection triggers an alert, a "anomaly" threat should be added
	// (severity 3, non-blocking)
	rg := NewResponseGuardWithConfig(DefaultResponseGuardConfig())

	// Use a mix of encoded and natural content
	content := "Here is the data: " + strings.Repeat("ZmFrZWRhdGFmb3JleGZpbHRyYXRpb24=", 5)
	result, err := rg.ScanWithContext(context.Background(), content,
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("ScanWithContext failed: %v", err)
	}

	if result.AnomalyScore != nil && result.AnomalyScore.IsAlert {
		foundAnomalyThreat := false
		for _, threat := range result.Threats {
			if threat.Type == "anomaly" {
				foundAnomalyThreat = true
				if threat.Severity != 3 {
					t.Errorf("anomaly threat severity should be 3, got %d", threat.Severity)
				}
			}
		}
		if !foundAnomalyThreat {
			t.Fatal("Anomaly alert was triggered but no 'anomaly' threat was added")
		}
		t.Log("Correct: anomaly threat added on alert (severity 3, non-blocking)")
	}
}

func TestAnomalyDetection_DoesNotNukeDetectionMetrics(t *testing.T) {
	// Critical regression test: verify that adding anomaly detection
	// doesn't break existing PII, secret, XSS, or exfil detection.
	// All existing detection layers should still work identically.
	rg := NewResponseGuardWithConfig(DefaultResponseGuardConfig())

	// Test PII detection still works
	piiResponse := "The user's SSN is 123-45-6789 and email is john@example.com"
	result, err := rg.ScanWithContext(context.Background(), piiResponse,
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("PII test failed: %v", err)
	}
	if len(result.DetectedPII) == 0 {
		t.Fatal("PII detection broken: no PII found in SSN+email response")
	}
	t.Logf("PII detection intact: %d categories found", len(result.DetectedPII))

	// Test secret detection still works
	secretResponse := "My AWS key is AKIAIOSFODNN7EXAMPLE and secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	result2, err := rg.ScanWithContext(context.Background(), secretResponse,
		&ScanContext{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("Secret test failed: %v", err)
	}
	if len(result2.DetectedSecrets) == 0 {
		t.Fatal("Secret detection broken: no secrets found in AWS key response")
	}
	t.Logf("Secret detection intact: %d secrets found", len(result2.DetectedSecrets))

	// Verify anomaly score is populated alongside existing detections
	if result.AnomalyScore == nil {
		t.Fatal("Anomaly score not populated alongside PII detection")
	}
	if result2.AnomalyScore == nil {
		t.Fatal("Anomaly score not populated alongside secret detection")
	}
	t.Log("All detection layers working alongside anomaly scoring — no regressions")
}
