// SPDX-License-Identifier: Apache-2.0
// Test stub for exfil_detect.go (P5: Egress Data Exfiltration Detection)

package response

import (
	"encoding/base64"
	"testing"
)

func TestNewExfilDetector(t *testing.T) {
	ed := NewExfilDetector()
	if ed == nil {
		t.Fatal("NewExfilDetector returned nil")
	}
	if ed.threshold != ExfilScoreThreshold {
		t.Errorf("expected threshold=%.1f, got %.1f", ExfilScoreThreshold, ed.threshold)
	}
}

func TestAnalyze_NoExfil(t *testing.T) {
	ed := NewExfilDetector()
	result := ed.Analyze(ExfilInput{
		ResponseBody:   "This is a normal response with no sensitive data.",
		SensitiveCount: 0,
	})
	if result.IsExfil {
		t.Error("expected no exfil for normal response")
	}
}

func TestAnalyze_Aggregation(t *testing.T) {
	ed := NewExfilDetector()
	// SensitiveCount=7 → 0.3, HasIngressAlert → 0.2 = 0.5 (below threshold)
	// Add encoded content → 0.25 = 0.75 (above threshold)
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	result := ed.Analyze(ExfilInput{
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})
	if !result.IsExfil {
		t.Error("expected exfil for high sensitive count with contributing factors")
	}
	found := false
	for _, f := range result.Flags {
		if f == "sensitive_data_aggregation" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive_data_aggregation flag")
	}
}

func TestAnalyze_EncodedContent(t *testing.T) {
	ed := NewExfilDetector()
	// base64-encoded "this is a secret message that is long enough"
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	result := ed.Analyze(ExfilInput{
		ResponseBody:   encoded,
		SensitiveCount: 2,
	})
	if !result.EncodedData {
		t.Error("expected encoded data detection")
	}
}

func TestAnalyze_IngressAlert(t *testing.T) {
	ed := NewExfilDetector()
	result := ed.Analyze(ExfilInput{
		ResponseBody:    "response",
		SensitiveCount:  4,
		HasIngressAlert: true,
	})
	found := false
	for _, f := range result.Flags {
		if f == "response_to_flagged_prompt" {
			found = true
		}
	}
	if !found {
		t.Error("expected response_to_flagged_prompt flag")
	}
}

func TestAnalyze_RepeatedAttempts(t *testing.T) {
	ed := NewExfilDetector()
	// First attempt: enough factors to trigger exfil (score >= 0.6)
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	ed.Analyze(ExfilInput{
		SessionID:       "sess-1",
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})
	// Second attempt: same factors + repeated attempt bonus
	result := ed.Analyze(ExfilInput{
		SessionID:       "sess-1",
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})
	if ed.GetSessionAttempts("sess-1") < 2 {
		t.Error("expected 2 tracked attempts")
	}
	found := false
	for _, f := range result.Flags {
		if f == "repeated_exfil_attempt" {
			found = true
		}
	}
	if !found {
		t.Error("expected repeated_exfil_attempt flag")
	}
}

func TestAnalyze_ScoreCapped(t *testing.T) {
	ed := NewExfilDetector()
	// Trigger all factors to push score above 1.0
	// First attempt to register the session
	ed.Analyze(ExfilInput{
		SessionID:      "sess-cap",
		SensitiveCount: 7,
	})
	// Second attempt with all factors
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	result := ed.Analyze(ExfilInput{
		SessionID:       "sess-cap",
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})
	if result.Score > 1.0 {
		t.Errorf("score should be capped at 1.0, got %.2f", result.Score)
	}
}

func TestDetectEncoding_NormalText(t *testing.T) {
	ed := NewExfilDetector()
	if ed.detectEncoding("This is just normal text.\nNo encoding here.") {
		t.Error("expected no encoding for normal text")
	}
}

func TestDetectEncoding_HexSequence(t *testing.T) {
	ed := NewExfilDetector()
	// 24-char hex string
	hexStr := "48656c6c6f20576f726c642054657374204461746121"
	if !ed.detectEncoding(hexStr) {
		t.Error("expected hex detection")
	}
}

func TestIsBase64_URL(t *testing.T) {
	ed := NewExfilDetector()
	if ed.isBase64("https://example.com/api/v1/data") {
		t.Error("should not flag URLs as base64")
	}
}

func TestIsBase64_FilePath(t *testing.T) {
	ed := NewExfilDetector()
	if ed.isBase64("/usr/local/bin/aegisgate") {
		t.Error("should not flag file paths as base64")
	}
}

func TestIsHex_ShortString(t *testing.T) {
	ed := NewExfilDetector()
	if ed.isHex("abc123") {
		t.Error("should not flag short hex strings")
	}
}

func TestIsHex_OddLength(t *testing.T) {
	ed := NewExfilDetector()
	if ed.isHex("abc1234") {
		t.Error("should not flag odd-length hex strings")
	}
}

func TestResetSession(t *testing.T) {
	ed := NewExfilDetector()
	// Need score >= 0.6 to register an attempt
	// SensitiveCount=7 → 0.3, HasIngressAlert → 0.2, encoded → 0.25 = 0.75
	encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret message that is long enough"))
	ed.Analyze(ExfilInput{
		SessionID:       "sess-reset",
		ResponseBody:    encoded,
		SensitiveCount:  7,
		HasIngressAlert: true,
	})
	if ed.GetSessionAttempts("sess-reset") == 0 {
		t.Fatal("expected attempts before reset")
	}
	ed.ResetSession("sess-reset")
	if ed.GetSessionAttempts("sess-reset") != 0 {
		t.Error("expected 0 attempts after reset")
	}
}
