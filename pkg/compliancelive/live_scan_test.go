// SPDX-License-Identifier: Apache-2.0

package compliancelive

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
)

func TestScanWithDefaultConfig(t *testing.T) {
	cfg := platformconfig.DefaultConfig()
	s := NewScanner(cfg)
	report := s.Scan(context.Background())

	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Results) != 10 {
		t.Errorf("expected 10 checks, got %d", len(report.Results))
	}
	if report.Summary["total"] != 10 {
		t.Errorf("summary total: got %d, want 10", report.Summary["total"])
	}
	if report.PassRate < 0 || report.PassRate > 100 {
		t.Errorf("pass rate out of range: %.1f%%", report.PassRate)
	}
}

func TestScanWithNilConfig(t *testing.T) {
	s := NewScanner(nil)
	report := s.Scan(context.Background())

	// With nil config, all checks should be Skip
	for _, r := range report.Results {
		if r.Status != StatusSkip {
			t.Errorf("check %s: expected skip with nil config, got %s", r.ID, r.Status)
		}
	}
}

func TestScanWithSecureConfig(t *testing.T) {
	cfg := platformconfig.DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.KeyFile = "/path/to/key.pem"
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableAuditMiddleware = true
	cfg.Security.EnableCSRF = true
	cfg.Security.MLThreatDetectionEnabled = true
	cfg.Proxy.RateLimit = 10000
	cfg.Proxy.LogLevel = "info"
	cfg.Dashboard.Enabled = true

	s := NewScanner(cfg)
	report := s.Scan(context.Background())

	// Most checks should pass with secure config
	passCount := report.Summary["pass"]
	if passCount < 7 {
		t.Errorf("expected at least 7 passes with secure config, got %d", passCount)
		t.Errorf("summary: %+v", report.Summary)
		for _, r := range report.Results {
			t.Logf("  %s: %s — %s", r.ID, r.Status, r.Message)
		}
	}
}

func TestScanWithInsecureConfig(t *testing.T) {
	cfg := &platformconfig.Config{}
	cfg.TLS.Enabled = false
	cfg.Security.EnableSecurityHeaders = false
	cfg.Security.EnableAuditMiddleware = false
	cfg.Security.EnableCSRF = false
	cfg.Security.MLThreatDetectionEnabled = false
	cfg.Proxy.RateLimit = 0
	cfg.Proxy.LogLevel = ""

	s := NewScanner(cfg)
	report := s.Scan(context.Background())

	failCount := report.Summary["fail"]
	if failCount < 2 {
		t.Errorf("expected at least 2 failures with insecure config, got %d", failCount)
	}
}

func TestFormatReport(t *testing.T) {
	cfg := platformconfig.DefaultConfig()
	s := NewScanner(cfg)
	report := s.Scan(context.Background())

	formatted := report.FormatReport()
	if formatted == "" {
		t.Error("expected non-empty report")
	}
	if !contains(formatted, "Live Compliance Scan Report") {
		t.Error("report missing header")
	}
	if !contains(formatted, "Pass Rate") {
		t.Error("report missing pass rate")
	}
}

func TestScanDuration(t *testing.T) {
	cfg := platformconfig.DefaultConfig()
	s := NewScanner(cfg)
	report := s.Scan(context.Background())

	if report.Duration == "" {
		t.Error("expected non-empty duration")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func init() {
	// Ensure time package is used (avoids unused import in some test configs)
	_ = time.Now
}
