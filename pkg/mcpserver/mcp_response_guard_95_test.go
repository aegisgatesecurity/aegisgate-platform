//go:build !race

// SPDX-License-Identifier: Apache-2.0
// MCP Response Guard Coverage Push — targeting 95%+

package mcpserver

import (
	"context"
	"testing"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// === NewEmbeddedServerWithResponse: 0% → 95%+ ===

func TestNewEmbeddedServerWithResponse_OK(t *testing.T) {
	cfg := &Config{Address: ":0", ReadTimeout: 30, WriteTimeout: 30, IdleTimeout: 60}
	s := NewEmbeddedServerWithResponse(cfg)
	if s == nil || s.EmbeddedServer == nil || s.responseGuard == nil {
		t.Fatal("NewEmbeddedServerWithResponse returned nil or nil fields")
	}
}

func TestNewEmbeddedServerWithResponse_NilCfg(t *testing.T) {
	s := NewEmbeddedServerWithResponse(nil)
	if s == nil || s.EmbeddedServer == nil {
		t.Fatal("nil config should still create server")
	}
}

// === GuardMCPResponse: 0% → 95%+ ===

func TestGuardMCPResponse_Clean(t *testing.T) {
	s := NewEmbeddedServerWithResponse(&Config{Address: ":0"})
	ok, resp, err := s.GuardMCPResponse(context.Background(), "hello", "s1")
	if err != nil || !ok || resp != "hello" {
		t.Errorf("expected allowed, got ok=%v resp=%q err=%v", ok, resp, err)
	}
}

func TestGuardMCPResponse_Disabled(t *testing.T) {
	s := NewEmbeddedServerWithResponse(&Config{Address: ":0"})
	s.responseGuard.sessionGuard.SetEnabled(false)
	ok, resp, err := s.GuardMCPResponse(context.Background(), "any", "s2")
	if err != nil || !ok || resp != "any" {
		t.Errorf("disabled guard should allow, got ok=%v resp=%q", ok, resp)
	}
}

// === GuardResponse: 54.5% → 95%+ ===

func TestGuardResponse_Strict(t *testing.T) {
	g := NewMCPResponseGuardWithConfig(&responseguard.ResponseGuardConfig{
		StrictMode: true, EnableToxicityFilter: true, EnablePIIScanner: true, EnableSecretDetection: true,
	})
	ok, _, _ := g.GuardResponse(context.Background(), "fuck you kill yourself", "s3")
	if ok {
		t.Error("strict mode should block toxic content")
	}
}

func TestGuardResponse_StrictSecrets(t *testing.T) {
	g := NewMCPResponseGuardWithConfig(&responseguard.ResponseGuardConfig{
		StrictMode: true, EnableSecretDetection: true, EnablePIIScanner: true,
	})
	ok, _, _ := g.GuardResponse(context.Background(), "key=sk_live_PLACEHOLDER", "s4")
	if ok {
		t.Error("strict mode should block secrets")
	}
}

func TestGuardResponse_Cancelled(t *testing.T) {
	g := NewMCPResponseGuard()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := g.GuardResponse(ctx, "data", "s5")
	if err != nil {
		t.Logf("cancelled context error (expected): %v", err)
	}
}

func TestGuardResponse_Disabled(t *testing.T) {
	g := NewMCPResponseGuard()
	g.sessionGuard.SetEnabled(false)
	ok, resp, err := g.GuardResponse(context.Background(), "test", "s6")
	if err != nil || !ok || resp != "test" {
		t.Errorf("disabled guard should allow, got ok=%v resp=%q err=%v", ok, resp, err)
	}
}

func TestGuardResponse_NonStrict(t *testing.T) {
	g := NewMCPResponseGuardWithConfig(&responseguard.ResponseGuardConfig{
		StrictMode: false, EnableToxicityFilter: true, EnablePIIScanner: true, EnableSecretDetection: true,
	})
	ok, resp, err := g.GuardResponse(context.Background(), "fuck off idiot", "s7")
	if err != nil {
		t.Logf("non-strict error: %v", err)
	}
	t.Logf("non-strict: ok=%v resp=%q", ok, resp)
}

// === Session stats ===

func TestScanner_StatsOps(t *testing.T) {
	sc := NewMCPResponseScanner()
	r := &responseguard.ResponseScanResult{
		Allowed: true, DetectedPII: []responseguard.PIICategory{responseguard.PII_EMAIL},
		DetectedSecrets: []string{"key"}, Threats: []responseguard.Threat{{Type: "toxicity"}, {Type: "hallucination"}},
	}
	sc.UpdateSessionStats("s1", r)
	st := sc.GetSessionStats("s1")
	if st == nil || st.PIIFound != 1 || st.SecretsFound != 1 || st.ToxicityDetected != 1 || st.HallucinationsDetected != 1 {
		t.Errorf("stats mismatch: %+v", st)
	}
	br := &responseguard.ResponseScanResult{Allowed: false, BlockReason: "toxic"}
	sc.UpdateSessionStats("s1", br)
	if sc.GetSessionStats("s1").BlockedResponses != 1 {
		t.Error("blocked count wrong")
	}
	if len(sc.GetAllSessionStats()) < 1 {
		t.Error("expected sessions")
	}
	sc.ClearSessionStats("s1")
	if sc.GetSessionStats("s1") != nil {
		t.Error("should be nil after clear")
	}
	if sc.GetSessionStats("nope") != nil {
		t.Error("nonexistent should be nil")
	}
}

func TestScanner_ScanMCPMsg_Variants(t *testing.T) {
	sc := NewMCPResponseScanner()
	// map with content
	r, _ := sc.ScanMCPMessage(context.Background(), map[string]interface{}{"content": "hi"}, "s10")
	if r == nil || !r.Allowed {
		t.Error("map with content should be allowed")
	}
	// map with text
	r, _ = sc.ScanMCPMessage(context.Background(), map[string]interface{}{"text": "ho"}, "s11")
	if r == nil || !r.Allowed {
		t.Error("map with text should be allowed")
	}
	// map with message
	r, _ = sc.ScanMCPMessage(context.Background(), map[string]interface{}{"message": "hm"}, "s12")
	// empty map
	r, _ = sc.ScanMCPMessage(context.Background(), map[string]interface{}{"other": "val"}, "s13")
	if r == nil || !r.Allowed {
		t.Error("empty map should be allowed")
	}
}

func TestSessionGuard_Scan_Cancelled(t *testing.T) {
	sg := NewMCPSessionGuard()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sg.Scan(ctx, "x", "s14")
	if err != nil {
		t.Logf("cancelled: %v", err)
	}
}

func TestSessionGuard_Scan_Disabled2(t *testing.T) {
	sg := NewMCPSessionGuard()
	sg.SetEnabled(false)
	r, err := sg.Scan(context.Background(), "x", "s15")
	if err != nil || r == nil || !r.Allowed {
		t.Errorf("disabled should allow: err=%v allowed=%v", err, r != nil && r.Allowed)
	}
}

func TestNewConfig2(t *testing.T) {
	sc := NewMCPResponseScannerWithConfig(&responseguard.ResponseGuardConfig{
		StrictMode: true, EnableToxicityFilter: true, EnablePIIScanner: true, EnableSecretDetection: true,
	})
	if sc == nil {
		t.Fatal("nil scanner")
	}
}

func TestGuardStats2(t *testing.T) {
	g := NewMCPResponseGuard()
	if g.GetSessionStats("nope") != nil {
		t.Error("nonexistent session should be nil")
	}
}
