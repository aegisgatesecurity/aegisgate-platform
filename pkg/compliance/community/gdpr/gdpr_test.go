package gdpr

import (
	"context"
	"testing"
)

func TestGDPRModule_New(t *testing.T) {
	m := NewGDPRModule()
	if m == nil {
		t.Fatal("NewGDPRModule returned nil")
	}
	if m.Framework() != "gdpr" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "gdpr")
	}
	if m.Version() != "Regulation (EU) 2016/679" {
		t.Errorf("Version() = %q", m.Version())
	}
}

func TestGDPRModule_All99ArticlesRegistered(t *testing.T) {
	m := NewGDPRModule()
	controls := m.Controls()
	if len(controls) != 99 {
		t.Errorf("Expected 99 controls (all GDPR articles), got %d", len(controls))
	}
	// Verify article 1 through 99 all present
	seen := make(map[string]bool)
	for _, c := range controls {
		seen[c.ID] = true
	}
	for i := 1; i <= 99; i++ {
		id := "GDPR-Art" + itoa(i)
		if !seen[id] {
			t.Errorf("Missing control %s", id)
		}
	}
}

func TestGDPRModule_AutomatedControls(t *testing.T) {
	m := NewGDPRModule()
	controls := m.Controls()
	auto := 0
	for _, c := range controls {
		if c.Automated && c.CheckFunc != nil {
			auto++
		}
	}
	if auto != 12 {
		t.Errorf("Expected 12 automated controls with CheckFunc, got %d", auto)
	}
}

func TestGDPRModule_ManualControlsHaveNoCheckFunc(t *testing.T) {
	m := NewGDPRModule()
	for _, c := range m.Controls() {
		if !c.Automated && c.CheckFunc != nil {
			t.Errorf("Manual control %s should not have CheckFunc", c.ID)
		}
	}
}

func TestGDPRModule_CheckAllAutomated(t *testing.T) {
	m := NewGDPRModule()
	ctx := context.Background()
	input := []byte("encryption aes tls access_control rbac consent privacy_policy audit_log breach_notification dpia")
	results, err := m.CheckAll(ctx, input)
	if err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}
	if len(results) != 12 {
		t.Errorf("Expected 12 results from automated controls, got %d", len(results))
	}
}

func TestGDPRModule_SecurityOfProcessing_Compliant(t *testing.T) {
	m := NewGDPRModule()
	ctx := context.Background()
	input := []byte("encryption enabled with aes-256, tls 1.3, access_control with rbac")
	results, err := m.CheckAll(ctx, input)
	if err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}
	for _, r := range results {
		if r.ControlID == "GDPR-Art32" {
			if r.Status != "compliant" {
				t.Errorf("Art32 status = %q, want compliant", r.Status)
			}
			return
		}
	}
	t.Error("Art32 result not found")
}

func TestGDPRModule_SecurityOfProcessing_NonCompliant(t *testing.T) {
	m := NewGDPRModule()
	ctx := context.Background()
	input := []byte("no security measures mentioned")
	results, err := m.CheckAll(ctx, input)
	if err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}
	for _, r := range results {
		if r.ControlID == "GDPR-Art32" {
			if r.Status != "non_compliant" {
				t.Errorf("Art32 status = %q, want non_compliant", r.Status)
			}
			return
		}
	}
	t.Error("Art32 result not found")
}

func TestGDPRModule_AllControlsHaveReferences(t *testing.T) {
	m := NewGDPRModule()
	for _, c := range m.Controls() {
		if len(c.References) == 0 {
			t.Errorf("Control %s has no references", c.ID)
		}
	}
}

func TestGDPRModule_AllControlsHaveCategory(t *testing.T) {
	m := NewGDPRModule()
	for _, c := range m.Controls() {
		if c.Category == "" {
			t.Errorf("Control %s has no category", c.ID)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
