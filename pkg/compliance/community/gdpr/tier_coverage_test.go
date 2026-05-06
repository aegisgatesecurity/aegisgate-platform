//go:build !race

package gdpr

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestGDPRFramework_GetTier(t *testing.T) {
	gf := NewGDPRFramework()
	ti := gf.GetTier()
	if ti.Name != "Community" {
		t.Errorf("GetTier().Name = %q, want %q", ti.Name, "Community")
	}
	if ti.Description == "" {
		t.Error("GetTier().Description is empty")
	}
}

func TestGDPRFramework_SupportsTier(t *testing.T) {
	gf := NewGDPRFramework()
	tests := []struct {
		tier string
		want bool
	}{
		{"Community", true},
		{"Enterprise", true},
		{"Premium", true},
		{"Developer", false},
		{"Free", false},
		{"", false},
	}
	for _, tt := range tests {
		got := gf.SupportsTier(tt.tier)
		if got != tt.want {
			t.Errorf("SupportsTier(%q) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

func TestGDPRFramework_GetConfig(t *testing.T) {
	gf := NewGDPRFramework()
	cfg := gf.GetConfig()
	if cfg == nil {
		t.Fatal("GetConfig() returned nil")
	}
	if cfg.Name != FrameworkName {
		t.Errorf("GetConfig().Name = %q, want %q", cfg.Name, FrameworkName)
	}
	if cfg.Version != FrameworkVersion {
		t.Errorf("GetConfig().Version = %q, want %q", cfg.Version, FrameworkVersion)
	}
	if !cfg.Enabled {
		t.Error("GetConfig().Enabled = false, want true")
	}
}

func TestGDPRFramework_InterfaceCompliance(t *testing.T) {
	var _ common.Framework = (*GDPRFramework)(nil)
}

func TestGDPRFramework_GetConfig_SamePointer(t *testing.T) {
	gf := NewGDPRFramework()
	cfg1 := gf.GetConfig()
	cfg2 := gf.GetConfig()
	if cfg1 != cfg2 {
		t.Error("GetConfig() should return the same config object pointer")
	}
}

func TestGDPRFramework_GetTier_DescriptionNotEmpty(t *testing.T) {
	gf := NewGDPRFramework()
	ti := gf.GetTier()
	if ti.Description != "GDPR compliance for EU data protection" {
		t.Errorf("TierInfo.Description = %q, want specific description", ti.Description)
	}
}
