//go:build !race

package owasp

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestOWASPFramework_GetTier(t *testing.T) {
	of := NewOWASPFramework()
	ti := of.GetTier()
	if ti.Name != "Community" {
		t.Errorf("GetTier().Name = %q, want %q", ti.Name, "Community")
	}
	if ti.Description == "" {
		t.Error("GetTier().Description is empty")
	}
}

func TestOWASPFramework_GetConfig(t *testing.T) {
	of := NewOWASPFramework()
	cfg := of.GetConfig()
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

func TestOWASPFramework_SupportsTier(t *testing.T) {
	of := NewOWASPFramework()
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
		got := of.SupportsTier(tt.tier)
		if got != tt.want {
			t.Errorf("SupportsTier(%q) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

func TestOWASPFramework_InterfaceCompliance(t *testing.T) {
	var _ common.Framework = (*OWASPFramework)(nil)
}

func TestOWASPFramework_GetConfig_SamePointer(t *testing.T) {
	of := NewOWASPFramework()
	cfg1 := of.GetConfig()
	cfg2 := of.GetConfig()
	if cfg1 != cfg2 {
		t.Error("GetConfig() should return the same config object pointer")
	}
}

func TestOWASPFramework_GetTier_DescriptionValue(t *testing.T) {
	of := NewOWASPFramework()
	ti := of.GetTier()
	if ti.Description != "OWASP Top 10 for AI/LLM applications" {
		t.Errorf("TierInfo.Description = %q, want specific description", ti.Description)
	}
}
