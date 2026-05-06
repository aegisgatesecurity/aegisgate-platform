//go:build !race

package atlas

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestAtlasFramework_GetConfig(t *testing.T) {
	af := NewAtlasFramework()
	cfg := af.GetConfig()
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

func TestAtlasFramework_GetTier(t *testing.T) {
	af := NewAtlasFramework()
	ti := af.GetTier()
	if ti.Name != "Community" {
		t.Errorf("GetTier().Name = %q, want %q", ti.Name, "Community")
	}
	if ti.Description == "" {
		t.Error("GetTier().Description is empty")
	}
}

func TestAtlasFramework_SupportsTier(t *testing.T) {
	af := NewAtlasFramework()
	tests := []struct {
		tier string
		want bool
	}{
		{"Community", true},
		{"Enterprise", true},
		{"Premium", true},
		{"Free", false},
		{"Developer", false},
		{"", false},
	}
	for _, tt := range tests {
		got := af.SupportsTier(tt.tier)
		if got != tt.want {
			t.Errorf("SupportsTier(%q) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

func TestAtlasFramework_InterfaceCompliance(t *testing.T) {
	// Verify AtlasFramework satisfies the Framework interface
	var _ common.Framework = (*AtlasFramework)(nil)
}

func TestAtlasFramework_GetConfig_ReturnsPointer(t *testing.T) {
	af := NewAtlasFramework()
	cfg1 := af.GetConfig()
	cfg2 := af.GetConfig()
	if cfg1 != cfg2 {
		t.Error("GetConfig() should return the same config object pointer")
	}
}

func TestAtlasFramework_GetTier_FieldValues(t *testing.T) {
	af := NewAtlasFramework()
	ti := af.GetTier()
	if ti.Name != "Community" {
		t.Errorf("TierInfo.Name = %q, want Community", ti.Name)
	}
	if ti.Description != "MITRE ATLAS framework for adversarial ML threats" {
		t.Errorf("TierInfo.Description = %q, want specific description", ti.Description)
	}
}
