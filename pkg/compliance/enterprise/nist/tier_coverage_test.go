//go:build !race

package nist

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestNISTFramework_GetTier(t *testing.T) {
	nf := NewNISTFramework()
	ti := nf.GetTier()
	if ti.Name != "Enterprise" {
		t.Errorf("GetTier().Name = %q, want %q", ti.Name, "Enterprise")
	}
	if ti.Description == "" {
		t.Error("GetTier().Description is empty")
	}
}

func TestNISTFramework_GetConfig(t *testing.T) {
	nf := NewNISTFramework()
	cfg := nf.GetConfig()
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

func TestNISTFramework_SupportsTier(t *testing.T) {
	nf := NewNISTFramework()
	tests := []struct {
		tier string
		want bool
	}{
		{"Enterprise", true},
		{"Premium", true},
		{"Community", false},
		{"Developer", false},
		{"Free", false},
		{"", false},
	}
	for _, tt := range tests {
		got := nf.SupportsTier(tt.tier)
		if got != tt.want {
			t.Errorf("SupportsTier(%q) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

func TestNISTFramework_InterfaceCompliance(t *testing.T) {
	var _ common.Framework = (*NISTFramework)(nil)
}

func TestNISTFramework_GetConfig_SamePointer(t *testing.T) {
	nf := NewNISTFramework()
	cfg1 := nf.GetConfig()
	cfg2 := nf.GetConfig()
	if cfg1 != cfg2 {
		t.Error("GetConfig() should return the same config object pointer")
	}
}

func TestNISTFramework_GetTier_DescriptionValue(t *testing.T) {
	nf := NewNISTFramework()
	ti := nf.GetTier()
	if ti.Description != "NIST AI Risk Management Framework (RMF) and SP 1500" {
		t.Errorf("TierInfo.Description = %q, want specific description", ti.Description)
	}
}

func TestNISTFramework_SupportsTier_EnterpriseOnly(t *testing.T) {
	nf := NewNISTFramework()
	// NIST is Enterprise tier, so Community and Developer tiers should not be supported
	if nf.SupportsTier("Community") {
		t.Error("NIST SupportsTier(Community) = true, want false")
	}
	if nf.SupportsTier("Developer") {
		t.Error("NIST SupportsTier(Developer) = true, want false")
	}
}
