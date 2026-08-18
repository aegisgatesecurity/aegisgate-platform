//go:build !race

package cjis

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestCJISModule_Tier(t *testing.T) {
	m := NewCJISModule()
	if m.BaseModule.Metadata().Tier != core.TierProfessional {
		t.Errorf("CJIS tier = %v, want %v", m.BaseModule.Metadata().Tier, core.TierProfessional)
	}
}

func TestCJISModule_FrameworkName(t *testing.T) {
	m := NewCJISModule()
	if m.Framework() != "cjis" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "cjis")
	}
}
