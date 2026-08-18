//go:build !race

package sox

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestSOXModule_Tier(t *testing.T) {
	m := NewSOXModule()
	if m.BaseModule.Metadata().Tier != core.TierProfessional {
		t.Errorf("SOX tier = %v, want %v", m.BaseModule.Metadata().Tier, core.TierProfessional)
	}
}

func TestSOXModule_FrameworkName(t *testing.T) {
	m := NewSOXModule()
	if m.Framework() != "sox" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "sox")
	}
}
