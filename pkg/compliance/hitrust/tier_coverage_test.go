//go:build !race

package hitrust

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestHITRUSTModule_Tier(t *testing.T) {
	m := NewHITRUSTModule()
	if m.BaseModule.Metadata().Tier != core.TierEnterprise {
		t.Errorf("HITRUST tier = %v, want %v", m.BaseModule.Metadata().Tier, core.TierEnterprise)
	}
}

func TestHITRUSTModule_FrameworkName(t *testing.T) {
	m := NewHITRUSTModule()
	if m.Framework() != "hitrust" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "hitrust")
	}
}
