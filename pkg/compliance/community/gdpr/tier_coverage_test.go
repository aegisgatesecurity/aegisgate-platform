//go:build !race

package gdpr

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestGDPRModule_Tier(t *testing.T) {
	m := NewGDPRModule()
	// GDPR is a Developer tier module per gating.go
	if m.BaseModule.Metadata().Tier != core.TierDeveloper {
		t.Errorf("GDPR tier = %v, want %v", m.BaseModule.Metadata().Tier, core.TierDeveloper)
	}
}

func TestGDPRModule_FrameworkName(t *testing.T) {
	m := NewGDPRModule()
	if m.Framework() != "gdpr" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "gdpr")
	}
}
