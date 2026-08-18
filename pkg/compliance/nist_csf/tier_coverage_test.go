//go:build !race

package nist_csf

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestNISTCSFModule_Tier(t *testing.T) {
	m := NewNISTCSFModule()
	if m.BaseModule.Metadata().Tier != core.TierProfessional {
		t.Errorf("NIST CSF tier = %v, want %v", m.BaseModule.Metadata().Tier, core.TierProfessional)
	}
}

func TestNISTCSFModule_FrameworkName(t *testing.T) {
	m := NewNISTCSFModule()
	if m.Framework() != "nist_csf" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "nist_csf")
	}
}
