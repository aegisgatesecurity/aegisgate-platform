// SPDX-License-Identifier: Apache-2.0
//go:build !race

package compliance

import (
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"testing"
)

func TestTier_String(t *testing.T) {
	tests := []struct {
		tierVal tier.Tier
		want string
	}{
		{tier.TierCommunity, "community"},
		{tier.TierEnterprise, "enterprise"},
		{tier.TierProfessional, "professional"},
		{tier.Tier(99), "unknown"},
		{tier.Tier(-1), "unknown"},
	}
	for _, tt := range tests {
		got := tt.tierVal.String()
		if got != tt.want {
			t.Errorf("Tier(%d).String()=%q, want %q", tt.tierVal, got, tt.want)
		}
	}
}

func TestTierManager_GetAvailableFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetAvailableFrameworks()
	if frameworks == nil {
		t.Error("GetAvailableFrameworks should not return nil")
	}
}
