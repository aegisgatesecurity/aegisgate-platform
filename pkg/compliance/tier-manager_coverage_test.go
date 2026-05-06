// SPDX-License-Identifier: Apache-2.0
//go:build !race

package compliance

import (
	"testing"
)

func TestTier_String(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierCommunity, "community"},
		{TierEnterprise, "enterprise"},
		{TierPremium, "premium"},
		{Tier(99), "unknown"},
		{Tier(-1), "unknown"},
	}
	for _, tt := range tests {
		got := tt.tier.String()
		if got != tt.want {
			t.Errorf("Tier(%d).String()=%q, want %q", tt.tier, got, tt.want)
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
