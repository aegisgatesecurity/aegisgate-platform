package tieradapter_test

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tieradapter"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	aglicense "github.com/aegisguardsecurity/aegisguard/pkg/license"
)

func TestRoundTripAegisGate(t *testing.T) {
	tests := []struct {
		name  string
		input tier.Tier
	}{
		{"community", tier.TierCommunity},
		{"developer", tier.TierDeveloper},
		{"professional", tier.TierProfessional},
		{"enterprise", tier.TierEnterprise},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tieradapter.ToAegisGateTier(tt.input)
			back := tieradapter.FromAegisGateTier(got)
			if back != tt.input {
				t.Errorf("round-trip mismatch: %v -> %v -> %v", tt.input, got, back)
			}
		})
	}
}

func TestRoundTripAegisGuard(t *testing.T) {
	tests := []struct {
		name  string
		input tier.Tier
	}{
		{"community", tier.TierCommunity},
		{"developer", tier.TierDeveloper},
		{"professional", tier.TierProfessional},
		{"enterprise", tier.TierEnterprise},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tieradapter.ToAegisGuardTier(tt.input)
			back := tieradapter.FromAegisGuardTier(got)
			if back != tt.input {
				t.Errorf("round-trip mismatch: %v -> %v -> %v", tt.input, got, back)
			}
		})
	}
}

func TestSpecificValues(t *testing.T) {
	// Verify AegisGate core.Tier values match
	if tieradapter.ToAegisGateTier(tier.TierCommunity) != core.TierCommunity {
		t.Error("Community tier mismatch")
	}
	if tieradapter.ToAegisGateTier(tier.TierEnterprise) != core.TierEnterprise {
		t.Error("Enterprise tier mismatch")
	}

	// Verify AegisGuard license.Tier values match
	if tieradapter.ToAegisGuardTier(tier.TierDeveloper) != aglicense.TierDeveloper {
		t.Error("Developer tier mismatch")
	}
	if tieradapter.ToAegisGuardTier(tier.TierProfessional) != aglicense.TierProfessional {
		t.Error("Professional tier mismatch")
	}
}

func TestParseAndConvert(t *testing.T) {
	pt, agt, aglt, err := tieradapter.ParseAndConvert("enterprise")
	if err != nil {
		t.Fatalf("ParseAndConvert failed: %v", err)
	}
	if pt != tier.TierEnterprise {
		t.Errorf("platform tier = %v, want enterprise", pt)
	}
	if agt != core.TierEnterprise {
		t.Errorf("aegisgate tier = %v, want enterprise", agt)
	}
	if aglt != aglicense.TierEnterprise {
		t.Errorf("aegisguard tier = %v, want enterprise", aglt)
	}
}

func TestParseAndConvertInvalid(t *testing.T) {
	_, _, _, err := tieradapter.ParseAndConvert("nonexistent")
	if err == nil {
		t.Error("expected error for invalid tier name")
	}
}
