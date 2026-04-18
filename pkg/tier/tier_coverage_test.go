package tier

import "testing"

func TestInvalidTierDefaults(t *testing.T) {
	invalid := Tier(255)

	tests := []struct {
		name     string
		got      interface{}
		want     interface{}
	}{
		{"RateLimitProxy default", invalid.RateLimitProxy(), 120},
		{"RateLimitMCP default", invalid.RateLimitMCP(), 60},
		{"MaxUsers default", invalid.MaxUsers(), 3},
		{"MaxAgents default", invalid.MaxAgents(), 2},
		{"LogRetentionDays default", invalid.LogRetentionDays(), 7},
		{"SupportLevel default", invalid.SupportLevel(), "community"},
		{"MaxConcurrentMCP default", invalid.MaxConcurrentMCP(), 5},
		{"MaxMCPToolsPerSession default", invalid.MaxMCPToolsPerSession(), 20},
		{"MCPExecTimeoutSeconds default", invalid.MCPExecTimeoutSeconds(), 30},
		{"MaxMCPSandboxMemoryMB default", invalid.MaxMCPSandboxMemoryMB(), 256},
		{"RequiredTier default", RequiredTier(Feature("nonexistent")), TierCommunity},
		{"RateLimit (deprecated) default", invalid.RateLimit(), 120},
		{"String default", invalid.String(), "unknown"},
		{"DisplayName default", invalid.DisplayName(), "Unknown"},
		{"CanAccess with invalid tier", invalid.CanAccess(TierCommunity), true},
		{"CanAccess invalid vs invalid", invalid.CanAccess(Tier(255)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}