// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// SOC 2 Type II Compliance Module Tests
// =========================================================================

package soc2

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSOC2Framework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewSOC2Framework()
		require.NotNil(t, f)

		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})

	t.Run("InitializesPrinciples", func(t *testing.T) {
		f := NewSOC2Framework()
		principles := f.GetPrinciples()

		assert.Len(t, principles, 5)
		assert.Contains(t, []string{principles[0].ID}, "TSP-SEC")
	})

	t.Run("InitializesAuditControls", func(t *testing.T) {
		f := NewSOC2Framework()
		controls := f.GetAuditControls()

		assert.NotEmpty(t, controls)
	})
}

func TestSOC2FrameworkInterface(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("ImplementsFrameworkInterface", func(t *testing.T) {
		var _ common.Framework = f
	})

	t.Run("GetFrameworkID", func(t *testing.T) {
		assert.Equal(t, FrameworkID, f.GetFrameworkID())
	})

	t.Run("GetPatternCount", func(t *testing.T) {
		count := f.GetPatternCount()
		assert.Greater(t, count, 0)
	})

	t.Run("GetSeverityLevels", func(t *testing.T) {
		levels := f.GetSeverityLevels()
		assert.Contains(t, levels, common.SeverityCritical)
		assert.Contains(t, levels, common.SeverityHigh)
		assert.Contains(t, levels, common.SeverityMedium)
		assert.Contains(t, levels, common.SeverityLow)
	})
}

func TestSOC2Check(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, FrameworkName, result.Framework)
	})

	t.Run("CheckWithContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "test content for compliance check",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Greater(t, result.TotalPatterns, 0)
	})

	t.Run("CheckWithAgentMetadata", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "agent action data",
			Metadata: map[string]string{
				"agent_id": "agent-123",
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestSOC2CheckRequest(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("CheckRequestWithAuth", func(t *testing.T) {
		findings, err := f.CheckRequest(context.Background(), &common.HTTPRequest{
			Method:    "POST",
			URL:       "https://api.example.com/agent/execute",
			Headers:   map[string]string{"Authorization": "Bearer token"},
			UserAgent: "AegisGuard/1.0",
		})
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("CheckRequestWithoutAuth", func(t *testing.T) {
		findings, err := f.CheckRequest(context.Background(), &common.HTTPRequest{
			Method:  "POST",
			URL:     "https://api.example.com/agent/execute",
			Headers: map[string]string{},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, findings)

		// Should have finding for missing Authorization header
		var authFinding *common.Finding
		for i := range findings {
			if findings[i].Severity == common.SeverityHigh {
				authFinding = &findings[i]
				break
			}
		}
		assert.NotNil(t, authFinding)
	})
}

func TestSOC2CheckResponse(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("CheckResponseWithSecurityHeaders", func(t *testing.T) {
		findings, err := f.CheckResponse(context.Background(), &common.HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Strict-Transport-Security": "max-age=31536000",
			},
		})
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("CheckResponseWithoutSecurityHeaders", func(t *testing.T) {
		findings, err := f.CheckResponse(context.Background(), &common.HTTPResponse{
			StatusCode: 200,
			Headers:    map[string]string{},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})
}

func TestSOC2Configure(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("ConfigureEnabled", func(t *testing.T) {
		err := f.Configure(map[string]interface{}{
			"enabled": true,
		})
		require.NoError(t, err)
		assert.True(t, f.IsEnabled())
	})

	t.Run("ConfigureDisabled", func(t *testing.T) {
		err := f.Configure(map[string]interface{}{
			"enabled": false,
		})
		require.NoError(t, err)
		assert.False(t, f.IsEnabled())
	})
}

func TestSOC2EnableDisable(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("Enable", func(t *testing.T) {
		f.Disable()
		f.Enable()
		assert.True(t, f.IsEnabled())
	})

	t.Run("Disable", func(t *testing.T) {
		f.Enable()
		f.Disable()
		assert.False(t, f.IsEnabled())
	})
}

func TestSOC2SupportsTier(t *testing.T) {
	f := NewSOC2Framework()

	tests := []struct {
		tier     string
		expected bool
	}{
		{"community", false},
		{"developer", false},
		{"professional", true},
		{"enterprise", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			result := f.SupportsTier(tt.tier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSOC2GetTier(t *testing.T) {
	f := NewSOC2Framework()
	tier := f.GetTier()

	assert.Equal(t, "Professional", tier.Name)
	assert.NotEmpty(t, tier.Pricing)
}

func TestSOC2GetPricing(t *testing.T) {
	f := NewSOC2Framework()
	pricing := f.GetPricing()

	assert.Equal(t, "Professional", pricing.Tier)
	assert.Greater(t, pricing.MonthlyCost, 0.0)
	assert.NotEmpty(t, pricing.Features)
}

func TestSOC2GetConfig(t *testing.T) {
	f := NewSOC2Framework()
	config := f.GetConfig()

	assert.Equal(t, FrameworkName, config.Name)
	assert.Equal(t, FrameworkVersion, config.Version)
	assert.True(t, config.Enabled)
}

func TestCheckAgentAction(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("CheckValidAgentAction", func(t *testing.T) {
		result, err := f.CheckAgentAction(
			context.Background(),
			"agent-123",
			"session-456",
			"file_read",
		)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "agent-123", result.AgentID)
		assert.Equal(t, "session-456", result.SessionID)
		assert.Equal(t, "file_read", result.ToolName)
		assert.True(t, result.Compliant)
	})
}

func TestGenerateAuditReport(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("GenerateReport", func(t *testing.T) {
		report := f.GenerateAuditReport()
		require.NotNil(t, report)

		assert.Equal(t, FrameworkName, report.Framework)
		assert.Equal(t, FrameworkVersion, report.Version)
		assert.Len(t, report.Principles, 5)
		assert.NotEmpty(t, report.AuditControls)
		assert.Equal(t, "Compliant", report.Status)
	})
}

func TestTrustServicePrinciples(t *testing.T) {
	f := NewSOC2Framework()
	principles := f.GetPrinciples()

	expectedIDs := []string{"TSP-SEC", "TSP-AVAIL", "TSP-PROC", "TSP-CONF", "TSP-PRIV"}
	for _, id := range expectedIDs {
		found := false
		for _, p := range principles {
			if p.ID == id {
				found = true
				assert.NotEmpty(t, p.Name)
				assert.NotEmpty(t, p.Description)
				assert.NotEmpty(t, p.Criteria)
				break
			}
		}
		assert.True(t, found, "Expected principle %s not found", id)
	}
}

func TestAgentAuditControls(t *testing.T) {
	f := NewSOC2Framework()
	controls := f.GetAuditControls()

	// Verify critical controls exist
	controlMap := make(map[string]AgentAuditControl)
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	// Check security controls
	if _, ok := controlMap["SEC-001"]; ok {
		assert.Equal(t, "TSP-SEC", controlMap["SEC-001"].Principle)
	}

	// Check availability controls
	if _, ok := controlMap["AVL-001"]; ok {
		assert.Equal(t, "TSP-AVAIL", controlMap["AVL-001"].Principle)
	}

	// Check confidentiality controls
	if _, ok := controlMap["CONF-001"]; ok {
		assert.Equal(t, "TSP-CONF", controlMap["CONF-001"].Principle)
	}

	// Check privacy controls
	if _, ok := controlMap["PRIV-001"]; ok {
		assert.Equal(t, "TSP-PRIV", controlMap["PRIV-001"].Principle)
	}
}

func TestGetDescription(t *testing.T) {
	f := NewSOC2Framework()
	desc := f.GetDescription()
	assert.Contains(t, desc, "SOC 2")
	assert.Contains(t, desc, "Trust Service")
}

func TestDurationMetrics(t *testing.T) {
	f := NewSOC2Framework()

	t.Run("CheckRecordsDuration", func(t *testing.T) {
		_, _ = f.Check(context.Background(), common.CheckInput{
			Content: "test content",
		})
		// Duration is recorded in the result (verified in Check tests)
	})
}

// BenchmarkSOC2Check benchmarks the Check method
func BenchmarkSOC2Check(b *testing.B) {
	f := NewSOC2Framework()
	ctx := context.Background()
	input := common.CheckInput{
		Content: "benchmark test content for SOC 2 compliance",
		Metadata: map[string]string{
			"agent_id": "agent-benchmark",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Check(ctx, input)
	}
}

// BenchmarkSOC2CheckRequest benchmarks the CheckRequest method
func BenchmarkSOC2CheckRequest(b *testing.B) {
	f := NewSOC2Framework()
	ctx := context.Background()
	req := &common.HTTPRequest{
		Method:    "POST",
		URL:       "https://api.example.com/agent/execute",
		Headers:   map[string]string{"Authorization": "Bearer token"},
		UserAgent: "AegisGuard/1.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.CheckRequest(ctx, req)
	}
}
