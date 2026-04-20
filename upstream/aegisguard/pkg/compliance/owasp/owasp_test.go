// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// OWASP LLM Top 10 Compliance Module Tests
// =========================================================================

package owasp

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOWASPLLMFramework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewOWASPLLMFramework()
		require.NotNil(t, f)
		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})
}

func TestOWASPLLMFrameworkInterface(t *testing.T) {
	f := NewOWASPLLMFramework()
	var _ common.Framework = f
}

func TestOWASPGetVulnerabilities(t *testing.T) {
	f := NewOWASPLLMFramework()
	vulns := f.GetVulnerabilities()

	assert.Len(t, vulns, 10) // OWASP LLM Top 10
}

func TestOWASPGetVulnerabilityByID(t *testing.T) {
	f := NewOWASPLLMFramework()

	t.Run("LLM01_Exists", func(t *testing.T) {
		v := f.GetVulnerabilityByID("LLM01")
		require.NotNil(t, v)
		assert.Equal(t, "Prompt Injection", v.Name)
	})

	t.Run("LLM02_Exists", func(t *testing.T) {
		v := f.GetVulnerabilityByID("LLM02")
		require.NotNil(t, v)
		assert.Equal(t, "Sensitive Information Disclosure", v.Name)
	})

	t.Run("InvalidID", func(t *testing.T) {
		v := f.GetVulnerabilityByID("INVALID")
		assert.Nil(t, v)
	})
}

func TestOWASPGetVulnerabilitiesBySeverity(t *testing.T) {
	f := NewOWASPLLMFramework()

	t.Run("Critical", func(t *testing.T) {
		vulns := f.GetVulnerabilitiesBySeverity(common.SeverityCritical)
		assert.NotEmpty(t, vulns)
	})
}

func TestOWASPCheck(t *testing.T) {
	f := NewOWASPLLMFramework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{Content: ""})
		require.NoError(t, err)
		assert.True(t, result.Passed)
		assert.Empty(t, result.Findings)
	})

	t.Run("CheckWithContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "Hello, how can I help you today?",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestOWASPCheckRequest(t *testing.T) {
	f := NewOWASPLLMFramework()
	ctx := context.Background()

	t.Run("CheckRequestWithContent", func(t *testing.T) {
		findings, err := f.CheckRequest(ctx, &common.HTTPRequest{
			Method: "POST",
			URL:    "https://api.example.com/agent/execute",
			Body:   "Normal request content",
		})
		require.NoError(t, err)
		assert.NotNil(t, findings) // Can be empty if no threats found
	})
}

func TestOWASPCheckResponse(t *testing.T) {
	f := NewOWASPLLMFramework()
	ctx := context.Background()

	t.Run("CheckResponseWithContent", func(t *testing.T) {
		findings, err := f.CheckResponse(ctx, &common.HTTPResponse{
			StatusCode: 200,
			Body:       "Normal response content",
		})
		require.NoError(t, err)
		assert.NotNil(t, findings)
	})
}

func TestOWASPConfigure(t *testing.T) {
	f := NewOWASPLLMFramework()

	t.Run("ConfigureEnabled", func(t *testing.T) {
		err := f.Configure(map[string]interface{}{"enabled": true})
		require.NoError(t, err)
		assert.True(t, f.IsEnabled())
	})

	t.Run("ConfigureDisabled", func(t *testing.T) {
		err := f.Configure(map[string]interface{}{"enabled": false})
		require.NoError(t, err)
		assert.False(t, f.IsEnabled())
	})
}

func TestOWASPEnableDisable(t *testing.T) {
	f := NewOWASPLLMFramework()
	f.Disable()
	assert.False(t, f.IsEnabled())
	f.Enable()
	assert.True(t, f.IsEnabled())
}

func TestOWASPGetTier(t *testing.T) {
	f := NewOWASPLLMFramework()
	tier := f.GetTier()
	assert.Equal(t, "Community", tier.Name)
}

func TestOWASPSupportsTier(t *testing.T) {
	f := NewOWASPLLMFramework()
	// OWASP LLM Top 10 applies to all tiers
	assert.True(t, f.SupportsTier("community"))
	assert.True(t, f.SupportsTier("developer"))
	assert.True(t, f.SupportsTier("professional"))
	assert.True(t, f.SupportsTier("enterprise"))
}

func TestOWASPGetFrameworkID(t *testing.T) {
	f := NewOWASPLLMFramework()
	assert.Equal(t, FrameworkID, f.GetFrameworkID())
}

func TestOWASPGetPatternCount(t *testing.T) {
	f := NewOWASPLLMFramework()
	assert.Equal(t, 10, f.GetPatternCount()) // Top 10
}

func TestOWASPVulnerabilities(t *testing.T) {
	f := NewOWASPLLMFramework()
	vulns := f.GetVulnerabilities()

	for _, vuln := range vulns {
		t.Run(vuln.ID, func(t *testing.T) {
			assert.NotEmpty(t, vuln.Patterns)
			assert.NotEmpty(t, vuln.Mitigation)
			assert.NotEmpty(t, vuln.Severity)
		})
	}
}

// Benchmark OWASP LLM Check
func BenchmarkOWASPCheck(b *testing.B) {
	f := NewOWASPLLMFramework()
	ctx := context.Background()
	input := common.CheckInput{
		Content: "Test content",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Check(ctx, input)
	}
}
