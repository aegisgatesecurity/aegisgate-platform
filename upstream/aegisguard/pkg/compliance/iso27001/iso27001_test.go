// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// ISO 27001 Compliance Module Tests
// =========================================================================

package iso27001

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewISO27001Framework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewISO27001Framework()
		require.NotNil(t, f)
		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})
}

func TestISO27001FrameworkInterface(t *testing.T) {
	f := NewISO27001Framework()
	var _ common.Framework = f
}

func TestISO27001GetControls(t *testing.T) {
	f := NewISO27001Framework()
	controls := f.GetControls()

	assert.NotEmpty(t, controls)
	assert.GreaterOrEqual(t, len(controls), 10)
}

func TestISO27001GetClauses(t *testing.T) {
	f := NewISO27001Framework()
	clauses := f.GetClauses()

	assert.NotEmpty(t, clauses)
	assert.Len(t, clauses, 7) // Clauses 4-10

	// Verify mandatory clauses
	for _, c := range clauses {
		if c.Number == "4" || c.Number == "5" || c.Number == "6" || c.Number == "7" || c.Number == "8" || c.Number == "9" || c.Number == "10" {
			assert.True(t, c.Mandatory)
		}
	}
}

func TestISO27001GetControlsByDomain(t *testing.T) {
	f := NewISO27001Framework()

	t.Run("A5Controls", func(t *testing.T) {
		controls := f.GetControlsByDomain("A.5")
		assert.NotEmpty(t, controls)
		for _, c := range controls {
			assert.Equal(t, "A.5", c.Domain)
		}
	})

	t.Run("A8Controls", func(t *testing.T) {
		controls := f.GetControlsByDomain("A.8")
		assert.NotEmpty(t, controls)
		for _, c := range controls {
			assert.Equal(t, "A.8", c.Domain)
		}
	})

	t.Run("InvalidDomain", func(t *testing.T) {
		controls := f.GetControlsByDomain("A.99")
		assert.Empty(t, controls)
	})
}

func TestISO27001Check(t *testing.T) {
	f := NewISO27001Framework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{Content: ""})
		require.NoError(t, err)
		assert.True(t, result.Passed)
	})

	t.Run("CheckWithContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "Test content for ISO 27001 compliance check",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestISO27001CheckRequest(t *testing.T) {
	f := NewISO27001Framework()

	t.Run("CheckRequestWithAuth", func(t *testing.T) {
		findings, err := f.CheckRequest(context.Background(), &common.HTTPRequest{
			Method:  "POST",
			URL:     "https://api.example.com/agent/execute",
			Headers: map[string]string{"Authorization": "Bearer token"},
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
	})
}

func TestISO27001Configure(t *testing.T) {
	f := NewISO27001Framework()

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

func TestISO27001EnableDisable(t *testing.T) {
	f := NewISO27001Framework()
	f.Disable()
	assert.False(t, f.IsEnabled())
	f.Enable()
	assert.True(t, f.IsEnabled())
}

func TestISO27001GetTier(t *testing.T) {
	f := NewISO27001Framework()
	tier := f.GetTier()
	assert.Equal(t, "Community", tier.Name)
}

func TestISO27001GetPricing(t *testing.T) {
	f := NewISO27001Framework()
	pricing := f.GetPricing()
	assert.Equal(t, "Community", pricing.Tier)
	assert.Equal(t, float64(0), pricing.MonthlyCost)
}

func TestISO27001SupportsTier(t *testing.T) {
	f := NewISO27001Framework()
	// ISO 27001 applies to all tiers
	assert.True(t, f.SupportsTier("community"))
	assert.True(t, f.SupportsTier("developer"))
	assert.True(t, f.SupportsTier("professional"))
	assert.True(t, f.SupportsTier("enterprise"))
}

func TestISO27001GetFrameworkID(t *testing.T) {
	f := NewISO27001Framework()
	assert.Equal(t, FrameworkID, f.GetFrameworkID())
}

func TestISO27001GetPatternCount(t *testing.T) {
	f := NewISO27001Framework()
	assert.Greater(t, f.GetPatternCount(), 0)
}
