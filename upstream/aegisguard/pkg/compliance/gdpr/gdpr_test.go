// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// GDPR Compliance Module Tests
// =========================================================================

package gdpr

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGDPRFramework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewGDPRFramework()
		require.NotNil(t, f)
		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})
}

func TestGDPRFrameworkInterface(t *testing.T) {
	f := NewGDPRFramework()
	var _ common.Framework = f
}

func TestGDPRCheck(t *testing.T) {
	f := NewGDPRFramework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{Content: ""})
		require.NoError(t, err)
		assert.True(t, result.Passed)
	})

	t.Run("CheckWithEmail", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "Email: user@example.com",
		})
		require.NoError(t, err)
		assert.False(t, result.Passed)
	})
}

func TestGDPRConfigure(t *testing.T) {
	f := NewGDPRFramework()

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

func TestGDPREnableDisable(t *testing.T) {
	f := NewGDPRFramework()
	f.Disable()
	assert.False(t, f.IsEnabled())
	f.Enable()
	assert.True(t, f.IsEnabled())
}

func TestGDPRGetTier(t *testing.T) {
	f := NewGDPRFramework()
	tier := f.GetTier()
	assert.Equal(t, "Community", tier.Name)
}

func TestGDPRGetConfig(t *testing.T) {
	f := NewGDPRFramework()
	config := f.GetConfig()
	assert.Equal(t, FrameworkName, config.Name)
}

func TestGDPRGetFrameworkID(t *testing.T) {
	f := NewGDPRFramework()
	assert.Equal(t, FrameworkID, f.GetFrameworkID())
}

func TestGDPRSupportsTier(t *testing.T) {
	f := NewGDPRFramework()
	// GDPR applies to all tiers
	assert.True(t, f.SupportsTier("community"))
	assert.True(t, f.SupportsTier("developer"))
	assert.True(t, f.SupportsTier("professional"))
	assert.True(t, f.SupportsTier("enterprise"))
}

func TestGDPRGetDataSubjectRights(t *testing.T) {
	f := NewGDPRFramework()
	rights := f.GetDataSubjectRights()
	assert.NotEmpty(t, rights)
	assert.GreaterOrEqual(t, len(rights), 5)
}
