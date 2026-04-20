// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// PCI-DSS Compliance Module Tests
// =========================================================================

package pci

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPCIDSSFramework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewPCIDSSFramework()
		require.NotNil(t, f)
		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})
}

func TestPCIDSSFrameworkInterface(t *testing.T) {
	f := NewPCIDSSFramework()
	var _ common.Framework = f
}

func TestPCIDSSCheck(t *testing.T) {
	f := NewPCIDSSFramework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{Content: ""})
		require.NoError(t, err)
		assert.True(t, result.Passed)
	})

	t.Run("CheckWithVisaCard", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "Card: 4111111111111111",
		})
		require.NoError(t, err)
		assert.False(t, result.Passed)
	})
}

func TestPCIDSSConfigure(t *testing.T) {
	f := NewPCIDSSFramework()

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

func TestPCIDSSEnableDisable(t *testing.T) {
	f := NewPCIDSSFramework()
	f.Disable()
	assert.False(t, f.IsEnabled())
	f.Enable()
	assert.True(t, f.IsEnabled())
}

func TestPCIDSSGetTier(t *testing.T) {
	f := NewPCIDSSFramework()
	tier := f.GetTier()
	assert.Equal(t, "Professional", tier.Name)
}

func TestPCIDSSGetConfig(t *testing.T) {
	f := NewPCIDSSFramework()
	config := f.GetConfig()
	assert.Equal(t, FrameworkName, config.Name)
}

func TestPCIDSSGetFrameworkID(t *testing.T) {
	f := NewPCIDSSFramework()
	assert.Equal(t, FrameworkID, f.GetFrameworkID())
}

func TestPCIDSSSupportsTier(t *testing.T) {
	f := NewPCIDSSFramework()
	assert.False(t, f.SupportsTier("community"))
	assert.False(t, f.SupportsTier("developer"))
	assert.True(t, f.SupportsTier("professional"))
	assert.True(t, f.SupportsTier("enterprise"))
}
