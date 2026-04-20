// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// HIPAA Compliance Module Tests
// =========================================================================

package hipaa

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHIPAAFramework(t *testing.T) {
	t.Run("CreatesFramework", func(t *testing.T) {
		f := NewHIPAAFramework()
		require.NotNil(t, f)
		assert.Equal(t, FrameworkName, f.GetName())
		assert.Equal(t, FrameworkVersion, f.GetVersion())
		assert.True(t, f.IsEnabled())
	})
}

func TestHIPAAFrameworkInterface(t *testing.T) {
	f := NewHIPAAFramework()
	var _ common.Framework = f
}

func TestHIPAAFrameworkCheck(t *testing.T) {
	f := NewHIPAAFramework()

	t.Run("CheckWithEmptyContent", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{Content: ""})
		require.NoError(t, err)
		assert.True(t, result.Passed)
	})

	t.Run("CheckWithSSN", func(t *testing.T) {
		result, err := f.Check(context.Background(), common.CheckInput{
			Content: "Patient SSN: 123-45-6789",
		})
		require.NoError(t, err)
		assert.False(t, result.Passed)
		assert.NotEmpty(t, result.Findings)
	})
}

func TestHIPAACheckPHI(t *testing.T) {
	f := NewHIPAAFramework()

	t.Run("DetectSSN", func(t *testing.T) {
		result, err := f.CheckPHI("SSN: 123-45-6789")
		require.NoError(t, err)
		assert.True(t, result.PHIDetected)
	})

	t.Run("CleanContent", func(t *testing.T) {
		result, err := f.CheckPHI("This is clean content")
		require.NoError(t, err)
		assert.False(t, result.PHIDetected)
	})
}

func TestHIPAAConfigure(t *testing.T) {
	f := NewHIPAAFramework()

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

func TestHIPAAEnableDisable(t *testing.T) {
	f := NewHIPAAFramework()
	f.Disable()
	assert.False(t, f.IsEnabled())
	f.Enable()
	assert.True(t, f.IsEnabled())
}

func TestHIPAAGetTier(t *testing.T) {
	f := NewHIPAAFramework()
	tier := f.GetTier()
	assert.Equal(t, "Professional", tier.Name)
}

func TestHIPAAGetConfig(t *testing.T) {
	f := NewHIPAAFramework()
	config := f.GetConfig()
	assert.Equal(t, FrameworkName, config.Name)
	assert.Equal(t, FrameworkVersion, config.Version)
	assert.True(t, config.Enabled)
}

func TestHIPAAGetFrameworkID(t *testing.T) {
	f := NewHIPAAFramework()
	assert.Equal(t, FrameworkID, f.GetFrameworkID())
}

func TestHIPAAGetPatternCount(t *testing.T) {
	f := NewHIPAAFramework()
	assert.Greater(t, f.GetPatternCount(), 0)
}

func TestHIPAAGetSeverityLevels(t *testing.T) {
	f := NewHIPAAFramework()
	levels := f.GetSeverityLevels()
	assert.Contains(t, levels, common.SeverityCritical)
	assert.Contains(t, levels, common.SeverityHigh)
}

func TestHIPAAGetDescription(t *testing.T) {
	f := NewHIPAAFramework()
	desc := f.GetDescription()
	assert.Contains(t, desc, "HIPAA")
}
