// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// Compliance Factory Tests
// =========================================================================

package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFrameworkFactory(t *testing.T) {
	t.Run("CreatesFactory", func(t *testing.T) {
		f := NewFrameworkFactory()
		require.NotNil(t, f)
	})
}

func TestCreateForTier(t *testing.T) {
	f := NewFrameworkFactory()

	t.Run("CommunityTier", func(t *testing.T) {
		reg, err := f.CreateForTier("community")
		require.NoError(t, err)
		require.NotNil(t, reg)

		// Community should have at least some frameworks
		count := len(reg.List())
		assert.GreaterOrEqual(t, count, 3) // MITRE ATLAS, NIST AI, OWASP LLM
	})

	t.Run("ProfessionalTier", func(t *testing.T) {
		reg, err := f.CreateForTier("professional")
		require.NoError(t, err)
		require.NotNil(t, reg)

		// Professional should have more frameworks than community
		count := len(reg.List())
		assert.GreaterOrEqual(t, count, 5) // All community + ISO 27001, GDPR, SOC2, HIPAA, PCI
	})

	t.Run("EnterpriseTier", func(t *testing.T) {
		reg, err := f.CreateForTier("enterprise")
		require.NoError(t, err)
		require.NotNil(t, reg)

		// Enterprise should have all frameworks
		count := len(reg.List())
		assert.GreaterOrEqual(t, count, 8) // All frameworks
	})
}

func TestCreateCommunity(t *testing.T) {
	f := NewFrameworkFactory()
	reg, err := f.CreateCommunity()
	require.NoError(t, err)
	require.NotNil(t, reg)

	count := len(reg.List())
	assert.GreaterOrEqual(t, count, 3)
}

func TestCreateProfessional(t *testing.T) {
	f := NewFrameworkFactory()
	reg, err := f.CreateProfessional()
	require.NoError(t, err)
	require.NotNil(t, reg)

	count := len(reg.List())
	assert.GreaterOrEqual(t, count, 5)
}

func TestCreateEnterprise(t *testing.T) {
	f := NewFrameworkFactory()
	reg, err := f.CreateEnterprise()
	require.NoError(t, err)
	require.NotNil(t, reg)

	count := len(reg.List())
	assert.GreaterOrEqual(t, count, 8)
}

func TestGetAllFrameworks(t *testing.T) {
	f := NewFrameworkFactory()
	frameworks := f.GetAllFrameworks()
	assert.Len(t, frameworks, 8) // MITRE ATLAS, NIST AI, OWASP LLM, ISO 27001, GDPR, SOC2, HIPAA, PCI
}
