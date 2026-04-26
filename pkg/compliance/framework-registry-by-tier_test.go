// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

// TestFrameworkRegistryByTier tests the GetByTier functions
func TestFrameworkRegistryByTier(t *testing.T) {
	registry := NewRegistry()

	t.Run("GetByTier", func(t *testing.T) {
		// GetByTier() returns frameworks for current tier
		frameworks := registry.GetByTier()
		// May be empty if no frameworks registered
		_ = frameworks
	})

	t.Run("GetByTierID Community", func(t *testing.T) {
		frameworks := registry.GetByTierID(TierCommunity)
		_ = frameworks
	})

	t.Run("GetAvailableFrameworks", func(t *testing.T) {
		frameworks := registry.GetAvailableFrameworks()
		// May be empty but should not panic
		_ = frameworks
	})
}

// TestFrameworkRegistryCheckFunctions tests CheckAll and CheckFramework
func TestFrameworkRegistryCheckFunctions(t *testing.T) {
	registry := NewRegistry()

	t.Run("CheckAll", func(t *testing.T) {
		input := common.CheckInput{}
		_, err := registry.CheckAll(nil, input)
		// May fail but should not panic
		_ = err
	})

	t.Run("CheckFramework not found", func(t *testing.T) {
		input := common.CheckInput{}
		_, err := registry.CheckFramework(nil, "nonexistent", input)
		// Should return error for nonexistent framework
		if err == nil {
			t.Error("CheckFramework should return error for nonexistent framework")
		}
	})
}
