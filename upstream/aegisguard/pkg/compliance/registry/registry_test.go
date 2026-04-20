// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// Compliance Registry Tests
// =========================================================================

package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFramework is a test implementation of common.Framework
type mockFramework struct {
	id, name, version, description string
	enabled                        bool
	tier                           string
	patternCount                   int
	severityLevels                 []common.Severity
	checkFunc                      func() (*common.CheckResult, error)
}

func (m *mockFramework) GetName() string                      { return m.name }
func (m *mockFramework) GetVersion() string                   { return m.version }
func (m *mockFramework) GetDescription() string               { return m.description }
func (m *mockFramework) IsEnabled() bool                      { return m.enabled }
func (m *mockFramework) Enable()                              { m.enabled = true }
func (m *mockFramework) Disable()                             { m.enabled = false }
func (m *mockFramework) GetFrameworkID() string               { return m.id }
func (m *mockFramework) GetPatternCount() int                 { return m.patternCount }
func (m *mockFramework) GetSeverityLevels() []common.Severity { return m.severityLevels }
func (m *mockFramework) GetTier() common.TierInfo             { return common.TierInfo{Name: m.tier} }
func (m *mockFramework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{Name: m.name, Version: m.version, Enabled: m.enabled}
}
func (m *mockFramework) SupportsTier(tier string) bool                 { return tier == m.tier || tier == "enterprise" }
func (m *mockFramework) Configure(config map[string]interface{}) error { return nil }
func (m *mockFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	if m.checkFunc != nil {
		return m.checkFunc()
	}
	return &common.CheckResult{
		Framework:       m.name,
		Passed:          true,
		Findings:        []common.Finding{},
		CheckedAt:       input.Timestamp,
		TotalPatterns:   m.patternCount,
		MatchedPatterns: 0,
	}, nil
}
func (m *mockFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	return []common.Finding{}, nil
}
func (m *mockFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func TestNewRegistry(t *testing.T) {
	t.Run("CreatesRegistry", func(t *testing.T) {
		reg := NewRegistry("community")
		require.NotNil(t, reg)
		assert.Equal(t, "community", reg.GetTier())
		assert.Equal(t, 0, reg.Count())
	})
}

func TestRegistryRegister(t *testing.T) {
	t.Run("RegisterFramework", func(t *testing.T) {
		reg := NewRegistry("community")
		fw := &mockFramework{
			id:          "test-fw",
			name:        "Test Framework",
			version:     "1.0",
			description: "Test framework",
			enabled:     true,
			tier:        "community",
		}

		err := reg.Register(fw)
		require.NoError(t, err)
		assert.Equal(t, 1, reg.Count())
	})

	t.Run("RegisterNil", func(t *testing.T) {
		reg := NewRegistry("community")
		err := reg.Register(nil)
		assert.Error(t, err)
	})

	t.Run("RegisterUnsupportedTier", func(t *testing.T) {
		reg := NewRegistry("community")
		fw := &mockFramework{
			id:   "test-fw",
			name: "Test Framework",
			tier: "enterprise",
		}

		err := reg.Register(fw)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tier not supported")
	})
}

func TestRegistryGet(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{
		id:   "test-fw",
		name: "Test Framework",
		tier: "community",
	}
	reg.Register(fw)

	t.Run("GetExisting", func(t *testing.T) {
		result, ok := reg.Get("test-fw")
		assert.True(t, ok)
		assert.Equal(t, "test-fw", result.GetFrameworkID())
	})

	t.Run("GetNonExisting", func(t *testing.T) {
		_, ok := reg.Get("non-existing")
		assert.False(t, ok)
	})
}

func TestRegistryList(t *testing.T) {
	reg := NewRegistry("community")

	t.Run("ListEmpty", func(t *testing.T) {
		frameworks := reg.List()
		assert.Empty(t, frameworks)
	})

	t.Run("ListWithFrameworks", func(t *testing.T) {
		reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community"})
		reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "community"})

		frameworks := reg.List()
		assert.Len(t, frameworks, 2)
	})
}

func TestRegistryUnregister(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "test-fw", name: "Test", tier: "community"}
	reg.Register(fw)

	t.Run("UnregisterExisting", func(t *testing.T) {
		reg.Unregister("test-fw")
		assert.Equal(t, 0, reg.Count())
	})

	t.Run("UnregisterNonExisting", func(t *testing.T) {
		reg.Unregister("non-existing") // Should not panic
	})
}

func TestRegistrySetTier(t *testing.T) {
	t.Run("SetTierValid", func(t *testing.T) {
		reg := NewRegistry("community")
		err := reg.SetTier("enterprise")
		require.NoError(t, err)
		assert.Equal(t, "enterprise", reg.GetTier())
	})
}

func TestRegistryEnableDisable(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "test-fw", name: "Test", tier: "community"}
	reg.Register(fw)

	t.Run("Enable", func(t *testing.T) {
		err := reg.Enable("test-fw")
		require.NoError(t, err)
	})

	t.Run("Disable", func(t *testing.T) {
		err := reg.Disable("test-fw")
		require.NoError(t, err)
	})

	t.Run("EnableNonExisting", func(t *testing.T) {
		err := reg.Enable("non-existing")
		assert.Error(t, err)
	})
}

func TestRegistryCheckAll(t *testing.T) {
	reg := NewRegistry("community")
	fw1 := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", patternCount: 10}
	fw2 := &mockFramework{id: "fw2", name: "Framework 2", tier: "community", patternCount: 5}
	reg.Register(fw1)
	reg.Register(fw2)

	// Explicitly enable frameworks
	reg.Enable("fw1")
	reg.Enable("fw2")

	result, err := reg.CheckAll(context.Background(), common.CheckInput{
		Content: "test content",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Frameworks, 2)
	assert.Equal(t, 15, result.TotalPatterns)
	assert.True(t, result.OverallPassed)
}

func TestRegistryCheckAllRequests(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community"}
	reg.Register(fw)

	// Explicitly enable framework
	reg.Enable("fw1")

	result, err := reg.CheckAllRequests(context.Background(), &common.HTTPRequest{
		Method: "POST",
		URL:    "https://api.example.com",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Frameworks, 1)
}

func TestRegistryCheckAllResponses(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community"}
	reg.Register(fw)

	// Explicitly enable framework
	reg.Enable("fw1")

	result, err := reg.CheckAllResponses(context.Background(), &common.HTTPResponse{
		StatusCode: 200,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Frameworks, 1)
}

func TestRegistryGetStats(t *testing.T) {
	reg := NewRegistry("community")
	reg.Register(&mockFramework{id: "fw1", name: "Framework 1", version: "1.0", tier: "community", patternCount: 10})
	reg.Register(&mockFramework{id: "fw2", name: "Framework 2", version: "2.0", tier: "community", patternCount: 5})

	stats := reg.GetStats()

	assert.Equal(t, "community", stats.Tier)
	assert.Equal(t, 2, stats.TotalFrameworks)
	assert.Len(t, stats.Frameworks, 2)
}

func TestRegistryConfigure(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "test-fw", name: "Test", tier: "community"}
	reg.Register(fw)

	err := reg.Configure("test-fw", map[string]interface{}{"enabled": true})
	require.NoError(t, err)
}

// mockFrameworkWithError creates a mock framework that returns an error during Check
func mockFrameworkWithError(id, name, tier string, err error) *mockFramework {
	return &mockFramework{
		id:   id,
		name: name,
		tier: tier,
		checkFunc: func() (*common.CheckResult, error) {
			return nil, err
		},
	}
}

func TestRegistryCheckAll_ContextCancellation(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community"}
	reg.Register(fw)
	reg.Enable("fw1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := reg.CheckAll(ctx, common.CheckInput{Content: "test"})
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegistryCheckAll_FrameworkError(t *testing.T) {
	reg := NewRegistry("community")
	err := fmt.Errorf("simulated error")
	fw := mockFrameworkWithError("fw1", "Framework 1", "community", err)
	reg.Register(fw)
	reg.Enable("fw1")

	result, err := reg.CheckAll(context.Background(), common.CheckInput{Content: "test"})
	assert.NoError(t, err)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "simulated error")
}

func TestRegistryCheckAll_EmptyInput(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", patternCount: 5}
	reg.Register(fw)
	reg.Enable("fw1")

	result, err := reg.CheckAll(context.Background(), common.CheckInput{Content: ""})
	assert.NoError(t, err)
	assert.Len(t, result.Frameworks, 1)
	assert.Equal(t, 5, result.TotalPatterns)
}

func TestRegistryCheckAllRequests_NilRequest(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community"}
	reg.Register(fw)
	reg.Enable("fw1")

	result, err := reg.CheckAllRequests(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegistryCheckAllResponses_NilResponse(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community"}
	reg.Register(fw)
	reg.Enable("fw1")

	result, err := reg.CheckAllResponses(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegistry_Concurrency(t *testing.T) {
	reg := NewRegistry("community")
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fw := &mockFramework{
				id:           fmt.Sprintf("fw%d", id),
				name:         fmt.Sprintf("Framework %d", id),
				version:      "1.0",
				description:  fmt.Sprintf("Framework %d", id),
				enabled:      true,
				tier:         "community",
				patternCount: 5,
			}
			err := reg.Register(fw)
			if err != nil {
				return // Skip duplicates
			}
			reg.Enable(fmt.Sprintf("fw%d", id))
			_, _ = reg.CheckAll(context.Background(), common.CheckInput{Content: "test"})
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 10, reg.Count())
}

// TestRegistry_RegisterAll tests batch registration of frameworks
func TestRegistry_RegisterAll(t *testing.T) {
	t.Run("RegisterAllSuccess", func(t *testing.T) {
		reg := NewRegistry("community")
		frameworks := []common.Framework{
			&mockFramework{id: "fw1", name: "Framework 1", tier: "community"},
			&mockFramework{id: "fw2", name: "Framework 2", tier: "community"},
		}

		err := reg.RegisterAll(frameworks)
		assert.NoError(t, err)
		assert.Equal(t, 2, reg.Count())
	})

	t.Run("RegisterAllPartialFailure", func(t *testing.T) {
		reg := NewRegistry("community")
		frameworks := []common.Framework{
			&mockFramework{id: "fw1", name: "Framework 1", tier: "community"},
			nil, // Invalid framework
		}

		err := reg.RegisterAll(frameworks)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil framework")
		assert.Equal(t, 1, reg.Count()) // Only 1 framework registered
	})
}

// TestRegistry_ListByTier tests filtering frameworks by tier
func TestRegistry_ListByTier(t *testing.T) {
	reg := NewRegistry("community")
	reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community"})
	reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "enterprise"})

	t.Run("ListCommunityTier", func(t *testing.T) {
		reg := NewRegistry("community")
		reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community"})
		reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "enterprise"})
		frameworks := reg.ListByTier()
		assert.Len(t, frameworks, 1)
		assert.Equal(t, "fw1", frameworks[0].GetFrameworkID())
	})

	t.Run("ListEnterpriseTier", func(t *testing.T) {
		reg := NewRegistry("enterprise")
		reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community"})
		reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "enterprise"})
		frameworks := reg.ListByTier()
		assert.Len(t, frameworks, 2)
	})
}

// TestRegistry_ListEnabled tests filtering enabled frameworks
func TestRegistry_ListEnabled(t *testing.T) {
	reg := NewRegistry("community")
	reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community", enabled: true})
	reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "community", enabled: false})

	frameworks := reg.ListEnabled()
	assert.Len(t, frameworks, 1)
	assert.Equal(t, "fw1", frameworks[0].GetFrameworkID())
}

// TestRegistry_CountEnabled tests counting enabled frameworks
func TestRegistry_CountEnabled(t *testing.T) {
	reg := NewRegistry("community")
	reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community", enabled: true})
	reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "community", enabled: false})

	assert.Equal(t, 1, reg.CountEnabled())
}

// TestRegistry_CheckByFramework tests checking with a specific framework
func TestRegistry_CheckByFramework(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", patternCount: 5}
	reg.Register(fw)
	reg.Enable("fw1")

	t.Run("CheckByFrameworkSuccess", func(t *testing.T) {
		result, err := reg.CheckByFramework(context.Background(), "fw1", common.CheckInput{Content: "test"})
		assert.NoError(t, err)
		assert.Equal(t, 5, result.TotalPatterns)
	})

	t.Run("CheckByFrameworkNotFound", func(t *testing.T) {
		_, err := reg.CheckByFramework(context.Background(), "fw2", common.CheckInput{Content: "test"})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFrameworkNotFound))
	})

	t.Run("CheckByFrameworkDisabled", func(t *testing.T) {
		reg.Disable("fw1")
		_, err := reg.CheckByFramework(context.Background(), "fw1", common.CheckInput{Content: "test"})
		assert.NoError(t, err) // Disabled frameworks are skipped, not an error
	})
}

// TestRegistry_CheckByFrameworks tests checking with specific frameworks
func TestRegistry_CheckByFrameworks(t *testing.T) {
	reg := NewRegistry("community")
	fw1 := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", patternCount: 5}
	fw2 := &mockFramework{id: "fw2", name: "Framework 2", tier: "community", patternCount: 3}
	reg.Register(fw1)
	reg.Register(fw2)
	reg.Enable("fw1")
	reg.Enable("fw2")

	t.Run("CheckByFrameworksSuccess", func(t *testing.T) {
		reg := NewRegistry("community")
		fw1 := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", patternCount: 5, enabled: true}
		fw2 := &mockFramework{id: "fw2", name: "Framework 2", tier: "community", patternCount: 3, enabled: true}
		reg.Register(fw1)
		reg.Register(fw2)
		reg.Enable("fw1")
		reg.Enable("fw2")

		result, err := reg.CheckByFrameworks(context.Background(), []string{"fw1", "fw2"}, common.CheckInput{Content: "test"})
		assert.NoError(t, err)
		assert.Len(t, result.Frameworks, 2)

		// Calculate total patterns from individual framework results
		totalPatterns := 0
		for _, fwResult := range result.Frameworks {
			totalPatterns += fwResult.TotalPatterns
		}
		assert.Equal(t, 8, totalPatterns)
	})

	t.Run("CheckByFrameworksNotFound", func(t *testing.T) {
		result, err := reg.CheckByFrameworks(context.Background(), []string{"fw1", "fw3"}, common.CheckInput{Content: "test"})
		assert.NoError(t, err)
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0], "fw3")
	})
}

// TestRegistry_EnableAll_DisableAll tests bulk enable/disable
func TestRegistry_EnableAll_DisableAll(t *testing.T) {
	reg := NewRegistry("community")
	reg.Register(&mockFramework{id: "fw1", name: "Framework 1", tier: "community", enabled: false})
	reg.Register(&mockFramework{id: "fw2", name: "Framework 2", tier: "community", enabled: false})

	t.Run("EnableAll", func(t *testing.T) {
		reg.EnableAll()
		assert.Equal(t, 2, reg.CountEnabled())
	})

	t.Run("DisableAll", func(t *testing.T) {
		reg.DisableAll()
		assert.Equal(t, 0, reg.CountEnabled())
	})
}

// TestRegistry_IsRegistered_IsEnabled tests registration and enablement checks
func TestRegistry_IsRegistered_IsEnabled(t *testing.T) {
	reg := NewRegistry("community")
	fw := &mockFramework{id: "fw1", name: "Framework 1", tier: "community", enabled: true}
	reg.Register(fw)

	t.Run("IsRegistered", func(t *testing.T) {
		assert.True(t, reg.IsRegistered("fw1"))
		assert.False(t, reg.IsRegistered("fw2"))
	})

	t.Run("IsEnabled", func(t *testing.T) {
		assert.True(t, reg.IsEnabled("fw1"))
		reg.Disable("fw1")
		assert.False(t, reg.IsEnabled("fw1"))
		assert.False(t, reg.IsEnabled("fw2"))
	})
}
