// SPDX-License-Identifier: Apache-2.0
//go:build !race

package compliance

import (
	"context"
	"errors"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

// mockCovFramework implements common.Framework for testing
type mockCovFramework struct {
	id           string
	name         string
	version      string
	desc         string
	enabled      bool
	patterns     int
	severities   []common.Severity
	shouldFail   bool
	returnErr    error
	returnResult *common.CheckResult
}

func (m *mockCovFramework) GetName() string        { return m.name }
func (m *mockCovFramework) GetVersion() string     { return m.version }
func (m *mockCovFramework) GetDescription() string { return m.desc }
func (m *mockCovFramework) Check(_ context.Context, _ common.CheckInput) (*common.CheckResult, error) {
	if m.shouldFail {
		return nil, m.returnErr
	}
	return m.returnResult, nil
}
func (m *mockCovFramework) CheckRequest(_ context.Context, _ *common.HTTPRequest) ([]common.Finding, error) {
	if m.shouldFail {
		return nil, m.returnErr
	}
	return nil, nil
}
func (m *mockCovFramework) CheckResponse(_ context.Context, _ *common.HTTPResponse) ([]common.Finding, error) {
	if m.shouldFail {
		return nil, m.returnErr
	}
	return nil, nil
}
func (m *mockCovFramework) Configure(_ map[string]interface{}) error { return nil }
func (m *mockCovFramework) IsEnabled() bool                          { return m.enabled }
func (m *mockCovFramework) Enable()                                  { m.enabled = true }
func (m *mockCovFramework) Disable()                                 { m.enabled = false }
func (m *mockCovFramework) GetFrameworkID() string                   { return m.id }
func (m *mockCovFramework) GetPatternCount() int                     { return m.patterns }
func (m *mockCovFramework) GetSeverityLevels() []common.Severity     { return m.severities }

// =========================================================================
// TestRegistry_CheckAll Coverage Tests
// =========================================================================

func TestRegistry_CheckAll_FrameworkFailure(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "failing-fw", Name: "Failing", Tier: TierCommunity})

	registry.Register(&mockCovFramework{
		id:         "failing-fw",
		name:       "Failing",
		version:    "1.0",
		desc:       "Failing framework",
		enabled:    true,
		shouldFail: true,
		returnErr:  errors.New("mock framework failure"),
	})

	_, err := registry.CheckAll(context.Background(), common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error when framework fails")
	}
}

func TestRegistry_CheckAll_OneFailsOneSucceeds(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "failing", Name: "Failing", Tier: TierCommunity})
	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "success", Name: "Success", Tier: TierCommunity})

	registry.Register(&mockCovFramework{
		id:         "failing",
		name:       "Failing",
		version:    "1.0",
		desc:       "Failing",
		enabled:    true,
		shouldFail: true,
		returnErr:  errors.New("mock failure"),
	})
	registry.Register(&mockCovFramework{
		id:      "success",
		name:    "Success",
		version: "1.0",
		desc:    "Success",
		enabled: true,
	})

	_, err := registry.CheckAll(context.Background(), common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error when one framework fails")
	}
}

func TestRegistry_CheckAll_DisabledFramework(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "enabled", Name: "Enabled", Tier: TierCommunity})
	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "disabled", Name: "Disabled", Tier: TierCommunity})

	registry.Register(&mockCovFramework{
		id: "enabled", name: "Enabled", version: "1.0", desc: "Enabled", enabled: true,
	})
	registry.Register(&mockCovFramework{
		id: "disabled", name: "Disabled", version: "1.0", desc: "Disabled", enabled: false,
	})

	results, err := registry.CheckAll(context.Background(), common.CheckInput{Content: "test"})
	if err != nil {
		t.Fatalf("CheckAll should not fail with disabled framework: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result (enabled only), got %d", len(results))
	}
}

// =========================================================================
// TestRegistry_CheckFramework Coverage Tests
// =========================================================================

func TestRegistry_CheckFramework_NotFound(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.CheckFramework(context.Background(), "nonexistent", common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error for nonexistent framework")
	}
}

func TestRegistry_CheckFramework_Disabled(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "disabled", Name: "Disabled", Tier: TierCommunity})
	registry.Register(&mockCovFramework{
		id: "disabled", name: "Disabled", version: "1.0", desc: "Disabled", enabled: false,
	})

	_, err := registry.CheckFramework(context.Background(), "disabled", common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error for disabled framework")
	}
}

func TestRegistry_CheckFramework_TierDenied(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "enterprise-fw", Name: "Enterprise", Tier: TierEnterprise})
	registry.tierManager.SetTier(TierCommunity)
	registry.Register(&mockCovFramework{
		id: "enterprise-fw", name: "Enterprise", version: "1.0", desc: "Enterprise", enabled: true,
	})

	_, err := registry.CheckFramework(context.Background(), "enterprise-fw", common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error for tier-denied framework")
	}
}

// TestRegistry_CheckFramework_RegistryTierDenied tests the tier access check in CheckFramework
func TestRegistry_CheckFramework_RegistryTierDenied(t *testing.T) {
	registry := NewRegistry()

	// Register the framework at Enterprise tier but set registry to Community
	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "enterprise-only", Name: "EnterpriseOnly", Tier: TierEnterprise})
	registry.SetTier(TierCommunity)
	registry.Register(&mockCovFramework{
		id: "enterprise-only", name: "EnterpriseOnly", version: "1.0", desc: "Enterprise only", enabled: true,
	})

	_, err := registry.CheckFramework(context.Background(), "enterprise-only", common.CheckInput{Content: "test"})
	if err == nil {
		t.Fatal("expected error when framework requires higher tier")
	}
}

// =========================================================================
// GetByTier (no args) Coverage Tests - returns frameworks for current tier
// =========================================================================

func TestRegistry_GetByTier_NoArgs_CommunityOnly(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "community", Name: "Community", Tier: TierCommunity})
	registry.tierManager.SetTier(TierCommunity)
	registry.Register(&mockCovFramework{id: "community", name: "Community", version: "1.0", desc: "Community", enabled: true})

	frameworks := registry.GetByTier()
	if len(frameworks) != 1 {
		t.Errorf("expected 1 community framework, got %d", len(frameworks))
	}
}

func TestRegistry_GetByTier_NoArgs_EnterpriseOnly(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "enterprise", Name: "Enterprise", Tier: TierEnterprise})
	registry.tierManager.SetTier(TierEnterprise)
	registry.Register(&mockCovFramework{id: "enterprise", name: "Enterprise", version: "1.0", desc: "Enterprise", enabled: true})

	frameworks := registry.GetByTier()
	if len(frameworks) != 1 {
		t.Errorf("expected 1 enterprise framework, got %d", len(frameworks))
	}
}

func TestRegistry_GetByTier_NoArgs_Premium(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "premium", Name: "Premium", Tier: TierPremium})
	registry.tierManager.SetTier(TierPremium)
	registry.Register(&mockCovFramework{id: "premium", name: "Premium", version: "1.0", desc: "Premium", enabled: true})

	frameworks := registry.GetByTier()
	if len(frameworks) != 1 {
		t.Errorf("expected 1 premium framework, got %d", len(frameworks))
	}
}

// =========================================================================
// GetByTierID (with Tier arg) Coverage Tests
// =========================================================================

func TestRegistry_GetByTierID_Community(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "community", Name: "Community", Tier: TierCommunity})
	registry.Register(&mockCovFramework{id: "community", name: "Community", version: "1.0", desc: "Community", enabled: true})

	frameworks := registry.GetByTierID(TierCommunity)
	if len(frameworks) != 1 {
		t.Errorf("expected 1 framework for community tier, got %d", len(frameworks))
	}
}

func TestRegistry_GetByTierID_Enterprise(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "community", Name: "Community", Tier: TierCommunity})
	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "enterprise", Name: "Enterprise", Tier: TierEnterprise})
	registry.Register(&mockCovFramework{id: "community", name: "Community", version: "1.0", desc: "Community", enabled: true})
	registry.Register(&mockCovFramework{id: "enterprise", name: "Enterprise", version: "1.0", desc: "Enterprise", enabled: true})

	frameworks := registry.GetByTierID(TierCommunity)
	if len(frameworks) != 1 {
		t.Errorf("expected 1 community framework, got %d", len(frameworks))
	}
}

// =========================================================================
// GetAvailableFrameworks Coverage Tests
// =========================================================================

func TestRegistry_GetAvailableFrameworks(t *testing.T) {
	registry := NewRegistry()

	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	registry.tierManager.RegisterFramework(FrameworkTier{FrameworkID: "fw2", Name: "FW2", Tier: TierCommunity})

	registry.Register(&mockCovFramework{id: "fw1", name: "FW1", version: "1.0", desc: "FW1", enabled: true})
	registry.Register(&mockCovFramework{id: "fw2", name: "FW2", version: "1.0", desc: "FW2", enabled: true})

	frameworks := registry.GetAvailableFrameworks()
	if len(frameworks) != 2 {
		t.Errorf("expected 2 available frameworks, got %d", len(frameworks))
	}
}
