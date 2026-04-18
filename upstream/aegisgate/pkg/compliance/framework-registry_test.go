// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

package compliance

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

// mockFramework implements common.Framework for testing
type mockFramework struct {
	id          string
	name        string
	version     string
	description string
	enabled     bool
}

func (m *mockFramework) GetFrameworkID() string          { return m.id }
func (m *mockFramework) GetName() string                 { return m.name }
func (m *mockFramework) GetVersion() string              { return m.version }
func (m *mockFramework) GetDescription() string          { return m.description }
func (m *mockFramework) IsEnabled() bool                 { return m.enabled }
func (m *mockFramework) Enable()                         { m.enabled = true }
func (m *mockFramework) Disable()                        { m.enabled = false }
func (m *mockFramework) GetPatternCount() int            { return 0 }
func (m *mockFramework) GetSeverityLevels() []common.Severity { return nil }
func (m *mockFramework) Configure(config map[string]interface{}) error { return nil }
func (m *mockFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	return &common.CheckResult{Framework: m.id, Passed: true}, nil
}
func (m *mockFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	return []common.Finding{}, nil
}
func (m *mockFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func newMockFramework(id string) *mockFramework {
	return &mockFramework{
		id:          id,
		name:        "Mock Framework",
		version:     "1.0.0",
		description: "A mock framework for testing",
		enabled:     true,
	}
}

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()
	if registry == nil {
		t.Fatal("NewRegistry() returned nil")
	}
	if registry.frameworks == nil {
		t.Error("Registry.frameworks should be initialized")
	}
	if registry.tierManager == nil {
		t.Error("Registry.tierManager should be initialized")
	}
}

func TestNewRegistryWithTierManager(t *testing.T) {
	tm := NewTierManager()
	registry := NewRegistryWithTierManager(tm)
	if registry == nil {
		t.Fatal("NewRegistryWithTierManager() returned nil")
	}
	if registry.tierManager != tm {
		t.Error("Registry.tierManager should be the provided tier manager")
	}
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)

	// Register framework in tier manager first
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "test-framework",
		Name:        "Test Framework",
		Tier:        TierCommunity,
	})

	tests := []struct {
		name      string
		framework common.Framework
		wantErr   bool
	}{
		{
			name:      "valid framework",
			framework: newMockFramework("test-framework"),
			wantErr:   false,
		},
		{
			name:      "nil framework",
			framework: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.Register(tt.framework)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistry_Unregister(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "test-framework",
		Name:        "Test Framework",
		Tier:        TierCommunity,
	})
	fw := newMockFramework("test-framework")

	// Register first
	_ = registry.Register(fw)

	// Unregister
	err := registry.Unregister("test-framework")
	if err != nil {
		t.Errorf("Unregister() error = %v", err)
	}

	// Unregister again - should fail
	err = registry.Unregister("test-framework")
	if err == nil {
		t.Error("Unregister() should fail for non-existent framework")
	}
}

func TestRegistry_Get(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "test-framework",
		Name:        "Test Framework",
		Tier:        TierCommunity,
	})
	fw := newMockFramework("test-framework")
	_ = registry.Register(fw)

	// Get existing
	got, err := registry.Get("test-framework")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if got == nil {
		t.Error("Get() returned nil for existing framework")
	}

	// Get non-existent
	_, err = registry.Get("non-existent")
	if err == nil {
		t.Error("Get() should fail for non-existent framework")
	}
}

func TestRegistry_GetRegisteredFramework(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "test-framework",
		Name:        "Test Framework",
		Tier:        TierCommunity,
	})
	fw := newMockFramework("test-framework")
	_ = registry.Register(fw)

	rf, err := registry.GetRegisteredFramework("test-framework")
	if err != nil {
		t.Errorf("GetRegisteredFramework() error = %v", err)
	}
	if rf == nil {
		t.Fatal("GetRegisteredFramework() returned nil")
	}
	if rf.Instance == nil {
		t.Error("RegisteredFramework.Instance should not be nil")
	}

	// Non-existent
	_, err = registry.GetRegisteredFramework("non-existent")
	if err == nil {
		t.Error("GetRegisteredFramework() should fail for non-existent")
	}
}

func TestRegistry_ListAll(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)

	// Empty registry
	frameworks := registry.ListAll()
	if len(frameworks) != 0 {
		t.Error("ListAll() should return empty for empty registry")
	}

	// Add frameworks
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw2", Name: "FW2", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))
	_ = registry.Register(newMockFramework("fw2"))

	frameworks = registry.ListAll()
	if len(frameworks) != 2 {
		t.Errorf("ListAll() returned %d frameworks, want 2", len(frameworks))
	}
}

func TestRegistry_ListAllWithMetadata(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))

	rfs := registry.ListAllWithMetadata()
	if len(rfs) != 1 {
		t.Errorf("ListAllWithMetadata() returned %d, want 1", len(rfs))
	}
	if rfs[0].LoadedAt == 0 {
		t.Error("RegisteredFramework.LoadedAt should not be zero")
	}
}

func TestRegistry_Count(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)

	if registry.Count() != 0 {
		t.Error("Count() should be 0 for empty registry")
	}

	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw2", Name: "FW2", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))
	_ = registry.Register(newMockFramework("fw2"))

	if registry.Count() != 2 {
		t.Errorf("Count() = %d, want 2", registry.Count())
	}
}

func TestRegistry_CountByTier(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))

	counts := registry.CountByTier()
	if counts == nil {
		t.Error("CountByTier() should not return nil")
	}
}

func TestRegistry_GetTierManager(t *testing.T) {
	registry := NewRegistry()
	tm := registry.GetTierManager()
	if tm == nil {
		t.Error("GetTierManager() should not return nil")
	}
}

func TestRegistry_SetTier_GetTier(t *testing.T) {
	registry := NewRegistry()

	registry.SetTier(TierEnterprise)

	if registry.GetTier() != TierEnterprise {
		t.Errorf("GetTier() = %v, want TierEnterprise", registry.GetTier())
	}
}

func TestRegistry_Clear(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))

	registry.Clear()

	if registry.Count() != 0 {
		t.Error("Clear() should remove all frameworks")
	}
}

func TestRegistry_GenerateReport(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{FrameworkID: "fw1", Name: "FW1", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("fw1"))

	report := registry.GenerateReport()
	if report == nil {
		t.Fatal("GenerateReport() returned nil")
	}

	if _, ok := report["total_frameworks"]; !ok {
		t.Error("Report should contain total_frameworks")
	}
	if _, ok := report["enabled_count"]; !ok {
		t.Error("Report should contain enabled_count")
	}
	if _, ok := report["current_tier"]; !ok {
		t.Error("Report should contain current_tier")
	}
}

func TestRegistry_EnableDisableFramework(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	tm.RegisterFramework(FrameworkTier{FrameworkID: "test", Name: "Test", Tier: TierCommunity})
	_ = registry.Register(newMockFramework("test"))

	// Disable
	err := registry.DisableFramework("test")
	if err != nil {
		t.Errorf("DisableFramework() error = %v", err)
	}

	// Enable
	err = registry.EnableFramework("test")
	if err != nil {
		t.Errorf("EnableFramework() error = %v", err)
	}

	// Non-existent
	err = registry.EnableFramework("non-existent")
	if err == nil {
		t.Error("EnableFramework() should fail for non-existent")
	}
}

func TestRegistry_GetEnabledFrameworks(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	fw := newMockFramework("test")
	fw.enabled = true
	tm.RegisterFramework(FrameworkTier{FrameworkID: "test", Name: "Test", Tier: TierCommunity})
	_ = registry.Register(fw)

	enabled := registry.GetEnabledFrameworks()
	t.Logf("GetEnabledFrameworks() returned %d frameworks", len(enabled))

	// Disable and check
	_ = registry.DisableFramework("test")
	enabled = registry.GetEnabledFrameworks()
	t.Logf("After disable: GetEnabledFrameworks() returned %d frameworks", len(enabled))
}

func TestRegistry_GetDisabledFrameworks(t *testing.T) {
	registry := NewRegistry()
	tm := NewTierManager()
	registry = NewRegistryWithTierManager(tm)
	fw := newMockFramework("test")
	fw.enabled = false
	tm.RegisterFramework(FrameworkTier{FrameworkID: "test", Name: "Test", Tier: TierCommunity})
	_ = registry.Register(fw)

	disabled := registry.GetDisabledFrameworks()
	t.Logf("GetDisabledFrameworks() returned %d frameworks", len(disabled))
}

func TestGetGlobalRegistry(t *testing.T) {
	// Reset first
	ResetGlobalRegistry()

	registry1 := GetGlobalRegistry()
	registry2 := GetGlobalRegistry()

	if registry1 != registry2 {
		t.Error("GetGlobalRegistry() should return same instance")
	}

	// Clean up
	ResetGlobalRegistry()
}

func TestResetGlobalRegistry(t *testing.T) {
	registry1 := GetGlobalRegistry()
	ResetGlobalRegistry()
	registry2 := GetGlobalRegistry()

	if registry1 == registry2 {
		t.Error("ResetGlobalRegistry() should create new instance")
	}

	// Clean up
	ResetGlobalRegistry()
}

// Signed-off-by: jcolvin <josh@aegisgatesecurity.io>