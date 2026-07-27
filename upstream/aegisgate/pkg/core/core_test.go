// Package core provides tests for the module system.
package core

import (
	"context"
	"testing"
)

// MockModule is a test module implementation.
type MockModule struct {
	*BaseModule
	initCalled  bool
	startCalled bool
	stopCalled  bool
	initError   error
	startError  error
	stopError   error
}

func NewMockModule(id, name string, tier Tier) *MockModule {
	return &MockModule{
		BaseModule: NewBaseModule(ModuleMetadata{
			ID:          id,
			Name:        name,
			Version:     "1.0.0",
			Description: "Test module",
			Tier:        tier,
			Category:    CategoryCore,
		}),
	}
}

func (m *MockModule) Initialize(ctx context.Context, config ModuleConfig) error {
	m.initCalled = true
	if m.initError != nil {
		return m.initError
	}
	return m.BaseModule.Initialize(ctx, config)
}

func (m *MockModule) Start(ctx context.Context) error {
	m.startCalled = true
	if m.startError != nil {
		return m.startError
	}
	return m.BaseModule.Start(ctx)
}

func (m *MockModule) Stop(ctx context.Context) error {
	m.stopCalled = true
	if m.stopError != nil {
		return m.stopError
	}
	return m.BaseModule.Stop(ctx)
}

func TestModuleStatus_String(t *testing.T) {
	tests := []struct {
		status   ModuleStatus
		expected string
	}{
		{StatusUnregistered, "unregistered"},
		{StatusRegistered, "registered"},
		{StatusInitialized, "initialized"},
		{StatusActive, "active"},
		{StatusDisabled, "disabled"},
		{StatusError, "error"},
		{ModuleStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("ModuleStatus(%d).String() = %q, want %q", tt.status, got, tt.expected)
		}
	}
}

func TestTier_String(t *testing.T) {
	tests := []struct {
		tier     Tier
		expected string
	}{
		{TierCommunity, "Community"},
		{TierDeveloper, "Developer"},
		{TierProfessional, "Professional"},
		{TierEnterprise, "Enterprise"},
	}

	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.expected {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.expected)
		}
	}
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry(nil)
	module := NewMockModule("test-module", "Test Module", TierDeveloper)

	err := registry.Register(module)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify module is registered
	if _, exists := registry.Get("test-module"); !exists {
		t.Error("Module not found in registry")
	}

	// Verify duplicate registration fails
	err = registry.Register(module)
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}
}

func TestRegistry_Initialize(t *testing.T) {
	registry := NewRegistry(nil)
	module := NewMockModule("test-module", "Test Module", TierCommunity)

	_ = registry.Register(module)

	ctx := context.Background()
	err := registry.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Verify module was initialized
	if !module.initCalled {
		t.Error("Initialize() was not called on module")
	}

	// Verify status
	if status := registry.GetStatus("test-module"); status != StatusInitialized {
		t.Errorf("Status = %v, want %v", status, StatusInitialized)
	}
}

func TestRegistry_StartStop(t *testing.T) {
	registry := NewRegistry(nil)
	module := NewMockModule("test-module", "Test Module", TierCommunity)

	_ = registry.Register(module)

	ctx := context.Background()
	if err := registry.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if err := registry.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify module was started
	if !module.startCalled {
		t.Error("Start() was not called on module")
	}

	// Verify status
	if status := registry.GetStatus("test-module"); status != StatusActive {
		t.Errorf("Status = %v, want %v", status, StatusActive)
	}

	// Stop
	if err := registry.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if !module.stopCalled {
		t.Error("Stop() was not called on module")
	}
}

func TestRegistry_DependencyOrder(t *testing.T) {
	registry := NewRegistry(nil)

	// Create modules with dependencies
	coreModule := NewMockModule("core", "Core", TierCommunity)
	depsModule := &MockModule{
		BaseModule: NewBaseModule(ModuleMetadata{
			ID:       "deps",
			Name:     "Deps",
			Version:  "1.0.0",
			Tier:     TierDeveloper,
			Category: CategoryCore,
		}),
	}

	_ = registry.Register(coreModule)
	_ = registry.Register(depsModule)

	// Get initialization order
	order, err := registry.getInitializationOrder()
	if err != nil {
		t.Fatalf("getInitializationOrder() error = %v", err)
	}

	// Ensure order is deterministic
	if len(order) != 2 {
		t.Errorf("Order length = %d, want 2", len(order))
	}
}

func TestLicenseManager_CoreTierAlwaysFree(t *testing.T) {
	lm := NewLicenseManager("")

	// Community tier should always be allowed (free tier)
	if !lm.IsModuleLicensed("any-module", TierCommunity) {
		t.Error("TierCommunity should always be licensed")
	}
}

func TestLicenseManager_ProfessionalRequiresLicense(t *testing.T) {
	lm := NewLicenseManager("")

	// Professional tier without license should fail
	if lm.IsModuleLicensed("any-module", TierProfessional) {
		t.Error("TierProfessional should not be licensed without a key")
	}
}

func TestRegistry_EnableDisable(t *testing.T) {
	registry := NewRegistry(nil)
	module := NewMockModule("test-module", "Test Module", TierCommunity)

	_ = registry.Register(module)

	ctx := context.Background()
	_ = registry.Initialize(ctx)
	registry.Start(ctx)

	// Disable
	err := registry.Disable(ctx, "test-module")
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}

	if status := registry.GetStatus("test-module"); status != StatusDisabled {
		t.Errorf("Status = %v, want %v", status, StatusDisabled)
	}

	// Re-enable
	err = registry.Enable(ctx, "test-module")
	if err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	if status := registry.GetStatus("test-module"); status != StatusActive {
		t.Errorf("Status = %v, want %v", status, StatusActive)
	}
}

func TestRegistry_ListByTier(t *testing.T) {
	registry := NewRegistry(nil)

	registry.Register(NewMockModule("core-mod", "Core Module", TierCommunity))
	registry.Register(NewMockModule("pro-mod", "Pro Module", TierProfessional))
	registry.Register(NewMockModule("enter-mod", "Enterprise Module", TierEnterprise))

	coreModules := registry.ListByTier(TierCommunity)
	if len(coreModules) != 1 || coreModules[0] != "core-mod" {
		t.Errorf("ListByTier(TierCommunity) = %v, want [core-mod]", coreModules)
	}

	proModules := registry.ListByTier(TierProfessional)
	if len(proModules) != 1 || proModules[0] != "pro-mod" {
		t.Errorf("ListByTier(TierProfessional) = %v, want [pro-mod]", proModules)
	}
}

func TestFeatureRegistry_EnableDisable(t *testing.T) {
	registry := NewRegistry(nil)
	fr := NewFeatureRegistry(registry)

	flag := FeatureFlag{
		ID:          "test-feature",
		Name:        "Test Feature",
		Description: "A test feature",
		Enabled:     false,
	}

	// Register
	if err := fr.Register(flag); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Check initial state
	if fr.IsEnabled("test-feature") {
		t.Error("Feature should not be enabled initially")
	}

	// Enable
	if err := fr.Enable("test-feature"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	if !fr.IsEnabled("test-feature") {
		t.Error("Feature should be enabled")
	}

	// Disable
	if err := fr.Disable("test-feature"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}

	if fr.IsEnabled("test-feature") {
		t.Error("Feature should be disabled")
	}
}

func TestFeatureRegistry_DuplicateRegistration(t *testing.T) {
	fr := NewFeatureRegistry(nil)

	flag := FeatureFlag{ID: "test", Name: "Test"}

	if err := fr.Register(flag); err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	if err := fr.Register(flag); err == nil {
		t.Error("Second Register() should fail for duplicate ID")
	}
}
