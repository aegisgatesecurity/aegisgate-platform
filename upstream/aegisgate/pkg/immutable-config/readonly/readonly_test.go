package readonly

import (
	"testing"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

// mockProvider implements immutableconfig.Provider for testing
type mockProvider struct {
	configs  map[string]*immutableconfig.ConfigData
	versions []*immutableconfig.ConfigVersion
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		configs:  make(map[string]*immutableconfig.ConfigData),
		versions: make([]*immutableconfig.ConfigVersion, 0),
	}
}

func (m *mockProvider) Initialize() error {
	return nil
}

func (m *mockProvider) Load(version string) (*immutableconfig.ConfigData, error) {
	config, exists := m.configs[version]
	if !exists {
		return nil, nil
	}
	return config, nil
}

func (m *mockProvider) Save(config *immutableconfig.ConfigData) (*immutableconfig.ConfigVersion, error) {
	m.configs[config.Version] = config
	version := immutableconfig.NewConfigVersion(config.Version, "test-hash")
	m.versions = append(m.versions, version)
	return version, nil
}

func (m *mockProvider) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	return m.versions, nil
}

func (m *mockProvider) Close() error {
	return nil
}

func TestNewReadOnlyProvider(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	if rop == nil {
		t.Fatal("Expected provider to be created")
	}

	if rop.IsSealed() {
		t.Error("Expected provider to not be sealed initially")
	}
}

func TestNewReadOnlyProviderWithOptions(t *testing.T) {
	mock := newMockProvider()
	opts := &ReadOnlyOptions{
		AutoSeal:        true,
		SealAfterWrites: 5,
	}
	rop := NewReadOnlyProvider(mock, opts)

	if rop == nil {
		t.Fatal("Expected provider to be created")
	}
}

func TestDefaultReadOnlyOptions(t *testing.T) {
	opts := DefaultReadOnlyOptions()

	if opts.AutoSeal {
		t.Error("Expected AutoSeal to be false by default")
	}

	if opts.SealAfterWrites != 0 {
		t.Errorf("Expected SealAfterWrites to be 0, got %d", opts.SealAfterWrites)
	}
}

func TestLoad(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Add a config to mock
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	mock.Save(config)

	// Load should work
	loaded, err := rop.Load("v1.0")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if loaded.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", loaded.Version)
	}
}

func TestSaveWhenNotSealed(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	_, err := rop.Save(config)

	if err != nil {
		t.Fatalf("Expected save to succeed when not sealed, got error: %v", err)
	}
}

func TestSaveWhenSealed(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Seal the provider
	if err := rop.Seal(); err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	_, err := rop.Save(config)

	if err == nil {
		t.Error("Expected error when saving to sealed provider")
	}
}

func TestSeal(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	if rop.IsSealed() {
		t.Error("Expected provider to not be sealed initially")
	}

	if err := rop.Seal(); err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	if !rop.IsSealed() {
		t.Error("Expected provider to be sealed after Seal()")
	}

	// Sealing again should fail
	if err := rop.Seal(); err == nil {
		t.Error("Expected error when sealing already sealed provider")
	}
}

func TestUnseal(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Seal
	rop.Seal()

	// Unseal
	if err := rop.Unseal(); err != nil {
		t.Fatalf("Failed to unseal: %v", err)
	}

	if rop.IsSealed() {
		t.Error("Expected provider to not be sealed after unseal")
	}
}

func TestSealedAt(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Before sealing
	if !rop.SealedAt().IsZero() {
		t.Error("Expected SealedAt to be zero time before sealing")
	}

	// Seal
	rop.Seal()

	// After sealing
	if rop.SealedAt().IsZero() {
		t.Error("Expected SealedAt to be non-zero after sealing")
	}

	// Unseal
	rop.Unseal()

	// After unsealing
	if !rop.SealedAt().IsZero() {
		t.Error("Expected SealedAt to be zero after unsealing")
	}
}

func TestModificationHistory(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Save a config (not sealed)
	config1 := immutableconfig.NewConfigData("v1.0", nil, nil)
	rop.Save(config1)

	// Seal and try to save
	rop.Seal()
	config2 := immutableconfig.NewConfigData("v2.0", nil, nil)
	rop.Save(config2)

	// Get modification history
	history := rop.GetModificationHistory()

	if len(history) != 2 {
		t.Errorf("Expected 2 modification records, got %d", len(history))
	}

	// First should not be blocked
	if history[0].Blocked {
		t.Error("Expected first modification to not be blocked")
	}

	// Second should be blocked
	if !history[1].Blocked {
		t.Error("Expected second modification to be blocked")
	}
}

func TestGetBlockedModifications(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Save while not sealed
	config1 := immutableconfig.NewConfigData("v1.0", nil, nil)
	rop.Save(config1)

	// Seal and try to save
	rop.Seal()
	config2 := immutableconfig.NewConfigData("v2.0", nil, nil)
	rop.Save(config2)
	config3 := immutableconfig.NewConfigData("v3.0", nil, nil)
	rop.Save(config3)

	blocked := rop.GetBlockedModifications()

	if len(blocked) != 2 {
		t.Errorf("Expected 2 blocked modifications, got %d", len(blocked))
	}
}

func TestClearModificationHistory(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Make some modifications
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	rop.Save(config)

	if len(rop.GetModificationHistory()) != 1 {
		t.Error("Expected 1 modification")
	}

	// Clear history
	rop.ClearModificationHistory()

	if len(rop.GetModificationHistory()) != 0 {
		t.Error("Expected history to be cleared")
	}
}

func TestIsModified(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	if rop.IsModified() {
		t.Error("Expected IsModified to be false initially")
	}

	// Save a config
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	rop.Save(config)

	if !rop.IsModified() {
		t.Error("Expected IsModified to be true after save")
	}

	// Reset
	rop.ResetModified()

	if rop.IsModified() {
		t.Error("Expected IsModified to be false after reset")
	}
}

func TestListVersions(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	// Add some configs
	for i := 1; i <= 3; i++ {
		version := string(rune('v')) + string(rune('0'+i))
		config := immutableconfig.NewConfigData(version, nil, nil)
		rop.Save(config)
	}

	versions, err := rop.ListVersions()
	if err != nil {
		t.Fatalf("Failed to list versions: %v", err)
	}

	if len(versions) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(versions))
	}
}

func TestClose(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	if err := rop.Close(); err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestInitialize(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)

	if err := rop.Initialize(); err != nil {
		t.Errorf("Unexpected error on initialize: %v", err)
	}
}

// ReadOnlyLayer tests

func TestNewReadOnlyLayer(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)
	layer := NewReadOnlyLayer(rop)

	if layer == nil {
		t.Fatal("Expected layer to be created")
	}
}

func TestReadOnlyLayerGet(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)
	layer := NewReadOnlyLayer(rop)

	// Add config
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	rop.Save(config)

	// Get through layer
	loaded, err := layer.Get("v1.0")
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}

	if loaded.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", loaded.Version)
	}
}

func TestReadOnlyLayerGetLatest(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)
	layer := NewReadOnlyLayer(rop)

	// Test with no configs
	_, err := layer.GetLatest()
	if err == nil {
		t.Error("Expected error when getting latest with no configs")
	}

	// Add configs
	config1 := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value1"}, nil)
	rop.Save(config1)

	latest, err := layer.GetLatest()
	if err != nil {
		t.Fatalf("Failed to get latest: %v", err)
	}

	if latest.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", latest.Version)
	}
}

func TestReadOnlyLayerListVersions(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)
	layer := NewReadOnlyLayer(rop)

	versions, err := layer.ListVersions()
	if err != nil {
		t.Fatalf("Failed to list versions: %v", err)
	}

	if versions == nil {
		t.Error("Expected non-nil versions slice")
	}
}

func TestReadOnlyLayerIsSealed(t *testing.T) {
	mock := newMockProvider()
	rop := NewReadOnlyProvider(mock, nil)
	layer := NewReadOnlyLayer(rop)

	if layer.IsSealed() {
		t.Error("Expected layer to not be sealed initially")
	}

	rop.Seal()

	// Layer should have captured initial seal state
	// Note: The layer captures the state at creation time
}
