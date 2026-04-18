package immutableconfig

import (
	"fmt"
	"testing"
)

func TestConfigManagerInitialize(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}
}

func TestConfigManagerSaveAndLoad(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Create and save config
	data := map[string]interface{}{
		"setting": "value",
	}
	metadata := map[string]string{
		"author": "test",
	}

	config := NewConfigData("v1.0", data, metadata)

	version, err := manager.SaveConfig(config)
	if err != nil {
		t.Errorf("Expected no error on save, got %v", err)
	}

	if version == nil {
		t.Errorf("Expected version to be returned")
	}

	// Load the config
	loadedConfig, err := manager.LoadConfig("v1.0")
	if err != nil {
		t.Errorf("Expected no error on load, got %v", err)
	}

	if loadedConfig == nil {
		t.Errorf("Expected config to be loaded")
	}

	if loadedConfig.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", loadedConfig.Version)
	}
}

func TestConfigManagerLoadLatest(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save multiple configs
	config1 := NewConfigData("v0.1", map[string]interface{}{"key": "value1"}, nil)
	_, _ = manager.SaveConfig(config1)

	config2 := NewConfigData("v0.2", map[string]interface{}{"key": "value2"}, nil)
	_, _ = manager.SaveConfig(config2)

	// Load latest
	loadedConfig, err := manager.LoadLatestConfig()
	if err != nil {
		t.Errorf("Expected no error on load latest, got %v", err)
	}

	if loadedConfig == nil {
		t.Errorf("Expected config to be loaded")
	}
}

func TestConfigManagerVersionHistory(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save configs
	config1 := NewConfigData("v0.1", nil, nil)
	_, _ = manager.SaveConfig(config1)

	config2 := NewConfigData("v0.2", nil, nil)
	_, _ = manager.SaveConfig(config2)

	// Get history
	history, err := manager.GetVersionHistory()
	if err != nil {
		t.Errorf("Expected no error on version history, got %v", err)
	}

	if len(history) != 2 {
		t.Errorf("Expected 2 versions in history, got %d", len(history))
	}
}

func TestConfigManagerGetCurrentConfig(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save config
	config := NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	manager.SaveConfig(config)

	// Get current config
	current := manager.GetCurrentConfig()

	if current == nil {
		t.Errorf("Expected current config to be returned")
	}

	if current.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", current.Version)
	}
}

func TestConfigManagerValidate(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save config
	config := NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	manager.SaveConfig(config)

	// Validate
	if err := manager.ValidateConfig(); err != nil {
		t.Errorf("Expected no error on validate, got %v", err)
	}
}

func TestConfigManagerGetLatestVersion(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save configs
	config1 := NewConfigData("v0.1", nil, nil)
	_, _ = manager.SaveConfig(config1)

	config2 := NewConfigData("v0.2", nil, nil)
	_, _ = manager.SaveConfig(config2)

	// Get latest version
	latestVersion := manager.GetLatestVersion()

	if latestVersion == "" {
		t.Errorf("Expected non-empty latest version")
	}
}

func TestConfigManagerGetConfigHash(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save config
	config := NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	manager.SaveConfig(config)

	// Get config hash
	hash := manager.GetConfigHash()

	if hash == "" {
		t.Errorf("Expected non-empty hash")
	}
}

func TestConfigManagerAuditLogger(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Initialize
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Get audit logger
	auditLogger := manager.GetAuditLogger()

	if auditLogger == nil {
		t.Errorf("Expected audit logger to be returned")
	}
}

func TestConfigManagerIntegration(t *testing.T) {
	p := NewInMemoryProvider()
	manager := NewConfigManager(p)

	// Full integration test
	if err := manager.Initialize(); err != nil {
		t.Errorf("Expected no error on initialize, got %v", err)
	}

	// Save multiple configs
	for i := 1; i <= 5; i++ {
		config := NewConfigData(
			fmt.Sprintf("v0.%d", i),
			map[string]interface{}{"counter": i},
			map[string]string{"author": "test"},
		)
		if _, err := manager.SaveConfig(config); err != nil {
			t.Errorf("Expected no error on save, got %v", err)
		}
	}

	// Load latest
	config, err := manager.LoadLatestConfig()
	if err != nil {
		t.Errorf("Expected no error on load latest, got %v", err)
	}
	if config == nil {
		t.Errorf("Expected config to be loaded")
	}

	// Validate
	if err := manager.ValidateConfig(); err != nil {
		t.Errorf("Expected no error on validate, got %v", err)
	}

	// Get history
	history, err := manager.GetVersionHistory()
	if err != nil {
		t.Errorf("Expected no error on version history, got %v", err)
	}
	if len(history) != 5 {
		t.Errorf("Expected 5 versions, got %d", len(history))
	}

	// Close
	if err := manager.Close(); err != nil {
		t.Errorf("Expected no error on close, got %v", err)
	}
}
