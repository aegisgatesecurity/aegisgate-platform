// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package immutableconfig

import (
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/integrity"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/logging"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/rollback"
)

// Provider interface for configuration storage
type Provider interface {
	Initialize() error
	Load(version string) (*ConfigData, error)
	Save(config *ConfigData) (*ConfigVersion, error)
	ListVersions() ([]*ConfigVersion, error)
	Close() error
}

// InMemoryProvider for testing
type InMemoryProvider struct {
	mu      sync.RWMutex
	storage map[string]*ConfigData
}

// NewInMemoryProvider creates a new in-memory provider
func NewInMemoryProvider() *InMemoryProvider {
	return &InMemoryProvider{
		storage: make(map[string]*ConfigData),
	}
}

// Initialize initializes the in-memory provider
func (p *InMemoryProvider) Initialize() error {
	return nil
}

// Load loads a specific version of the configuration
func (p *InMemoryProvider) Load(version string) (*ConfigData, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.storage[version], nil
}

// Save saves a new configuration version
func (p *InMemoryProvider) Save(config *ConfigData) (*ConfigVersion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.storage[config.Version] = config
	return &ConfigVersion{
		Version:   config.Version,
		Timestamp: time.Now().Format(time.RFC3339Nano),
	}, nil
}

// ListVersions lists all versions
func (p *InMemoryProvider) ListVersions() ([]*ConfigVersion, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var versions []*ConfigVersion
	for _, config := range p.storage {
		versions = append(versions, &ConfigVersion{
			Version:   config.Version,
			Timestamp: config.Created,
		})
	}
	return versions, nil
}

// Close closes the in-memory provider
func (p *InMemoryProvider) Close() error {
	return nil
}

// ConfigManager manages immutable configuration with versioning
type ConfigManager struct {
	mu          sync.RWMutex
	current     *ConfigData
	provider    Provider
	integrity   *integrity.IntegrityChecker
	auditLogger *logging.AuditLogger
	rollbackMgr *rollback.RollbackManager
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(provider Provider) *ConfigManager {
	return &ConfigManager{
		provider:    provider,
		integrity:   integrity.NewIntegrityChecker(),
		auditLogger: logging.NewAuditLogger(1000),
		rollbackMgr: rollback.NewRollbackManager(10, true),
	}
}

// Initialize initializes the config manager
func (cm *ConfigManager) Initialize() error {
	if err := cm.provider.Initialize(); err != nil {
		return err
	}
	return nil
}

// LoadConfig loads a specific version of the configuration
func (cm *ConfigManager) LoadConfig(version string) (*ConfigData, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	config, err := cm.provider.Load(version)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config version %s not found", version)
	}

	// Verify integrity
	verified, err := cm.integrity.Verify(config.Hash, config.Version, config.Data, config.Metadata)
	if err != nil {
		return nil, err
	}

	if !verified {
		cm.auditLogger.Log(
			logging.EventIntegrityFail,
			version,
			"load",
			"Integrity verification failed for version",
			config.Hash,
			"",
		)
		return nil, fmt.Errorf("integrity verification failed for version %s", version)
	}

	// Log the load operation
	cm.auditLogger.Log(
		logging.EventConfigLoad,
		version,
		"load",
		fmt.Sprintf("Loaded configuration version %s", version),
		config.Hash,
		config.Signature,
	)

	cm.current = config
	return config, nil
}

// LoadLatestConfig loads the most recent configuration
// This version avoids calling LoadConfig to prevent deadlock
func (cm *ConfigManager) LoadLatestConfig() (*ConfigData, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	versions, err := cm.provider.ListVersions()
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no configurations available")
	}

	// Get the latest version (by timestamp)
	var latestVersion string
	var latestTime string
	for _, v := range versions {
		if v.Timestamp > latestTime {
			latestTime = v.Timestamp
			latestVersion = v.Version
		}
	}

	// Load the config directly without acquiring the lock again
	config, err := cm.provider.Load(latestVersion)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config version %s not found", latestVersion)
	}

	// Verify integrity
	verified, err := cm.integrity.Verify(config.Hash, config.Version, config.Data, config.Metadata)
	if err != nil {
		return nil, err
	}

	if !verified {
		cm.auditLogger.Log(
			logging.EventIntegrityFail,
			latestVersion,
			"load",
			"Integrity verification failed for version",
			config.Hash,
			"",
		)
		return nil, fmt.Errorf("integrity verification failed for version %s", latestVersion)
	}

	// Log the load operation
	cm.auditLogger.Log(
		logging.EventConfigLoad,
		latestVersion,
		"load",
		fmt.Sprintf("Loaded configuration version %s", latestVersion),
		config.Hash,
		config.Signature,
	)

	cm.current = config
	return config, nil
}

// SaveConfig saves a new configuration version
func (cm *ConfigManager) SaveConfig(config *ConfigData) (*ConfigVersion, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Generate hash
	hash, err := cm.integrity.ComputeHash(config.Version, config.Data, config.Metadata)
	if err != nil {
		return nil, err
	}
	config.Hash = hash

	// Save to provider
	version, err := cm.provider.Save(config)
	if err != nil {
		return nil, err
	}

	// Record in rollback manager
	if err := cm.rollbackMgr.AddVersion(config.Version, hash, 0, "system"); err != nil {
		return nil, err
	}

	// Log the save operation
	cm.auditLogger.Log(
		logging.EventConfigSave,
		config.Version,
		"save",
		fmt.Sprintf("Saved configuration version %s", config.Version),
		hash,
		config.Signature,
	)

	cm.current = config
	return version, nil
}

// GetVersionHistory gets the version history
func (cm *ConfigManager) GetVersionHistory() ([]*ConfigVersion, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.provider.ListVersions()
}

// RollbackToVersion rolls back to a specific version
func (cm *ConfigManager) RollbackToVersion(version string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Load the target version
	targetConfig, err := cm.provider.Load(version)
	if err != nil {
		return err
	}

	if targetConfig == nil {
		return fmt.Errorf("version %s not found", version)
	}

	// Create a new version with rollback marker
	newVersion := fmt.Sprintf("%s-rollback", version)
	rollbackConfig := &ConfigData{
		Version:  newVersion,
		Created:  time.Now().UTC().Format(time.RFC3339Nano),
		Data:     targetConfig.Data,
		Metadata: targetConfig.Metadata,
	}

	// Save the rollback version
	_, err = cm.provider.Save(rollbackConfig)
	if err != nil {
		return err
	}

	// Record in rollback manager
	if err := cm.rollbackMgr.RollbackToVersion(version, newVersion); err != nil {
		cm.auditLogger.Log(logging.EventConfigRollback, newVersion, "rollback", fmt.Sprintf("Failed to record rollback from %s to %s: %v", cm.current.Version, version, err), "", "")
	}
	cm.auditLogger.Log(
		logging.EventConfigRollback,
		newVersion,
		"rollback",
		fmt.Sprintf("Rolled back from %s to %s", cm.current.Version, version),
		rollbackConfig.Hash,
		rollbackConfig.Signature,
	)

	cm.current = rollbackConfig
	return nil
}

// ValidateConfig validates the current configuration
func (cm *ConfigManager) ValidateConfig() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.current == nil {
		return fmt.Errorf("no current configuration loaded")
	}

	return cm.current.Validate()
}

// GetCurrentConfig returns the current configuration
func (cm *ConfigManager) GetCurrentConfig() *ConfigData {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.current
}

// GetLatestVersion returns the latest version string
func (cm *ConfigManager) GetLatestVersion() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	versions, _ := cm.provider.ListVersions()
	if len(versions) == 0 {
		return ""
	}

	var latestVersion string
	for _, v := range versions {
		if v.Timestamp > latestVersion {
			latestVersion = v.Version
		}
	}
	return latestVersion
}

// GetConfigHash returns the hash of the current configuration
func (cm *ConfigManager) GetConfigHash() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.current == nil {
		return ""
	}
	return cm.current.Hash
}

// GetAuditLogger returns the audit logger
func (cm *ConfigManager) GetAuditLogger() *logging.AuditLogger {
	return cm.auditLogger
}

// Close closes the config manager
func (cm *ConfigManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.provider != nil {
		return cm.provider.Close()
	}
	return nil
}
