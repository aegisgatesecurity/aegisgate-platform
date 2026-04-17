// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package immutableconfig

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/logging"
)

// API provides the main interface for configuration operations
type API struct {
	manager *ConfigManager
}

// NewAPI creates a new API instance
func NewAPI(manager *ConfigManager) *API {
	return &API{manager: manager}
}

// LoadConfig loads a specific version of the configuration
func (api *API) LoadConfig(version string) (*ConfigData, error) {
	return api.manager.LoadConfig(version)
}

// LoadLatestConfig loads the most recent configuration
func (api *API) LoadLatestConfig() (*ConfigData, error) {
	return api.manager.LoadLatestConfig()
}

// SaveConfig saves a new configuration version
func (api *API) SaveConfig(config *ConfigData) (*ConfigVersion, error) {
	return api.manager.SaveConfig(config)
}

// GetVersionHistory gets the version history
func (api *API) GetVersionHistory() ([]*ConfigVersion, error) {
	return api.manager.GetVersionHistory()
}

// RollbackToVersion rolls back to a specific version
func (api *API) RollbackToVersion(version string) error {
	return api.manager.RollbackToVersion(version)
}

// ValidateConfig validates the current configuration
func (api *API) ValidateConfig() error {
	return api.manager.ValidateConfig()
}

// GetCurrentConfig returns the current configuration
func (api *API) GetCurrentConfig() *ConfigData {
	return api.manager.GetCurrentConfig()
}

// GetLatestVersion returns the latest version string
func (api *API) GetLatestVersion() string {
	return api.manager.GetLatestVersion()
}

// GetConfigHash returns the hash of the current configuration
func (api *API) GetConfigHash() string {
	return api.manager.GetConfigHash()
}

// GetAuditLogger returns the audit logger
func (api *API) GetAuditLogger() *logging.AuditLogger {
	return api.manager.GetAuditLogger()
}

// Close closes the API and underlying resources
func (api *API) Close() error {
	return api.manager.Close()
}
