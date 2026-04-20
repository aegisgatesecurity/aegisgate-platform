// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package immutableconfig

import (
	"fmt"
	"time"
)

// ConfigData represents immutable configuration data
type ConfigData struct {
	Version   string                 `json:"version" yaml:"version"`
	Created   string                 `json:"created" yaml:"created"`
	Data      map[string]interface{} `json:"data" yaml:"data"`
	Metadata  map[string]string      `json:"metadata" yaml:"metadata"`
	Hash      string                 `json:"hash" yaml:"hash"`
	Signature string                 `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// ConfigVersion represents a versioned configuration state
type ConfigVersion struct {
	Version   string `json:"version" yaml:"version"`
	Timestamp string `json:"timestamp" yaml:"timestamp"`
	Hash      string `json:"hash" yaml:"hash"`
	Signature string `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// NewConfigData creates a new configuration data instance
func NewConfigData(version string, data map[string]interface{}, metadata map[string]string) *ConfigData {
	return &ConfigData{
		Version:   version,
		Created:   time.Now().UTC().Format(time.RFC3339),
		Data:      data,
		Metadata:  metadata,
		Hash:      "",
		Signature: "",
	}
}

// Validate validates the configuration data
func (c *ConfigData) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if c.Data == nil {
		c.Data = make(map[string]interface{})
	}
	if c.Metadata == nil {
		c.Metadata = make(map[string]string)
	}
	return nil
}

// GetVersion returns the configuration version
func (c *ConfigData) GetVersion() string {
	return c.Version
}

// GetCreated returns the creation timestamp
func (c *ConfigData) GetCreated() string {
	return c.Created
}

// GetData returns the configuration data
func (c *ConfigData) GetData() map[string]interface{} {
	return c.Data
}

// GetMetadata returns the configuration metadata
func (c *ConfigData) GetMetadata() map[string]string {
	return c.Metadata
}

// Get retrieves a value from the configuration data
func (c *ConfigData) Get(key string) (interface{}, bool) {
	if c.Data == nil {
		return nil, false
	}
	value, exists := c.Data[key]
	return value, exists
}

// Set sets a value in the configuration data
func (c *ConfigData) Set(key string, value interface{}) {
	if c.Data == nil {
		c.Data = make(map[string]interface{})
	}
	c.Data[key] = value
}

// String implements fmt.Stringer
func (c *ConfigData) String() string {
	hashPreview := c.Hash
	if len(hashPreview) > 16 {
		hashPreview = hashPreview[:16]
	}
	return fmt.Sprintf("ConfigData{Version: %s, Created: %s, Hash: %s}",
		c.Version, c.Created, hashPreview)
}

// NewConfigVersion creates a new config version
func NewConfigVersion(version string, hash string) *ConfigVersion {
	// Truncate hash to 16 characters for display purposes
	truncatedHash := hash
	if len(hash) > 16 {
		truncatedHash = hash[:16]
	}
	return &ConfigVersion{
		Version:   version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hash:      truncatedHash,
	}
}
