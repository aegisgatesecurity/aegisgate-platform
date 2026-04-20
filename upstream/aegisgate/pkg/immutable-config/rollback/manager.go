// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package rollback

import (
	"fmt"
	"sync"
	"time"
)

// RollbackManager manages configuration rollbacks
type RollbackManager struct {
	versions       map[string]*VersionInfo
	mu             sync.RWMutex
	maxVersions    int
	enableRollback bool
}

// VersionInfo contains version metadata
type VersionInfo struct {
	Version   string
	Timestamp time.Time
	Hash      string
	Size      int
	Author    string
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(maxVersions int, enableRollback bool) *RollbackManager {
	return &RollbackManager{
		versions:       make(map[string]*VersionInfo),
		maxVersions:    maxVersions,
		enableRollback: enableRollback,
	}
}

// AddVersion adds a version to the rollback manager
func (rm *RollbackManager) AddVersion(version string, hash string, size int, author string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.enableRollback {
		return fmt.Errorf("rollback is disabled")
	}

	rm.versions[version] = &VersionInfo{
		Version:   version,
		Timestamp: time.Now().UTC(),
		Hash:      hash,
		Size:      size,
		Author:    author,
	}

	// Trim old versions if we exceed max
	rm.trimVersions()

	return nil
}

// GetVersion gets version information
func (rm *RollbackManager) GetVersion(version string) (*VersionInfo, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	info, exists := rm.versions[version]
	if !exists {
		return nil, fmt.Errorf("version %s not found", version)
	}

	return info, nil
}

// GetLatestVersion gets the latest version
func (rm *RollbackManager) GetLatestVersion() (string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var latestVersion string
	var latestTime time.Time

	for version, info := range rm.versions {
		if info.Timestamp.After(latestTime) {
			latestTime = info.Timestamp
			latestVersion = version
		}
	}

	if latestVersion == "" {
		return "", fmt.Errorf("no versions available")
	}

	return latestVersion, nil
}

// ListVersions lists all available versions
func (rm *RollbackManager) ListVersions() []*VersionInfo {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var versions []*VersionInfo
	for _, info := range rm.versions {
		versions = append(versions, info)
	}

	// Sort by timestamp (newest first)
	for i := 0; i < len(versions)-1; i++ {
		for j := i + 1; j < len(versions); j++ {
			if versions[j].Timestamp.After(versions[i].Timestamp) {
				versions[i], versions[j] = versions[j], versions[i]
			}
		}
	}

	return versions
}

// DeleteVersion removes a version
func (rm *RollbackManager) DeleteVersion(version string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.enableRollback {
		return fmt.Errorf("rollback is disabled")
	}

	delete(rm.versions, version)
	return nil
}

// RollbackToVersion performs rollback to a specific version
func (rm *RollbackManager) RollbackToVersion(version string, currentVersion string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.enableRollback {
		return fmt.Errorf("rollback is disabled")
	}

	// Record the rollback
	rm.versions[currentVersion] = &VersionInfo{
		Version:   currentVersion,
		Timestamp: time.Now().UTC(),
		Hash:      "rollback-" + version,
		Size:      -1,
		Author:    "system",
	}

	return nil
}

// trimVersions removes old versions beyond maxVersions
func (rm *RollbackManager) trimVersions() {
	if len(rm.versions) <= rm.maxVersions {
		return
	}

	// Inline version of ListVersions to avoid deadlock from double locking
	var versions []*VersionInfo
	for _, info := range rm.versions {
		versions = append(versions, info)
	}

	// Sort by timestamp (newest first)
	for i := 0; i < len(versions)-1; i++ {
		for j := i + 1; j < len(versions); j++ {
			if versions[j].Timestamp.After(versions[i].Timestamp) {
				versions[i], versions[j] = versions[j], versions[i]
			}
		}
	}

	// Remove oldest versions
	for i := rm.maxVersions; i < len(versions); i++ {
		delete(rm.versions, versions[i].Version)
	}
}

// GetInfo returns rollback manager info
func (rm *RollbackManager) GetInfo() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]interface{}{
		"total_versions":  len(rm.versions),
		"max_versions":    rm.maxVersions,
		"enable_rollback": rm.enableRollback,
	}
}
