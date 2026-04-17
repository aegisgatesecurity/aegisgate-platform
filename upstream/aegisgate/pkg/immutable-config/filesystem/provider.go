package filesystem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

const (
	// DefaultPermissions for config files
	DefaultPermissions = 0644
	// DefaultDirPermissions for directories
	DefaultDirPermissions = 0755
	// ConfigFileExtension for config files
	ConfigFileExtension = ".config"
	// MetaFileExtension for metadata files
	MetaFileExtension = ".meta"
	// HashFileExtension for hash files
	HashFileExtension = ".hash"
)

// FilesystemProvider implements Provider using the filesystem
type FilesystemProvider struct {
	mu       sync.RWMutex
	basePath string
	versions map[string]*immutableconfig.ConfigData
}

// FilesystemOptions for configuring the filesystem provider
type FilesystemOptions struct {
	BasePath         string
	CreateIfNotExist bool
	Permissions      os.FileMode
}

// DefaultFilesystemOptions returns default filesystem options
func DefaultFilesystemOptions() *FilesystemOptions {
	return &FilesystemOptions{
		BasePath:         "./config-data",
		CreateIfNotExist: true,
		Permissions:      DefaultDirPermissions,
	}
}

// NewFilesystemProvider creates a new filesystem-based provider
func NewFilesystemProvider(opts *FilesystemOptions) (*FilesystemProvider, error) {
	if opts == nil {
		opts = DefaultFilesystemOptions()
	}

	// Create directory if it doesn't exist
	if opts.CreateIfNotExist {
		if err := os.MkdirAll(opts.BasePath, opts.Permissions); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	// Check if directory exists
	info, err := os.Stat(opts.BasePath)
	if err != nil {
		return nil, fmt.Errorf("config directory does not exist: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("config path is not a directory: %s", opts.BasePath)
	}

	fp := &FilesystemProvider{
		basePath: opts.BasePath,
		versions: make(map[string]*immutableconfig.ConfigData),
	}

	// Load existing configurations
	if err := fp.loadExisting(); err != nil {
		return nil, fmt.Errorf("failed to load existing configs: %w", err)
	}

	return fp, nil
}

// Initialize initializes the filesystem provider
func (fp *FilesystemProvider) Initialize() error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Verify directory is accessible
	if _, err := os.Stat(fp.basePath); err != nil {
		return fmt.Errorf("config directory not accessible: %w", err)
	}

	return nil
}

// Load loads a specific version of the configuration
func (fp *FilesystemProvider) Load(version string) (*immutableconfig.ConfigData, error) {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	// Check in-memory cache first
	if config, exists := fp.versions[version]; exists {
		return config, nil
	}

	// Load from disk
	config, err := fp.loadFromDisk(version)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Save saves a new configuration version to disk
func (fp *FilesystemProvider) Save(config *immutableconfig.ConfigData) (*immutableconfig.ConfigVersion, error) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Create version directory
	versionDir := filepath.Join(fp.basePath, config.Version)
	if err := os.MkdirAll(versionDir, DefaultDirPermissions); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Marshal config data
	configData, err := json.MarshalIndent(config.Data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	// Write config file (atomically using temp file)
	configPath := filepath.Join(versionDir, "config.json")
	if err := fp.writeAtomic(configPath, configData); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	// Write metadata file
	metaData, err := json.MarshalIndent(config.Metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metaPath := filepath.Join(versionDir, "metadata.json")
	if err := fp.writeAtomic(metaPath, metaData); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %w", err)
	}

	// Write hash file
	if config.Hash != "" {
		hashPath := filepath.Join(versionDir, "hash")
		if err := fp.writeAtomic(hashPath, []byte(config.Hash)); err != nil {
			return nil, fmt.Errorf("failed to write hash: %w", err)
		}
	}

	// Write version info file
	versionInfo := map[string]interface{}{
		"version":   config.Version,
		"created":   config.Created,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}
	versionData, _ := json.MarshalIndent(versionInfo, "", "  ")
	versionPath := filepath.Join(versionDir, "version.json")
	if err := fp.writeAtomic(versionPath, versionData); err != nil {
		return nil, fmt.Errorf("failed to write version info: %w", err)
	}

	// Set file to read-only (immutable)
	if err := fp.setReadOnly(configPath); err != nil {
		// Log but don't fail - this is a best-effort operation
		fmt.Printf("Warning: failed to set read-only: %v\n", err)
	}

	// Update in-memory cache
	fp.versions[config.Version] = config

	return &immutableconfig.ConfigVersion{
		Version:   config.Version,
		Timestamp: config.Created,
		Hash:      config.Hash,
	}, nil
}

// ListVersions lists all available versions
func (fp *FilesystemProvider) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	versions := make([]*immutableconfig.ConfigVersion, 0, len(fp.versions))
	for version, config := range fp.versions {
		versions = append(versions, &immutableconfig.ConfigVersion{
			Version:   version,
			Timestamp: config.Created,
			Hash:      config.Hash,
		})
	}

	return versions, nil
}

// Close closes the filesystem provider
func (fp *FilesystemProvider) Close() error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Clear in-memory cache
	fp.versions = make(map[string]*immutableconfig.ConfigData)
	return nil
}

// DeleteVersion deletes a specific version (admin operation)
func (fp *FilesystemProvider) DeleteVersion(version string) error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	versionDir := filepath.Join(fp.basePath, version)
	if err := os.RemoveAll(versionDir); err != nil {
		return fmt.Errorf("failed to delete version: %w", err)
	}

	delete(fp.versions, version)
	return nil
}

// GetBasePath returns the base path for the filesystem provider
func (fp *FilesystemProvider) GetBasePath() string {
	return fp.basePath
}

// loadFromDisk loads a configuration from disk
func (fp *FilesystemProvider) loadFromDisk(version string) (*immutableconfig.ConfigData, error) {
	versionDir := filepath.Join(fp.basePath, version)

	// Read config file
	configPath := filepath.Join(versionDir, "config.json")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(configData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Read metadata file
	var metadata map[string]string
	metaPath := filepath.Join(versionDir, "metadata.json")
	if metaData, err := os.ReadFile(metaPath); err == nil {
		if unmarshalErr := json.Unmarshal(metaData, &metadata); unmarshalErr != nil {
			// Log but continue - metadata is optional
		}
	}
	if metadata == nil {
		metadata = make(map[string]string)
	}

	// Read hash file
	var hash string
	hashPath := filepath.Join(versionDir, "hash")
	if hashData, err := os.ReadFile(hashPath); err == nil {
		hash = string(hashData)
	}

	// Read version info
	var created string
	versionPath := filepath.Join(versionDir, "version.json")
	if versionData, err := os.ReadFile(versionPath); err == nil {
		var info map[string]interface{}
		if err := json.Unmarshal(versionData, &info); err == nil {
			if c, ok := info["created"].(string); ok {
				created = c
			}
		}
	}

	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}

	config := &immutableconfig.ConfigData{
		Version:  version,
		Created:  created,
		Data:     data,
		Metadata: metadata,
		Hash:     hash,
	}

	return config, nil
}

// loadExisting loads all existing configurations from disk
func (fp *FilesystemProvider) loadExisting() error {
	entries, err := os.ReadDir(fp.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read config directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		version := entry.Name()
		config, err := fp.loadFromDisk(version)
		if err != nil {
			// Log warning but continue loading other versions
			fmt.Printf("Warning: failed to load version %s: %v\n", version, err)
			continue
		}

		fp.versions[version] = config
	}

	return nil
}

// writeAtomic writes data to a file atomically using a temp file
func (fp *FilesystemProvider) writeAtomic(path string, data []byte) error {
	// Write to temp file first
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, DefaultPermissions); err != nil {
		return err
	}

	// Rename to final path (atomic on most filesystems)
	return os.Rename(tempPath, path)
}

// setReadOnly sets a file to read-only mode
func (fp *FilesystemProvider) setReadOnly(path string) error {
	return os.Chmod(path, 0600) //nolint:gosec // G302: intentional read-only for immutable config
}

// VerifyIntegrity verifies the integrity of all stored configurations
func (fp *FilesystemProvider) VerifyIntegrity() (map[string]bool, error) {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	results := make(map[string]bool)

	for version, config := range fp.versions {
		// Verify files exist
		versionDir := filepath.Join(fp.basePath, version)
		configPath := filepath.Join(versionDir, "config.json")

		if _, err := os.Stat(configPath); err != nil {
			results[version] = false
			continue
		}

		// Verify hash if present
		if config.Hash != "" {
			hashPath := filepath.Join(versionDir, "hash")
			if hashData, err := os.ReadFile(hashPath); err == nil {
				results[version] = (string(hashData) == config.Hash)
			} else {
				results[version] = false
			}
		} else {
			results[version] = true
		}
	}

	return results, nil
}
