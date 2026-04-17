// Package sandbox provides feed-level sandboxing capabilities
package sandbox

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/config"
	"os"
	"time"
)

// Config represents sandbox configuration
type Config struct {
	DefaultQuota            ResourceQuota
	DefaultIsolationLevel   IsolationLevel
	EnableAudit             bool
	ContainerImage          string
	ResourceMonitorInterval time.Duration
	CleanupInterval         time.Duration
}

// DefaultConfig returns the default sandbox configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultQuota: ResourceQuota{
			CPU:     1000,      // 1 CPU core
			Memory:  1 << 30,   // 1GB
			Disk:    10 << 30,  // 10GB
			Network: 100 << 20, // 100MB/s
			Files:   10000,
			Process: 100,
		},
		DefaultIsolationLevel:   IsolationFull,
		EnableAudit:             true,
		ContainerImage:          "aegisgate/sandbox:latest",
		ResourceMonitorInterval: 5 * time.Second,
		CleanupInterval:         1 * time.Hour,
	}
}

// LoadConfig loads sandbox configuration from environment
func LoadConfig() *Config {
	cfg := DefaultConfig()

	if cpu := os.Getenv("SANDBOX_CPU_QUOTA"); cpu != "" {
		// Parse CPU quota
	}

	if memory := os.Getenv("SANDBOX_MEMORY_QUOTA"); memory != "" {
		// Parse memory quota
	}

	if disk := os.Getenv("SANDBOX_DISK_QUOTA"); disk != "" {
		// Parse disk quota
	}

	return cfg
}

// FromConfig converts config package to sandbox Config
func FromConfig(appConfig *config.Config) *Config {
	sandboxConfig := DefaultConfig()

	if appConfig != nil {
		// Map application config to sandbox config
	}

	return sandboxConfig
}
