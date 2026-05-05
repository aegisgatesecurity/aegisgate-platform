// SPDX-License-Identifier: Apache-2.0
package a2a

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RateLimitConfig struct {
	Capacity int    `yaml:"capacity"`
	Refill   int    `yaml:"refill"`
	Interval string `yaml:"interval"`
}

type Config struct {
	Secret    string          `yaml:"secret"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// LoadConfig reads the A2A configuration from the given path.
// It validates the provided path to avoid path traversal attacks and ensures the file resides under the "configs" directory.
func LoadConfig(path string) (*Config, error) {
	// Disallow obvious directory traversal patterns.
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid config path: %s", path)
	}
	// Resolve absolute path.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("could not resolve absolute path: %w", err)
	}
	// Ensure the file is inside a "configs" directory.
	if !strings.Contains(absPath, string(filepath.Separator)+"configs"+string(filepath.Separator)) {
		return nil, fmt.Errorf("config must be located within configs directory: %s", absPath)
	}

	// #nosec G304 – reading a config file whose path is validated above
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading a2a config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing a2a yaml: %w", err)
	}
	// Validate interval format
	if _, err := time.ParseDuration(cfg.RateLimit.Interval); err != nil {
		return nil, fmt.Errorf("invalid rate_limit.interval: %w", err)
	}
	return &cfg, nil
}
