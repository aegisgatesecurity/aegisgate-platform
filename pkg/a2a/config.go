// SPDX-License-Identifier: Apache-2.0
package a2a

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"time"
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
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
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
