package a2a

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type CapsConfig struct {
	Agents map[string][]string `yaml:"agents"`
}

// LoadCaps loads capability configuration from a YAML file.
// It validates the provided path to avoid path traversal and restricts inclusion to the "configs" directory.
func LoadCaps(path string) (map[string][]string, error) {
	// Disallow obvious directory traversal patterns.
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid config path: %s", path)
	}
	// Resolve absolute path.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("could not resolve absolute path: %w", err)
	}
	// Ensure the file resides under a "configs" directory (project-relative).
	if !strings.Contains(absPath, string(filepath.Separator)+"configs"+string(filepath.Separator)) {
		return nil, fmt.Errorf("config must be located within configs directory: %s", absPath)
	}
	// #nosec G304 – reading a config file whose path is validated above
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var cfg CapsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Agents, nil
}
