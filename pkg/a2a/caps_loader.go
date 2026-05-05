package a2a

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type CapsConfig struct {
	Agents map[string][]string `yaml:"agents"`
}

// LoadCaps loads capability configuration from a YAML file.
func LoadCaps(path string) (map[string][]string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg CapsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Agents, nil
}
