// pkg/core/load.go
package core

import (
	"os"

	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
	toml "github.com/pelletier/go-toml/v2"
)

func LoadConfig(path string) (manifest.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return manifest.Config{}, err
	}
	var cfg manifest.Config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return manifest.Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return manifest.Config{}, err
	}
	return cfg, nil
}
