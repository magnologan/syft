package config

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type FileDigestsIndexer struct {
	Enabled  bool         `yaml:"enabled" mapstructure:"enabled"`
	Scope    string       `yaml:"scope" mapstructure:"scope"`
	ScopeOpt source.Scope `yaml:"-"`
	Digests  []string     `yaml:"digests" mapstructure:"digests"`
}

func (cfg *FileDigestsIndexer) build() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}
