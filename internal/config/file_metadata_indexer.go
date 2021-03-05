package config

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type FileMetadataIndexer struct {
	Enabled  bool         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt source.Scope `yaml:"-" json:"-"`
}

func (cfg *FileMetadataIndexer) build() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}
