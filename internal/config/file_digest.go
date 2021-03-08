package config

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type FileDigest struct {
	CatalogingEnabled bool         `yaml:"cataloging-enabled" json:"cataloging-enabled" mapstructure:"cataloging-enabled"`
	Scope             string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt          source.Scope `yaml:"-" json:"-"`
	Algorithms        []string     `yaml:"algorithms" json:"algorithms" mapstructure:"algorithms"`
}

func (cfg *FileDigest) build() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}
