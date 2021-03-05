package poweruser

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type JsonDocumentConfig struct {
	PowerUserConfig   config.PowerUser
	ApplicationConfig config.Application
	PackageCatalog    *pkg.Catalog
	FileCatalog       *file.Catalog
	Distro            *distro.Distro
	SourceMetadata    source.Metadata
	Scope             source.Scope
}
