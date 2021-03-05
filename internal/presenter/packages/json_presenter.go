package packages

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// JsonPresenter is a JSON presentation object for the syft results
type JsonPresenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
	distro      *distro.Distro
	scope       source.Scope
}

// NewJsonPresenter creates a new JSON presenter object for the given cataloging results.
func NewJsonPresenter(catalog *pkg.Catalog, s source.Metadata, d *distro.Distro, scope source.Scope) *JsonPresenter {
	return &JsonPresenter{
		catalog:     catalog,
		srcMetadata: s,
		distro:      d,
		scope:       scope,
	}
}

// Present the catalog results to the given writer.
func (pres *JsonPresenter) Present(output io.Writer) error {
	// we do not pass in configuration for backwards compatibility
	doc, err := NewJsonDocument(pres.catalog, pres.srcMetadata, pres.distro, pres.scope, nil)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
