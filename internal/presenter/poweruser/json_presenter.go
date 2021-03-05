package poweruser

import (
	"encoding/json"
	"io"
)

// JsonPresenter is a JSON presentation object for the syft results
type JsonPresenter struct {
	config JsonDocumentConfig
}

// NewJsonPresenter creates a new JSON presenter object for the given cataloging results.
func NewJsonPresenter(config JsonDocumentConfig) *JsonPresenter {
	return &JsonPresenter{
		config: config,
	}
}

// Present the PackageCatalog results to the given writer.
func (p *JsonPresenter) Present(output io.Writer) error {
	doc, err := NewJsonDocument(p.config)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
