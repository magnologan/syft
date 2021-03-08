package poweruser

import (
	"github.com/anchore/syft/internal/presenter/packages"
)

type JsonDocument struct {
	FileMetadata []JsonFileMetadata `json:"fileMetadata"`
	FileDigests  []JsonFileDigests  `json:"fileDigests"`
	packages.JsonDocument
}

// NewJsonDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJsonDocument(config JsonDocumentConfig) (JsonDocument, error) {
	pkgsDoc, err := packages.NewJsonDocument(config.PackageCatalog, config.SourceMetadata, config.Distro, config.ApplicationConfig.Packages.ScopeOpt, config.ApplicationConfig)
	if err != nil {
		return JsonDocument{}, err
	}

	fileMetadata, err := NewJsonFileMetadata(config.FileMetadata)
	if err != nil {
		return JsonDocument{}, err
	}

	fileDigests, err := NewJsonFileDigests(config.FileDigests)
	if err != nil {
		return JsonDocument{}, err
	}

	return JsonDocument{
		FileMetadata: fileMetadata,
		FileDigests:  fileDigests,
		JsonDocument: pkgsDoc,
	}, nil
}
