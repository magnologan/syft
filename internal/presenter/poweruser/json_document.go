package poweruser

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/presenter/packages"
)

type JsonDocument struct {
	FileMetadata []JsonFileMetadata `json:"fileMetadata"`
	FileDigests  []JsonFileDigests  `json:"fileDigests"`
	packages.JsonDocument
}

// NewJsonDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJsonDocument(config JsonDocumentConfig) (JsonDocument, error) {
	runtimeConfig := JsonDescriptorConfiguration{
		Application: config.ApplicationConfig,
		PowerUser:   config.PowerUserConfig,
	}
	pkgsDoc, err := packages.NewJsonDocument(config.PackageCatalog, config.SourceMetadata, config.Distro, config.Scope, &runtimeConfig)
	if err != nil {
		return JsonDocument{}, err
	}

	fileMetadata, err := NewJsonFileMetadata(config.FileCatalog)
	if err != nil {
		return JsonDocument{}, err
	}

	fileDigests, err := NewJsonFileDigests(config.FileCatalog)
	if err != nil {
		return JsonDocument{}, err
	}

	return JsonDocument{
		FileMetadata: fileMetadata,
		FileDigests:  fileDigests,
		JsonDocument: pkgsDoc,
	}, nil
}

type JsonDescriptorConfiguration struct {
	Application config.Application `json:"application"`
	PowerUser   config.PowerUser   `json:"powerUser"`
}
