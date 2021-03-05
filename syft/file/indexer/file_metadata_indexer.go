package indexer

import (
	"crypto"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

const FileMetadataIndex = "fileMetadata"

type FileMetadataIndexer struct {
	resolver source.FileResolver
	catalog  file.IndexCataloger
	hashes   []crypto.Hash
}

func NewFileMetadataIndexer(resolver source.FileResolver, catalog *file.Catalog) *FileMetadataIndexer {
	return &FileMetadataIndexer{
		resolver: resolver,
		catalog:  catalog.NewIndexedCatalogEntryFactory(FileMetadataIndex),
	}
}

func (i *FileMetadataIndexer) Index() error {
	for location := range i.resolver.AllLocations() {
		metadata, err := i.resolver.FileMetadataByLocation(location)
		if err != nil {
			return err
		}

		i.catalog(location, metadata)
	}
	return nil
}
