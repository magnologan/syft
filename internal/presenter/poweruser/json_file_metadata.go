package poweruser

import (
	"fmt"
	"strconv"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/indexer"
	"github.com/anchore/syft/syft/source"
)

type JsonFileMetadata struct {
	Location source.Location       `json:"location"`
	Metadata JsonFileMetadataEntry `json:"metadata"`
}

type JsonFileMetadataEntry struct {
	Mode    int             `json:"mode"`
	Type    source.FileType `json:"type"`
	UserID  int             `json:"userID"`
	GroupID int             `json:"groupID"`
}

func NewJsonFileMetadata(fileCatalog *file.Catalog) ([]JsonFileMetadata, error) {
	index := indexer.FileMetadataIndex
	results := make([]JsonFileMetadata, 0)
	for _, location := range fileCatalog.GetLocations(index) {
		allMetadata := fileCatalog.GetMetadata(index, location)
		if len(allMetadata) > 1 {
			return nil, fmt.Errorf("discovered multiple metadata in file catalog @ index=%q location=%+v", index, location)
		} else if len(allMetadata) == 0 {
			continue
		}

		metadata, ok := allMetadata[0].(source.FileMetadata)
		if !ok {
			return nil, fmt.Errorf("unexptected type found in file catalog @ index=%q location=%+v", index, location)
		}

		mode, err := strconv.Atoi(fmt.Sprintf("%o", metadata.Mode))
		if err != nil {
			return nil, fmt.Errorf("invalid mode found in file catalog @ index=%q location=%+v mode=%q: %w", index, location, metadata.Mode, err)
		}

		results = append(results, JsonFileMetadata{
			Location: location,
			Metadata: JsonFileMetadataEntry{
				Mode:    mode,
				Type:    metadata.Type,
				UserID:  metadata.UserID,
				GroupID: metadata.GroupID,
			},
		})
	}
	return results, nil
}
