package poweruser

import (
	"fmt"
	"strconv"

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

func NewJsonFileMetadata(data map[source.Location]source.FileMetadata) ([]JsonFileMetadata, error) {
	results := make([]JsonFileMetadata, 0)
	for location, metadata := range data {

		mode, err := strconv.Atoi(fmt.Sprintf("%o", metadata.Mode))
		if err != nil {
			return nil, fmt.Errorf("invalid mode found in file catalog @ location=%+v mode=%q: %w", location, metadata.Mode, err)
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
