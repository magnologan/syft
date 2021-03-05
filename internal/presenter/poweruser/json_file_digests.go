package poweruser

import (
	"fmt"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/indexer"
	"github.com/anchore/syft/syft/source"
)

type JsonFileDigests struct {
	Location source.Location `json:"location"`
	Digests  []file.Digest   `json:"digests"`
}

func NewJsonFileDigests(fileCatalog *file.Catalog) ([]JsonFileDigests, error) {
	index := indexer.FileDigestsIndex
	results := make([]JsonFileDigests, 0)
	for _, location := range fileCatalog.GetLocations(index) {
		allDigests := fileCatalog.GetMetadata(index, location)
		if len(allDigests) > 1 {
			return nil, fmt.Errorf("discovered multiple metadata entries in file catalog @ index=%q location=%+v", index, location)
		} else if len(allDigests) == 0 {
			continue
		}

		digests, ok := allDigests[0].([]file.Digest)
		if !ok {
			return nil, fmt.Errorf("unexptected type found in file catalog @ index=%q location=%+v", index, location)
		}

		results = append(results, JsonFileDigests{
			Location: location,
			Digests:  digests,
		})
	}
	return results, nil
}
