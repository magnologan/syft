package poweruser

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type JsonFileDigests struct {
	Location source.Location `json:"location"`
	Digests  []file.Digest   `json:"digests"`
}

func NewJsonFileDigests(data map[source.Location][]file.Digest) ([]JsonFileDigests, error) {
	results := make([]JsonFileDigests, 0)
	for location, digests := range data {
		results = append(results, JsonFileDigests{
			Location: location,
			Digests:  digests,
		})
	}
	return results, nil
}
