package packages

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

// JsonSource object represents the thing that was cataloged
type JsonSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

// NewJsonSource creates a new source object to be represented into JSON.
func NewJsonSource(src source.Metadata, scope source.Scope) (JsonSource, error) {
	switch src.Scheme {
	case source.ImageScheme:
		return JsonSource{
			Type: "image",
			Target: struct {
				Scope source.Scope
				source.ImageMetadata
			}{
				Scope:         scope,
				ImageMetadata: src.ImageMetadata,
			},
		}, nil
	case source.DirectoryScheme:
		return JsonSource{
			Type:   "directory",
			Target: src.Path,
		}, nil
	default:
		return JsonSource{}, fmt.Errorf("unsupported source: %q", src.Scheme)
	}
}
