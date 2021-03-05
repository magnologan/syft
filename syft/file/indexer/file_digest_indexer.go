package indexer

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

const FileDigestsIndex = "fileDigests"

var supportedHashAlgorithms = make(map[string]crypto.Hash)

type FileDigestsIndexerConfig struct {
	Resolver       source.FileResolver
	HashAlgorithms []string
}

type FileDigestsIndexer struct {
	config  FileDigestsIndexerConfig
	catalog file.IndexCataloger
	hashes  []crypto.Hash
}

func init() {
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		lower := strings.ToLower(h.String())
		name := strings.Replace(lower, "-", "", -1)
		supportedHashAlgorithms[name] = h
	}
}

func NewFileDigestsIndexer(config FileDigestsIndexerConfig, catalog *file.Catalog) (*FileDigestsIndexer, error) {
	indexer := &FileDigestsIndexer{
		config:  config,
		catalog: catalog.NewIndexedCatalogEntryFactory(FileDigestsIndex),
	}

	for _, hashStr := range config.HashAlgorithms {
		lowerHashStr := strings.ToLower(hashStr)
		hashObj, ok := supportedHashAlgorithms[lowerHashStr]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		indexer.hashes = append(indexer.hashes, hashObj)
	}

	return indexer, nil
}

func (i *FileDigestsIndexer) Index() error {
	for location := range i.config.Resolver.AllLocations() {
		result, err := i.index(location)
		if err != nil {
			return nil
		}

		i.catalog(location, result)
	}
	return nil
}

func (i *FileDigestsIndexer) index(location source.Location) ([]file.Digest, error) {
	contentReader, err := i.config.Resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer contentReader.Close()

	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(i.hashes))
	writers := make([]io.Writer, len(i.hashes))
	for idx, hashObj := range i.hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(io.MultiWriter(writers...), contentReader)
	if err != nil {
		return nil, fmt.Errorf("unable to observe contents of %+v: %+v", location.RealPath, err)
	}

	var result = make([]file.Digest, len(i.hashes))

	if size > 0 {
		// only capture digests when there is content. It is important to do this based on SIZE and not
		// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
		// file type but a body is still allowed.
		for idx, hasher := range hashers {
			result[idx] = file.Digest{
				Algorithm: i.hashes[idx].String(),
				Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
			}
		}
	}

	return result, nil
}
