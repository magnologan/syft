package cmd

import (
	"github.com/anchore/syft/internal/presenter/poweruser"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type powerUserTask func(*poweruser.JsonDocumentConfig) error

func powerUserTasks(src source.Source) ([]powerUserTask, error) {
	var tasks []powerUserTask
	var err error
	var task powerUserTask

	task, err = catalogPackagesTask(src)
	if err != nil {
		return nil, err
	} else if task != nil {
		tasks = append(tasks, task)
	}

	task, err = catalogFileMetadataTask(src)
	if err != nil {
		return nil, err
	} else if task != nil {
		tasks = append(tasks, task)
	}

	task, err = catalogFileDigestTask(src)
	if err != nil {
		return nil, err
	} else if task != nil {
		tasks = append(tasks, task)
	}

	return tasks, nil
}

func catalogPackagesTask(src source.Source) (powerUserTask, error) {
	if !appConfig.Packages.CatalogingEnabled {
		return nil, nil
	}

	task := func(results *poweruser.JsonDocumentConfig) error {
		packageCatalog, theDistro, err := syft.CatalogPackages(src, appConfig.Packages.ScopeOpt)
		if err != nil {
			return err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return nil
	}

	return task, nil
}

func catalogFileMetadataTask(src source.Source) (powerUserTask, error) {
	if !appConfig.FileMetadata.CatalogingEnabled {
		return nil, nil
	}

	resolver, err := src.FileResolver(appConfig.FileMetadata.ScopeOpt)
	if err != nil {
		return nil, err
	}

	task := func(results *poweruser.JsonDocumentConfig) error {
		result, err := file.NewMetadataCataloger(resolver).Catalog()
		if err != nil {
			return err
		}
		results.FileMetadata = result
		return nil
	}

	return task, nil
}

func catalogFileDigestTask(src source.Source) (powerUserTask, error) {
	if !appConfig.FileDigest.CatalogingEnabled {
		return nil, nil
	}

	resolver, err := src.FileResolver(appConfig.FileDigest.ScopeOpt)
	if err != nil {
		return nil, err
	}

	cataloger, err := file.NewDigestsCataloger(resolver, appConfig.FileDigest.Algorithms)
	if err != nil {
		return nil, err
	}

	task := func(results *poweruser.JsonDocumentConfig) error {
		result, err := cataloger.Catalog()
		if err != nil {
			return err
		}
		results.FileDigests = result
		return nil
	}

	return task, nil
}
