package cmd

import (
	"fmt"

	"github.com/anchore/syft/syft/file/indexer"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

var powerUserOpts = struct {
	configPath string
}{}

var powerUserCmd = &cobra.Command{
	Use:           "power-user [SOURCE]",
	Short:         "Run bulk operations on container images",
	Example:       `  {{.appName}} power-user <image>`,
	Args:          cobra.ExactArgs(1),
	Hidden:        true,
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
			return fmt.Errorf("cannot profile CPU and memory simultaneously")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU {
			defer profile.Start(profile.CPUProfile).Stop()
		} else if appConfig.Dev.ProfileMem {
			defer profile.Start(profile.MemProfile).Stop()
		}

		return powerUserExec(cmd, args)
	},
	ValidArgsFunction: dockerImageValidArgsFunction,
}

func init() {
	powerUserCmd.Flags().StringVarP(&powerUserOpts.configPath, "config", "c", "", "config file path with all power-user options")

	rootCmd.AddCommand(powerUserCmd)
}

func powerUserExec(_ *cobra.Command, args []string) error {
	errs := powerUserExecWorker(args[0])
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}

func powerUserExecWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		powerUserConfig, err := config.LoadPowerUserConfig(viper.New(), powerUserOpts.configPath, *appConfig)
		if err != nil {
			errs <- err
			return
		}

		log.Debugf("power-user config:\n%s", color.Magenta.Sprint(powerUserConfig.String()))

		checkForApplicationUpdate()

		src, cleanup, err := source.New(userInput)
		if err != nil {
			errs <- err
			return
		}
		defer cleanup()

		if src.Metadata.Scheme != source.ImageScheme {
			errs <- fmt.Errorf("the power-user subcommand only allows for 'image' schemes, given %q", src.Metadata.Scheme)
			return
		}

		//if powerUserConfig.PackagesCataloger.Enabled {
		//	catalog, d, err := syft.CatalogPackages(src, powerUserConfig.PackagesCataloger.ScopeOpt)
		//	if err != nil {
		//		errs <- fmt.Errorf("failed to catalog input: %+v", err)
		//		return
		//	}
		//}

		_, err = runIndexers(*powerUserConfig, src)
		if err != nil {
			errs <- err
			return
		}

		bus.Publish(partybus.Event{
			Type:  event.PresenterReady,
			Value: packages.Presenter(packages.JSONPresenterOption, packages.PresenterConfig{}),
		})
	}()
	return errs
}

func runIndexers(powerUserConfig config.PowerUser, src source.Source) (*file.Catalog, error) {
	var indexers []file.Indexer
	fileCatalog := file.NewCatalog()

	if powerUserConfig.FileMetadataIndexer.Enabled {
		resolver, err := src.FileResolver(powerUserConfig.FileMetadataIndexer.ScopeOpt)
		if err != nil {
			return nil, err
		}
		indexers = append(indexers, indexer.NewFileMetadataIndexer(resolver, fileCatalog))
	}

	if powerUserConfig.FileDigestsIndexer.Enabled {
		resolver, err := src.FileResolver(powerUserConfig.FileDigestsIndexer.ScopeOpt)
		if err != nil {
			return nil, err
		}
		fileDigestsConfig := indexer.FileDigestsIndexerConfig{
			Resolver:       resolver,
			HashAlgorithms: powerUserConfig.FileDigestsIndexer.Digests,
		}
		idxr, err := indexer.NewFileDigestsIndexer(fileDigestsConfig, fileCatalog)
		if err != nil {
			return nil, fmt.Errorf("unable to create file digests indexer: %w", err)
		}
		indexers = append(indexers, idxr)
	}

	for _, i := range indexers {
		if err := i.Index(); err != nil {
			return nil, err
		}
	}
	return fileCatalog, nil
}
