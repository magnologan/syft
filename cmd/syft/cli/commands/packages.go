package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/ui"
)

func Packages(app clio.Application, scanCmd *cobra.Command) *cobra.Command {
	id := app.ID()

	opts := defaultScanOptions()

	cmd := app.SetupCommand(&cobra.Command{
		Use:     "packages [SOURCE]",
		Short:   scanCmd.Short,
		Long:    scanCmd.Long,
		Args:    scanCmd.Args,
		Example: scanCmd.Example,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runScan(cmd.Context(), id, opts, args[0])
		},
	}, opts)

	cmd.Deprecated = "use `syft scan` instead"

	return cmd
}
