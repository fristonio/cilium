// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/version"
)

var (
	Halo = cell.Module(
		"halo",
		"Halo",

		Infrastructure,
		ControlPlane,
		DataPlane,

		cell.Invoke(
			registerHooks,
		),
	)

	Infrastructure = cell.Module(
		"halo-infra",
		"Halo Infrastructure",

		// Register the pprof HTTP handlers, to get runtime profiling data.
		cell.ProvidePrivate(func(cfg haloPprofConfig) pprof.Config {
			return cfg.Config()
		}),
		pprof.Cell(defaultHaloPprofConfig),

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.EnableGops, defaults.GopsPortHalo),
	)

	// ControlPlane implements the control functions.
	ControlPlane = cell.Module(
		"halo-controlplane",
		"Halo Control Plane",
	)

	// DataPlane implements the datapath functions.
	DataPlane = cell.Module(
		"halo-dataplane",
		"Halo Data Plane",
	)

	binaryName = filepath.Base(os.Args[0])
)

func NewHaloCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)

			initEnv(logger, h.Viper())

			// Pass the DefaultSlogLogger to the hive after being initialized
			// with the initEnv which sets up the logging.DefaultSlogLogger with
			// the user-options.
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, err.Error())
			}
		},
	}

	h.RegisterFlags(cmd.Flags())

	cmd.AddCommand(cmdref.NewCmd(cmd))

	// slogloggercheck: using default logger for configuration initialization
	cobra.OnInitialize(option.InitConfig(logging.DefaultSlogLogger, cmd, "Cilium-Halo", "cilium-halo", h.Viper()))

	return cmd
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func registerHooks(log *slog.Logger, lc cell.Lifecycle, shutdowner hive.Shutdowner) {
	var wg sync.WaitGroup
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			wg.Add(1)
			go func() {
				wg.Done()
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			wg.Wait()
			return nil
		},
	})
}

func initEnv(logger *slog.Logger, vp *viper.Viper) {
	// Setup logging with the options directly from Viper. There's no dependency
	// from this function with the rest of the DaemonConfig.
	option.Config.SetupLogging(vp, binaryName)
	// Populate the global config with the options from Viper
	option.Config.Populate(logger, vp)

	// add hooks after setting up metrics in the option.Config
	logging.AddHandlers(metrics.NewLoggingHook())

	// Register the user options in the logs
	option.LogRegisteredSlogOptions(vp, logger)
	logger.Info("Cilium Halo", logfields.Version, version.Version)
}
