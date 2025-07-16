// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
)

func InitGlobalFlags(logger *slog.Logger, cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(vp, option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(vp, option.ConfigDir)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(vp, option.DebugArg)

	flags.Bool(EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(vp, EnableMetrics)

	// Logging flags
	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(vp, option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-halo, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local4"}`)
	option.BindEnv(vp, option.LogOpt)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(vp, option.Version)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(vp, option.CMDRef)

	vp.BindPFlags(flags)
}

const (
	// pprofHalo enables pprof debugging endpoint for the halo
	pprofHalo = "halo-pprof"

	// pprofAddress is the port that the pprof listens on
	pprofAddress = "halo-pprof-address"

	// pprofPort is the port that the pprof listens on
	pprofPort = "halo-pprof-port"
)

var defaultHaloPprofConfig = haloPprofConfig{
	HaloPprof:        false,
	HaloPprofAddress: PprofAddressHalo,
	HaloPprofPort:    PprofPortHalo,
}

// haloPprofConfig holds the configuration for the halo pprof cell.
type haloPprofConfig struct {
	HaloPprof        bool
	HaloPprofAddress string
	HaloPprofPort    uint16
}

func (def haloPprofConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(pprofHalo, def.HaloPprof, "Enable serving pprof debugging API")
	flags.String(pprofAddress, def.HaloPprofAddress, "Address that pprof listens on")
	flags.Uint16(pprofPort, def.HaloPprofPort, "Port that pprof listens on")
}

func (def haloPprofConfig) Config() pprof.Config {
	return pprof.Config{
		Pprof:        def.HaloPprof,
		PprofAddress: def.HaloPprofAddress,
		PprofPort:    def.HaloPprofPort,
	}
}
