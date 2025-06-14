// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"database/sql"

	"github.com/golang-cz/devslog"
	_ "github.com/marcboeker/go-duckdb/v2"
	"github.com/spf13/cobra"

	"github.com/cilium/workerpool"
)

var buildDebugStateCmd = &cobra.Command{
	Use:   "cilium-debugtool",
	Short: "Builds a sql database to debug the state of cilium-agent",
	Run: func(cmd *cobra.Command, args []string) {
		err := buildDebugState()
		if err != nil {
			slog.With("Error", err).Error("Failed to build debug state")
			os.Exit(1)
		}
	},
}

var (
	ciliumNamespaceName string
	ciliumPodName       string

	debugStatePath string
	dbName         string

	stepCount    int
	stepWaitTime time.Duration
)

func init() {
	opts := &devslog.Options{
		HandlerOptions: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
		MaxSlicePrintSize: 4,
		SortKeys:          true,
		NewLineAfterLog:   false,
		StringerFormatter: false,
	}
	logger := slog.New(devslog.NewHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	buildDebugStateCmd.Flags().StringVar(&ciliumNamespaceName, "cilium-namespace", "kube-system", "Cilium Namespace Name")
	buildDebugStateCmd.Flags().StringVar(&ciliumPodName, "cilium-pod", "", "Cilium Pod Name")
	buildDebugStateCmd.Flags().StringVar(&debugStatePath, "dump-path", "debug-state", "Dump Directory")
	buildDebugStateCmd.Flags().StringVar(&dbName, "db-name", "cilium-debug-state.db", "Database Name")

	buildDebugStateCmd.Flags().IntVar(&stepCount, "count", 1, "Number of steps for state collection")
	buildDebugStateCmd.Flags().DurationVar(&stepWaitTime, "wait", time.Second*60, "Step duration for state collection")
}

func getRunCiliumPodCommand(command string) string {
	return fmt.Sprintf("kubectl -n %s exec %s -- %s", ciliumNamespaceName, ciliumPodName, command)
}

func getKubectlLogsCommand(namespace, podName string) string {
	return fmt.Sprintf("kubectl -n %s logs %s", namespace, podName)
}

func debugStateCommands() map[string]string {
	return map[string]string{
		"nodes":           "cilium-dbg node list --output json",
		"nodeid":          "cilium-dbg nodeid list --output json",
		"metrics":         "cilium-dbg metrics list --output json",
		"identities":      "cilium-dbg identity list --output json",
		"endpoints":       "cilium-dbg endpoint list --output json",
		"ipcache":         "cilium-dbg ip list --output json",
		"policy":          "cilium-dbg policy get | head -n -1 | jq .",
		"policyselectors": "cilium-dbg policy selectors --output json",
		"services":        "cilium-dbg service list --output json",
		"fqdncache":       "cilium-dbg fqdn cache list --output json",

		// BPF Related
		"umapstate":    "cilium-dbg map list --output json | jq .[]",
		"bpfconfig":    "cilium-dbg  bpf config list --output json",
		"bpfendpoints": "cilium-dbg bpf endpoint list --output json | jq '. | to_entries'",
		"bpfipcache":   "cilium-dbg bpf ipcache list --output json | jq '. | to_entries'",
		"bpfmetrics":   "cilium-dbg bpf metrics list --output json",
		"bpfnodeid":    "cilium-dbg bpf nodeid list --output json",
		"bpfpolicy":    "cilium-dbg bpf policy list --output json",

		// LocalState
		"epstate":        "bash -c 'cat $(find /var/run/cilium/state -name ep_config.json)'",
		"allocatorstate": "cat /var/run/cilium/state/local_allocator_state.json",
		"nodestate":      "cat /var/run/cilium/state/nodes.json",
	}
}

func debugLogsCommands() map[string]string {
	return map[string]string{
		"agentlogs":  getKubectlLogsCommand(ciliumNamespaceName, ciliumPodName),
		"policylogs": getRunCiliumPodCommand("cat /var/run/cilium/state/endpoint-policy.log"),
	}
}

func collectState(db *sql.DB, firstRun bool) {
	wp := workerpool.New(runtime.NumCPU())

	for ctx, command := range debugStateCommands() {
		err := wp.Submit(ctx, func(_ context.Context) error {
			slog.With("Context", ctx).Info("Processing Debug State context")
			prompt := getRunCiliumPodCommand(command)

			runTime, err := runCommandAndWriteToFile(prompt, ctx)
			if err != nil {
				slog.With("Context", ctx).With("Command", command).Warn("Failed to process debug state command")
				return err
			}

			return loadJSONToDB(db, ctx, runTime, firstRun)
		})

		if err != nil {
			slog.With("Error", err).With("Context", ctx).Warn("Failed to submit task for command")
		}
	}

	_, err := wp.Drain()
	if err != nil {
		slog.With("Error", err).Error("Error waiting for commands to complete")
	}

	err = wp.Close()
	if err != nil {
		slog.With("Error", err).Error("Failed to close worker pool")
	}
}

func collectLogs(db *sql.DB) {
	for ctx, command := range debugLogsCommands() {
		slog.With("Context", ctx).Info("Processing Debug Logs context")
		runTime, err := runLogsCommandAndWriteToFile(command, ctx)
		if err != nil {
			slog.With("Context", ctx).With("command", command).Warn("Failed to process debug log command")
			continue
		}

		loadJSONToDB(db, ctx, runTime, true)
	}
}

func buildDebugState() error {
	if ciliumPodName == "" {
		return errors.New("cilium-pod-name required")
	}

	err := os.MkdirAll(debugStatePath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create debug state directory: %v", err)
	}

	dbPath, _ := filepath.Abs(path.Join(debugStatePath, dbName))
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		slog.With("Error", err).With("Name", dbName).Error("Failed to open DuckDB database")
		return err
	}

	slog.With("Name", dbName).With("Path", dbPath).Info("Database Connected")
	defer func() {
		if err := db.Close(); err != nil {
			slog.With("Error", err).Error("Error closing database")
		}
		slog.Info("Database connection closed")
	}()

	for i := range stepCount {
		step := i + 1

		slog.With("Step", step).Info("Starting state collection")
		collectState(db, step == 1)
		slog.With("Step", step).Info("State collection complete")

		if step == stepCount {
			collectLogs(db)
		} else {
			time.Sleep(stepWaitTime)
			slog.With("NextRun", time.Now().Add(stepWaitTime)).Info("Sleeping till next Run")
		}
	}

	return nil
}

func main() {
	if err := buildDebugStateCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
