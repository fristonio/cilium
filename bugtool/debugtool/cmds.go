package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var logsToJsonCmd = &cobra.Command{
	Use:   "logs-to-json",
	Short: "Convert cilium structured log file to json",
	Run: func(cmd *cobra.Command, args []string) {
		err := convertLogsToJson(logFilePath)
		if err != nil {
			slog.With("Error", err).Error("Failed to build debug state")
			os.Exit(1)
		}
	},
}

var (
	logFilePath string
)

func init() {
	logsToJsonCmd.Flags().StringVar(&logFilePath, "log-file", "", "Path to the log file")
}

func convertLogsToJson(filePath string) error {
	filePath, _ = filepath.Abs(filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		slog.With("Error", err).With("File", filePath).Error("Failed to read Log file")
		return err
	}

	fileDir := filepath.Dir(filePath)
	fileName := filepath.Base(filePath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	jsonFilePath := filepath.Join(fileDir, fmt.Sprintf("%s.json", fileNameWithoutExt))
	slog.With("FilePath", jsonFilePath).Info("Exporting logs to json file")

	return convertAndWriteLogsToJsonFile(jsonFilePath, content)
}
