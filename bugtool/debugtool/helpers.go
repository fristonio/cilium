package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

func getDebugStateFilePath(name string) string {
	return path.Join(debugStatePath, fmt.Sprintf("%s.json", name))
}

func runCommandAndWriteToFile(prompt, fileName string) (time.Time, error) {
	t := time.Now()
	data, err := execCommand(prompt)
	if err != nil {
		return t, err
	}

	return t, writeToJsonFile(fileName, data)
}

func runLogsCommandAndWriteToFile(prompt, fileName string) (time.Time, error) {
	t := time.Now()
	data, err := execCommand(prompt)
	if err != nil {
		return t, err
	}

	parsedData := parseLogData(data)
	jsonData, err := json.Marshal(parsedData)
	if err != nil {
		slog.With("Error", err).Error("Failed to marshal parsed log JSON data")
		return t, err
	}

	return t, writeToJsonFile(fileName, jsonData)
}

func execCommand(prompt string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	slog.With("Command", prompt).Info("Running Command")
	output, err := exec.CommandContext(ctx, "bash", "-c", prompt).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		slog.With("Error", err).With("Command", prompt).Error("Failed to run command")
		return nil, fmt.Errorf("exec timeout")
	}

	return output, err
}

func writeToJsonFile(name string, data []byte) error {
	filePath := getDebugStateFilePath(name)

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		slog.With("Error", err).With("File", filePath).Error("Failed to open file")
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		slog.With("Error", err).With("File", filePath).Error("Failed to write data to file")
		return err
	}

	return nil
}

func loadJSONToDB(db *sql.DB, fileName string, runTime time.Time, createTable bool) error {
	filePath := getDebugStateFilePath(fileName)

	tableCmd := fmt.Sprintf("INSERT INTO %s ", fileName)
	if createTable {
		tableCmd = fmt.Sprintf("CREATE OR REPLACE TABLE %s AS", fileName)
	}

	loadJSONSQL := fmt.Sprintf(`%s SELECT TIMESTAMP '%s' as LogTime, * FROM read_json('%s')`,
		tableCmd, runTime.Format("2006-01-02 15:04:05"), filePath)

	res, err := db.Exec(loadJSONSQL)
	if err != nil {
		slog.With("Error", err).With("Table", fileName).Error("Failed to execute SQL to load JSON data")
		return err
	}

	rows, err := res.RowsAffected()
	slog.With("Rows", rows).With("Table", fileName).Info("JSON Loading complete")
	return err
}

func parseLogData(data []byte) []map[string]interface{} {
	dataReader := bytes.NewReader(data)

	var logsData []map[string]interface{}
	scanner := bufio.NewScanner(dataReader)
	for scanner.Scan() {
		line := scanner.Text()
		parsedData, err := parseLogLine(line)
		if err != nil {
			slog.With("Error", err).With("line", line).Warn("Error parsing log line")
			continue
		}

		logsData = append(logsData, parsedData)
	}

	return logsData
}

func parseLogLine(line string) (map[string]interface{}, error) {
	jsonObject := make(map[string]interface{})
	data := make(map[string]interface{})

	knownKeys := []string{
		"time",
		"func",
		"level",
		"msg",
		"module",
		"source",
		"subsys",
		"duration",
	}

	// Regex to match key="value with spaces" or key=valueWithoutSpaces
	// This is a simplified regex and might need refinement for complex cases
	re := regexp.MustCompile(`(\S+)=(?:"([^"]*)"|(\S+))`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		key := match[1]
		var value string
		if match[2] != "" { // Quoted value
			value = match[2]
		} else { // Unquoted value
			value = match[3]
		}

		// Basic type inference (can be expanded)
		var finalValue interface{}
		if val, err := json.Marshal(value); err == nil { // Always quote string values
			finalValue = string(val) // Keep as string, json.Marshal adds quotes
			// Remove the outer quotes for simple strings so it's not double quoted later
			if strings.HasPrefix(finalValue.(string), `"`) && strings.HasSuffix(finalValue.(string), `"`) {
				finalValue = strings.Trim(finalValue.(string), `"`)
			}
		} else {
			finalValue = value
		}

		// Attempt to parse known numeric types, booleans, etc.
		if i, err := strconv.Atoi(value); err == nil {
			finalValue = i
		} else if f, err := strconv.ParseFloat(value, 64); err == nil {
			finalValue = f
		} else if b, err := strconv.ParseBool(value); err == nil {
			finalValue = b
		}
		// Add more type parsing as needed (e.g., time, durations)

		if slices.Contains(knownKeys, key) {
			jsonObject[key] = finalValue
		} else {
			data[key] = finalValue
		}
	}

	jsonObject["data"] = data
	return jsonObject, nil
}
