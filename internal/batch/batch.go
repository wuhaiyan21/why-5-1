package batch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"logalyzer/internal/analyzer"
	"logalyzer/internal/config"
	"logalyzer/internal/report"
	"logalyzer/internal/tailer"
)

type ScanResult struct {
	Name       string
	OutputDir  string
	Analyzer   *analyzer.Analyzer
	Since      time.Time
	Until      time.Time
	Err        error
}

func RunBatch(bc *config.BatchConfig, baseConfigPath string, outputParentDir string, pollInterval time.Duration) ([]report.BatchSummaryRow, error) {
	if err := os.MkdirAll(outputParentDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output parent dir %q: %w", outputParentDir, err)
	}

	summaryRows := make([]report.BatchSummaryRow, 0, len(bc.Entries))

	for _, entry := range bc.Entries {
		result := processEntry(entry, baseConfigPath, outputParentDir, pollInterval)

		row := report.BuildSummaryRow(result.Name, result.Analyzer, result.Err)
		summaryRows = append(summaryRows, row)

		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] 组 %q 扫描失败: %v\n", result.Name, result.Err)
		} else {
			fmt.Fprintf(os.Stderr, "[OK]   组 %q 扫描完成，输出: %s\n", result.Name, result.OutputDir)
		}
	}

	report.SortSummaryRows(summaryRows)

	csvContent, err := report.GenerateSummaryCSV(summaryRows)
	if err != nil {
		return summaryRows, fmt.Errorf("failed to generate summary CSV: %w", err)
	}

	summaryPath := filepath.Join(outputParentDir, "summary.csv")
	if err := os.WriteFile(summaryPath, []byte(csvContent), 0644); err != nil {
		return summaryRows, fmt.Errorf("failed to write summary CSV to %q: %w", summaryPath, err)
	}
	fmt.Fprintf(os.Stderr, "\n汇总对比表已写入: %s\n", summaryPath)

	return summaryRows, nil
}

func processEntry(entry config.BatchEntry, baseConfigPath string, outputParentDir string, pollInterval time.Duration) ScanResult {
	result := ScanResult{
		Name: entry.Name,
	}

	entryOutputDir := filepath.Join(outputParentDir, sanitizeDirName(entry.Name))
	result.OutputDir = entryOutputDir

	if err := os.MkdirAll(entryOutputDir, 0755); err != nil {
		result.Err = fmt.Errorf("failed to create output dir: %w", err)
		return result
	}

	configPath := baseConfigPath
	if entry.Config != "" {
		configPath = entry.Config
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		result.Err = fmt.Errorf("failed to load config: %w", err)
		return result
	}

	cfg.LogDir = entry.LogDir
	if len(entry.LogFiles) > 0 {
		cfg.LogFiles = entry.LogFiles
	}

	absLogDir, err := filepath.Abs(cfg.LogDir)
	if err == nil {
		cfg.LogDir = absLogDir
	}

	if _, statErr := os.Stat(cfg.LogDir); os.IsNotExist(statErr) {
		result.Err = fmt.Errorf("log directory does not exist: %s", cfg.LogDir)
		return result
	} else if statErr != nil {
		result.Err = fmt.Errorf("failed to stat log dir: %w", statErr)
		return result
	}

	since, until, err := entry.ParseTimeRange()
	if err != nil {
		result.Err = err
		return result
	}
	result.Since = since
	result.Until = until

	a := analyzer.New(cfg, since, until)
	result.Analyzer = a

	patterns := cfg.LogFiles
	if len(patterns) == 0 {
		patterns = []string{"*.log"}
	}

	t := tailer.New(cfg.LogDir, patterns, pollInterval, false)
	if err := t.Start(); err != nil {
		result.Err = fmt.Errorf("failed to start tailer: %w", err)
		return result
	}

	doneProcessing := make(chan struct{})
	go func() {
		for line := range t.LineChan() {
			a.ProcessLine(line.FilePath, line.Line, line.Time)
		}
		close(doneProcessing)
	}()

	<-doneProcessing

	jsonReport, err := report.GenerateJSON(a, since, until)
	if err != nil {
		result.Err = fmt.Errorf("failed to generate JSON report: %w", err)
		return result
	}

	jsonPath := filepath.Join(entryOutputDir, "report.json")
	if err := os.WriteFile(jsonPath, []byte(jsonReport), 0644); err != nil {
		result.Err = fmt.Errorf("failed to write JSON report: %w", err)
		return result
	}

	mdReport := report.Generate(a, since, until)
	mdPath := filepath.Join(entryOutputDir, "report.md")
	if err := os.WriteFile(mdPath, []byte(mdReport), 0644); err != nil {
		result.Err = fmt.Errorf("failed to write markdown report: %w", err)
		return result
	}

	return result
}

func sanitizeDirName(name string) string {
	invalid := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := name
	for _, ch := range invalid {
		result = strings.ReplaceAll(result, ch, "_")
	}
	result = filepath.Base(result)
	if result == "" || result == "." || result == ".." {
		result = "_"
	}
	return result
}
