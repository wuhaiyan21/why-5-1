package batch

import (
	"fmt"
	"io"
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

func RunBatch(bc *config.BatchConfig, baseConfigPath string, outputParentDir string, pollInterval time.Duration, verbose bool, generateHTML bool) ([]report.BatchSummaryRow, []ScanResult, error) {
	if err := os.MkdirAll(outputParentDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create output parent dir %q: %w", outputParentDir, err)
	}

	summaryRows := make([]report.BatchSummaryRow, 0, len(bc.Entries))
	scanResults := make([]ScanResult, 0, len(bc.Entries))

	for _, entry := range bc.Entries {
		var logWriter io.Writer
		if verbose {
			logWriter = os.Stderr
		} else {
			logWriter = io.Discard
		}

		result := processEntry(entry, baseConfigPath, outputParentDir, pollInterval, logWriter)
		scanResults = append(scanResults, result)

		row := report.BuildSummaryRow(result.Name, result.Analyzer, result.Err)
		summaryRows = append(summaryRows, row)

		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] %-25s 失败: %v\n", len(summaryRows), len(bc.Entries), result.Name, result.Err)
		} else {
			sevSummary := fmt.Sprintf("C:%d E:%d W:%d I:%d D:%d", row.Critical, row.Error, row.Warning, row.Info, row.Debug)
			fmt.Fprintf(os.Stderr, "[%d/%d] %-25s 成功 | %s | 规则命中: %d\n", len(summaryRows), len(bc.Entries), result.Name, sevSummary, row.RuleHitCount)
		}
	}

	report.SortSummaryRows(summaryRows)

	csvContent, err := report.GenerateSummaryCSV(summaryRows)
	if err != nil {
		return summaryRows, scanResults, fmt.Errorf("failed to generate summary CSV: %w", err)
	}

	summaryPath := filepath.Join(outputParentDir, "summary.csv")
	if err := os.WriteFile(summaryPath, []byte(csvContent), 0644); err != nil {
		return summaryRows, scanResults, fmt.Errorf("failed to write summary CSV to %q: %w", summaryPath, err)
	}
	fmt.Fprintf(os.Stderr, "\n汇总对比表已写入: %s\n", summaryPath)

	if generateHTML {
		groupDetails := make([]report.GroupDetail, len(scanResults))
		for i, r := range scanResults {
			groupDetails[i] = report.GroupDetail{
				Name:      r.Name,
				Analyzer:  r.Analyzer,
				Since:     r.Since,
				Until:     r.Until,
				Err:       r.Err,
				OutputDir: r.OutputDir,
			}
		}
		htmlContent, err := report.GenerateComparisonHTML(summaryRows, groupDetails)
		if err != nil {
			return summaryRows, scanResults, fmt.Errorf("failed to generate HTML report: %w", err)
		}
		htmlPath := filepath.Join(outputParentDir, "comparison_report.html")
		if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
			return summaryRows, scanResults, fmt.Errorf("failed to write HTML report to %q: %w", htmlPath, err)
		}
		fmt.Fprintf(os.Stderr, "HTML对比报告已写入: %s\n", htmlPath)
	}

	return summaryRows, scanResults, nil
}

func processEntry(entry config.BatchEntry, baseConfigPath string, outputParentDir string, pollInterval time.Duration, logWriter io.Writer) ScanResult {
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

	fmt.Fprintf(logWriter, "==> 开始扫描组: %s\n", entry.Name)
	fmt.Fprintf(logWriter, "    日志目录: %s\n", cfg.LogDir)
	if !since.IsZero() {
		fmt.Fprintf(logWriter, "    时间范围: %s ~ %s\n", since.Format("2006-01-02 15:04:05"), until.Format("2006-01-02 15:04:05"))
	}

	t := tailer.New(cfg.LogDir, patterns, pollInterval, false)
	if err := t.Start(); err != nil {
		result.Err = fmt.Errorf("failed to start tailer: %w", err)
		return result
	}

	doneProcessing := make(chan struct{})
	go func() {
		lineCount := 0
		for line := range t.LineChan() {
			a.ProcessLine(line.FilePath, line.Line, line.Time)
			lineCount++
			if lineCount%1000 == 0 {
				fmt.Fprintf(logWriter, "    已处理 %d 行...\n", lineCount)
			}
		}
		fmt.Fprintf(logWriter, "    处理完成，共 %d 行\n", lineCount)
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
