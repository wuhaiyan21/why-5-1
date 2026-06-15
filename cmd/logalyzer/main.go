package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"logalyzer/internal/analyzer"
	"logalyzer/internal/config"
	"logalyzer/internal/report"
	"logalyzer/internal/tailer"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config YAML file")
	sinceStr := flag.String("since", "", "Start time filter (format: 2006-01-02T15:04:05)")
	untilStr := flag.String("until", "", "End time filter (format: 2006-01-02T15:04:05)")
	logDir := flag.String("log-dir", "", "Log directory (overrides config)")
	once := flag.Bool("once", false, "Read existing log content once and exit, do not follow new lines")
	follow := flag.Bool("follow", true, "Follow log files continuously (default: true, use --once to disable)")
	pollInterval := flag.Duration("poll-interval", 500*time.Millisecond, "Polling interval for log files")
	output := flag.String("output", "", "Output file for report (default: stdout)")
	format := flag.String("format", "markdown", "Report format: markdown or json")
	flag.Parse()

	if *once {
		*follow = false
	}

	formatLower := strings.ToLower(*format)
	if formatLower != "markdown" && formatLower != "json" {
		fmt.Fprintf(os.Stderr, "Invalid --format: %s (must be 'markdown' or 'json')\n", *format)
		os.Exit(1)
	}

	var since, until time.Time
	var err error

	if *sinceStr != "" {
		since, err = time.Parse("2006-01-02T15:04:05", *sinceStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --since format: %v\n", err)
			os.Exit(1)
		}
	}

	if *untilStr != "" {
		until, err = time.Parse("2006-01-02T15:04:05", *untilStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --until format: %v\n", err)
			os.Exit(1)
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *logDir != "" {
		cfg.LogDir = *logDir
	}

	if cfg.LogDir == "" {
		cfg.LogDir = "."
	}

	absLogDir, err := filepath.Abs(cfg.LogDir)
	if err == nil {
		cfg.LogDir = absLogDir
	}

	a := analyzer.New(cfg, since, until)

	patterns := cfg.LogFiles
	if len(patterns) == 0 {
		patterns = []string{"*.log"}
	}

	t := tailer.New(cfg.LogDir, patterns, *pollInterval, *follow)
	if err := t.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start tailer: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if *follow {
		fmt.Fprintln(os.Stderr, "Following log files... Press Ctrl+C to stop and generate report.")
	}

	doneProcessing := make(chan struct{})
	go func() {
		for line := range t.LineChan() {
			a.ProcessLine(line.FilePath, line.Line, line.Time)
		}
		close(doneProcessing)
	}()

	if *follow {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nStopping...")
		t.Stop()
	}

	<-doneProcessing

	var reportContent string
	if formatLower == "json" {
		reportContent, err = report.GenerateJSON(a, since, until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate JSON report: %v\n", err)
			os.Exit(1)
		}
	} else {
		reportContent = report.Generate(a, since, until)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(reportContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write report: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *output)
	} else {
		fmt.Println(reportContent)
	}

	exitCode := checkAlertThresholds(a, cfg.AlertThresholds)
	os.Exit(exitCode)
}

func checkAlertThresholds(a *analyzer.Analyzer, thresholds config.AlertThresholds) int {
	if thresholds.Critical == 0 && thresholds.Error == 0 {
		return 0
	}

	counts := a.GetSeverityCounts()
	countMap := make(map[string]int)
	for _, sc := range counts {
		countMap[sc.Severity] = sc.Count
	}

	triggered := false

	if thresholds.Critical > 0 {
		criticalCount := countMap["critical"]
		if criticalCount >= thresholds.Critical {
			fmt.Fprintf(os.Stderr, "ALERT: critical threshold exceeded (%d/%d)\n", criticalCount, thresholds.Critical)
			triggered = true
		}
	}

	if thresholds.Error > 0 {
		errorCount := countMap["error"]
		if errorCount >= thresholds.Error {
			fmt.Fprintf(os.Stderr, "ALERT: error threshold exceeded (%d/%d)\n", errorCount, thresholds.Error)
			triggered = true
		}
	}

	if triggered {
		return 2
	}
	return 0
}
