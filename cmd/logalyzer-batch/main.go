package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"logalyzer/internal/batch"
	"logalyzer/internal/config"
	"logalyzer/internal/report"
)

func main() {
	batchConfig := flag.String("batch-config", "batch-config.yaml", "Path to batch config YAML file")
	outputDir := flag.String("output", "./batch-results", "Output parent directory for batch results")
	baseConfig := flag.String("config", "config.yaml", "Path to base config YAML file (used when entry has no override)")
	pollInterval := flag.Duration("poll-interval", 500*time.Millisecond, "Polling interval for log files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: logalyzer-batch [options]\n\n")
		fmt.Fprintf(os.Stderr, "批量日志对比扫描工具：按顺序对多组日志目录执行离线扫描，并生成汇总对比表。\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n输出结构:\n")
		fmt.Fprintf(os.Stderr, "  <output>/\n")
		fmt.Fprintf(os.Stderr, "    summary.csv          汇总对比表 (CSV)\n")
		fmt.Fprintf(os.Stderr, "    <entry-name-1>/\n")
		fmt.Fprintf(os.Stderr, "      report.json        该组的 JSON 摘要报告\n")
		fmt.Fprintf(os.Stderr, "      report.md          该组的 Markdown 报告\n")
		fmt.Fprintf(os.Stderr, "    <entry-name-2>/\n")
		fmt.Fprintf(os.Stderr, "      report.json\n")
		fmt.Fprintf(os.Stderr, "      report.md\n")
		fmt.Fprintf(os.Stderr, "    ...\n")
	}
	flag.Parse()

	bc, err := config.LoadBatch(*batchConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load batch config: %v\n", err)
		os.Exit(1)
	}

	report.PrintCSVHeaderDescriptions()
	fmt.Fprintf(os.Stderr, "\n开始批量扫描，共 %d 组...\n", len(bc.Entries))

	rows, err := batch.RunBatch(bc, *baseConfig, *outputDir, *pollInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batch scan completed with errors: %v\n", err)
	}

	successCount := 0
	for _, r := range rows {
		if r.Success {
			successCount++
		}
	}
	fmt.Fprintf(os.Stderr, "\n批量扫描完成: %d/%d 组成功\n", successCount, len(rows))

	if err != nil {
		os.Exit(1)
	}
}
