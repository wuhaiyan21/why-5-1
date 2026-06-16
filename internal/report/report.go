package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"logalyzer/internal/analyzer"
)

type GroupDetail struct {
	Name       string
	Analyzer   *analyzer.Analyzer
	Since      time.Time
	Until      time.Time
	Err        error
	OutputDir  string
}

type SeverityCountJSON struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type TopRuleJSON struct {
	Rank        int    `json:"rank"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	UniqueCount int    `json:"unique_count"`
	TotalCount  int    `json:"total_count"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	Message     string `json:"message"`
}

type FileStatJSON struct {
	Path       string `json:"path"`
	TotalLines int    `json:"total_lines"`
}

type TimeRangeJSON struct {
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Since     string `json:"since_filter,omitempty"`
	Until     string `json:"until_filter,omitempty"`
	HasMatches bool  `json:"has_matches"`
}

type HourlyBucketJSON struct {
	Hour          string            `json:"hour"`
	SeverityCount map[string]int    `json:"severity_count"`
}

type ReportJSON struct {
	Title          string              `json:"title"`
	GeneratedAt    string              `json:"generated_at"`
	TimeRange      TimeRangeJSON       `json:"time_range"`
	SeverityCounts []SeverityCountJSON `json:"severity_counts"`
	TopRules       []TopRuleJSON       `json:"top_rules"`
	FileStats      []FileStatJSON      `json:"file_stats"`
	HourlyStats    []HourlyBucketJSON  `json:"hourly_stats"`
}

func Generate(a *analyzer.Analyzer, since, until time.Time) string {
	var sb strings.Builder

	sb.WriteString("# 日志聚合分析报告\n\n")

	sb.WriteString("## 时间范围\n\n")
	first, last := a.GetTimeRange()
	if !first.IsZero() {
		sb.WriteString(fmt.Sprintf("- 首次出现: %s\n", first.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("- 末次出现: %s\n", last.Format("2006-01-02 15:04:05")))
	} else {
		sb.WriteString("- 无匹配记录\n")
	}
	if !since.IsZero() {
		sb.WriteString(fmt.Sprintf("- 过滤起始 (--since): %s\n", since.Format("2006-01-02 15:04:05")))
	}
	if !until.IsZero() {
		sb.WriteString(fmt.Sprintf("- 过滤截止 (--until): %s\n", until.Format("2006-01-02 15:04:05")))
	}
	sb.WriteString("\n")

	sb.WriteString("## 各严重级别计数\n\n")
	sb.WriteString("| 严重级别 | 计数 (去重后) |\n")
	sb.WriteString("|----------|---------------|\n")
	severityCounts := a.GetSeverityCounts()
	if len(severityCounts) == 0 {
		sb.WriteString("| - | 0 |\n")
	} else {
		for _, sc := range severityCounts {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", sc.Severity, sc.Count))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## 命中规则 Top 10\n\n")
	sb.WriteString("| 排名 | 规则名称 | 严重级别 | 去重计数 | 总次数 | 首次出现 | 末次出现 |\n")
	sb.WriteString("|------|----------|----------|----------|--------|----------|----------|\n")
	topRules := a.GetTopRules(10)
	if len(topRules) == 0 {
		sb.WriteString("| - | - | - | 0 | 0 | - | - |\n")
	} else {
		for i, rule := range topRules {
			repeatNote := ""
			if rule.Count > rule.UniqueCount {
				repeatNote = fmt.Sprintf(" (重复%d次)", rule.Count)
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %d | %d | %s | %s |\n",
				i+1,
				rule.RuleName,
				rule.Severity,
				rule.UniqueCount,
				rule.Count,
				rule.FirstSeen.Format("2006-01-02 15:04:05"),
				rule.LastSeen.Format("2006-01-02 15:04:05"),
			))
			_ = repeatNote
		}
	}
	sb.WriteString("\n")

	sb.WriteString("### 消息详情 (含重复标记)\n\n")
	if len(topRules) == 0 {
		sb.WriteString("无匹配消息。\n")
	} else {
		for i, rule := range topRules {
			repeatInfo := ""
			if rule.Count > rule.UniqueCount {
				repeatInfo = fmt.Sprintf(" **[重复 %d 次，去重后计 %d 次]**", rule.Count, rule.UniqueCount)
			}
			sb.WriteString(fmt.Sprintf("%d. **%s** (%s)%s\n",
				i+1,
				rule.RuleName,
				rule.Severity,
				repeatInfo,
			))
			sb.WriteString(fmt.Sprintf("   - 消息: `%s`\n", truncate(rule.Message, 100)))
			sb.WriteString(fmt.Sprintf("   - 首次: %s\n", rule.FirstSeen.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("   - 末次: %s\n", rule.LastSeen.Format("2006-01-02 15:04:05")))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("## 各文件行数摘要\n\n")
	sb.WriteString("| 文件路径 | 总行数 |\n")
	sb.WriteString("|----------|--------|\n")
	fileStats := a.GetFileStats()
	if len(fileStats) == 0 {
		sb.WriteString("| - | 0 |\n")
	} else {
		for _, fs := range fileStats {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", fs.Path, fs.TotalLines))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## 按小时聚合统计\n\n")
	hourlyBuckets := a.GetHourlyBuckets()
	allSeverities := collectAllSeverities(severityCounts, hourlyBuckets)
	if len(hourlyBuckets) == 0 {
		sb.WriteString("无匹配记录，小时统计为空。\n")
	} else {
		sb.WriteString("| 小时桶 |")
		for _, sev := range allSeverities {
			sb.WriteString(fmt.Sprintf(" %s |", sev))
		}
		sb.WriteString(" 合计 |\n")
		sb.WriteString("|--------|")
		for range allSeverities {
			sb.WriteString("--------|")
		}
		sb.WriteString("------|\n")
		for _, bucket := range hourlyBuckets {
			sb.WriteString(fmt.Sprintf("| %s |", bucket.Hour))
			total := 0
			for _, sev := range allSeverities {
				cnt := bucket.SeverityCount[sev]
				total += cnt
				sb.WriteString(fmt.Sprintf(" %d |", cnt))
			}
			sb.WriteString(fmt.Sprintf(" %d |\n", total))
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

func GenerateJSON(a *analyzer.Analyzer, since, until time.Time) (string, error) {
	first, last := a.GetTimeRange()
	severityCounts := a.GetSeverityCounts()
	topRules := a.GetTopRules(10)
	fileStats := a.GetFileStats()
	hourlyBuckets := a.GetHourlyBuckets()

	tr := TimeRangeJSON{
		HasMatches: !first.IsZero(),
	}
	if !first.IsZero() {
		tr.FirstSeen = first.Format("2006-01-02 15:04:05")
		tr.LastSeen = last.Format("2006-01-02 15:04:05")
	}
	if !since.IsZero() {
		tr.Since = since.Format("2006-01-02 15:04:05")
	}
	if !until.IsZero() {
		tr.Until = until.Format("2006-01-02 15:04:05")
	}

	scJSON := make([]SeverityCountJSON, 0, len(severityCounts))
	for _, sc := range severityCounts {
		scJSON = append(scJSON, SeverityCountJSON{
			Severity: sc.Severity,
			Count:    sc.Count,
		})
	}

	trJSON := make([]TopRuleJSON, 0, len(topRules))
	for i, rule := range topRules {
		trJSON = append(trJSON, TopRuleJSON{
			Rank:        i + 1,
			RuleName:    rule.RuleName,
			Severity:    rule.Severity,
			UniqueCount: rule.UniqueCount,
			TotalCount:  rule.Count,
			FirstSeen:   rule.FirstSeen.Format("2006-01-02 15:04:05"),
			LastSeen:    rule.LastSeen.Format("2006-01-02 15:04:05"),
			Message:     rule.Message,
		})
	}

	fsJSON := make([]FileStatJSON, 0, len(fileStats))
	for _, fs := range fileStats {
		fsJSON = append(fsJSON, FileStatJSON{
			Path:       fs.Path,
			TotalLines: fs.TotalLines,
		})
	}

	hsJSON := make([]HourlyBucketJSON, 0, len(hourlyBuckets))
	for _, hb := range hourlyBuckets {
		hsJSON = append(hsJSON, HourlyBucketJSON{
			Hour:          hb.Hour,
			SeverityCount: hb.SeverityCount,
		})
	}

	report := ReportJSON{
		Title:          "日志聚合分析报告",
		GeneratedAt:    time.Now().Format("2006-01-02 15:04:05"),
		TimeRange:      tr,
		SeverityCounts: scJSON,
		TopRules:       trJSON,
		FileStats:      fsJSON,
		HourlyStats:    hsJSON,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON report: %w", err)
	}
	return string(data), nil
}

func collectAllSeverities(counts []analyzer.SeverityCount, buckets []analyzer.HourlyBucket) []string {
	set := make(map[string]struct{})
	for _, sc := range counts {
		set[sc.Severity] = struct{}{}
	}
	for _, b := range buckets {
		for sev := range b.SeverityCount {
			set[sev] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for sev := range set {
		result = append(result, sev)
	}
	severityOrder := map[string]int{
		"critical": 0,
		"error":    1,
		"warning":  2,
		"info":     3,
		"debug":    4,
	}
	sort.Slice(result, func(i, j int) bool {
		oi, oki := severityOrder[result[i]]
		oj, okj := severityOrder[result[j]]
		if oki && okj {
			return oi < oj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return result[i] < result[j]
	})
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

type BatchSummaryRow struct {
	Name         string
	Success      bool
	ErrorMsg     string
	Critical     int
	Error        int
	Warning      int
	Info         int
	Debug        int
	RuleHitCount int
	TimeStart    string
	TimeEnd      string
}

var CSVHeaders = []string{
	"name",
	"success",
	"error",
	"critical",
	"error_count",
	"warning",
	"info",
	"debug",
	"rule_hits",
	"time_start",
	"time_end",
}

var CSVHeaderDescriptions = map[string]string{
	"name":        "配置组名称标识",
	"success":     "扫描是否成功 (true/false)",
	"error":       "失败原因 (成功时为空)",
	"critical":    "critical级别去重计数",
	"error_count": "error级别去重计数",
	"warning":     "warning级别去重计数",
	"info":        "info级别去重计数",
	"debug":       "debug级别去重计数",
	"rule_hits":   "命中规则数量 (去重后不同规则数)",
	"time_start":  "日志时间范围起始 (首次匹配时间)",
	"time_end":    "日志时间范围结束 (末次匹配时间)",
}

func BuildSummaryRow(name string, a *analyzer.Analyzer, scanErr error) BatchSummaryRow {
	row := BatchSummaryRow{
		Name:    name,
		Success: scanErr == nil,
	}
	if scanErr != nil {
		row.ErrorMsg = scanErr.Error()
		return row
	}

	sevCounts := make(map[string]int)
	for _, sc := range a.GetSeverityCounts() {
		sevCounts[sc.Severity] = sc.Count
	}
	row.Critical = sevCounts["critical"]
	row.Error = sevCounts["error"]
	row.Warning = sevCounts["warning"]
	row.Info = sevCounts["info"]
	row.Debug = sevCounts["debug"]

	row.RuleHitCount = len(a.GetTopRules(1000000))

	first, last := a.GetTimeRange()
	if !first.IsZero() {
		row.TimeStart = first.Format("2006-01-02 15:04:05")
	}
	if !last.IsZero() {
		row.TimeEnd = last.Format("2006-01-02 15:04:05")
	}
	return row
}

func SortSummaryRows(rows []BatchSummaryRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Critical != rows[j].Critical {
			return rows[i].Critical > rows[j].Critical
		}
		return rows[i].Name < rows[j].Name
	})
}

func GenerateSummaryCSV(rows []BatchSummaryRow) (string, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)

	if err := w.Write(CSVHeaders); err != nil {
		return "", fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, r := range rows {
		record := []string{
			r.Name,
			fmt.Sprintf("%t", r.Success),
			r.ErrorMsg,
			fmt.Sprintf("%d", r.Critical),
			fmt.Sprintf("%d", r.Error),
			fmt.Sprintf("%d", r.Warning),
			fmt.Sprintf("%d", r.Info),
			fmt.Sprintf("%d", r.Debug),
			fmt.Sprintf("%d", r.RuleHitCount),
			r.TimeStart,
			r.TimeEnd,
		}
		if err := w.Write(record); err != nil {
			return "", fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("failed to flush CSV: %w", err)
	}
	return buf.String(), nil
}

func PrintCSVHeaderDescriptions() {
	fmt.Fprintln(os.Stderr, "=== 汇总对比表 CSV 列说明 ===")
	for _, h := range CSVHeaders {
		desc, ok := CSVHeaderDescriptions[h]
		if !ok {
			desc = "-"
		}
		fmt.Fprintf(os.Stderr, "  %-15s %s\n", h, desc)
	}
	fmt.Fprintln(os.Stderr, "==============================")
}

var severityColors = map[string]string{
	"critical": "#dc2626",
	"error":    "#ea580c",
	"warning":  "#d97706",
	"info":     "#2563eb",
	"debug":    "#6b7280",
}

func severityColor(sev string) string {
	if c, ok := severityColors[sev]; ok {
		return c
	}
	return "#6b7280"
}

func maxCount(rows []BatchSummaryRow, getCount func(BatchSummaryRow) int) int {
	max := 0
	for _, r := range rows {
		if c := getCount(r); c > max {
			max = c
		}
	}
	if max == 0 {
		max = 1
	}
	return max
}

func GenerateComparisonHTML(rows []BatchSummaryRow, details []GroupDetail) (string, error) {
	var sb strings.Builder

	detailMap := make(map[string]GroupDetail)
	for _, d := range details {
		detailMap[d.Name] = d
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>日志批量对比报告</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; background: #f3f4f6; color: #111827; line-height: 1.6; padding: 20px; }
  .container { max-width: 1400px; margin: 0 auto; }
  h1 { font-size: 28px; font-weight: 700; margin-bottom: 20px; color: #111827; }
  h2 { font-size: 20px; font-weight: 600; margin: 0 0 16px 0; color: #1f2937; }
  h3 { font-size: 16px; font-weight: 600; margin: 20px 0 12px 0; color: #374151; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; }
  .summary-table { width: 100%; border-collapse: collapse; font-size: 14px; }
  .summary-table th, .summary-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  .summary-table th { background: #f9fafb; font-weight: 600; color: #374151; position: sticky; top: 0; }
  .summary-table tr:hover { background: #f9fafb; }
  .success-badge { background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
  .failed-badge { background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
  .severity-bar { display: flex; gap: 2px; height: 20px; border-radius: 4px; overflow: hidden; background: #f3f4f6; }
  .severity-segment { height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-size: 11px; font-weight: 500; min-width: 0; transition: width 0.3s ease; }
  .bar-chart { display: flex; flex-direction: column; gap: 8px; }
  .bar-row { display: flex; align-items: center; gap: 12px; }
  .bar-label { width: 80px; font-size: 13px; color: #4b5563; font-weight: 500; }
  .bar-track { flex: 1; height: 24px; background: #f3f4f6; border-radius: 4px; overflow: hidden; position: relative; }
  .bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; display: flex; align-items: center; padding: 0 8px; color: white; font-size: 12px; font-weight: 500; }
  .bar-value { width: 50px; text-align: right; font-size: 13px; font-weight: 600; color: #374151; }
  .rules-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .rules-table th, .rules-table td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  .rules-table th { background: #f9fafb; font-weight: 600; color: #374151; }
  .sev-critical { color: #dc2626; font-weight: 600; }
  .sev-error { color: #ea580c; font-weight: 600; }
  .sev-warning { color: #d97706; font-weight: 600; }
  .sev-info { color: #2563eb; font-weight: 600; }
  .sev-debug { color: #6b7280; font-weight: 600; }
  .time-range { background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px 16px; border-radius: 4px; font-size: 14px; color: #1e40af; }
  .failed-group { background: #fef2f2; border-left: 4px solid #ef4444; padding: 20px; border-radius: 8px; }
  .failed-group h3 { color: #991b1b; margin-top: 0; }
  .failed-reason { font-family: "Consolas", "Monaco", monospace; background: #fee2e2; padding: 8px 12px; border-radius: 4px; font-size: 13px; color: #991b1b; word-break: break-all; }
  .group-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
  .group-header h2 { margin: 0; }
  .index-badge { background: #3b82f6; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 600; }
  .section-divider { height: 1px; background: #e5e7eb; margin: 20px 0; }
  .info-note { font-size: 13px; color: #6b7280; margin-top: 8px; }
  .generated-at { font-size: 12px; color: #9ca3af; text-align: right; margin-top: 20px; }
</style>
</head>
<body>
<div class="container">
  <h1>📊 日志批量对比报告</h1>
  <div class="generated-at">生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</div>
`)

	sb.WriteString(`
  <div class="card">
    <h2>📋 汇总对比表</h2>
    <table class="summary-table">
      <thead>
        <tr>
          <th>序号</th>
          <th>名称</th>
          <th>状态</th>
          <th>Critical</th>
          <th>Error</th>
          <th>Warning</th>
          <th>Info</th>
          <th>Debug</th>
          <th>规则命中</th>
          <th>时间范围</th>
        </tr>
      </thead>
      <tbody>
`)

	maxCritical := maxCount(rows, func(r BatchSummaryRow) int { return r.Critical })
	maxError := maxCount(rows, func(r BatchSummaryRow) int { return r.Error })
	maxWarning := maxCount(rows, func(r BatchSummaryRow) int { return r.Warning })
	maxInfo := maxCount(rows, func(r BatchSummaryRow) int { return r.Info })
	maxDebug := maxCount(rows, func(r BatchSummaryRow) int { return r.Debug })

	for i, row := range rows {
		statusBadge := `<span class="success-badge">成功</span>`
		if !row.Success {
			statusBadge = `<span class="failed-badge">失败</span>`
		}

		timeRange := "-"
		if row.TimeStart != "" && row.TimeEnd != "" {
			timeRange = row.TimeStart + "<br>~ " + row.TimeEnd
		}

		sb.WriteString(fmt.Sprintf(`
        <tr>
          <td>%d</td>
          <td><strong>%s</strong></td>
          <td>%s</td>
          <td class="sev-critical">%d</td>
          <td class="sev-error">%d</td>
          <td class="sev-warning">%d</td>
          <td class="sev-info">%d</td>
          <td class="sev-debug">%d</td>
          <td>%d</td>
          <td style="font-size:12px">%s</td>
        </tr>
`, i+1, row.Name, statusBadge, row.Critical, row.Error, row.Warning, row.Info, row.Debug, row.RuleHitCount, timeRange))
	}

	sb.WriteString(`
      </tbody>
    </table>
  </div>
`)

	for i, row := range rows {
		detail, ok := detailMap[row.Name]
		if !ok {
			continue
		}

		sb.WriteString(fmt.Sprintf(`
  <div class="card" id="group-%d">
    <div class="group-header">
      <span class="index-badge">%d</span>
      <h2>%s</h2>
      %s
    </div>
`, i+1, i+1, row.Name, map[bool]string{true: `<span class="success-badge">成功</span>`, false: `<span class="failed-badge">失败</span>`}[row.Success]))

		if !row.Success {
			sb.WriteString(fmt.Sprintf(`
    <div class="failed-group">
      <h3>❌ 扫描失败</h3>
      <p class="info-note">该组扫描过程中发生错误，以下为失败原因：</p>
      <div class="failed-reason">%v</div>
    </div>
`, detail.Err))
		} else {
			sb.WriteString(`
    <h3>📈 各级别计数对比</h3>
    <div class="bar-chart">
`)

			sevData := []struct {
				label string
				count int
				max   int
				color string
			}{
				{"Critical", row.Critical, maxCritical, severityColor("critical")},
				{"Error", row.Error, maxError, severityColor("error")},
				{"Warning", row.Warning, maxWarning, severityColor("warning")},
				{"Info", row.Info, maxInfo, severityColor("info")},
				{"Debug", row.Debug, maxDebug, severityColor("debug")},
			}

			for _, sd := range sevData {
				width := 0
				if sd.max > 0 {
					width = (sd.count * 100) / sd.max
				}
				if width == 0 && sd.count > 0 {
					width = 2
				}
				sb.WriteString(fmt.Sprintf(`
      <div class="bar-row">
        <span class="bar-label sev-%s">%s</span>
        <div class="bar-track">
          <div class="bar-fill" style="width: %d%%; background: %s;">%d</div>
        </div>
        <span class="bar-value">%d</span>
      </div>
`, strings.ToLower(sd.label), sd.label, width, sd.color, sd.count, sd.count))
			}

			sb.WriteString(`
    </div>

    <h3>🎯 命中规则 Top 5</h3>
`)

			topRules := detail.Analyzer.GetTopRules(5)
			if len(topRules) == 0 {
				sb.WriteString(`
    <p class="info-note">无命中规则。</p>
`)
			} else {
				sb.WriteString(`
    <table class="rules-table">
      <thead>
        <tr>
          <th>排名</th>
          <th>规则名称</th>
          <th>严重级别</th>
          <th>去重计数</th>
          <th>总次数</th>
          <th>消息</th>
        </tr>
      </thead>
      <tbody>
`)
				for j, rule := range topRules {
					sevClass := "sev-" + strings.ToLower(rule.Severity)
					sb.WriteString(fmt.Sprintf(`
        <tr>
          <td>%d</td>
          <td><strong>%s</strong></td>
          <td class="%s">%s</td>
          <td>%d</td>
          <td>%d</td>
          <td style="font-family: monospace; font-size: 12px; max-width: 400px;">%s</td>
        </tr>
`, j+1, rule.RuleName, sevClass, rule.Severity, rule.UniqueCount, rule.Count, truncate(rule.Message, 80)))
				}
				sb.WriteString(`
      </tbody>
    </table>
`)
			}

			sb.WriteString(`
    <h3>⏰ 时间范围</h3>
`)
			first, last := detail.Analyzer.GetTimeRange()
			timeInfo := ""
			if !first.IsZero() {
				timeInfo += fmt.Sprintf("<strong>首次出现:</strong> %s<br>", first.Format("2006-01-02 15:04:05"))
				timeInfo += fmt.Sprintf("<strong>末次出现:</strong> %s<br>", last.Format("2006-01-02 15:04:05"))
			} else {
				timeInfo += "无匹配记录<br>"
			}
			if !detail.Since.IsZero() {
				timeInfo += fmt.Sprintf("<strong>过滤起始:</strong> %s<br>", detail.Since.Format("2006-01-02 15:04:05"))
			}
			if !detail.Until.IsZero() {
				timeInfo += fmt.Sprintf("<strong>过滤截止:</strong> %s<br>", detail.Until.Format("2006-01-02 15:04:05"))
			}
			sb.WriteString(fmt.Sprintf(`
    <div class="time-range">
      %s
    </div>
`, timeInfo))
		}

		sb.WriteString(`
  </div>
`)
	}

	sb.WriteString(`
  <div class="generated-at">
    报告生成完毕 | 共 ` + fmt.Sprintf("%d", len(rows)) + ` 组
  </div>
</div>
</body>
</html>
`)

	return sb.String(), nil
}
