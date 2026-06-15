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
