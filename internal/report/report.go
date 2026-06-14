package report

import (
	"fmt"
	"strings"
	"time"

	"logalyzer/internal/analyzer"
)

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

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
