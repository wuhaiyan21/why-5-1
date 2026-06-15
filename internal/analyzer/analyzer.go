package analyzer

import (
	"sort"
	"sync"
	"time"

	"logalyzer/internal/config"
	"logalyzer/internal/logparser"
)

type RuleMatch struct {
	RuleName    string
	Severity    string
	Message     string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	UniqueCount int
}

type FileStats struct {
	Path       string
	TotalLines int
}

type HourlyBucket struct {
	Hour          string
	SeverityCount map[string]int
}

type Analyzer struct {
	cfg           *config.Config
	rules         []config.Rule
	dedupeWindow  time.Duration
	since         time.Time
	until         time.Time

	mu            sync.Mutex
	severityCount map[string]int
	ruleMatches   map[string]*RuleMatch
	fileStats     map[string]*FileStats
	hourlyBuckets map[string]map[string]int

	dedupeCache   map[string][]time.Time
}

func New(cfg *config.Config, since, until time.Time) *Analyzer {
	dedupeWindow := time.Duration(cfg.DedupeWindow) * time.Minute
	if dedupeWindow == 0 {
		dedupeWindow = 5 * time.Minute
	}

	rules := make([]config.Rule, len(cfg.Rules))
	copy(rules, cfg.Rules)
	for i := range rules {
		if rules[i].Priority == 0 {
			rules[i].Priority = len(cfg.Rules) - i
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	return &Analyzer{
		cfg:           cfg,
		rules:         rules,
		dedupeWindow:  dedupeWindow,
		since:         since,
		until:         until,
		severityCount: make(map[string]int),
		ruleMatches:   make(map[string]*RuleMatch),
		fileStats:     make(map[string]*FileStats),
		hourlyBuckets: make(map[string]map[string]int),
		dedupeCache:   make(map[string][]time.Time),
	}
}

func (a *Analyzer) ProcessLine(filePath string, line string, receiveTime time.Time) {
	parsed := logparser.ParseLine(line)
	logTime := parsed.Time
	if !parsed.HasTime {
		logTime = receiveTime
	}

	if !a.since.IsZero() && logTime.Before(a.since) {
		return
	}
	if !a.until.IsZero() && logTime.After(a.until) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.fileStats[filePath]; !ok {
		a.fileStats[filePath] = &FileStats{Path: filePath}
	}
	a.fileStats[filePath].TotalLines++

	for _, rule := range a.rules {
		if rule.Regex.MatchString(line) {
			a.countMatch(rule, parsed.Message, logTime)
			break
		}
	}
}

func (a *Analyzer) countMatch(rule config.Rule, message string, t time.Time) {
	key := rule.Name + "||" + message

	isDuplicate := a.checkDuplicate(key, t)

	match, ok := a.ruleMatches[key]
	if !ok {
		match = &RuleMatch{
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Message:     message,
			FirstSeen:   t,
			LastSeen:    t,
			Count:       1,
			UniqueCount: 1,
		}
		a.ruleMatches[key] = match
		a.severityCount[rule.Severity]++
		a.countHourly(rule.Severity, t, 1)
	} else {
		match.Count++
		if t.Before(match.FirstSeen) {
			match.FirstSeen = t
		}
		if t.After(match.LastSeen) {
			match.LastSeen = t
		}
		if !isDuplicate {
			match.UniqueCount++
			a.severityCount[rule.Severity]++
			a.countHourly(rule.Severity, t, 1)
		}
	}
}

func (a *Analyzer) countHourly(severity string, t time.Time, delta int) {
	hourKey := t.Format("2006-01-02 15:00")
	bucket, ok := a.hourlyBuckets[hourKey]
	if !ok {
		bucket = make(map[string]int)
		a.hourlyBuckets[hourKey] = bucket
	}
	bucket[severity] += delta
}

func (a *Analyzer) checkDuplicate(key string, t time.Time) bool {
	times, ok := a.dedupeCache[key]
	if !ok {
		a.dedupeCache[key] = []time.Time{t}
		return false
	}

	cutoff := t.Add(-a.dedupeWindow)
	valid := make([]time.Time, 0, len(times))
	for _, prev := range times {
		if prev.After(cutoff) {
			valid = append(valid, prev)
		}
	}

	isDuplicate := len(valid) > 0
	a.dedupeCache[key] = append(valid, t)

	if len(a.dedupeCache[key]) > 1000 {
		a.dedupeCache[key] = a.dedupeCache[key][len(a.dedupeCache[key])-500:]
	}

	return isDuplicate
}

type SeverityCount struct {
	Severity string
	Count    int
}

func (a *Analyzer) GetSeverityCounts() []SeverityCount {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make([]SeverityCount, 0, len(a.severityCount))
	for sev, count := range a.severityCount {
		result = append(result, SeverityCount{Severity: sev, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result
}

func (a *Analyzer) GetTopRules(topN int) []RuleMatch {
	a.mu.Lock()
	defer a.mu.Unlock()

	matches := make([]RuleMatch, 0, len(a.ruleMatches))
	for _, m := range a.ruleMatches {
		matches = append(matches, *m)
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].UniqueCount > matches[j].UniqueCount
	})

	if topN > len(matches) {
		topN = len(matches)
	}

	return matches[:topN]
}

func (a *Analyzer) GetFileStats() []FileStats {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make([]FileStats, 0, len(a.fileStats))
	for _, fs := range a.fileStats {
		result = append(result, *fs)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalLines > result[j].TotalLines
	})

	return result
}

func (a *Analyzer) GetTimeRange() (first, last time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	firstSet := false
	for _, m := range a.ruleMatches {
		if !firstSet || m.FirstSeen.Before(first) {
			first = m.FirstSeen
			firstSet = true
		}
		if m.LastSeen.After(last) {
			last = m.LastSeen
		}
	}
	return
}

func (a *Analyzer) GetHourlyBuckets() []HourlyBucket {
	a.mu.Lock()
	defer a.mu.Unlock()

	hours := make([]string, 0, len(a.hourlyBuckets))
	for h := range a.hourlyBuckets {
		hours = append(hours, h)
	}
	sort.Strings(hours)

	result := make([]HourlyBucket, 0, len(hours))
	for _, h := range hours {
		sevMap := a.hourlyBuckets[h]
		sevCopy := make(map[string]int, len(sevMap))
		for k, v := range sevMap {
			sevCopy[k] = v
		}
		result = append(result, HourlyBucket{
			Hour:          h,
			SeverityCount: sevCopy,
		})
	}
	return result
}
