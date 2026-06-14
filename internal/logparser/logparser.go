package logparser

import (
	"regexp"
	"time"
)

type ParsedLine struct {
	Time    time.Time
	Message string
	HasTime bool
}

var timePatterns = []struct {
	regex   *regexp.Regexp
	format  string
	trimLen int
}{
	{
		regex:   regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})`),
		format:  "2006-01-02 15:04:05",
		trimLen: 19,
	},
	{
		regex:   regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)`),
		format:  "2006-01-02T15:04:05.000",
		trimLen: 0,
	},
	{
		regex:   regexp.MustCompile(`^\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]`),
		format:  "02/Jan/2006:15:04:05 -0700",
		trimLen: 0,
	},
	{
		regex:   regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})`),
		format:  "Jan  2 15:04:05",
		trimLen: 0,
	},
}

func ParseLine(line string) ParsedLine {
	for _, tp := range timePatterns {
		match := tp.regex.FindStringSubmatch(line)
		if len(match) >= 2 {
			timeStr := match[1]
			if tp.trimLen > 0 {
				timeStr = timeStr[:tp.trimLen]
			}
			
			format := tp.format
			if len(match[0]) > 10 && match[0][10] == 'T' {
				format = "2006-01-02T15:04:05"
			}

			t, err := time.Parse(format, timeStr)
			if err == nil {
				message := line[len(match[0]):]
				if len(message) > 0 && message[0] == ' ' {
					message = message[1:]
				}
				return ParsedLine{
					Time:    t,
					Message: message,
					HasTime: true,
				}
			}
		}
	}

	return ParsedLine{
		Time:    time.Now(),
		Message: line,
		HasTime: false,
	}
}
