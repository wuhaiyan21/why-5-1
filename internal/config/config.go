package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
	Priority int    `yaml:"priority"`
	Regex    *regexp.Regexp
}

type AlertThresholds struct {
	Critical int `yaml:"critical"`
	Error    int `yaml:"error"`
}

type Config struct {
	LogDir          string          `yaml:"log_dir"`
	LogFiles        []string        `yaml:"log_files"`
	Rules           []Rule          `yaml:"rules"`
	DedupeWindow    int             `yaml:"dedupe_window_minutes"`
	AlertThresholds AlertThresholds `yaml:"alert_thresholds"`
}

type BatchEntry struct {
	Name     string `yaml:"name"`
	LogDir   string `yaml:"log_dir"`
	Config   string `yaml:"config,omitempty"`
	Since    string `yaml:"since,omitempty"`
	Until    string `yaml:"until,omitempty"`
	LogFiles []string `yaml:"log_files,omitempty"`
}

type BatchConfig struct {
	BaseConfig string      `yaml:"base_config"`
	Entries    []BatchEntry `yaml:"entries"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.DedupeWindow == 0 {
		cfg.DedupeWindow = 5
	}

	for i := range cfg.Rules {
		re, err := regexp.Compile(cfg.Rules[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in rule %q: %w", cfg.Rules[i].Name, err)
		}
		cfg.Rules[i].Regex = re
	}

	return &cfg, nil
}

func LoadBatch(path string) (*BatchConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch config file: %w", err)
	}

	var bc BatchConfig
	if err := yaml.Unmarshal(data, &bc); err != nil {
		return nil, fmt.Errorf("failed to parse batch config file: %w", err)
	}

	if len(bc.Entries) == 0 {
		return nil, fmt.Errorf("batch config has no entries")
	}

	seen := make(map[string]struct{})
	for i, e := range bc.Entries {
		if e.Name == "" {
			return nil, fmt.Errorf("batch entry %d has empty name", i)
		}
		if e.LogDir == "" {
			return nil, fmt.Errorf("batch entry %q has empty log_dir", e.Name)
		}
		if _, dup := seen[e.Name]; dup {
			return nil, fmt.Errorf("duplicate batch entry name: %q", e.Name)
		}
		seen[e.Name] = struct{}{}
	}

	return &bc, nil
}

func (e BatchEntry) ParseTimeRange() (since, until time.Time, err error) {
	if e.Since != "" {
		since, err = time.Parse("2006-01-02T15:04:05", e.Since)
		if err != nil {
			err = fmt.Errorf("invalid since format for %q: %w", e.Name, err)
			return
		}
	}
	if e.Until != "" {
		until, err = time.Parse("2006-01-02T15:04:05", e.Until)
		if err != nil {
			err = fmt.Errorf("invalid until format for %q: %w", e.Name, err)
			return
		}
	}
	return
}
