package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
	Regex    *regexp.Regexp
}

type Config struct {
	LogDir       string `yaml:"log_dir"`
	LogFiles     []string `yaml:"log_files"`
	Rules        []Rule `yaml:"rules"`
	DedupeWindow int    `yaml:"dedupe_window_minutes"`
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
