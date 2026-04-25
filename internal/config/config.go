package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	CA        CAConfig        `yaml:"ca"`
	DNS       DNSConfig       `yaml:"dns"`
	Secrets   []SecretConfig  `yaml:"secrets"`
	Policies  []PolicyRule    `yaml:"policies"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

type ServerConfig struct {
	Listen       string `yaml:"listen"`
	HealthListen string `yaml:"health_listen"`
}

type CAConfig struct {
	Auto       bool   `yaml:"auto"`
	CertOutput string `yaml:"cert_output"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
}

type DNSConfig struct {
	Servers         []string    `yaml:"servers"`
	DoT             DoTConfig   `yaml:"dot"`
	Cache           CacheConfig `yaml:"cache"`
	DenyResolvedIPs []string    `yaml:"deny_resolved_ips"`
}

type DoTConfig struct {
	Enabled bool   `yaml:"enabled"`
	Server  string `yaml:"server"`
}

type CacheConfig struct {
	Enabled bool `yaml:"enabled"`
	MaxTTL  int  `yaml:"max_ttl"`
}

type SecretConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type PolicyRule struct {
	Name    string        `yaml:"name"`
	Host    string        `yaml:"host"`
	Path    string        `yaml:"path"`
	Methods []string      `yaml:"methods"`
	Action  string        `yaml:"action"`
	Inject  *InjectConfig `yaml:"inject,omitempty"`
}

type InjectConfig struct {
	Headers map[string]string `yaml:"headers"`
	Query   map[string]string `yaml:"query"`
}

type TelemetryConfig struct {
	Logs    LogsConfig    `yaml:"logs"`
	Traces  TracesConfig  `yaml:"traces"`
	Metrics MetricsConfig `yaml:"metrics"`
}

type LogsConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type TracesConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

type MetricsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "0.0.0.0:8080"
	}
	if c.Server.HealthListen == "" {
		c.Server.HealthListen = "0.0.0.0:9090"
	}
	if c.Telemetry.Logs.Level == "" {
		c.Telemetry.Logs.Level = "info"
	}
	if c.Telemetry.Logs.Format == "" {
		c.Telemetry.Logs.Format = "json"
	}
	if c.DNS.Cache.MaxTTL == 0 {
		c.DNS.Cache.MaxTTL = 300
	}
	for i := range c.Policies {
		if c.Policies[i].Path == "" {
			c.Policies[i].Path = "/**"
		}
	}
}

func (c *Config) Validate() error {
	seen := make(map[string]bool)
	for i, p := range c.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy %d: name is required", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("policy %q: duplicate name", p.Name)
		}
		seen[p.Name] = true
		if p.Host == "" {
			return fmt.Errorf("policy %q: host is required", p.Name)
		}
		if p.Action == "" {
			return fmt.Errorf("policy %q: action is required", p.Name)
		}
		action := strings.ToLower(p.Action)
		if action != "allow" && action != "deny" {
			return fmt.Errorf("policy %q: action must be 'allow' or 'deny', got %q", p.Name, p.Action)
		}
		if action == "deny" && p.Inject != nil {
			return fmt.Errorf("policy %q: deny rules cannot have inject", p.Name)
		}
		for _, m := range p.Methods {
			if m != strings.ToUpper(m) {
				return fmt.Errorf("policy %q: method %q should be uppercase", p.Name, m)
			}
		}
	}
	for _, s := range c.Secrets {
		switch s.Type {
		case "env", "file":
		default:
			return fmt.Errorf("secret source type %q not supported (use 'env' or 'file')", s.Type)
		}
		if s.Type == "file" && s.Path == "" {
			return fmt.Errorf("secret source 'file' requires path")
		}
	}
	for _, cidr := range c.DNS.DenyResolvedIPs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid CIDR in deny_resolved_ips: %q: %w", cidr, err)
		}
	}
	return nil
}
