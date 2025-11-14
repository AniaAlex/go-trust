// Package config provides configuration management for the Go-Trust application.
// It supports loading configuration from YAML files and environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SUNET/go-trust/pkg/validation"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration structure.
// It includes settings for the server, logging, pipeline processing, and security.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Pipeline PipelineConfig `yaml:"pipeline"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig contains HTTP server configuration settings.
type ServerConfig struct {
	Host        string        `yaml:"host"`
	Port        string        `yaml:"port"`
	Frequency   time.Duration `yaml:"frequency"`
	ExternalURL string        `yaml:"external_url"` // External URL for PDP discovery (e.g., https://pdp.example.com)
	TLS         TLSConfig     `yaml:"tls"`
}

// TLSConfig contains TLS/HTTPS server configuration settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`  // Enable TLS/HTTPS
	CertFile string `yaml:"cert_file"` // Path to TLS certificate file
	KeyFile  string `yaml:"key_file"`  // Path to TLS private key file
}

// LoggingConfig contains logging configuration settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// PipelineConfig contains pipeline processing configuration settings.
type PipelineConfig struct {
	Timeout        time.Duration `yaml:"timeout"`
	MaxRequestSize int64         `yaml:"max_request_size"`
	MaxRedirects   int           `yaml:"max_redirects"`
	AllowedHosts   []string      `yaml:"allowed_hosts"`
}

// SecurityConfig contains security-related configuration settings.
type SecurityConfig struct {
	RateLimitRPS   int      `yaml:"rate_limit_rps"`
	EnableCORS     bool     `yaml:"enable_cors"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:      "127.0.0.1",
			Port:      "6001",
			Frequency: 5 * time.Minute,
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "",
				KeyFile:  "",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Pipeline: PipelineConfig{
			Timeout:        30 * time.Second,
			MaxRequestSize: 10 * 1024 * 1024, // 10MB
			MaxRedirects:   3,
			AllowedHosts:   []string{},
		},
		Security: SecurityConfig{
			RateLimitRPS:   100,
			EnableCORS:     false,
			AllowedOrigins: []string{},
		},
	}
}

// LoadConfig loads configuration from a YAML file and applies environment variable overrides.
// It returns the merged configuration or an error if loading fails.
//
// Environment variables override configuration file values using the GT_ prefix:
//   - GT_HOST, GT_PORT, GT_FREQUENCY for server settings
//   - GT_LOG_LEVEL, GT_LOG_FORMAT, GT_LOG_OUTPUT for logging
//   - GT_RATE_LIMIT_RPS for security settings
//
// If configPath is empty, only default values and environment variables are used.
func LoadConfig(configPath string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Load from file if path provided
	if configPath != "" {
		// Validate config path before loading
		if err := validation.ValidateConfigPath(configPath); err != nil {
			return nil, fmt.Errorf("invalid config path: %w", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Apply environment variable overrides
	applyEnvOverrides(cfg)

	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration.
// Environment variables take precedence over config file values.
func applyEnvOverrides(cfg *Config) {
	// Server configuration
	if v := os.Getenv("GT_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GT_PORT"); v != "" {
		cfg.Server.Port = v
	}
	if v := os.Getenv("GT_FREQUENCY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.Frequency = d
		}
	}
	if v := os.Getenv("GT_EXTERNAL_URL"); v != "" {
		cfg.Server.ExternalURL = v
	}

	// TLS configuration
	if v := os.Getenv("GT_TLS_ENABLED"); v != "" {
		cfg.Server.TLS.Enabled = strings.ToLower(v) == "true" || v == "1"
	}
	if v := os.Getenv("GT_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLS.CertFile = v
	}
	if v := os.Getenv("GT_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLS.KeyFile = v
	}

	// Logging configuration
	if v := os.Getenv("GT_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("GT_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("GT_LOG_OUTPUT"); v != "" {
		cfg.Logging.Output = v
	}

	// Pipeline configuration
	if v := os.Getenv("GT_PIPELINE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Pipeline.Timeout = d
		}
	}
	if v := os.Getenv("GT_MAX_REQUEST_SIZE"); v != "" {
		if size, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.Pipeline.MaxRequestSize = size
		}
	}
	if v := os.Getenv("GT_MAX_REDIRECTS"); v != "" {
		if redirects, err := strconv.Atoi(v); err == nil {
			cfg.Pipeline.MaxRedirects = redirects
		}
	}
	if v := os.Getenv("GT_ALLOWED_HOSTS"); v != "" {
		cfg.Pipeline.AllowedHosts = strings.Split(v, ",")
	}

	// Security configuration
	if v := os.Getenv("GT_RATE_LIMIT_RPS"); v != "" {
		if rps, err := strconv.Atoi(v); err == nil {
			cfg.Security.RateLimitRPS = rps
		}
	}
	if v := os.Getenv("GT_ENABLE_CORS"); v != "" {
		cfg.Security.EnableCORS = strings.ToLower(v) == "true" || v == "1"
	}
	if v := os.Getenv("GT_ALLOWED_ORIGINS"); v != "" {
		cfg.Security.AllowedOrigins = strings.Split(v, ",")
	}
}

// Validate checks if the configuration is valid.
// It returns an error if any configuration value is invalid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port == "" {
		return fmt.Errorf("server port cannot be empty")
	}
	if c.Server.Frequency <= 0 {
		return fmt.Errorf("server frequency must be positive")
	}

	// Validate TLS configuration
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("TLS certificate file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}
		// Check if certificate and key files exist
		if err := validation.ValidateFilePath(c.Server.TLS.CertFile); err != nil {
			return fmt.Errorf("invalid TLS certificate file: %w", err)
		}
		if err := validation.ValidateFilePath(c.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("invalid TLS key file: %w", err)
		}
	}

	// Validate logging configuration
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true, "fatal": true}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	validFormats := map[string]bool{"text": true, "json": true}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	// Validate pipeline configuration
	if c.Pipeline.Timeout <= 0 {
		return fmt.Errorf("pipeline timeout must be positive")
	}
	if c.Pipeline.MaxRequestSize <= 0 {
		return fmt.Errorf("max request size must be positive")
	}
	if c.Pipeline.MaxRedirects < 0 {
		return fmt.Errorf("max redirects cannot be negative")
	}

	// Validate security configuration
	if c.Security.RateLimitRPS <= 0 {
		return fmt.Errorf("rate limit RPS must be positive")
	}

	return nil
}
