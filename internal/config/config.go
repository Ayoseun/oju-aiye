package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AppConfig represents general application settings.
type AppConfig struct {
	Environment string `yaml:"environment"`
	LogLevel    string `yaml:"log_level"`
	// Profile is a free-form label shown in the console, for example "mac-local" or "remote-gpu".
	Profile  string `yaml:"profile"`
	HTTPPort int    `yaml:"http_port"`
}

// ResearchConfig defines operational limits for research runs.
type ResearchConfig struct {
	MaxConcurrentJobs               int  `yaml:"max_concurrent_jobs"`
	MaxHypothesesPerJob             int  `yaml:"max_hypotheses_per_job"`
	MaxIterationsPerHypothesis      int  `yaml:"max_iterations_per_hypothesis"`
	MaxAgentRetries                 int  `yaml:"max_agent_retries"`
	JobTimeoutSeconds               int  `yaml:"job_timeout_seconds"`
	RequireReviewerBeforeValidation bool `yaml:"require_reviewer_before_validation"`
}

func (r ResearchConfig) JobTimeout() time.Duration {
	return time.Duration(r.JobTimeoutSeconds) * time.Second
}

// ValidationConfig defines resource constraints for the isolated test runner.
type ValidationConfig struct {
	Enabled           bool   `yaml:"enabled"`
	NetworkAccess     string `yaml:"network_access"`
	MaxRuntimeSeconds int    `yaml:"max_runtime_seconds"`
	MaxMemoryMB       int    `yaml:"max_memory_mb"`
	MaxCPUSeconds     int    `yaml:"max_cpu_seconds"`
	MaxProcesses      int    `yaml:"max_processes"`
	MaxArtifactMB     int    `yaml:"max_artifact_mb"`
}

func (v ValidationConfig) MaxRuntime() time.Duration {
	return time.Duration(v.MaxRuntimeSeconds) * time.Second
}

// ModelRoleConfig specifies adapter settings for a specific role (scout/investigator/reviewer).
type ModelRoleConfig struct {
	Adapter         string  `yaml:"adapter"`
	ModelID         string  `yaml:"model_id"`
	BaseURL         string  `yaml:"base_url"`
	APIKeyEnv       string  `yaml:"api_key_env"`
	TimeoutSeconds  int     `yaml:"timeout_seconds"`
	MaxOutputTokens int     `yaml:"max_output_tokens"`
	Temperature     float64 `yaml:"temperature"`
	// Remote marks the endpoint as another machine even if it looks local (an SSH tunnel to a
	// GPU box appears as localhost). It only affects what the console tells you.
	Remote bool `yaml:"remote"`
	// AllowInsecureHTTP permits plain http to a non-local host. Only for private, trusted networks.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
}

func (m ModelRoleConfig) Timeout() time.Duration {
	if m.TimeoutSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(m.TimeoutSeconds) * time.Second
}

// GetAPIKey resolves the API key from the environment variable specified in APIKeyEnv.
func (m ModelRoleConfig) GetAPIKey() string {
	if m.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(m.APIKeyEnv)
}

// StorageConfig defines persistence and artifact settings.
type StorageConfig struct {
	PostgresDSNEnv    string `yaml:"postgres_dsn_env"`
	ArtifactBackend   string `yaml:"artifact_backend"`
	ArtifactDirectory string `yaml:"artifact_directory"`
}

func (s StorageConfig) GetPostgresDSN() string {
	if s.PostgresDSNEnv == "" {
		return os.Getenv("DATABASE_URL")
	}
	return os.Getenv(s.PostgresDSNEnv)
}

// Config represents the complete system configuration.
type Config struct {
	App        AppConfig                  `yaml:"app"`
	Research   ResearchConfig             `yaml:"research"`
	Validation ValidationConfig           `yaml:"validation"`
	Models     map[string]ModelRoleConfig `yaml:"models"`
	Storage    StorageConfig              `yaml:"storage"`
}

var envPattern = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)(?::-([^}]*))?\}`)

// expandEnv replaces ${VAR} and ${VAR:-default} with environment values.
// A variable that is unset (or empty) and has no default is reported as an
// error instead of silently expanding to an empty string.
func expandEnv(raw []byte) ([]byte, error) {
	var missing []string
	seen := map[string]bool{}
	out := envPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		sub := envPattern.FindSubmatch(match)
		name := string(sub[1])
		if v := os.Getenv(name); v != "" {
			return []byte(v)
		}
		if len(sub[2]) > 0 {
			return sub[2]
		}
		if !seen[name] {
			seen[name] = true
			missing = append(missing, name)
		}
		return nil
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("unset environment variables referenced in config (no default): %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// Load loads and parses a YAML configuration file with environment variable expansion.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	expanded, err := expandEnv(data)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		App: AppConfig{
			Environment: "development",
			LogLevel:    "info",
			HTTPPort:    8080,
		},
		Research: ResearchConfig{
			MaxConcurrentJobs:               1,
			MaxHypothesesPerJob:             20,
			MaxIterationsPerHypothesis:      4,
			MaxAgentRetries:                 2,
			JobTimeoutSeconds:               1800,
			RequireReviewerBeforeValidation: true,
		},
		Validation: ValidationConfig{
			Enabled:           true,
			NetworkAccess:     "disabled",
			MaxRuntimeSeconds: 120,
			MaxMemoryMB:       1024,
			MaxCPUSeconds:     60,
			MaxProcesses:      64,
			MaxArtifactMB:     100,
		},
		Storage: StorageConfig{
			ArtifactBackend:   "local",
			ArtifactDirectory: "./var/artifacts",
		},
	}

	if err := yaml.Unmarshal(expanded, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks essential constraints and required fields.
func (c *Config) Validate() error {
	if c.Research.MaxHypothesesPerJob <= 0 {
		return fmt.Errorf("research.max_hypotheses_per_job must be positive")
	}
	if c.Research.MaxIterationsPerHypothesis <= 0 {
		return fmt.Errorf("research.max_iterations_per_hypothesis must be positive")
	}

	requiredRoles := []string{"scout", "investigator", "reviewer"}
	for _, role := range requiredRoles {
		m, ok := c.Models[role]
		if !ok {
			return fmt.Errorf("missing required model role configuration: %s", role)
		}
		if m.Adapter == "" {
			return fmt.Errorf("model adapter for role %s cannot be empty", role)
		}
	}

	return c.validateEndpoints()
}
