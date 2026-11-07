package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	content := `
app:
  environment: test
  log_level: debug
  http_port: 9090

research:
  max_concurrent_jobs: 2
  max_hypotheses_per_job: 10
  max_iterations_per_hypothesis: 3
  max_agent_retries: 1
  job_timeout_seconds: 600
  require_reviewer_before_validation: true

validation:
  enabled: true
  network_access: disabled
  max_runtime_seconds: 60
  max_memory_mb: 512
  max_cpu_seconds: 30
  max_processes: 32
  max_artifact_mb: 50

models:
  scout:
    adapter: fake
    model_id: test-scout-model
    base_url: http://localhost:11434
    api_key_env: TEST_API_KEY
    timeout_seconds: 30
    max_output_tokens: 1000
    temperature: 0.2
  investigator:
    adapter: fake
    model_id: test-investigator-model
    base_url: http://localhost:11434
    api_key_env: TEST_API_KEY
    timeout_seconds: 60
    max_output_tokens: 2000
    temperature: 0.1
  reviewer:
    adapter: fake
    model_id: test-reviewer-model
    base_url: http://localhost:11434
    api_key_env: TEST_API_KEY
    timeout_seconds: 60
    max_output_tokens: 1500
    temperature: 0.1

storage:
  postgres_dsn_env: TEST_DB_URL
  artifact_backend: local
  artifact_directory: /tmp/artifacts
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	t.Setenv("TEST_API_KEY", "secret-test-key")
	t.Setenv("TEST_DB_URL", "postgres://localhost/testdb")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}

	if cfg.App.Environment != "test" {
		t.Errorf("expected environment 'test', got '%s'", cfg.App.Environment)
	}
	if cfg.Research.MaxHypothesesPerJob != 10 {
		t.Errorf("expected MaxHypothesesPerJob 10, got %d", cfg.Research.MaxHypothesesPerJob)
	}

	scoutModel := cfg.Models["scout"]
	if scoutModel.GetAPIKey() != "secret-test-key" {
		t.Errorf("expected API key 'secret-test-key', got '%s'", scoutModel.GetAPIKey())
	}
	if cfg.Storage.GetPostgresDSN() != "postgres://localhost/testdb" {
		t.Errorf("expected DSN 'postgres://localhost/testdb', got '%s'", cfg.Storage.GetPostgresDSN())
	}
}

func TestMissingModelRoleFails(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.yaml")

	content := `
models:
  scout:
    adapter: fake
    model_id: test-scout
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("expected error for missing model roles, got nil")
	}
}

func TestExpandEnvDefaultsAndMissing(t *testing.T) {
	t.Setenv("PRESENT_VAR", "set")
	out, err := expandEnv([]byte("a=${PRESENT_VAR} b=${ABSENT_WITH_DEFAULT:-fallback}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "a=set b=fallback" {
		t.Fatalf("unexpected expansion: %q", out)
	}

	_, err = expandEnv([]byte("x=${ABSENT_NO_DEFAULT_ONE} y=${ABSENT_NO_DEFAULT_TWO}"))
	if err == nil {
		t.Fatal("expected error for unset variables without defaults")
	}
	for _, name := range []string{"ABSENT_NO_DEFAULT_ONE", "ABSENT_NO_DEFAULT_TWO"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error should name %s: %v", name, err)
		}
	}
}
