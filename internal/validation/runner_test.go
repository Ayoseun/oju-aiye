package validation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/config"
	"vuln-research/internal/domain"
)

func TestValidationRunnerCleanPass(t *testing.T) {
	tempDir := t.TempDir()
	runner := NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 10,
	}, tempDir)

	hypID := uuid.New()
	req := ExecutionRequest{
		HypothesisID: hypID,
		Command:      "echo",
		Args:         []string{"assertion passed"},
		Timeout:      2 * time.Second,
	}

	res, err := runner.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	if res.Outcome != domain.ValidationOutcomeRefuted {
		t.Errorf("expected clean pass outcome 'refuted', got '%s'", res.Outcome)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
}

func TestValidationRunnerInvariantFailure(t *testing.T) {
	tempDir := t.TempDir()
	runner := NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 10,
	}, tempDir)

	hypID := uuid.New()
	// Simulate a test assertion failure via non-zero exit code
	req := ExecutionRequest{
		HypothesisID: hypID,
		Command:      "sh",
		Args:         []string{"-c", "echo 'AssertionFailed: balance < 0' >&2; exit 1"},
		Timeout:      2 * time.Second,
	}

	res, err := runner.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	if res.Outcome != domain.ValidationOutcomeReproduced {
		t.Errorf("expected reproduced outcome, got '%s'", res.Outcome)
	}
	if res.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", res.ExitCode)
	}
}

func TestValidationRunnerSetupFailure(t *testing.T) {
	tempDir := t.TempDir()
	runner := NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 10,
	}, tempDir)

	hypID := uuid.New()
	req := ExecutionRequest{
		HypothesisID: hypID,
		Command:      "sh",
		Args:         []string{"-c", "echo 'error: package not found' >&2; exit 1"},
		Timeout:      2 * time.Second,
	}

	res, err := runner.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	if res.Outcome != domain.ValidationOutcomeSetupFailed {
		t.Errorf("expected setup_failed outcome, got '%s'", res.Outcome)
	}
}

func TestValidationRunnerTimeoutEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	runner := NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 2,
	}, tempDir)

	hypID := uuid.New()
	// Command sleeps longer than timeout
	req := ExecutionRequest{
		HypothesisID: hypID,
		Command:      "sleep",
		Args:         []string{"10"},
		Timeout:      1 * time.Second,
	}

	res, err := runner.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	if res.Outcome != domain.ValidationOutcomeInconclusive {
		t.Errorf("expected inconclusive outcome for timeout, got '%s'", res.Outcome)
	}
}
