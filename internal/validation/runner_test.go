package validation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
		Timeout:      10 * time.Second,
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
		HypothesisID:     hypID,
		Command:          "sh",
		Args:             []string{"-c", "echo 'AssertionFailed: balance < 0' >&2; exit 1"},
		Timeout:          10 * time.Second,
		FailureSignature: "AssertionFailed: balance < 0",
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
		Timeout:      10 * time.Second,
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

func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	return NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 10,
	}, t.TempDir())
}

// A missing tool (exit 127) must be a setup failure, never a "reproduced" finding.
func TestValidationRunnerMissingToolIsSetupFailure(t *testing.T) {
	res, err := newTestRunner(t).Execute(context.Background(), ExecutionRequest{
		HypothesisID: uuid.New(),
		Command:      "sh",
		Args:         []string{"-c", "definitely-not-a-real-binary-xyz"},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != domain.ValidationOutcomeSetupFailed {
		t.Fatalf("expected setup_failed for exit %d, got %s", res.ExitCode, res.Outcome)
	}
}

// Host secrets must not leak into model-generated test commands.
func TestValidationRunnerScrubsEnvironment(t *testing.T) {
	t.Setenv("OJU_TEST_SECRET", "hunter2")
	res, err := newTestRunner(t).Execute(context.Background(), ExecutionRequest{
		HypothesisID: uuid.New(),
		Command:      "sh",
		Args:         []string{"-c", `[ -z "$OJU_TEST_SECRET" ]`},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("host secret leaked into sandbox (exit %d, outcome %s)", res.ExitCode, res.Outcome)
	}
}

// Tests run against a copy of the source: the original tree is never modified,
// and .git is not copied.
func TestValidationRunnerStagesSourceCopy(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "vault.sol"), []byte("contract V{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".git", "config"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := newTestRunner(t).Execute(context.Background(), ExecutionRequest{
		HypothesisID: uuid.New(),
		SourceDir:    src,
		Command:      "sh",
		Args:         []string{"-c", "test -f vault.sol && test ! -e .git && touch mutated"},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("command should see vault.sol and no .git in the staged copy (exit %d)", res.ExitCode)
	}
	if _, statErr := os.Stat(filepath.Join(src, "mutated")); statErr == nil {
		t.Fatal("test modified the original source tree")
	}
}

// A child that keeps the output pipes open must not hang the runner past the timeout.
func TestValidationRunnerTimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	res, err := newTestRunner(t).Execute(context.Background(), ExecutionRequest{
		HypothesisID: uuid.New(),
		Command:      "sh",
		Args:         []string{"-c", "sleep 30 & sleep 30"},
		Timeout:      1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("runner hung for %v after timeout", elapsed)
	}
	if res.Outcome != domain.ValidationOutcomeInconclusive {
		t.Fatalf("expected inconclusive on timeout, got %s", res.Outcome)
	}
}

// Output artifacts are stored as <sha256>.log so artifact://<sha256> maps to exactly one file.
func TestValidationRunnerStoresContentAddressedArtifacts(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(config.ValidationConfig{Enabled: true, NetworkAccess: "disabled", MaxRuntimeSeconds: 10}, dir)
	res, err := r.Execute(context.Background(), ExecutionRequest{
		HypothesisID: uuid.New(),
		Command:      "sh",
		Args:         []string{"-c", "echo evidence-line"},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := strings.TrimPrefix(res.StdoutArtifact, "artifact://")
	if len(sum) != 64 {
		t.Fatalf("expected artifact://<sha256>, got %q", res.StdoutArtifact)
	}
	data, err := os.ReadFile(filepath.Join(dir, sum+".log"))
	if err != nil {
		t.Fatalf("artifact file not found by hash: %v", err)
	}
	if !strings.Contains(string(data), "evidence-line") {
		t.Fatalf("unexpected artifact content: %q", data)
	}
}

// The point of the failure-signature contract: a non-zero exit is only proof when the
// output also contains what the hypothesis said the exploit would print.
func TestFailureSignatureContract(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		signature string
		want      domain.ValidationOutcome
		noteHas   string
	}{
		{"failure with declared signature is reproduced", "echo 'invariant broken: balance < 0'; exit 1", "invariant broken: balance", domain.ValidationOutcomeReproduced, "declared failure signature"},
		{"signature printed on stderr counts too", "echo 'invariant broken: balance < 0' >&2; exit 1", "invariant broken: balance", domain.ValidationOutcomeReproduced, ""},
		{"failure without any signature is inconclusive", "exit 1", "", domain.ValidationOutcomeInconclusive, "no failure_signature"},
		{"failure with unrelated output is inconclusive", "echo 'syntax error near unexpected token'; exit 2", "invariant broken: balance", domain.ValidationOutcomeInconclusive, "did not contain"},
		{"generic short signature is not accepted", "echo FAIL; exit 1", "FAIL", domain.ValidationOutcomeInconclusive, "too short"},
		{"clean exit is refuted even if the signature is printed", "echo 'invariant broken: balance < 0'; exit 0", "invariant broken: balance", domain.ValidationOutcomeRefuted, ""},
		{"missing tool stays a setup failure despite a matching signature", "echo 'invariant broken: balance'; nonexistent-binary-xyz", "invariant broken: balance", domain.ValidationOutcomeSetupFailed, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := newTestRunner(t).Execute(context.Background(), ExecutionRequest{
				HypothesisID:     uuid.New(),
				Command:          "sh",
				Args:             []string{"-c", tc.script},
				FailureSignature: tc.signature,
				Timeout:          5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s (exit %d, notes %q)", res.Outcome, tc.want, res.ExitCode, res.Notes)
			}
			if tc.noteHas != "" && !strings.Contains(res.Notes, tc.noteHas) {
				t.Fatalf("notes %q should mention %q", res.Notes, tc.noteHas)
			}
		})
	}
}
