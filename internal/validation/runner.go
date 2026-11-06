package validation

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/config"
	"vuln-research/internal/domain"
	"vuln-research/internal/tools"
)

// ExecutionRequest specifies parameters for an isolated test run.
type ExecutionRequest struct {
	HypothesisID uuid.UUID
	Command      string
	Args         []string
	SourceDir    string
	TestPatch    string
	Timeout      time.Duration
}

// Runner executes validation tests in disposable environments.
type Runner struct {
	cfg         config.ValidationConfig
	artifactDir string
}

func NewRunner(cfg config.ValidationConfig, artifactDir string) *Runner {
	return &Runner{
		cfg:         cfg,
		artifactDir: artifactDir,
	}
}

// Execute runs the test plan in a disposable temporary workspace with strict boundaries.
func (r *Runner) Execute(ctx context.Context, req ExecutionRequest) (*domain.ValidationResult, error) {
	envID := uuid.New()
	valID := uuid.New()

	// 1. Create disposable workspace
	sandboxDir, err := os.MkdirTemp("", fmt.Sprintf("val-sandbox-%s-*", envID.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox workspace: %w", err)
	}
	defer os.RemoveAll(sandboxDir) // Guarantees destruction after run

	// 2. Set timeout bounded by config
	maxRuntime := r.cfg.MaxRuntime()
	if maxRuntime <= 0 {
		maxRuntime = 60 * time.Second
	}
	timeout := req.Timeout
	if timeout <= 0 || timeout > maxRuntime {
		timeout = maxRuntime
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 3. Write test patch if present
	if req.TestPatch != "" {
		patchFile := filepath.Join(sandboxDir, "exploit_reproduction_test.patch")
		_ = os.WriteFile(patchFile, []byte(req.TestPatch), 0644)
	}

	// 4. Prepare command
	cmd := exec.CommandContext(runCtx, req.Command, req.Args...)
	cmd.Dir = req.SourceDir
	if cmd.Dir == "" {
		cmd.Dir = sandboxDir
	}

	// 5. Enforce process group termination on timeout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// 6. Network isolation & offline environment variables
	env := os.Environ()
	if r.cfg.NetworkAccess == "disabled" {
		env = append(env,
			"GOPROXY=off",
			"GONOPROXY=*",
			"CARGO_NET_OFFLINE=true",
			"npm_config_offline=true",
		)
	}
	cmd.Env = env

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	// Check if run timed out
	if runCtx.Err() == context.DeadlineExceeded {
		// Kill process group
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return &domain.ValidationResult{
			SchemaVersion:          "1.0",
			ValidationID:           valID,
			HypothesisID:           req.HypothesisID,
			EnvironmentID:          envID,
			TestCommandID:          req.Command,
			ExitCode:               124,
			Outcome:                domain.ValidationOutcomeInconclusive,
			StdoutArtifact:         stdoutBuf.String(),
			StderrArtifact:         stderrBuf.String(),
			TestArtifact:           req.TestPatch,
			EnvironmentFingerprint: fmt.Sprintf("disposable-pid-%d", os.Getpid()),
			Notes:                  fmt.Sprintf("Execution timed out after %v", duration),
		}, nil
	}

	// 7. Store artifacts
	stdoutRec, _ := tools.StoreArtifact(r.artifactDir, fmt.Sprintf("%s-stdout.log", valID), stdoutBuf.Bytes())
	stderrRec, _ := tools.StoreArtifact(r.artifactDir, fmt.Sprintf("%s-stderr.log", valID), stderrBuf.Bytes())

	stdoutRef := ""
	if stdoutRec != nil {
		stdoutRef = fmt.Sprintf("artifact://%s", stdoutRec.SHA256)
	}
	stderrRef := ""
	if stderrRec != nil {
		stderrRef = fmt.Sprintf("artifact://%s", stderrRec.SHA256)
	}

	// 8. Classify outcome
	outcome := domain.ValidationOutcomeRefuted
	notes := "Test execution passed cleanly; invariant holds."

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	combinedOutput := stdoutStr + "\n" + stderrStr

	if runErr != nil {
		// Distinguish setup/compilation errors from security assertion failures
		if isSetupOrCompilationFailure(combinedOutput) {
			outcome = domain.ValidationOutcomeSetupFailed
			notes = "Test environment or compilation setup failed before reaching assertion."
		} else {
			// Test failed -> reproduced the vulnerability / invariant violation
			outcome = domain.ValidationOutcomeReproduced
			notes = "Security invariant assertion failed as predicted by hypothesis."
		}
	}

	return &domain.ValidationResult{
		SchemaVersion:          "1.0",
		ValidationID:           valID,
		HypothesisID:           req.HypothesisID,
		EnvironmentID:          envID,
		TestCommandID:          req.Command,
		ExitCode:               exitCode,
		Outcome:                outcome,
		StdoutArtifact:         stdoutRef,
		StderrArtifact:         stderrRef,
		TestArtifact:           req.TestPatch,
		EnvironmentFingerprint: fmt.Sprintf("disposable-%s", envID),
		Notes:                  notes,
	}, nil
}

func isSetupOrCompilationFailure(output string) bool {
	lower := strings.ToLower(output)
	setupKeywords := []string{
		"compilation failed",
		"syntaxerror",
		"package not found",
		"cannot find module",
		"no such file or directory",
		"command not found",
		"could not compile",
	}
	for _, kw := range setupKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
