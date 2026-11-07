package validation

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

	// 4. Copy the target source into the sandbox so tests never mutate the original
	workDir := sandboxDir
	if req.SourceDir != "" {
		workDir = filepath.Join(sandboxDir, "src")
		if err := copySourceTree(req.SourceDir, workDir, r.maxCopyBytes()); err != nil {
			return nil, fmt.Errorf("failed to stage source into sandbox: %w", err)
		}
	}

	// 5. Prepare command (optionally inside a network-less namespace)
	name, args, isolation := r.wrapCommand(req.Command, req.Args)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Dir = workDir

	// Kill the whole process group on timeout and don't wait forever on pipes
	// held open by grandchildren.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second

	// 6. Scrubbed environment: host secrets are not inherited.
	env := sandboxEnv(sandboxDir)
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
			Notes:                  fmt.Sprintf("Execution timed out after %v. Isolation: %s", duration, isolation),
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
		if exitCode == 126 || exitCode == 127 || isSetupOrCompilationFailure(combinedOutput) {
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
		Notes:                  notes + " Isolation: " + isolation,
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

// sandboxEnv builds a minimal environment so host secrets (API keys, tokens)
// are not visible to model-generated test commands.
func sandboxEnv(sandboxDir string) []string {
	env := []string{
		"HOME=" + sandboxDir,
		"TMPDIR=" + sandboxDir,
	}
	passthrough := []string{
		"PATH", "LANG", "LC_ALL", "TERM",
		"GOROOT", "GOPATH", "GOCACHE", "GOMODCACHE",
		"CARGO_HOME", "RUSTUP_HOME", "FOUNDRY_DIR", "NODE_PATH",
	}
	for _, k := range passthrough {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

var (
	netnsOnce      sync.Once
	netnsAvailable bool
)

// canUseNetworkNamespace probes (once) whether `unshare -rn` works unprivileged here.
func canUseNetworkNamespace() bool {
	netnsOnce.Do(func() {
		if _, err := exec.LookPath("unshare"); err != nil {
			return
		}
		netnsAvailable = exec.Command("unshare", "-rn", "true").Run() == nil
	})
	return netnsAvailable
}

// wrapCommand runs the command in a fresh network namespace when network access
// is disabled and the kernel allows it. It reports the isolation level actually
// achieved so results never overstate it.
func (r *Runner) wrapCommand(command string, args []string) (string, []string, string) {
	if r.cfg.NetworkAccess != "disabled" {
		return command, args, "network allowed; no namespace isolation"
	}
	if canUseNetworkNamespace() {
		wrapped := append([]string{"-rn", "--", "sh", "-c", `ip link set lo up 2>/dev/null; exec "$@"`, "sh", command}, args...)
		return "unshare", wrapped, "network namespace (no network); env scrubbed; not a full sandbox"
	}
	return command, args, "ADVISORY ONLY: offline env vars set but no network namespace available; run inside a container for real isolation"
}

func (r *Runner) maxCopyBytes() int64 {
	if r.cfg.MaxArtifactMB > 0 {
		return int64(r.cfg.MaxArtifactMB) << 20
	}
	return 256 << 20
}

// copySourceTree copies regular files from src to dst, skipping .git and symlinks.
func copySourceTree(src, dst string, maxBytes int64) error {
	var total int64
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, sockets, devices
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > maxBytes {
			return fmt.Errorf("source tree exceeds %d MB staging limit", maxBytes>>20)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()|0o200)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}
