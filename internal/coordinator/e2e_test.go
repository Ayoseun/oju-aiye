package coordinator_test

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/config"
	"vuln-research/internal/coordinator"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/replay"
	"vuln-research/internal/store"
	"vuln-research/internal/tools"
)

// TestEndToEndReplay runs the whole pipeline (real HTTP model adapter, schema validation,
// validation runner executing a real `go test`) against a scripted model, on a vulnerable
// and a patched copy of the same code. The scripted model makes the same claim both times;
// only the validation step can tell the two apart.
func TestEndToEndReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test skipped in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; needed to run the reproduction test")
	}

	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	oldWD, _ := os.Getwd()
	if err := os.Chdir(root); err != nil { // prompts/ and schemas/ are loaded relative to the repo root
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	replaySrv, err := replay.New("testdata/scenarios/traversal")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(replaySrv)
	defer httpSrv.Close()

	t.Setenv("REPLAY_BASE_URL", httpSrv.URL+"/v1")
	t.Setenv("E2E_ARTIFACT_DIR", t.TempDir())
	t.Setenv("GOCACHE", filepath.Join(os.TempDir(), "oju-e2e-gocache")) // shared so the 2nd run is fast

	cfg, err := config.Load("configs/config.e2e.yaml")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		target      string
		wantJob     domain.JobStatus
		wantHyp     domain.HypothesisStatus
		wantOutcome domain.ValidationOutcome
	}{
		{"vulnerable", "testdata/targets/traversal-vulnerable", domain.JobStatusConfirmed, domain.HypothesisConfirmed, domain.ValidationOutcomeReproduced},
		{"patched", "testdata/targets/traversal-patched", domain.JobStatusRefuted, domain.HypothesisRefuted, domain.ValidationOutcomeRefuted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()

			s := store.NewMemoryStore()
			reg := models.NewRegistry()
			for role, m := range cfg.Models {
				reg.Register(role, models.NewOpenAICompatibleAdapter(models.OpenAICompatibleConfig{
					BaseURL: m.BaseURL, ModelID: m.ModelID, Timeout: m.Timeout(),
					MaxRetries: cfg.Research.MaxAgentRetries, ProviderName: m.Adapter,
				}))
			}
			coord, err := coordinator.NewCoordinator(cfg, s, reg)
			if err != nil {
				t.Fatal(err)
			}

			repoPath, _ := filepath.Abs(tc.target)
			job := &domain.ResearchJob{
				ID: uuid.New(), RepositoryRef: repoPath, RepositoryRevision: "HEAD",
				AuthorizationScope: map[string]interface{}{"authorized": true},
				Status:             domain.JobStatusQueued, ConfigSnapshot: map[string]interface{}{},
			}
			if err := s.CreateJob(ctx, job); err != nil {
				t.Fatal(err)
			}

			sourceContext := "Repository reference: " + repoPath
			if inv, err := tools.InventoryRepository(repoPath); err == nil {
				if sum, err := inv.BuildContextSummary(repoPath, 30000); err == nil {
					sourceContext = sum
				}
			}
			if err := coord.RunJob(ctx, job.ID, sourceContext); err != nil {
				t.Fatalf("RunJob: %v", err)
			}

			got, err := s.GetJob(ctx, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.wantJob {
				t.Fatalf("job status = %s (%s), want %s", got.Status, got.ErrorSummary, tc.wantJob)
			}

			hyps, err := s.ListHypotheses(ctx, job.ID)
			if err != nil || len(hyps) != 1 {
				t.Fatalf("hypotheses = %d, err = %v; want exactly 1", len(hyps), err)
			}
			if hyps[0].Status != tc.wantHyp {
				t.Fatalf("hypothesis status = %s, want %s", hyps[0].Status, tc.wantHyp)
			}
			runs, err := s.ListValidationRuns(ctx, hyps[0].HypothesisID)
			if err != nil || len(runs) != 1 {
				t.Fatalf("validation runs = %d, err = %v; want exactly 1", len(runs), err)
			}
			if runs[0].Outcome != tc.wantOutcome {
				t.Fatalf("validation outcome = %s (exit %d), want %s\nnotes: %s", runs[0].Outcome, runs[0].ExitCode, tc.wantOutcome, runs[0].Notes)
			}
			t.Logf("outcome=%s exit=%d isolation=%q", runs[0].Outcome, runs[0].ExitCode, runs[0].Notes)
		})
	}

	for _, role := range []string{"scout", "investigator", "reviewer"} {
		if got := replaySrv.Count(role); got != 2 {
			t.Errorf("%s was called %d times, want 2 (once per target)", role, got)
		}
	}
}
