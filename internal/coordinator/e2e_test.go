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
)

// pipelineResult is everything an end-to-end test might want to assert on.
type pipelineResult struct {
	job     *domain.ResearchJob
	hyps    []*domain.Hypothesis
	reviews map[uuid.UUID][]*domain.ReviewResult
	runs    map[uuid.UUID][]*domain.ValidationResult
	replay  *replay.Server
	store   *store.MemoryStore
}

// runPipeline runs the real coordinator (real HTTP model adapter, schema validation and
// validation runner) against a scripted model and a target directory.
func runPipeline(t *testing.T, scenario, target string) pipelineResult {
	t.Helper()
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

	replaySrv, err := replay.New(scenario)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(replaySrv)
	t.Cleanup(httpSrv.Close)

	t.Setenv("REPLAY_BASE_URL", httpSrv.URL+"/v1")
	t.Setenv("E2E_ARTIFACT_DIR", t.TempDir())
	t.Setenv("GOCACHE", filepath.Join(os.TempDir(), "oju-e2e-gocache")) // shared so later runs are fast

	cfg, err := config.Load("configs/config.e2e.yaml")
	if err != nil {
		t.Fatal(err)
	}

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

	repoPath, _ := filepath.Abs(target)
	job := &domain.ResearchJob{
		ID: uuid.New(), RepositoryRef: repoPath, RepositoryRevision: "HEAD",
		AuthorizationScope: map[string]interface{}{"authorized": true},
		Status:             domain.JobStatusQueued, ConfigSnapshot: map[string]interface{}{},
	}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	// RunJob may return an error for jobs that legitimately end `failed`; the tests assert on state.
	_ = coord.RunJob(ctx, job.ID)

	res := pipelineResult{
		reviews: map[uuid.UUID][]*domain.ReviewResult{},
		runs:    map[uuid.UUID][]*domain.ValidationResult{},
		replay:  replaySrv, store: s,
	}
	if res.job, err = s.GetJob(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if res.hyps, err = s.ListHypotheses(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	for _, h := range res.hyps {
		res.reviews[h.HypothesisID], _ = s.ListReviews(ctx, h.HypothesisID)
		res.runs[h.HypothesisID], _ = s.ListValidationRuns(ctx, h.HypothesisID)
	}
	return res
}

// TestEndToEndReplay runs the whole pipeline on a vulnerable and a patched copy of the same
// code. The scripted model makes the same claim both times; only the validation step can
// tell the two apart.
func TestEndToEndReplay(t *testing.T) {
	cases := []struct {
		name        string
		scenario    string
		target      string
		wantJob     domain.JobStatus
		wantHyp     domain.HypothesisStatus
		wantOutcome domain.ValidationOutcome
	}{
		{"vulnerable", "testdata/scenarios/traversal", "testdata/targets/traversal-vulnerable", domain.JobStatusConfirmed, domain.HypothesisConfirmed, domain.ValidationOutcomeReproduced},
		{"patched", "testdata/scenarios/traversal", "testdata/targets/traversal-patched", domain.JobStatusRefuted, domain.HypothesisRefuted, domain.ValidationOutcomeRefuted},
		// The test fails on the vulnerable code, but the model declared a signature the output
		// never contains. The old "any non-zero exit" rule would have confirmed this.
		{"failing test with wrong signature is not confirmed", "testdata/scenarios/traversal-wrong-signature", "testdata/targets/traversal-vulnerable", domain.JobStatusInconclusive, domain.HypothesisInconclusive, domain.ValidationOutcomeInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runPipeline(t, tc.scenario, tc.target)
			if r.job.Status != tc.wantJob {
				t.Fatalf("job status = %s (%s), want %s", r.job.Status, r.job.ErrorSummary, tc.wantJob)
			}
			if len(r.hyps) != 1 {
				t.Fatalf("hypotheses = %d, want exactly 1", len(r.hyps))
			}
			h := r.hyps[0]
			if h.Status != tc.wantHyp {
				t.Fatalf("hypothesis status = %s, want %s", h.Status, tc.wantHyp)
			}
			runs := r.runs[h.HypothesisID]
			if len(runs) != 1 {
				t.Fatalf("validation runs = %d, want exactly 1", len(runs))
			}
			if runs[0].Outcome != tc.wantOutcome {
				t.Fatalf("validation outcome = %s (exit %d), want %s\nnotes: %s", runs[0].Outcome, runs[0].ExitCode, tc.wantOutcome, runs[0].Notes)
			}
			for _, role := range []string{"scout", "investigator", "reviewer"} {
				if n := r.replay.Count(role); n != 1 {
					t.Errorf("%s was called %d times, want 1", role, n)
				}
			}
			t.Logf("outcome=%s exit=%d notes=%q", runs[0].Outcome, runs[0].ExitCode, runs[0].Notes)
		})
	}
}
