package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"vuln-research/internal/config"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/store"
)

func TestCoordinatorFullThreeAgentPipeline(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()

	cfg := &config.Config{
		Models: map[string]config.ModelRoleConfig{
			"scout":        {Adapter: "fake", ModelID: "scout-v1"},
			"investigator": {Adapter: "fake", ModelID: "inv-v1"},
			"reviewer":     {Adapter: "fake", ModelID: "rev-v1"},
		},
		Research: config.ResearchConfig{
			MaxConcurrentJobs:          1,
			MaxHypothesesPerJob:        5,
			MaxIterationsPerHypothesis: 3,
		},
		Validation: config.ValidationConfig{
			Enabled:           true,
			MaxRuntimeSeconds: 10,
		},
	}

	scoutFake := models.NewFakeAdapter("scout-v1")
	invFake := models.NewFakeAdapter("inv-v1")
	revFake := models.NewFakeAdapter("rev-v1")

	// 1. Scout response: 1 candidate
	scoutFake.EnqueueResponse(`[
		{
			"schema_version": "1.0",
			"candidate_id": "a0000000-0000-0000-0000-000000000001",
			"repository_path": "src/vault.sol",
			"symbol": "flashLoan",
			"line_start": 50,
			"line_end": 75,
			"suspected_class": "CWE-841",
			"rationale": "Flash loan callback executes before fee check",
			"observed_facts": ["Balance check after external call"],
			"assumptions": [],
			"suggested_next_steps": ["Check reentrancy guard"],
			"confidence": 0.95
		}
	]`, 120, 60)

	// 2. Investigator response: 1 hypothesis
	invFake.EnqueueResponse(`{
		"schema_version": "1.0",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"title": "Cross-function reentrancy during flash loan execution",
		"weakness": {
			"cwe": "CWE-841",
			"category": "reentrancy"
		},
		"affected_locations": [
			{
				"path": "src/vault.sol",
				"symbol": "flashLoan",
				"line_start": 50,
				"line_end": 75
			}
		],
		"security_invariant": "Vault total assets must equal or exceed user deposits plus accrued fees",
		"preconditions": ["Vault has active collateral deposits"],
		"attacker_controlled_inputs": ["callbackData"],
		"expected_failure": "Total assets decrease after reentrant deposit",
		"impact": "Drain of vault liquidity",
		"supporting_evidence_ids": [],
		"counterarguments": [],
		"failure_signature": "AssertionFailed: invariant violated",
		"validation_plan": ["echo 'AssertionFailed: invariant violated' >&2; exit 1"],
		"status": "proposed"
	}`, 200, 100)

	// 3. Reviewer response: accept_for_validation
	revFake.EnqueueResponse(`{
		"schema_version": "1.0",
		"review_id": "c0000000-0000-0000-0000-000000000003",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"decision": "accept_for_validation",
		"supporting_points": ["Reentrancy lock is absent on deposit function"],
		"counterarguments": [],
		"missing_evidence": [],
		"falsification_tests": ["Run reentrant deposit simulation"],
		"rationale": "Clear vulnerability path without mitigations",
		"reviewer_model": "rev-v1"
	}`, 180, 90)

	reg := models.NewRegistry()
	reg.Register("scout", scoutFake)
	reg.Register("investigator", invFake)
	reg.Register("reviewer", revFake)

	coord, err := NewCoordinator(cfg, s, reg)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	// The coordinator reads the target from disk, so the job needs a real directory.
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "src", "vault.sol"),
		[]byte("contract Vault { function flashLoan() {} }"), 0o644); err != nil {
		t.Fatal(err)
	}

	jobID := uuid.New()
	job := &domain.ResearchJob{
		ID:                 jobID,
		RepositoryRef:      repoDir,
		RepositoryRevision: "main",
		Status:             domain.JobStatusQueued,
		IterationLimit:     4,
	}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Execute full workflow
	if err := coord.RunJob(ctx, jobID); err != nil {
		t.Fatalf("RunJob returned error: %v", err)
	}

	// Verify job reached confirmed
	finalJob, err := s.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to fetch final job: %v", err)
	}
	if finalJob.Status != domain.JobStatusConfirmed {
		t.Errorf("expected job status confirmed, got: %s", finalJob.Status)
	}

	// Verify candidates persisted
	cands, _ := s.ListCandidates(ctx, jobID)
	if len(cands) != 1 {
		t.Errorf("expected 1 candidate persisted, got %d", len(cands))
	}

	// Verify hypotheses persisted and updated to confirmed
	hyps, _ := s.ListHypotheses(ctx, jobID)
	if len(hyps) != 1 {
		t.Fatalf("expected 1 hypothesis persisted, got %d", len(hyps))
	}
	if hyps[0].Status != domain.HypothesisConfirmed {
		t.Errorf("expected hypothesis status confirmed, got: %s", hyps[0].Status)
	}

	// Verify reviews persisted
	reviews, _ := s.ListReviews(ctx, hyps[0].HypothesisID)
	if len(reviews) != 1 {
		t.Errorf("expected 1 review persisted, got %d", len(reviews))
	}
	if reviews[0].Decision != domain.ReviewAcceptForValidation {
		t.Errorf("expected review decision accept_for_validation, got: %s", reviews[0].Decision)
	}

	// Verify validation runs persisted
	valRuns, _ := s.ListValidationRuns(ctx, hyps[0].HypothesisID)
	if len(valRuns) != 1 {
		t.Fatalf("expected 1 validation run persisted, got %d", len(valRuns))
	}
	if valRuns[0].Outcome != domain.ValidationOutcomeReproduced {
		t.Errorf("expected validation outcome reproduced, got: %s", valRuns[0].Outcome)
	}
}
