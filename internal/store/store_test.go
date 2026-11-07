package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
)

func TestMemoryStoreJobLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	jobID := uuid.New()
	job := &domain.ResearchJob{
		ID:                 jobID,
		RepositoryRef:      "local://audit-repo",
		RepositoryRevision: "v1.0.0",
		AuthorizationScope: map[string]interface{}{"authorized": true},
		Status:             domain.JobStatusQueued,
		ConfigSnapshot:     map[string]interface{}{},
		IterationLimit:     4,
	}

	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	fetched, err := s.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to get job: %v", err)
	}
	if fetched.Status != domain.JobStatusQueued {
		t.Errorf("expected status %s, got %s", domain.JobStatusQueued, fetched.Status)
	}

	// Legal transition
	if err := s.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusPreparingTarget, "initializing"); err != nil {
		t.Fatalf("legal status transition failed: %v", err)
	}

	updated, _ := s.GetJob(ctx, jobID)
	if updated.Status != domain.JobStatusPreparingTarget {
		t.Errorf("expected status %s, got %s", domain.JobStatusPreparingTarget, updated.Status)
	}

	// Illegal transition (preparing_target cannot jump to confirmed)
	if err := s.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusConfirmed, "illegal jump"); err == nil {
		t.Fatalf("expected error on illegal state transition, got nil")
	}
}

func TestMemoryStoreCandidatesAndHypotheses(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	jobID := uuid.New()
	candID := uuid.New()
	cand := &domain.Candidate{
		SchemaVersion:      "1.0",
		CandidateID:        candID,
		RepositoryPath:     "contracts/vault.sol",
		Symbol:             "withdraw",
		LineStart:          10,
		LineEnd:            25,
		SuspectedClass:     "CWE-287",
		Rationale:          "Missing modifier",
		ObservedFacts:      []string{"No onlyOwner"},
		Assumptions:        []string{},
		SuggestedNextSteps: []string{},
		Confidence:         0.9,
	}

	if err := s.CreateCandidate(ctx, jobID, cand); err != nil {
		t.Fatalf("failed to create candidate: %v", err)
	}

	cands, err := s.ListCandidates(ctx, jobID)
	if err != nil || len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d (err: %v)", len(cands), err)
	}

	hypID := uuid.New()
	hyp := &domain.Hypothesis{
		SchemaVersion:            "1.0",
		HypothesisID:             hypID,
		CandidateID:              candID,
		Title:                    "Reentrancy on withdraw",
		Weakness:                 domain.Weakness{CWE: "CWE-841", Category: "business_logic"},
		AffectedLocations:        []domain.AffectedLocation{{Path: "contracts/vault.sol", Symbol: "withdraw", LineStart: 10, LineEnd: 25}},
		SecurityInvariant:        "Vault balance must never drop below liabilities",
		Preconditions:            []string{},
		AttackerControlledInputs: []string{},
		ExpectedFailure:          "Drain funds",
		Impact:                   "Loss of TVL",
		SupportingEvidenceIDs:    []string{},
		Counterarguments:         []string{},
		ValidationPlan:           []string{"forge test"},
		Status:                   domain.HypothesisProposed,
	}

	if err := s.CreateHypothesis(ctx, jobID, hyp); err != nil {
		t.Fatalf("failed to create hypothesis: %v", err)
	}

	fetchedHyp, err := s.GetHypothesis(ctx, hypID)
	if err != nil || fetchedHyp.Title != "Reentrancy on withdraw" {
		t.Fatalf("failed to fetch hypothesis: %v", err)
	}
}

func TestUpdateJobStatusFailedPersistsReason(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	job := &domain.ResearchJob{ID: uuid.New(), Status: domain.JobStatusQueued}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateJobStatus(ctx, job.ID, "coordinator", domain.JobStatusFailed, "Scout failed: connection refused"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorSummary != "Scout failed: connection refused" || got.FinishedAt == nil {
		t.Fatalf("failure reason/finish time not persisted: %+v", got)
	}
}
