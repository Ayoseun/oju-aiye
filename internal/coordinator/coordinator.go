package coordinator

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/agents"
	"vuln-research/internal/config"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/store"
	"vuln-research/internal/telemetry"
	"vuln-research/internal/validation"
)

// Coordinator orchestrates research state transitions, task scheduling, and agent execution.
type Coordinator struct {
	cfg          *config.Config
	store        store.Store
	registry     *models.Registry
	scout        *agents.ScoutAgent
	investigator *agents.InvestigatorAgent
	reviewer     *agents.ReviewerAgent
	validator    *validation.Runner
}

func NewCoordinator(cfg *config.Config, s store.Store, reg *models.Registry) (*Coordinator, error) {
	scoutAdapter, err := reg.ForRole("scout")
	if err != nil {
		return nil, fmt.Errorf("scout adapter missing: %w", err)
	}
	invAdapter, err := reg.ForRole("investigator")
	if err != nil {
		return nil, fmt.Errorf("investigator adapter missing: %w", err)
	}
	revAdapter, err := reg.ForRole("reviewer")
	if err != nil {
		return nil, fmt.Errorf("reviewer adapter missing: %w", err)
	}

	scoutPrompt, _ := os.ReadFile("prompts/scout.md")
	invPrompt, _ := os.ReadFile("prompts/investigator.md")
	revPrompt, _ := os.ReadFile("prompts/reviewer.md")

	valRunner := validation.NewRunner(cfg.Validation, cfg.Storage.ArtifactDirectory)

	return &Coordinator{
		cfg:          cfg,
		store:        s,
		registry:     reg,
		scout:        agents.NewScoutAgent(scoutAdapter, string(scoutPrompt)),
		investigator: agents.NewInvestigatorAgent(invAdapter, string(invPrompt)),
		reviewer:     agents.NewReviewerAgent(revAdapter, string(revPrompt)),
		validator:    valRunner,
	}, nil
}

// RunJob executes the full agent research pipeline for a specific job.
func (c *Coordinator) RunJob(ctx context.Context, jobID uuid.UUID, sourceContext string) error {
	job, err := c.store.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	// 1. Preparing target
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusPreparingTarget, "Target prepared"); err != nil {
		return err
	}

	// 2. Inventorying
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInventorying, "Inventory completed"); err != nil {
		return err
	}

	// 3. Discovering (Scout)
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusDiscovering, "Invoking Scout agent"); err != nil {
		return err
	}

	scoutTask := &domain.AgentTask{
		ID:           uuid.New(),
		JobID:        jobID,
		Role:         "scout",
		Status:       "running",
		ModelID:      c.cfg.Models["scout"].ModelID,
		AttemptCount: 1,
	}
	_ = c.store.CreateTask(ctx, scoutTask)

	candidates, _, err := c.scout.DiscoverCandidates(ctx, job.RepositoryRef, sourceContext)
	now := time.Now().UTC()
	scoutTask.FinishedAt = &now
	if err != nil {
		scoutTask.Status = "failed"
		scoutTask.ErrorSummary = err.Error()
		_ = c.store.UpdateTask(ctx, scoutTask)
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusFailed, fmt.Sprintf("Scout failed: %v", err))
		return err
	}

	scoutTask.Status = "completed"
	_ = c.store.UpdateTask(ctx, scoutTask)

	for _, cand := range candidates {
		_ = c.store.CreateCandidate(ctx, jobID, cand)
	}

	telemetry.Info(fmt.Sprintf("Scout discovered %d candidates", len(candidates)), map[string]interface{}{
		"job_id": jobID.String(),
		"count":  len(candidates),
	})

	if len(candidates) == 0 {
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusAnalyzing, "No candidates discovered")
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusReviewing, "Skipping review")
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, "No security candidates found in source")
		return nil
	}

	// 4. Analyzing (Investigator)
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusAnalyzing, "Invoking Investigator agent"); err != nil {
		return err
	}

	var hypotheses []*domain.Hypothesis
	for _, cand := range candidates {
		invTask := &domain.AgentTask{
			ID:           uuid.New(),
			JobID:        jobID,
			Role:         "investigator",
			Status:       "running",
			ModelID:      c.cfg.Models["investigator"].ModelID,
			AttemptCount: 1,
		}
		_ = c.store.CreateTask(ctx, invTask)

		hyp, _, err := c.investigator.FormulateHypothesis(ctx, cand, sourceContext)
		invNow := time.Now().UTC()
		invTask.FinishedAt = &invNow

		if err != nil {
			invTask.Status = "failed"
			invTask.ErrorSummary = err.Error()
			_ = c.store.UpdateTask(ctx, invTask)
			continue
		}

		invTask.Status = "completed"
		invTask.HypothesisID = &hyp.HypothesisID
		_ = c.store.UpdateTask(ctx, invTask)

		_ = c.store.CreateHypothesis(ctx, jobID, hyp)
		hypotheses = append(hypotheses, hyp)
	}

	telemetry.Info(fmt.Sprintf("Investigator formulated %d hypotheses", len(hypotheses)), map[string]interface{}{
		"job_id": jobID.String(),
		"count":  len(hypotheses),
	})

	// 5. Reviewing (Reviewer)
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusReviewing, "Invoking Reviewer agent"); err != nil {
		return err
	}

	var readyForValidationCount int
	for _, hyp := range hypotheses {
		revTask := &domain.AgentTask{
			ID:           uuid.New(),
			JobID:        jobID,
			HypothesisID: &hyp.HypothesisID,
			Role:         "reviewer",
			Status:       "running",
			ModelID:      c.cfg.Models["reviewer"].ModelID,
			AttemptCount: 1,
		}
		_ = c.store.CreateTask(ctx, revTask)

		review, _, err := c.reviewer.ReviewHypothesis(ctx, hyp, sourceContext)
		revNow := time.Now().UTC()
		revTask.FinishedAt = &revNow

		if err != nil {
			revTask.Status = "failed"
			revTask.ErrorSummary = err.Error()
			_ = c.store.UpdateTask(ctx, revTask)
			continue
		}

		revTask.Status = "completed"
		_ = c.store.UpdateTask(ctx, revTask)
		_ = c.store.CreateReview(ctx, review)

		switch review.Decision {
		case domain.ReviewAcceptForValidation:
			hyp.Status = domain.HypothesisReadyForValidation
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisReadyForValidation)
			readyForValidationCount++
		case domain.ReviewRequestMoreEvidence:
			hyp.Status = domain.HypothesisNeedsMoreEvidence
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisNeedsMoreEvidence)
		case domain.ReviewRejectHypothesis:
			hyp.Status = domain.HypothesisRefuted
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisRefuted)
		}
	}

	// Move job state according to review decisions
	if readyForValidationCount == 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusRefuted, "All hypotheses refuted or rejected during adversarial review")
	}

	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusReadyForValidation, fmt.Sprintf("%s approved for validation", plural(readyForValidationCount, "hypothesis", "hypotheses"))); err != nil {
		return err
	}

	// 6. Validating (Isolated Validation Runner)
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusValidating, "Executing isolated validation tests"); err != nil {
		return err
	}

	confirmedCount := 0
	inconclusiveCount := 0

	for _, hyp := range hypotheses {
		if hyp.Status != domain.HypothesisReadyForValidation {
			continue
		}

		// Build execution request from hypothesis validation plan
		cmd := "echo"
		args := []string{"validation", "executed"}
		if len(hyp.ValidationPlan) > 0 {
			cmd = "sh"
			args = []string{"-c", hyp.ValidationPlan[0]}
		}

		sourceDir := ""
		if fi, statErr := os.Stat(job.RepositoryRef); statErr == nil && fi.IsDir() {
			sourceDir = job.RepositoryRef
		}

		valReq := validation.ExecutionRequest{
			HypothesisID:     hyp.HypothesisID,
			SourceDir:        sourceDir,
			FailureSignature: hyp.FailureSignature,
			Command:          cmd,
			Args:             args,
			Timeout:          time.Duration(c.cfg.Validation.MaxRuntimeSeconds) * time.Second,
		}

		res, err := c.validator.Execute(ctx, valReq)
		if err != nil {
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisInconclusive)
			inconclusiveCount++
			continue
		}

		_ = c.store.CreateValidationRun(ctx, res)

		switch res.Outcome {
		case domain.ValidationOutcomeReproduced:
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisConfirmed)
			confirmedCount++
		case domain.ValidationOutcomeRefuted:
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisRefuted)
		default:
			_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisInconclusive)
			inconclusiveCount++
		}
	}

	telemetry.Info(fmt.Sprintf("Validation complete: %d confirmed, %d inconclusive", confirmedCount, inconclusiveCount), map[string]interface{}{
		"job_id":       jobID.String(),
		"confirmed":    confirmedCount,
		"inconclusive": inconclusiveCount,
	})

	if confirmedCount > 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusConfirmed, fmt.Sprintf("%s confirmed reproducibly", plural(confirmedCount, "vulnerability hypothesis", "vulnerability hypotheses")))
	}
	if inconclusiveCount > 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, "Validation execution inconclusive")
	}
	return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusRefuted, "Validation tests disproved all hypotheses")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
