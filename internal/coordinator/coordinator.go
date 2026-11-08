package coordinator

import (
	"context"
	"fmt"
	"os"
	"strings"
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
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, "No security candidates found in source")
	}

	// 4. Analyzing (Investigator)
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusAnalyzing, "Invoking Investigator agent"); err != nil {
		return err
	}

	var (
		hypotheses  []*domain.Hypothesis
		candidateOf = map[uuid.UUID]*domain.Candidate{} // hypothesis ID -> its candidate, for revisions
		problems    []string                            // agent failures that left something unanalyzed
	)
	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		hyp, err := c.investigate(ctx, jobID, cand, nil, nil, sourceContext)
		if err != nil {
			problems = append(problems, fmt.Sprintf("investigator failed on %s: %v", cand.RepositoryPath, err))
			continue
		}
		_ = c.store.CreateHypothesis(ctx, jobID, hyp)
		hypotheses = append(hypotheses, hyp)
		candidateOf[hyp.HypothesisID] = cand
	}

	telemetry.Info(fmt.Sprintf("Investigator formulated %d hypotheses", len(hypotheses)), map[string]interface{}{
		"job_id": jobID.String(),
		"count":  len(hypotheses),
	})

	// If the Investigator failed on every candidate, nothing was analyzed. Say so; this must
	// never look like an all-clear.
	if len(hypotheses) == 0 {
		msg := fmt.Sprintf("Investigator produced no usable hypothesis for any of %s", plural(len(candidates), "candidate", "candidates"))
		if len(problems) > 0 {
			msg += ": " + problems[0]
		}
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusFailed, msg)
		return fmt.Errorf("%s", msg)
	}

	// 5. Reviewing (Reviewer), with a bounded revise-and-re-review loop. When the Reviewer asks
	// for more evidence, its feedback goes back to the Investigator, which revises the same
	// hypothesis. max_iterations_per_hypothesis caps the review rounds (1 = never revise).
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusReviewing, "Invoking Reviewer agent"); err != nil {
		return err
	}

	maxRounds := c.cfg.Research.MaxIterationsPerHypothesis
	if maxRounds < 1 {
		maxRounds = 1
	}

	var readyForValidationCount, rejectedCount, unresolvedCount int
	pending := hypotheses
	for round := 1; len(pending) > 0; round++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		var needMore []*domain.Hypothesis
		feedback := map[uuid.UUID]*domain.ReviewResult{}
		for _, hyp := range pending {
			review, err := c.review(ctx, jobID, hyp, sourceContext)
			if err != nil {
				// Unreviewed is unresolved, not refuted: keep it visible and say why.
				problems = append(problems, fmt.Sprintf("reviewer failed on %q: %v", hyp.Title, err))
				hyp.Status = domain.HypothesisInconclusive
				_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisInconclusive)
				unresolvedCount++
				continue
			}

			switch review.Decision {
			case domain.ReviewAcceptForValidation:
				hyp.Status = domain.HypothesisReadyForValidation
				_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisReadyForValidation)
				readyForValidationCount++
			case domain.ReviewRequestMoreEvidence:
				hyp.Status = domain.HypothesisNeedsMoreEvidence
				_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisNeedsMoreEvidence)
				if round < maxRounds {
					needMore = append(needMore, hyp)
					feedback[hyp.HypothesisID] = review
				} else {
					problems = append(problems, fmt.Sprintf("%q still needed more evidence after %s", hyp.Title, plural(round, "review round", "review rounds")))
					unresolvedCount++
				}
			case domain.ReviewRejectHypothesis:
				hyp.Status = domain.HypothesisRefuted
				_ = c.store.UpdateHypothesisStatus(ctx, hyp.HypothesisID, domain.HypothesisRefuted)
				rejectedCount++
			}
		}
		if len(needMore) == 0 {
			break
		}

		// Revision round: hand the Reviewer's feedback back to the Investigator.
		if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusNeedsMoreEvidence,
			fmt.Sprintf("More evidence requested for %s (review round %d of %d)", plural(len(needMore), "hypothesis", "hypotheses"), round, maxRounds)); err != nil {
			return err
		}
		if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusAnalyzing, "Investigator revising hypotheses from reviewer feedback"); err != nil {
			return err
		}

		pending = nil
		for _, hyp := range needMore {
			revised, err := c.investigate(ctx, jobID, candidateOf[hyp.HypothesisID], hyp, feedback[hyp.HypothesisID], sourceContext)
			if err != nil {
				problems = append(problems, fmt.Sprintf("investigator could not revise %q: %v", hyp.Title, err))
				unresolvedCount++ // stays needs_more_evidence
				continue
			}
			_ = c.store.UpdateHypothesis(ctx, revised)
			*hyp = *revised // later phases use the revised hypothesis
			pending = append(pending, hyp)
		}

		if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusReviewing,
			fmt.Sprintf("Re-reviewing %s", plural(len(pending), "revised hypothesis", "revised hypotheses"))); err != nil {
			return err
		}
	}

	// Nothing to validate: say exactly why. "Refuted" is reserved for hypotheses the Reviewer
	// explicitly rejected; anything unresolved or broken is inconclusive, never an all-clear.
	if readyForValidationCount == 0 {
		if unresolvedCount > 0 {
			return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive,
				fmt.Sprintf("Nothing could be validated; %s unresolved. %s", plural(unresolvedCount, "hypothesis", "hypotheses"), summarizeProblems(problems)))
		}
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusRefuted,
			"All hypotheses were rejected during adversarial review; none were tested")
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

	unresolvedNote := ""
	if unresolvedCount > 0 {
		unresolvedNote = fmt.Sprintf("; %s unresolved", plural(unresolvedCount, "hypothesis", "hypotheses"))
	}
	if confirmedCount > 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusConfirmed, fmt.Sprintf("%s confirmed reproducibly%s", plural(confirmedCount, "vulnerability hypothesis", "vulnerability hypotheses"), unresolvedNote))
	}
	if inconclusiveCount > 0 || unresolvedCount > 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, fmt.Sprintf("Validation inconclusive for %d%s. %s", inconclusiveCount, unresolvedNote, summarizeProblems(problems)))
	}
	return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusRefuted, "Validation tests disproved all hypotheses")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// summarizeProblems keeps job reasons short: the first two problems plus a count of the rest.
func summarizeProblems(problems []string) string {
	switch {
	case len(problems) == 0:
		return ""
	case len(problems) <= 2:
		return strings.Join(problems, "; ")
	default:
		return fmt.Sprintf("%s; %s (+%d more)", problems[0], problems[1], len(problems)-2)
	}
}

// investigate runs the Investigator for a candidate (previous == nil) or revises an existing
// hypothesis from Reviewer feedback, recording an agent task either way.
func (c *Coordinator) investigate(ctx context.Context, jobID uuid.UUID, cand *domain.Candidate, previous *domain.Hypothesis, feedback *domain.ReviewResult, sourceContext string) (*domain.Hypothesis, error) {
	task := &domain.AgentTask{
		ID:           uuid.New(),
		JobID:        jobID,
		Role:         "investigator",
		Status:       "running",
		ModelID:      c.cfg.Models["investigator"].ModelID,
		AttemptCount: 1,
	}
	if previous != nil {
		task.HypothesisID = &previous.HypothesisID
	}
	_ = c.store.CreateTask(ctx, task)

	var (
		hyp *domain.Hypothesis
		err error
	)
	if previous == nil {
		hyp, _, err = c.investigator.FormulateHypothesis(ctx, cand, sourceContext)
	} else {
		hyp, _, err = c.investigator.ReviseHypothesis(ctx, cand, previous, feedback, sourceContext)
	}

	now := time.Now().UTC()
	task.FinishedAt = &now
	if err != nil {
		task.Status = "failed"
		task.ErrorSummary = err.Error()
		_ = c.store.UpdateTask(ctx, task)
		return nil, err
	}
	task.Status = "completed"
	task.HypothesisID = &hyp.HypothesisID
	_ = c.store.UpdateTask(ctx, task)
	return hyp, nil
}

// review runs the Reviewer on a hypothesis and records the task and the review.
func (c *Coordinator) review(ctx context.Context, jobID uuid.UUID, hyp *domain.Hypothesis, sourceContext string) (*domain.ReviewResult, error) {
	task := &domain.AgentTask{
		ID:           uuid.New(),
		JobID:        jobID,
		HypothesisID: &hyp.HypothesisID,
		Role:         "reviewer",
		Status:       "running",
		ModelID:      c.cfg.Models["reviewer"].ModelID,
		AttemptCount: 1,
	}
	_ = c.store.CreateTask(ctx, task)

	review, _, err := c.reviewer.ReviewHypothesis(ctx, hyp, sourceContext)
	now := time.Now().UTC()
	task.FinishedAt = &now
	if err != nil {
		task.Status = "failed"
		task.ErrorSummary = err.Error()
		_ = c.store.UpdateTask(ctx, task)
		return nil, err
	}
	task.Status = "completed"
	_ = c.store.UpdateTask(ctx, task)
	_ = c.store.CreateReview(ctx, review)
	return review, nil
}
