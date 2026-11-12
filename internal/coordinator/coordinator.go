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
	"vuln-research/internal/scope"
	"vuln-research/internal/store"
	"vuln-research/internal/telemetry"
	"vuln-research/internal/tools"
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
func (c *Coordinator) RunJob(ctx context.Context, jobID uuid.UUID) error {
	job, err := c.store.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	// 1. Preparing target
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusPreparingTarget, "Target prepared"); err != nil {
		return err
	}

	// 2. Inventorying: which files the program puts in scope, and how they are batched.
	sc := c.loadScope(job)
	files, err := tools.ScopedFiles(job.RepositoryRef, sc)
	if err != nil {
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusFailed, fmt.Sprintf("Could not read target: %v", err))
		return err
	}
	chunks, err := tools.BuildChunks(job.RepositoryRef, files, c.cfg.Research.ScoutChunkBytes, c.cfg.Research.MaxFileBytes)
	if err != nil {
		_ = c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusFailed, fmt.Sprintf("Could not read target: %v", err))
		return err
	}
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInventorying,
		fmt.Sprintf("%d files in scope, read in %d batches", len(files), len(chunks))); err != nil {
		return err
	}
	if len(chunks) == 0 {
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, "No source files in scope")
	}

	jc := c.jobContext(job.RepositoryRef, sc, files, chunks)

	// 3. Discovering (Scout), one batch at a time so the whole target is read.
	if err := c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusDiscovering, "Invoking Scout agent"); err != nil {
		return err
	}

	var candidates []*domain.Candidate
	seen := map[string]bool{}
	scoutFailures := 0

	scannedBatches := 0
	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if max := c.cfg.Research.MaxScoutBatches; max > 0 && scannedBatches >= max {
			telemetry.Info(fmt.Sprintf("Stopping the scan after %d of %d batches", scannedBatches, len(chunks)), map[string]interface{}{
				"job_id": jobID.String(),
			})
			break
		}
		scannedBatches++

		chunkCands, failures, err := c.scoutChunk(ctx, jobID, job.RepositoryRef, agents.SourceChunk{
			Index: chunk.Index,
			Total: chunk.Total,
			Files: chunk.Files,
			Text:  chunk.Text,
		}, jc)
		scoutFailures += failures
		if err != nil {
			telemetry.Error(fmt.Sprintf("Scout failed on batch %d of %d", chunk.Index, chunk.Total), "SCOUT_BATCH_FAILED", map[string]interface{}{
				"job_id": jobID.String(),
				"batch":  chunk.Index,
				"error":  err.Error(),
			})
			continue
		}

		for _, cand := range chunkCands {
			key := fmt.Sprintf("%s:%s:%d", cand.RepositoryPath, cand.Symbol, cand.LineStart)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, cand)
			_ = c.store.CreateCandidate(ctx, jobID, cand)
		}
	}

	telemetry.Info(fmt.Sprintf("Scout discovered %d candidates in %d batches", len(candidates), len(chunks)), map[string]interface{}{
		"job_id":  jobID.String(),
		"count":   len(candidates),
		"batches": len(chunks),
	})

	if len(candidates) == 0 {
		reason := "No security candidates found in source"
		if scoutFailures > 0 {
			reason = fmt.Sprintf("No security candidates found, and %d of %d batches could not be read", scoutFailures, len(chunks))
		}
		return c.store.UpdateJobStatus(ctx, jobID, "coordinator", domain.JobStatusInconclusive, reason)
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

	limit := c.cfg.Research.MaxHypothesesPerJob
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		hyp, err := c.investigate(ctx, jobID, cand, nil, nil, c.candidateContext(job, files, cand), jc)
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
			review, err := c.review(ctx, jobID, hyp, c.candidateContext(job, files, candidateOf[hyp.HypothesisID]), jc)
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
			revised, err := c.investigate(ctx, jobID, candidateOf[hyp.HypothesisID], hyp, feedback[hyp.HypothesisID], c.candidateContext(job, files, candidateOf[hyp.HypothesisID]), jc)
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

// scoutChunk reads one batch of source. A model that finds nothing in a batch is asked
// again, because a shared endpoint is flaky and a batch is a large part of the target.
//
// When the model refuses the batch because it is too large for its output budget, the
// batch is split and each half is read on its own: asking again with the same input
// would fail the same way, and the model may simply not have room to think about that
// much code at once.
func (c *Coordinator) scoutChunk(ctx context.Context, jobID uuid.UUID, repoRef string, chunk agents.SourceChunk, jc agents.JobContext) ([]*domain.Candidate, int, error) {
	attempts := c.cfg.Research.MaxBatchRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}

		scoutTask := &domain.AgentTask{
			ID:           uuid.New(),
			JobID:        jobID,
			Role:         "scout",
			Status:       "running",
			ModelID:      c.cfg.Models["scout"].ModelID,
			AttemptCount: attempt + 1,
		}
		_ = c.store.CreateTask(ctx, scoutTask)

		cands, _, err := c.scout.DiscoverCandidates(ctx, repoRef, chunk, jc)

		now := time.Now().UTC()
		scoutTask.FinishedAt = &now
		if err != nil {
			scoutTask.Status = "failed"
			scoutTask.ErrorSummary = err.Error()
			_ = c.store.UpdateTask(ctx, scoutTask)
			lastErr = err

			if isOversizeRefusal(err) {
				halves := splitChunk(chunk)
				if len(halves) > 1 {
					telemetry.Info(fmt.Sprintf("Batch %d was too large for the model; reading it as %d smaller batches", chunk.Index, len(halves)), map[string]interface{}{
						"job_id": jobID.String(),
						"batch":  chunk.Index,
					})
					var all []*domain.Candidate
					failures := 0
					for _, half := range halves {
						halfCands, halfFailures, halfErr := c.scoutChunk(ctx, jobID, repoRef, half, jc)
						all = append(all, halfCands...)
						failures += halfFailures
						if halfErr != nil {
							return all, failures + 1, halfErr
						}
					}
					return all, failures, nil
				}
			}
			continue
		}

		scoutTask.Status = "completed"
		_ = c.store.UpdateTask(ctx, scoutTask)
		return cands, 0, nil
	}

	return nil, 1, lastErr
}

// minSplitBytes is the smallest batch the Scout is asked to read. Below this a batch is
// not split again: the model is not refusing because of the size.
const minSplitBytes = 8000

// isOversizeRefusal reports whether the model refused because the batch was too large for
// its output budget, rather than because of a rate limit or a broken request.
func isOversizeRefusal(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "output_token_limit_exceeded") ||
		strings.Contains(msg, "exhausted its output token limit") ||
		strings.Contains(msg, "maximum context length") ||
		strings.Contains(msg, "context length exceeded")
}

// splitChunk divides a batch at its file boundaries, so each half holds whole files.
func splitChunk(chunk agents.SourceChunk) []agents.SourceChunk {
	const marker = "\n--- File: "
	parts := strings.Split(chunk.Text, marker)
	if len(parts) < 3 {
		return nil // nothing to split at a file boundary
	}

	half := len(parts) / 2
	groups := [][]string{parts[:half], parts[half:]}

	var chunks []agents.SourceChunk
	for _, group := range groups {
		text := marker + strings.Join(group, marker)
		if len(text) < minSplitBytes {
			continue
		}
		var files []string
		for _, part := range group {
			name := part
			if idx := strings.Index(part, "\n"); idx > 0 {
				name = part[:idx]
			}
			if idx := strings.Index(name, " ("); idx > 0 {
				name = name[:idx]
			}
			if name != "" {
				files = append(files, name)
			}
		}
		chunks = append(chunks, agents.SourceChunk{
			Index: chunk.Index,
			Total: chunk.Total,
			Files: files,
			Text:  text,
		})
	}
	return chunks
}

// loadScope reads the audit scope recorded on the job. A job without a scope audits the whole
// repository and tells the agents nothing about the program.
func (c *Coordinator) loadScope(job *domain.ResearchJob) *scope.Scope {
	if job.ConfigSnapshot == nil {
		return nil
	}
	path, _ := job.ConfigSnapshot["scope_file"].(string)
	if path == "" {
		return nil
	}
	sc, err := scope.Load(path)
	if err != nil {
		telemetry.Error("Could not read the scope file; auditing the whole repository", "SCOPE_LOAD_FAILED", map[string]interface{}{
			"job_id": job.ID.String(),
			"scope":  path,
			"error":  err.Error(),
		})
		return nil
	}
	return sc
}

// jobContext describes the audit program to the agents.
func (c *Coordinator) jobContext(root string, sc *scope.Scope, files []string, chunks []tools.Chunk) agents.JobContext {
	jc := agents.JobContext{}
	if sc == nil {
		return jc
	}
	jc.KnownIssues = sc.KnownIssues

	var note string
	if len(sc.Include) > 0 {
		note += fmt.Sprintf("Only these paths are in scope: %s.\n", strings.Join(sc.Include, ", "))
	}
	if len(sc.Exclude) > 0 {
		note += fmt.Sprintf("These paths are explicitly out of scope and must not be reported on: %s.\n", strings.Join(sc.Exclude, ", "))
	}
	note += fmt.Sprintf("The audit surface is %d files, read in %d batches. Report only on code you have seen in the source you were given.", len(files), len(chunks))
	jc.ScopeNote = note

	kind := tools.DescribeProject(root, files)
	if kind.Language != "" {
		jc.TargetNote = fmt.Sprintf("Language: %s. Build tool: %s. The project's own tests live in %s/ and are run with `%s`. A validation plan that proves a finding must use that toolchain.",
			kind.Language, kind.BuildTool, kind.TestDir, kind.TestCommand)
	}
	return jc
}

// candidateContext returns the source of the file a candidate points at. The Investigator and
// the Reviewer have to reason about the code itself: at the scale of a real program, a single
// shared excerpt of the whole repository would not even contain the file they are judging.
func (c *Coordinator) candidateContext(job *domain.ResearchJob, files []string, cand *domain.Candidate) string {
	if cand == nil {
		return ""
	}
	rel := tools.ResolveScopedPath(files, cand.RepositoryPath)
	if rel == "" {
		rel = cand.RepositoryPath
	}
	ctx := tools.FileContextForSymbol(job.RepositoryRef, rel, cand.LineStart, cand.LineEnd, cand.Symbol, c.cfg.Research.AgentContextBytes)
	if ctx == "" {
		return fmt.Sprintf("The source of %s could not be read.", rel)
	}
	return ctx
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
func (c *Coordinator) investigate(ctx context.Context, jobID uuid.UUID, cand *domain.Candidate, previous *domain.Hypothesis, feedback *domain.ReviewResult, contextSnippet string, jc agents.JobContext) (*domain.Hypothesis, error) {
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
		hyp, _, err = c.investigator.FormulateHypothesis(ctx, cand, contextSnippet, jc)
	} else {
		hyp, _, err = c.investigator.ReviseHypothesis(ctx, cand, previous, feedback, contextSnippet, jc)
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
func (c *Coordinator) review(ctx context.Context, jobID uuid.UUID, hyp *domain.Hypothesis, primarySourceContext string, jc agents.JobContext) (*domain.ReviewResult, error) {
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

	review, _, err := c.reviewer.ReviewHypothesis(ctx, hyp, primarySourceContext, jc)
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
