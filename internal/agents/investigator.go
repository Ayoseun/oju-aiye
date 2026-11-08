package agents

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/schema"
)

// InvestigatorAgent analyzes a candidate in detail to formulate a falsifiable hypothesis.
type InvestigatorAgent struct {
	Adapter      models.ModelAdapter
	SystemPrompt string
}

func NewInvestigatorAgent(adapter models.ModelAdapter, systemPrompt string) *InvestigatorAgent {
	return &InvestigatorAgent{
		Adapter:      adapter,
		SystemPrompt: systemPrompt,
	}
}

// FormulateHypothesis evaluates the candidate within surrounding source context.
func (inv *InvestigatorAgent) FormulateHypothesis(ctx context.Context, candidate *domain.Candidate, contextSnippet string) (*domain.Hypothesis, models.ModelResponse, error) {
	candJSON, _ := json.MarshalIndent(candidate, "", "  ")

	promptInput := fmt.Sprintf("Candidate under analysis:\n%s\n\nSurrounding Source Context:\n%s\n\nFormulate a structured hypothesis as JSON.", string(candJSON), contextSnippet)

	req := models.ModelRequest{
		Role:            "investigator",
		SystemPrompt:    inv.SystemPrompt,
		Input:           promptInput,
		MaxOutputTokens: 4000,
		Temperature:     0.1,
		ResponseSchema:  string(schema.KindHypothesis),
	}

	jsonBytes, resp, err := CallAndValidate(ctx, inv.Adapter, req, schema.KindHypothesis)
	if err != nil {
		return nil, resp, fmt.Errorf("investigator analysis failed: %w", err)
	}

	var hypothesis domain.Hypothesis
	if err := json.Unmarshal(jsonBytes, &hypothesis); err != nil {
		return nil, resp, fmt.Errorf("failed to unmarshal hypothesis: %w", err)
	}

	if hypothesis.HypothesisID == uuid.Nil {
		hypothesis.HypothesisID = uuid.New()
	}
	hypothesis.CandidateID = candidate.CandidateID

	return &hypothesis, resp, nil
}

// ReviseHypothesis asks the Investigator to address a Reviewer's request for more evidence.
// It returns the same hypothesis (same ID), revised, so a finding evolves across rounds
// instead of spawning duplicates.
func (inv *InvestigatorAgent) ReviseHypothesis(ctx context.Context, candidate *domain.Candidate, previous *domain.Hypothesis, review *domain.ReviewResult, contextSnippet string) (*domain.Hypothesis, models.ModelResponse, error) {
	candJSON, _ := json.MarshalIndent(candidate, "", "  ")
	prevJSON, _ := json.MarshalIndent(previous, "", "  ")
	feedback, _ := json.MarshalIndent(map[string]interface{}{
		"decision":            review.Decision,
		"rationale":           review.Rationale,
		"counterarguments":    review.Counterarguments,
		"missing_evidence":    review.MissingEvidence,
		"falsification_tests": review.FalsificationTests,
	}, "", "  ")

	promptInput := fmt.Sprintf("Candidate under analysis:\n%s\n\nYour previous hypothesis:\n%s\n\nReviewer feedback (the Reviewer asked for more evidence):\n%s\n\nSurrounding Source Context:\n%s\n\nRevise the hypothesis to address the Reviewer's feedback: answer the counterarguments, supply the missing evidence, and make the validation_plan and failure_signature concrete. Return the full revised hypothesis as JSON using the same schema.",
		string(candJSON), string(prevJSON), string(feedback), contextSnippet)

	req := models.ModelRequest{
		Role:            "investigator",
		SystemPrompt:    inv.SystemPrompt,
		Input:           promptInput,
		MaxOutputTokens: 4000,
		Temperature:     0.1,
		ResponseSchema:  string(schema.KindHypothesis),
	}

	jsonBytes, resp, err := CallAndValidate(ctx, inv.Adapter, req, schema.KindHypothesis)
	if err != nil {
		return nil, resp, fmt.Errorf("investigator revision failed: %w", err)
	}

	var revised domain.Hypothesis
	if err := json.Unmarshal(jsonBytes, &revised); err != nil {
		return nil, resp, fmt.Errorf("failed to unmarshal revised hypothesis: %w", err)
	}

	revised.HypothesisID = previous.HypothesisID
	revised.CandidateID = candidate.CandidateID
	revised.Status = domain.HypothesisUnderReview
	return &revised, resp, nil
}
