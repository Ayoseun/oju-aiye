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
