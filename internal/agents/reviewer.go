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

// ReviewerAgent independently critiques the Investigator's hypothesis.
type ReviewerAgent struct {
	Adapter      models.ModelAdapter
	SystemPrompt string
}

func NewReviewerAgent(adapter models.ModelAdapter, systemPrompt string) *ReviewerAgent {
	return &ReviewerAgent{
		Adapter:      adapter,
		SystemPrompt: systemPrompt,
	}
}

// ReviewHypothesis examines the hypothesis against primary source code and determines next action.
func (r *ReviewerAgent) ReviewHypothesis(ctx context.Context, hyp *domain.Hypothesis, primarySourceContext string, jc JobContext) (*domain.ReviewResult, models.ModelResponse, error) {
	hypJSON, _ := json.MarshalIndent(hyp, "", "  ")

	promptInput := fmt.Sprintf("Hypothesis under review:\n%s\n\nPrimary Source of the file under review (this is the only code you have):\n%s\n\nProvide an independent adversarial critique as JSON.", string(hypJSON), primarySourceContext)

	req := models.ModelRequest{
		Role:            "reviewer",
		SystemPrompt:    jc.preamble() + r.SystemPrompt,
		Input:           promptInput,
		MaxOutputTokens: 3000,
		Temperature:     0.1,
		ResponseSchema:  string(schema.KindReviewResult),
	}

	jsonBytes, resp, err := CallAndValidateRepairing(ctx, r.Adapter, req, schema.KindReviewResult,
		[]string{"supporting_points", "counterarguments", "missing_evidence", "falsification_tests"},
		map[string]string{"schema_version": "1.0"},
		[]string{"review_id", "hypothesis_id"})
	if err != nil {
		return nil, resp, fmt.Errorf("reviewer evaluation failed: %w", err)
	}

	var review domain.ReviewResult
	if err := json.Unmarshal(jsonBytes, &review); err != nil {
		return nil, resp, fmt.Errorf("failed to unmarshal review result: %w", err)
	}

	if review.ReviewID == uuid.Nil {
		review.ReviewID = uuid.New()
	}
	review.HypothesisID = hyp.HypothesisID

	return &review, resp, nil
}
