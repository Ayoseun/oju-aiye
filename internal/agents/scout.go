package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/schema"
)

// ScoutAgent discovers candidate vulnerability paths in target source code.
type ScoutAgent struct {
	Adapter      models.ModelAdapter
	SystemPrompt string
}

func NewScoutAgent(adapter models.ModelAdapter, systemPrompt string) *ScoutAgent {
	return &ScoutAgent{
		Adapter:      adapter,
		SystemPrompt: systemPrompt,
	}
}

// DiscoverCandidates scans provided file snippets and returns validated candidates.
func (s *ScoutAgent) DiscoverCandidates(ctx context.Context, repoRef string, filesContext string) ([]*domain.Candidate, models.ModelResponse, error) {
	promptInput := fmt.Sprintf("Repository: %s\n\nSource Code Context:\n%s\n\nIdentify potential security candidates as JSON.", repoRef, filesContext)

	req := models.ModelRequest{
		Role:            "scout",
		SystemPrompt:    s.SystemPrompt,
		Input:           promptInput,
		MaxOutputTokens: 2500,
		Temperature:     0.1,
		ResponseSchema:  string(schema.KindCandidate),
	}

	resp, err := s.Adapter.Generate(ctx, req)
	if err != nil {
		return nil, resp, fmt.Errorf("scout model generation failed: %w", err)
	}

	cleanJSON := ExtractJSON(resp.Content)

	// Could be an array of candidates or a single candidate object
	var candidates []*domain.Candidate

	if strings.HasPrefix(cleanJSON, "[") {
		var rawList []json.RawMessage
		if err := json.Unmarshal([]byte(cleanJSON), &rawList); err != nil {
			return nil, resp, fmt.Errorf("failed to unmarshal candidate array: %w", err)
		}
		for _, rawItem := range rawList {
			if err := schema.Validate(schema.KindCandidate, rawItem); err != nil {
				return nil, resp, fmt.Errorf("candidate in array failed schema validation: %w", err)
			}
			var cand domain.Candidate
			if err := json.Unmarshal(rawItem, &cand); err != nil {
				return nil, resp, err
			}
			if cand.CandidateID == uuid.Nil {
				cand.CandidateID = uuid.New()
			}
			candidates = append(candidates, &cand)
		}
	} else {
		// Single candidate
		if err := schema.Validate(schema.KindCandidate, []byte(cleanJSON)); err != nil {
			return nil, resp, fmt.Errorf("candidate object failed schema validation: %w", err)
		}
		var cand domain.Candidate
		if err := json.Unmarshal([]byte(cleanJSON), &cand); err != nil {
			return nil, resp, err
		}
		if cand.CandidateID == uuid.Nil {
			cand.CandidateID = uuid.New()
		}
		candidates = append(candidates, &cand)
	}

	return candidates, resp, nil
}
