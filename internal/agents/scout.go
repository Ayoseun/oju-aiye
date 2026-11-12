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

// maxCandidatesPerChunk keeps one answer inside a small output budget. The Scout sees the
// whole target, one batch at a time, so the cap only limits how much it reports per call.
const maxCandidatesPerChunk = 3

func NewScoutAgent(adapter models.ModelAdapter, systemPrompt string) *ScoutAgent {
	return &ScoutAgent{
		Adapter:      adapter,
		SystemPrompt: systemPrompt,
	}
}

// DiscoverCandidates scans one chunk of the target and returns validated candidates.
// The target is split into chunks so a codebase larger than one model context is still
// read in full.
func (s *ScoutAgent) DiscoverCandidates(ctx context.Context, repoRef string, chunk SourceChunk, jc JobContext) ([]*domain.Candidate, models.ModelResponse, error) {
	promptInput := fmt.Sprintf("Repository: %s\n\nFiles in this batch (%d of %d):\n%s\nSource Code Context:\n%s\n\nIdentify potential security candidates in this batch as JSON, at most %d of them. Report only candidates whose code you can actually see above.",
		repoRef, chunk.Index, chunk.Total, chunk.fileList(), chunk.Text, maxCandidatesPerChunk)

	systemPrompt := jc.preamble() + s.SystemPrompt

	req := models.ModelRequest{
		Role:            "scout",
		SystemPrompt:    systemPrompt,
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

	// The model may answer with an array of candidates, a single candidate, or an object
	// wrapping the array under a key. All three are accepted.
	rawItems, err := candidateItems(cleanJSON)
	if err != nil {
		return nil, resp, err
	}

	// One malformed candidate must not throw away the rest of the batch: a model that
	// gets one field wrong on one finding would otherwise lose every finding in the
	// batch. Candidates that do not satisfy the schema are skipped and counted.
	var candidates []*domain.Candidate
	var rejected int
	for _, rawItem := range rawItems {
		if err := schema.Validate(schema.KindCandidate, rawItem); err != nil {
			rejected++
			continue
		}
		var cand domain.Candidate
		if err := json.Unmarshal(rawItem, &cand); err != nil {
			rejected++
			continue
		}
		if cand.CandidateID == uuid.Nil {
			cand.CandidateID = uuid.New()
		}
		candidates = append(candidates, &cand)
	}

	if len(candidates) == 0 && rejected > 0 {
		return nil, resp, fmt.Errorf("no candidate in this batch satisfied the schema (%d rejected)", rejected)
	}

	return candidates, resp, nil
}

// candidateItems pulls the candidate objects out of the model's answer, whatever shape it
// used: an array, a single object, or an object wrapping an array under a key.
func candidateItems(cleanJSON string) ([]json.RawMessage, error) {
	if strings.HasPrefix(cleanJSON, "[") {
		var rawList []json.RawMessage
		if err := json.Unmarshal([]byte(cleanJSON), &rawList); err != nil {
			return nil, fmt.Errorf("failed to unmarshal candidate array: %w", err)
		}
		return rawList, nil
	}

	if rawList, ok := wrappedCandidateList(cleanJSON); ok {
		return rawList, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cleanJSON), &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal candidate object: %w", err)
	}
	return []json.RawMessage{json.RawMessage(cleanJSON)}, nil
}

// wrappedCandidateList finds an array of candidates inside an object, under any of the
// keys models use for it.
func wrappedCandidateList(cleanJSON string) ([]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cleanJSON), &obj); err != nil {
		return nil, false
	}
	for _, key := range []string{"candidates", "results", "findings", "candidates_list"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
			return list, true
		}
	}
	return nil, false
}
