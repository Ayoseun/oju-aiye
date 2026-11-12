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
	var (
		lastErr error
		resp    models.ModelResponse
	)
	for attempt := 0; attempt < scoutAttempts; attempt++ {
		cands, r, err := s.discoverOnce(ctx, repoRef, chunk, jc, attempt)
		resp = r
		if err == nil {
			return cands, resp, nil
		}
		lastErr = err
	}
	return nil, resp, lastErr
}

// scoutAttempts is how many times a batch is asked for. A model asked the same way
// twice can answer `{}` twice, so the later attempts carry a nudge.
const scoutAttempts = 3

func (s *ScoutAgent) discoverOnce(ctx context.Context, repoRef string, chunk SourceChunk, jc JobContext, attempt int) ([]*domain.Candidate, models.ModelResponse, error) {
	promptInput := fmt.Sprintf("Repository: %s\n\nFiles in this batch (%d of %d):\n%s\nSource Code Context:\n%s\n\nIdentify potential security candidates in this batch as JSON, at most %d of them. Report only candidates whose code you can actually see above.\n\nAnswer with one JSON object of this exact shape:\n{\"schema_version\":\"1.0\",\"candidates\":[{\"candidate_id\":\"c1\",\"repository_path\":\"<file above>\",\"symbol\":\"<function>\",\"line_start\":<int>,\"line_end\":<int>,\"suspected_class\":\"CWE-<id>\",\"rationale\":\"<one sentence>\",\"observed_facts\":[\"<fact from the code>\"],\"assumptions\":[\"<assumption>\"],\"suggested_next_steps\":[\"<next step>\"],\"confidence\":<0.0-1.0>}]}",
		repoRef, chunk.Index, chunk.Total, chunk.fileList(), chunk.Text, maxCandidatesPerChunk)

	if attempt > 0 {
		promptInput += fmt.Sprintf("\n\nYour previous answer (%d attempts ago) could not be read as a candidate list. Answer again with the JSON object above, filled in from the source code in this batch.", attempt)
	}

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

	// A batch holds one file more often than not, so a candidate that forgot the path
	// can be pointed at the file it was read from.
	onlyFile := ""
	if len(chunk.Files) == 1 {
		onlyFile = chunk.Files[0]
	}

	// One malformed candidate must not throw away the rest of the batch: a model that
	// gets one field wrong on one finding would otherwise lose every finding in the
	// batch. Candidates that do not satisfy the schema are skipped and counted.
	var candidates []*domain.Candidate
	var rejected int
	var firstRejection string
	var firstRejectedRaw string
	for _, rawItem := range rawItems {
		repaired := repairCandidate(rawItem, onlyFile)
		if err := schema.Validate(schema.KindCandidate, repaired); err != nil {
			rejected++
			if firstRejection == "" {
				firstRejection = err.Error()
				firstRejectedRaw = string(rawItem)
			}
			continue
		}
		var cand domain.Candidate
		if err := json.Unmarshal(repaired, &cand); err != nil {
			rejected++
			continue
		}
		if cand.CandidateID == uuid.Nil {
			cand.CandidateID = uuid.New()
		}
		candidates = append(candidates, &cand)
	}

	if len(candidates) == 0 && rejected == 0 {
		// The model looked at the batch and reported nothing. That is an answer, not
		// a failure.
		return candidates, resp, nil
	}

	if len(candidates) == 0 && rejected > 0 {
		return nil, resp, fmt.Errorf("no candidate in this batch satisfied the schema (%d rejected). First error: %s (content: %s)",
			rejected, firstRejection, truncate(firstRejectedRaw, 300))
	}

	return candidates, resp, nil
}

// repairCandidate fixes the fields a model commonly leaves empty: a missing path, a line
// number of zero, a missing list. The fields that carry the substance of a candidate
// (the rationale and the class) stay required.
func repairCandidate(raw json.RawMessage, onlyFile string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}

	changed := false
	setIfEmpty := func(key, value string) {
		current, ok := obj[key]
		if !ok {
			return
		}
		var s string
		if err := json.Unmarshal(current, &s); err != nil || s != "" {
			return
		}
		if encoded, err := json.Marshal(value); err == nil {
			obj[key] = encoded
			changed = true
		}
	}
	setIfEmpty("repository_path", onlyFile)
	setIfEmpty("symbol", "unknown")

	// Fields the model regularly leaves out entirely.
	if _, ok := obj["schema_version"]; !ok {
		if encoded, err := json.Marshal("1.0"); err == nil {
			obj["schema_version"] = encoded
			changed = true
		}
	}
	// The model writes "c1" where a UUID belongs. The schema accepts a string, but the
	// domain type is uuid.UUID, and the finding is lost when the two disagree.
	if ensureUUID(obj, "candidate_id") {
		changed = true
	}
	if _, ok := obj["confidence"]; !ok {
		obj["confidence"] = json.RawMessage("0.5")
		changed = true
	}

	// A line number of zero is not a line.
	for _, key := range []string{"line_start", "line_end"} {
		current, ok := obj[key]
		if !ok {
			continue
		}
		var n int
		if err := json.Unmarshal(current, &n); err == nil && n < 1 {
			obj[key] = json.RawMessage("1")
			changed = true
		}
	}

	for _, key := range []string{"observed_facts", "assumptions", "suggested_next_steps"} {
		if _, ok := obj[key]; !ok {
			obj[key] = json.RawMessage("[]")
			changed = true
		}
	}

	if !changed {
		return raw
	}
	repaired, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return repaired
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
// keys models use for it. An empty array is a valid answer: it means the model looked at
// the batch and found nothing worth reporting.
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
		if err := json.Unmarshal(raw, &list); err == nil {
			return list, true
		}
	}
	return nil, false
}
