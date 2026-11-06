package agents

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
)

func TestScoutAgent(t *testing.T) {
	ctx := context.Background()
	fake := models.NewFakeAdapter("test-scout")

	fake.EnqueueResponse(`[
		{
			"schema_version": "1.0",
			"candidate_id": "a0000000-0000-0000-0000-000000000001",
			"repository_path": "src/token.sol",
			"symbol": "transfer",
			"line_start": 20,
			"line_end": 45,
			"suspected_class": "CWE-284",
			"rationale": "Missing authorization check on recipient",
			"observed_facts": ["No caller verification"],
			"assumptions": ["Recipient can be contract"],
			"suggested_next_steps": ["Check caller validation"],
			"confidence": 0.8
		}
	]`, 100, 50)

	scout := NewScoutAgent(fake, "Scout instructions")
	cands, resp, err := scout.DiscoverCandidates(ctx, "local://repo", "function transfer() {}")
	if err != nil {
		t.Fatalf("unexpected scout error: %v", err)
	}

	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if cands[0].Symbol != "transfer" {
		t.Errorf("expected symbol 'transfer', got '%s'", cands[0].Symbol)
	}
	if resp.InputTokens != 100 {
		t.Errorf("expected 100 input tokens, got %d", resp.InputTokens)
	}
}

func TestInvestigatorAgent(t *testing.T) {
	ctx := context.Background()
	fake := models.NewFakeAdapter("test-investigator")

	fake.EnqueueResponse(`{
		"schema_version": "1.0",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"title": "Unrestricted transfer allows unauthorized drain",
		"weakness": {
			"cwe": "CWE-284",
			"category": "access_control"
		},
		"affected_locations": [
			{
				"path": "src/token.sol",
				"symbol": "transfer",
				"line_start": 20,
				"line_end": 45
			}
		],
		"security_invariant": "Only token holder may transfer balance",
		"preconditions": ["Attacker has active account"],
		"attacker_controlled_inputs": ["recipient", "amount"],
		"expected_failure": "Tokens transferred without owner signature",
		"impact": "Drain user balance",
		"supporting_evidence_ids": [],
		"counterarguments": [],
		"validation_plan": ["Run test TestUnauthorizedTransfer"],
		"status": "proposed"
	}`, 150, 80)

	cand := &domain.Candidate{
		CandidateID:    uuid.New(),
		RepositoryPath: "src/token.sol",
		Symbol:         "transfer",
		LineStart:      20,
		LineEnd:        45,
	}

	inv := NewInvestigatorAgent(fake, "Investigator instructions")
	hyp, _, err := inv.FormulateHypothesis(ctx, cand, "function transfer() public {}")
	if err != nil {
		t.Fatalf("unexpected investigator error: %v", err)
	}

	if hyp.Title != "Unrestricted transfer allows unauthorized drain" {
		t.Errorf("unexpected hypothesis title: %s", hyp.Title)
	}
	if hyp.Weakness.CWE != "CWE-284" {
		t.Errorf("unexpected CWE: %s", hyp.Weakness.CWE)
	}
}

func TestReviewerAgent(t *testing.T) {
	ctx := context.Background()
	fake := models.NewFakeAdapter("test-reviewer")

	fake.EnqueueResponse(`{
		"schema_version": "1.0",
		"review_id": "c0000000-0000-0000-0000-000000000003",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"decision": "accept_for_validation",
		"supporting_points": ["Confirmed transfer lacks msg.sender assert"],
		"counterarguments": [],
		"missing_evidence": [],
		"falsification_tests": ["Execute transfer from unauthorized address"],
		"rationale": "High severity logic flaw",
		"reviewer_model": "test-reviewer"
	}`, 200, 100)

	hyp := &domain.Hypothesis{
		HypothesisID: uuid.New(),
		Title:        "Unrestricted transfer",
	}

	reviewer := NewReviewerAgent(fake, "Reviewer instructions")
	review, _, err := reviewer.ReviewHypothesis(ctx, hyp, "contract Token { function transfer() {} }")
	if err != nil {
		t.Fatalf("unexpected reviewer error: %v", err)
	}

	if review.Decision != domain.ReviewAcceptForValidation {
		t.Errorf("expected decision accept_for_validation, got %s", review.Decision)
	}
}
