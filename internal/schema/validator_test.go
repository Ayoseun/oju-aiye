package schema

import (
	"testing"
)

func TestValidateCandidate(t *testing.T) {
	validCandidate := []byte(`{
		"schema_version": "1.0",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"repository_path": "src/auth/session.go",
		"symbol": "ValidateSession",
		"line_start": 40,
		"line_end": 92,
		"suspected_class": "CWE-287",
		"rationale": "The code path may accept a session without validating its binding.",
		"observed_facts": ["Session token accepted without signature check"],
		"assumptions": ["Caller passes unverified cookie"],
		"suggested_next_steps": ["Check caller validation in router"],
		"confidence": 0.85
	}`)

	if err := Validate(KindCandidate, validCandidate); err != nil {
		t.Fatalf("expected valid candidate to pass validation, got: %v", err)
	}

	invalidCandidateMissingField := []byte(`{
		"schema_version": "1.0",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"repository_path": "src/auth/session.go"
	}`)

	if err := Validate(KindCandidate, invalidCandidateMissingField); err == nil {
		t.Fatalf("expected invalid candidate to fail validation, got nil")
	}

	invalidCandidateConfidenceRange := []byte(`{
		"schema_version": "1.0",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"repository_path": "src/auth/session.go",
		"symbol": "ValidateSession",
		"line_start": 40,
		"line_end": 92,
		"suspected_class": "CWE-287",
		"rationale": "Missing check",
		"observed_facts": [],
		"assumptions": [],
		"suggested_next_steps": [],
		"confidence": 1.5
	}`)

	if err := Validate(KindCandidate, invalidCandidateConfidenceRange); err == nil {
		t.Fatalf("expected confidence > 1.0 to fail validation, got nil")
	}
}

func TestValidateHypothesis(t *testing.T) {
	validHypothesis := []byte(`{
		"schema_version": "1.0",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"title": "Unauthenticated session reuse allows account takeover",
		"weakness": {
			"cwe": "CWE-287",
			"category": "authentication"
		},
		"affected_locations": [
			{
				"path": "src/auth/session.go",
				"symbol": "ValidateSession",
				"line_start": 40,
				"line_end": 92
			}
		],
		"security_invariant": "A session token must only authenticate the account for which it was signed.",
		"preconditions": ["Attacker has observed any previously expired token"],
		"attacker_controlled_inputs": ["X-Session-ID header"],
		"expected_failure": "Session accepted as valid for root account",
		"impact": "Complete authentication bypass",
		"supporting_evidence_ids": ["ev-1", "ev-2"],
		"counterarguments": ["Middleware might filter bad tokens"],
		"validation_plan": ["Run test TestSessionReplay"],
		"status": "proposed"
	}`)

	if err := Validate(KindHypothesis, validHypothesis); err != nil {
		t.Fatalf("expected valid hypothesis to pass validation, got: %v", err)
	}

	invalidStatus := []byte(`{
		"schema_version": "1.0",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"candidate_id": "a0000000-0000-0000-0000-000000000001",
		"title": "Title",
		"weakness": { "cwe": "CWE-287", "category": "auth" },
		"affected_locations": [{ "path": "a.go", "symbol": "foo", "line_start": 1, "line_end": 10 }],
		"security_invariant": "inv",
		"preconditions": [],
		"attacker_controlled_inputs": [],
		"expected_failure": "fail",
		"impact": "impact",
		"supporting_evidence_ids": [],
		"counterarguments": [],
		"validation_plan": [],
		"status": "invalid_status_enum"
	}`)

	if err := Validate(KindHypothesis, invalidStatus); err == nil {
		t.Fatalf("expected invalid status enum to fail validation, got nil")
	}
}

func TestValidateReviewResult(t *testing.T) {
	validReview := []byte(`{
		"schema_version": "1.0",
		"review_id": "c0000000-0000-0000-0000-000000000003",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"decision": "accept_for_validation",
		"supporting_points": ["Token signature check is indeed bypassed when header is missing"],
		"counterarguments": ["None observed in caller chain"],
		"missing_evidence": [],
		"falsification_tests": ["Send expired token with empty signature"],
		"rationale": "High confidence based on code inspection at session.go:65",
		"reviewer_model": "test-reviewer-model"
	}`)

	if err := Validate(KindReviewResult, validReview); err != nil {
		t.Fatalf("expected valid review to pass validation, got: %v", err)
	}
}

func TestValidateValidationResult(t *testing.T) {
	validValidation := []byte(`{
		"schema_version": "1.0",
		"validation_id": "d0000000-0000-0000-0000-000000000004",
		"hypothesis_id": "b0000000-0000-0000-0000-000000000002",
		"environment_id": "e0000000-0000-0000-0000-000000000005",
		"test_command_id": "go_test_session_replay",
		"exit_code": 0,
		"outcome": "reproduced",
		"stdout_artifact": "artifact://stdout-1",
		"stderr_artifact": "artifact://stderr-1",
		"test_artifact": "artifact://test-patch-1",
		"environment_fingerprint": "sha256:abcd1234abcd1234",
		"notes": "Session replay successfully authenticated as admin"
	}`)

	if err := Validate(KindValidationResult, validValidation); err != nil {
		t.Fatalf("expected valid validation result to pass validation, got: %v", err)
	}
}
