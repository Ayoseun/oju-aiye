package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// SchemaKind identifies supported contract schemas.
type SchemaKind string

const (
	KindCandidate        SchemaKind = "candidate"
	KindHypothesis       SchemaKind = "hypothesis"
	KindReviewResult     SchemaKind = "review_result"
	KindValidationResult SchemaKind = "validation_result"
)

var (
	compilerMu sync.Mutex
	schemas    = map[SchemaKind]*jsonschema.Schema{}
)

// Schema raw JSON definitions
const (
	candidateSchemaRaw = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Candidate",
  "type": "object",
  "required": [
    "schema_version",
    "candidate_id",
    "repository_path",
    "symbol",
    "line_start",
    "line_end",
    "suspected_class",
    "rationale",
    "observed_facts",
    "assumptions",
    "suggested_next_steps",
    "confidence"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "candidate_id": { "type": "string" },
    "repository_path": { "type": "string", "minLength": 1 },
    "symbol": { "type": "string" },
    "line_start": { "type": "integer", "minimum": 1 },
    "line_end": { "type": "integer", "minimum": 1 },
    "suspected_class": { "type": "string", "minLength": 1 },
    "rationale": { "type": "string", "minLength": 1 },
    "observed_facts": { "type": "array", "items": { "type": "string" } },
    "assumptions": { "type": "array", "items": { "type": "string" } },
    "suggested_next_steps": { "type": "array", "items": { "type": "string" } },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
  },
  "additionalProperties": false
}`

	hypothesisSchemaRaw = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Hypothesis",
  "type": "object",
  "required": [
    "schema_version",
    "hypothesis_id",
    "candidate_id",
    "title",
    "weakness",
    "affected_locations",
    "security_invariant",
    "preconditions",
    "attacker_controlled_inputs",
    "expected_failure",
    "impact",
    "supporting_evidence_ids",
    "counterarguments",
    "validation_plan",
    "status"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "hypothesis_id": { "type": "string" },
    "candidate_id": { "type": "string" },
    "title": { "type": "string", "minLength": 1 },
    "weakness": {
      "type": "object",
      "required": ["cwe", "category"],
      "properties": {
        "cwe": { "type": "string", "minLength": 1 },
        "category": { "type": "string", "minLength": 1 }
      },
      "additionalProperties": false
    },
    "affected_locations": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["path", "symbol", "line_start", "line_end"],
        "properties": {
          "path": { "type": "string", "minLength": 1 },
          "symbol": { "type": "string" },
          "line_start": { "type": "integer", "minimum": 1 },
          "line_end": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
      }
    },
    "security_invariant": { "type": "string", "minLength": 1 },
    "preconditions": { "type": "array", "items": { "type": "string" } },
    "attacker_controlled_inputs": { "type": "array", "items": { "type": "string" } },
    "expected_failure": { "type": "string", "minLength": 1 },
    "impact": { "type": "string", "minLength": 1 },
    "supporting_evidence_ids": { "type": "array", "items": { "type": "string" } },
    "counterarguments": { "type": "array", "items": { "type": "string" } },
    "validation_plan": { "type": "array", "items": { "type": "string" } },
    "status": {
      "type": "string",
      "enum": ["proposed", "under_review", "ready_for_validation", "confirmed", "refuted", "inconclusive", "needs_more_evidence"]
    }
  },
  "additionalProperties": false
}`

	reviewSchemaRaw = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ReviewResult",
  "type": "object",
  "required": [
    "schema_version",
    "review_id",
    "hypothesis_id",
    "decision",
    "supporting_points",
    "counterarguments",
    "missing_evidence",
    "falsification_tests",
    "rationale",
    "reviewer_model"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "review_id": { "type": "string" },
    "hypothesis_id": { "type": "string" },
    "decision": {
      "type": "string",
      "enum": ["accept_for_validation", "request_more_evidence", "reject_hypothesis"]
    },
    "supporting_points": { "type": "array", "items": { "type": "string" } },
    "counterarguments": { "type": "array", "items": { "type": "string" } },
    "missing_evidence": { "type": "array", "items": { "type": "string" } },
    "falsification_tests": { "type": "array", "items": { "type": "string" } },
    "rationale": { "type": "string", "minLength": 1 },
    "reviewer_model": { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}`

	validationResultSchemaRaw = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ValidationResult",
  "type": "object",
  "required": [
    "schema_version",
    "validation_id",
    "hypothesis_id",
    "environment_id",
    "test_command_id",
    "exit_code",
    "outcome",
    "stdout_artifact",
    "stderr_artifact",
    "test_artifact",
    "environment_fingerprint",
    "notes"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "validation_id": { "type": "string" },
    "hypothesis_id": { "type": "string" },
    "environment_id": { "type": "string" },
    "test_command_id": { "type": "string", "minLength": 1 },
    "exit_code": { "type": "integer" },
    "outcome": {
      "type": "string",
      "enum": ["reproduced", "refuted", "inconclusive", "setup_failed"]
    },
    "stdout_artifact": { "type": "string" },
    "stderr_artifact": { "type": "string" },
    "test_artifact": { "type": "string" },
    "environment_fingerprint": { "type": "string" },
    "notes": { "type": "string" }
  },
  "additionalProperties": false
}`
)

func init() {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020

	raws := map[SchemaKind]string{
		KindCandidate:        candidateSchemaRaw,
		KindHypothesis:       hypothesisSchemaRaw,
		KindReviewResult:     reviewSchemaRaw,
		KindValidationResult: validationResultSchemaRaw,
	}

	for kind, raw := range raws {
		url := fmt.Sprintf("%s.json", kind)
		if err := compiler.AddResource(url, bytes.NewReader([]byte(raw))); err != nil {
			panic(fmt.Sprintf("failed to add schema resource for %s: %v", kind, err))
		}
		sch, err := compiler.Compile(url)
		if err != nil {
			panic(fmt.Sprintf("failed to compile schema for %s: %v", kind, err))
		}
		schemas[kind] = sch
	}
}

// Validate validates arbitrary JSON bytes against the given SchemaKind.
func Validate(kind SchemaKind, jsonBytes []byte) error {
	compilerMu.Lock()
	sch, ok := schemas[kind]
	compilerMu.Unlock()

	if !ok {
		return fmt.Errorf("unrecognized schema kind: %s", kind)
	}

	var v interface{}
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}

	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("schema validation failure for %s: %w", kind, err)
	}
	return nil
}
