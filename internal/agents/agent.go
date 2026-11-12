package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"vuln-research/internal/models"
	"vuln-research/internal/schema"
)

// ExtractJSON strips markdown code fences (e.g. ```json ... ```) if present.
func ExtractJSON(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "```json") {
		trimmed = strings.TrimPrefix(trimmed, "```json")
		if idx := strings.LastIndex(trimmed, "```"); idx != -1 {
			trimmed = trimmed[:idx]
		}
	} else if strings.HasPrefix(trimmed, "```") {
		trimmed = strings.TrimPrefix(trimmed, "```")
		if idx := strings.LastIndex(trimmed, "```"); idx != -1 {
			trimmed = trimmed[:idx]
		}
	}
	return strings.TrimSpace(trimmed)
}

// CallAndValidate issues a ModelRequest, sanitizes JSON, and validates against the specified schema kind.
func CallAndValidate(ctx context.Context, adapter models.ModelAdapter, req models.ModelRequest, kind schema.SchemaKind) ([]byte, models.ModelResponse, error) {
	return CallAndValidateRepairing(ctx, adapter, req, kind, nil, nil)
}

// CallAndValidateRepairing is CallAndValidate with structural repair: missing boilerplate
// fields are filled in before the schema is applied, so a finding is not lost because the
// model left an empty list out.
func CallAndValidateRepairing(ctx context.Context, adapter models.ModelAdapter, req models.ModelRequest, kind schema.SchemaKind, arrays []string, strings map[string]string) ([]byte, models.ModelResponse, error) {
	resp, err := adapter.Generate(ctx, req)
	if err != nil {
		return nil, resp, fmt.Errorf("model generation failed: %w", err)
	}

	cleanJSON := ExtractJSON(resp.Content)
	jsonBytes := []byte(cleanJSON)

	if err := schema.Validate(kind, jsonBytes); err != nil && len(arrays)+len(strings) > 0 {
		repaired, repairErr := repair(jsonBytes, arrays, strings)
		if repairErr == nil {
			if repairedErr := schema.Validate(kind, repaired); repairedErr == nil {
				return repaired, resp, nil
			}
		}
	}

	if err := schema.Validate(kind, jsonBytes); err != nil {
		return nil, resp, fmt.Errorf("schema validation failure: %w (content: %s)", err, truncate(cleanJSON, 400))
	}

	return jsonBytes, resp, nil
}

// truncate keeps an error message readable when the model's answer was long.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

// UnmarshalJSON validates and unmarshals into the destination struct.
func UnmarshalJSON(jsonBytes []byte, dest interface{}) error {
	return json.Unmarshal(jsonBytes, dest)
}

// repair fills in the structural fields a model tends to leave out, so that a finding is
// not thrown away over an empty list. The fields that carry the substance of a finding
// (the invariant, the expected failure, the impact, the validation plan) stay required:
// a hypothesis without them is not a hypothesis.
func repair(jsonBytes []byte, arrays []string, strings map[string]string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return nil, err
	}

	for _, key := range arrays {
		if _, ok := obj[key]; ok {
			continue
		}
		obj[key] = json.RawMessage(`[]`)
	}
	for key, value := range strings {
		if _, ok := obj[key]; ok {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		obj[key] = encoded
	}

	return json.Marshal(obj)
}

// JobContext carries what the agents must know about the audit program beyond the code
// itself: which parts are in scope, and which findings are already known.
type JobContext struct {
	// ScopeNote describes the audit surface, so the agents do not report on excluded code.
	ScopeNote string
	// KnownIssues lists findings that are already public and therefore cannot be
	// rewarded. The agents are told to look for something else.
	KnownIssues string
	// TargetNote describes the project: its language and how its tests are run. A
	// model asked to write a test for a Solidity project without being told what
	// the project is will write a Go test for it.
	TargetNote string
}

// preamble renders the program context that is prepended to every agent prompt.
func (jc JobContext) preamble() string {
	var parts []string
	if jc.ScopeNote != "" {
		parts = append(parts, "## Scope of this audit\n"+jc.ScopeNote)
	}
	if jc.TargetNote != "" {
		parts = append(parts, "## The target\n"+jc.TargetNote)
	}
	if jc.KnownIssues != "" {
		parts = append(parts, "## Already known (not eligible for a reward)\n"+
			"These findings are already public. Do not report them again; look for a different "+
			"root cause, or a different weakness in the same code.\n\n"+jc.KnownIssues)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n\n") + "\n\n"
}

// SourceChunk is a batch of source files presented to an agent in one model call. A target
// larger than one model context is split into several chunks, so the whole codebase is read.
type SourceChunk struct {
	// Index is the position of this chunk in the target, starting at 1.
	Index int
	// Total is how many chunks the target was split into.
	Total int
	// Files are the repository-relative paths in this chunk.
	Files []string
	// Text is the rendered source of those files.
	Text string
}

// fileList renders the chunk's file list for a prompt.
func (c SourceChunk) fileList() string {
	var sb strings.Builder
	for _, f := range c.Files {
		sb.WriteString("- ")
		sb.WriteString(f)
		sb.WriteString("\n")
	}
	return sb.String()
}
