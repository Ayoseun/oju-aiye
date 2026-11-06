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
	resp, err := adapter.Generate(ctx, req)
	if err != nil {
		return nil, resp, fmt.Errorf("model generation failed: %w", err)
	}

	cleanJSON := ExtractJSON(resp.Content)
	jsonBytes := []byte(cleanJSON)

	if err := schema.Validate(kind, jsonBytes); err != nil {
		return nil, resp, fmt.Errorf("schema validation failure: %w (content: %s)", err, cleanJSON)
	}

	return jsonBytes, resp, nil
}

// UnmarshalJSON validates and unmarshals into the destination struct.
func UnmarshalJSON(jsonBytes []byte, dest interface{}) error {
	return json.Unmarshal(jsonBytes, dest)
}
