package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stripAnnotations removes keys that document a schema without constraining what it accepts
// (the validator does not assert "format" or read "description").
func stripAnnotations(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range x {
			if k == "format" || k == "description" {
				continue
			}
			out[k] = stripAnnotations(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = stripAnnotations(val)
		}
		return out
	}
	return v
}

// The validator compiles its own copy of each schema, while schemas/*.json is what the
// README and prompts point people at. They must accept the same documents, or the docs lie.
func TestSchemaFilesMatchEmbeddedSchemas(t *testing.T) {
	embedded := map[string]string{
		"candidate":         candidateSchemaRaw,
		"hypothesis":        hypothesisSchemaRaw,
		"review":            reviewSchemaRaw,
		"validation-result": validationResultSchemaRaw,
	}
	for name, raw := range embedded {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "schemas", name+".schema.json")
			fileBytes, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("no standalone schema file for %q (%v)", name, err)
			}
			var fromFile, fromGo map[string]interface{}
			if err := json.Unmarshal(fileBytes, &fromFile); err != nil {
				t.Fatalf("%s is not valid JSON: %v", path, err)
			}
			if err := json.Unmarshal([]byte(raw), &fromGo); err != nil {
				t.Fatalf("embedded %s schema is not valid JSON: %v", name, err)
			}
			if !reflect.DeepEqual(stripAnnotations(fromFile), stripAnnotations(fromGo)) {
				t.Fatalf("%s differs from the schema compiled into internal/schema/validator.go; update both", path)
			}
		})
	}
}
