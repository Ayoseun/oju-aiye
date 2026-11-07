package replay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ask(t *testing.T, s *Server, user string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"model": "m", "messages": []map[string]string{
		{"role": "system", "content": "sys"}, {"role": "user", "content": user}}})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body))))
	var out struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Choices) == 0 {
		return rec.Code, ""
	}
	return rec.Code, out.Choices[0].Message.Content
}

func TestRoleDetectionUUIDTemplatingAndCounts(t *testing.T) {
	s, err := New("../../testdata/scenarios/traversal")
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"Identify potential security candidates as JSON.":      "scout",
		"Formulate a structured hypothesis as JSON.":           "investigator",
		"Provide an independent adversarial critique as JSON.": "reviewer",
	}
	for prompt, role := range cases {
		code, content := ask(t, s, prompt)
		if code != http.StatusOK || !json.Valid([]byte(content)) {
			t.Fatalf("%s: code=%d valid=%v", role, code, json.Valid([]byte(content)))
		}
		if strings.Contains(content, "{{uuid}}") {
			t.Fatalf("%s: uuid placeholder not replaced", role)
		}
		if s.Count(role) != 1 {
			t.Fatalf("%s count = %d, want 1", role, s.Count(role))
		}
	}

	// Two replies for the same role must not reuse IDs (parallel jobs share one process).
	_, a := ask(t, s, "Identify potential security candidates as JSON.")
	_, b := ask(t, s, "Identify potential security candidates as JSON.")
	if a == b {
		t.Fatal("expected fresh UUIDs per reply")
	}

	if code, _ := ask(t, s, "something unrelated"); code != http.StatusBadRequest {
		t.Fatalf("unknown caller should get 400, got %d", code)
	}
}

func TestNewRejectsMissingScenario(t *testing.T) {
	if _, err := New(t.TempDir()); err == nil {
		t.Fatal("expected error for empty scenario dir")
	}
}
