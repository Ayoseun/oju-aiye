// Package replay implements a tiny OpenAI-compatible chat server that answers each
// agent role with a canned JSON file. It lets the whole pipeline (real HTTP adapter,
// schema validation, validation runner, reports) run without a GPU or a real model.
package replay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// Server serves <scenarioDir>/{scout,investigator,reviewer}.json as model replies.
// Any "{{uuid}}" in a file is replaced with a fresh UUID on every reply.
type Server struct {
	replies map[string]string
	mu      sync.Mutex
	counts  map[string]int
}

var roles = []string{"scout", "investigator", "reviewer"}

// New loads a scenario directory.
func New(scenarioDir string) (*Server, error) {
	s := &Server{replies: map[string]string{}, counts: map[string]int{}}
	for _, role := range roles {
		b, err := os.ReadFile(filepath.Join(scenarioDir, role+".json"))
		if err != nil {
			return nil, fmt.Errorf("scenario %q: %w", scenarioDir, err)
		}
		if !json.Valid([]byte(strings.ReplaceAll(string(b), "{{uuid}}", "00000000-0000-0000-0000-000000000000"))) {
			return nil, fmt.Errorf("scenario %q: %s.json is not valid JSON", scenarioDir, role)
		}
		s.replies[role] = string(b)
	}
	return s, nil
}

// Count reports how many times a role has been asked for a reply.
func (s *Server) Count(role string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[role]
}

// roleOf identifies the calling agent from the fixed phrases the agents put in the user message.
func roleOf(userMsg string) string {
	switch {
	case strings.Contains(userMsg, "Identify potential security candidates"):
		return "scout"
	case strings.Contains(userMsg, "Formulate a structured hypothesis"):
		return "investigator"
	case strings.Contains(userMsg, "independent adversarial critique"):
		return "reviewer"
	}
	return ""
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]string{{"id": "replay"}}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		s.chat(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
		return
	}
	var user string
	for _, m := range req.Messages {
		if m.Role == "user" {
			user = m.Content
		}
	}
	role := roleOf(user)
	if role == "" {
		http.Error(w, `{"error":{"message":"replay: could not tell which agent is calling"}}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.counts[role]++
	s.mu.Unlock()

	content := s.replies[role]
	for strings.Contains(content, "{{uuid}}") {
		content = strings.Replace(content, "{{uuid}}", uuid.NewString(), 1)
	}
	fmt.Fprintf(os.Stderr, "replay: %s reply (%d bytes)\n", role, len(content))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":     "replay-" + uuid.NewString(),
		"object": "chat.completion",
		"model":  req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": content},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{"prompt_tokens": len(user) / 4, "completion_tokens": len(content) / 4, "total_tokens": (len(user) + len(content)) / 4},
	})
}
