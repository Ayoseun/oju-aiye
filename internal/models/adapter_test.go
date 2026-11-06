package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFakeAdapter(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeAdapter("mock-llama-3")

	fake.EnqueueResponse(`{"candidate_id":"test-1"}`, 50, 100)

	resp, err := fake.Generate(ctx, ModelRequest{
		Role:         "scout",
		SystemPrompt: "You are a scout.",
		Input:        "Inspect this code.",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Content != `{"candidate_id":"test-1"}` {
		t.Errorf("unexpected content: %s", resp.Content)
	}
	if resp.InputTokens != 50 || resp.OutputTokens != 100 {
		t.Errorf("unexpected token counts: in=%d, out=%d", resp.InputTokens, resp.OutputTokens)
	}
	if resp.ModelID != "mock-llama-3" {
		t.Errorf("unexpected model id: %s", resp.ModelID)
	}

	if err := fake.Health(ctx); err != nil {
		t.Errorf("expected healthy fake adapter: %v", err)
	}
}

func TestRegistryForRole(t *testing.T) {
	reg := NewRegistry()
	scoutAdapter := NewFakeAdapter("scout-model")
	invAdapter := NewFakeAdapter("inv-model")

	reg.Register("scout", scoutAdapter)
	reg.Register("investigator", invAdapter)

	gotScout, err := reg.ForRole("scout")
	if err != nil || gotScout != scoutAdapter {
		t.Errorf("expected scout adapter, got err: %v", err)
	}

	gotInv, err := reg.ForRole("investigator")
	if err != nil || gotInv != invAdapter {
		t.Errorf("expected investigator adapter, got err: %v", err)
	}

	_, err = reg.ForRole("reviewer")
	if err == nil {
		t.Errorf("expected error for unregistered role reviewer, got nil")
	}
}

func TestOpenAICompatibleAdapter(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++

		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}

		if r.URL.Path == "/v1/chat/completions" {
			// Simulate transient 500 error on first attempt, then success
			if attempts == 1 {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			resp := chatCompletionResponse{
				Choices: []chatCompletionChoice{
					{Message: chatMessage{Role: "assistant", Content: `{"result":"vulnerable"}`}},
				},
				Usage: chatCompletionUsage{
					PromptTokens:     120,
					CompletionTokens: 45,
					TotalTokens:      165,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := NewOpenAICompatibleAdapter(OpenAICompatibleConfig{
		BaseURL:      server.URL,
		APIKey:       "secret-token",
		ModelID:      "qwen2.5-coder:32b",
		Timeout:      5 * time.Second,
		MaxRetries:   2,
		ProviderName: "test-server",
	})

	if err := adapter.Health(ctx); err != nil {
		t.Fatalf("health check failed: %v", err)
	}

	resp, err := adapter.Generate(ctx, ModelRequest{
		Role:         "investigator",
		SystemPrompt: "System instructions",
		Input:        "Input code",
	})
	if err != nil {
		t.Fatalf("expected successful generation with retry, got: %v", err)
	}

	if resp.Content != `{"result":"vulnerable"}` {
		t.Errorf("unexpected content: %s", resp.Content)
	}
	if resp.InputTokens != 120 || resp.OutputTokens != 45 {
		t.Errorf("unexpected usage counts: in=%d, out=%d", resp.InputTokens, resp.OutputTokens)
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts due to simulated transient error, got %d", attempts)
	}
}
