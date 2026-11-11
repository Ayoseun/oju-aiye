package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestOpenAICompatibleAdapterRetriesFreeLimit covers the free-tier rate limit that some
// endpoints report as 402 with a limit-related body (Pollinations answers 402 FREE_LIMIT).
// Before this was retryable, a single rate-limited call failed the whole audit.
func TestOpenAICompatibleAdapterRetriesFreeLimit(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusPaymentRequired)
			_, _ = w.Write([]byte(`{"error":{"code":"FREE_LIMIT","message":"Free limit reached: 1 reply every 45 seconds per IP. Retry after 29s"}}`))
			return
		}
		resp := chatCompletionResponse{
			Choices: []chatCompletionChoice{
				{Message: chatMessage{Role: "assistant", Content: `{"result":"ok"}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	adapter := NewOpenAICompatibleAdapter(OpenAICompatibleConfig{
		BaseURL:        server.URL,
		ModelID:        "openai-fast",
		Timeout:        5 * time.Second,
		MaxRetries:     2,
		ProviderName:   "test-server",
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  50 * time.Millisecond,
	})

	resp, err := adapter.Generate(ctx, ModelRequest{Role: "scout", Input: "code"})
	if err != nil {
		t.Fatalf("expected the 402 free limit to be retried, got: %v", err)
	}
	if resp.Content != `{"result":"ok"}` {
		t.Errorf("unexpected content: %s", resp.Content)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

// TestOpenAICompatibleAdapterDoesNotRetryPaymentRequired makes sure a genuine billing failure
// is reported instead of being retried into the ground.
func TestOpenAICompatibleAdapterDoesNotRetryPaymentRequired(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"message":"insufficient credits on your account"}}`))
	}))
	defer server.Close()

	adapter := NewOpenAICompatibleAdapter(OpenAICompatibleConfig{
		BaseURL:        server.URL,
		ModelID:        "paid-model",
		Timeout:        5 * time.Second,
		MaxRetries:     3,
		ProviderName:   "test-server",
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  50 * time.Millisecond,
	})

	if _, err := adapter.Generate(ctx, ModelRequest{Role: "scout", Input: "code"}); err == nil {
		t.Fatal("expected an error for an exhausted balance")
	}
	if attempts != 1 {
		t.Errorf("expected the request not to be retried, got %d attempts", attempts)
	}
}

func TestIsRetryableStatus(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{http.StatusTooManyRequests, "rate limited", true},
		{http.StatusInternalServerError, "boom", true},
		{http.StatusBadGateway, "", true},
		{http.StatusPaymentRequired, `{"error":{"code":"FREE_LIMIT"}}`, true},
		{http.StatusPaymentRequired, "Free limit reached. Retry after 29s", true},
		{http.StatusPaymentRequired, "insufficient credits", false},
		{http.StatusBadRequest, `{"code":"output_token_limit_exceeded"}`, true},
		{http.StatusBadRequest, "malformed request", false},
		{http.StatusUnauthorized, "bad key", false},
		{http.StatusBadRequest, "malformed request", false},
	}
	for _, c := range cases {
		if got := isRetryableStatus(c.status, []byte(c.body)); got != c.want {
			t.Errorf("isRetryableStatus(%d, %q) = %v, want %v", c.status, c.body, got, c.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("29"); got != 29*time.Second {
		t.Errorf("expected 29s, got %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("expected 0 for an empty header, got %v", got)
	}
	if got := parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"); got != 0 {
		t.Errorf("expected 0 for an http-date header, got %v", got)
	}
}

// TestOpenAICompatibleAdapterSendsReasoningEffort makes sure the parameter reaches the
// provider only when the operator asked for it: endpoints that do not know it reject the
// whole request.
func TestOpenAICompatibleAdapterSendsReasoningEffort(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name        string
		configured  string
		wantPresent bool
	}{
		{name: "not configured", configured: "", wantPresent: false},
		{name: "configured", configured: "none", wantPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&body)
				resp := chatCompletionResponse{
					Choices: []chatCompletionChoice{
						{Message: chatMessage{Role: "assistant", Content: `{}`}, FinishReason: "stop"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			adapter := NewOpenAICompatibleAdapter(OpenAICompatibleConfig{
				BaseURL:         server.URL,
				ModelID:         "gpt-oss-20b",
				Timeout:         5 * time.Second,
				ProviderName:    "test-server",
				ReasoningEffort: tc.configured,
			})
			if _, err := adapter.Generate(ctx, ModelRequest{Role: "scout", Input: "code"}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, present := body["reasoning_effort"]
			if present != tc.wantPresent {
				t.Errorf("reasoning_effort present = %v, want %v (body: %v)", present, tc.wantPresent, body)
			}
			if tc.wantPresent && body["reasoning_effort"] != tc.configured {
				t.Errorf("reasoning_effort = %v, want %q", body["reasoning_effort"], tc.configured)
			}
		})
	}
}

// TestOpenAICompatibleAdapterReportsTruncation covers a provider that stops at its output
// budget: the answer is half a JSON object. The adapter must say so, instead of letting the
// agent report a puzzling "malformed JSON".
func TestOpenAICompatibleAdapterReportsTruncation(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []chatCompletionChoice{
				{
					Message:      chatMessage{Role: "assistant", Content: `{"schema_version":"1.0","title":"cut off`},
					FinishReason: "length",
				},
			},
			Usage: chatCompletionUsage{PromptTokens: 100, CompletionTokens: 1500, TotalTokens: 1600},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	adapter := NewOpenAICompatibleAdapter(OpenAICompatibleConfig{
		BaseURL:      server.URL,
		ModelID:      "openai-fast",
		Timeout:      5 * time.Second,
		MaxRetries:   1,
		ProviderName: "test-server",
	})

	resp, err := adapter.Generate(ctx, ModelRequest{Role: "investigator", Input: "code"})
	if err == nil {
		t.Fatal("expected an error for a truncated answer")
	}
	if !resp.Truncated() {
		t.Error("expected the response to be flagged as truncated")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected the error to mention truncation, got: %v", err)
	}
}
