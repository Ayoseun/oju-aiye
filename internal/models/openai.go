package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// OpenAICompatibleConfig defines parameters for an OpenAI-compatible endpoint.
type OpenAICompatibleConfig struct {
	BaseURL       string
	APIKey        string
	ModelID       string
	Timeout       time.Duration
	MaxRetries    int
	ProviderName  string
	UseJSONFormat bool
	// RetryBaseDelay is the wait before the first retry; each further retry doubles it.
	// Free and shared endpoints rate-limit hard, so this is deliberately generous.
	RetryBaseDelay time.Duration
	// RetryMaxDelay caps a single wait between attempts.
	RetryMaxDelay time.Duration
	// ReasoningEffort is passed through to providers that support it ("none", "low", ...).
	// It is empty by default: not every endpoint accepts the parameter, and some reject
	// unknown values, so it is only sent when the operator asks for it.
	ReasoningEffort string
}

// OpenAICompatibleAdapter communicates with any OpenAI-compatible HTTP inference API.
type OpenAICompatibleAdapter struct {
	cfg    OpenAICompatibleConfig
	client *http.Client
}

func NewOpenAICompatibleAdapter(cfg OpenAICompatibleConfig) *OpenAICompatibleAdapter {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.ProviderName == "" {
		cfg.ProviderName = "openai-compatible"
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 2 * time.Second
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = 60 * time.Second
	}
	// Trim trailing slash on BaseURL
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &OpenAICompatibleAdapter{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatCompletionRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float64         `json:"temperature"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
	// ReasoningEffort is only set when the operator configured it, because endpoints
	// that do not know the parameter reject the whole request.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

type chatCompletionChoice struct {
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatCompletionResponse struct {
	Choices []chatCompletionChoice `json:"choices"`
	Usage   chatCompletionUsage    `json:"usage"`
	Error   *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (a *OpenAICompatibleAdapter) Generate(ctx context.Context, req ModelRequest) (ModelResponse, error) {
	start := time.Now()

	messages := []chatMessage{
		{Role: "system", Content: req.SystemPrompt},
		{Role: "user", Content: req.Input},
	}

	payload := chatCompletionRequest{
		Model:           a.cfg.ModelID,
		Messages:        messages,
		Temperature:     req.Temperature,
		MaxTokens:       req.MaxOutputTokens,
		ReasoningEffort: a.cfg.ReasoningEffort,
	}

	if a.cfg.UseJSONFormat || req.ResponseSchema != "" {
		payload.ResponseFormat = &responseFormat{Type: "json_object"}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return ModelResponse{}, fmt.Errorf("failed to marshal completion request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/chat/completions", a.cfg.BaseURL)
	if !strings.HasSuffix(a.cfg.BaseURL, "/v1") && !strings.Contains(a.cfg.BaseURL, "/v1") {
		endpoint = fmt.Sprintf("%s/v1/chat/completions", a.cfg.BaseURL)
	} else if strings.HasSuffix(a.cfg.BaseURL, "/v1") {
		endpoint = fmt.Sprintf("%s/chat/completions", a.cfg.BaseURL)
	}

	var lastErr error
	wait := a.cfg.RetryBaseDelay

	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ModelResponse{}, ctx.Err()
			case <-time.After(wait):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return ModelResponse{}, fmt.Errorf("failed to create http request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		if a.cfg.APIKey != "" {
			httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.cfg.APIKey))
		}

		resp, err := a.client.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("http request failed (attempt %d): %w", attempt+1, err)
			wait = a.nextRetryDelay(wait, "")
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		// Handle transient server errors with retries
		if isRetryableStatus(resp.StatusCode, respBytes) {
			lastErr = fmt.Errorf("transient http error code %d: %s", resp.StatusCode, string(respBytes))
			wait = a.nextRetryDelay(wait, resp.Header.Get("Retry-After"))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return ModelResponse{}, fmt.Errorf("inference api error (status %d): %s", resp.StatusCode, string(respBytes))
		}

		var parsed chatCompletionResponse
		if err := json.Unmarshal(respBytes, &parsed); err != nil {
			return ModelResponse{}, fmt.Errorf("failed to unmarshal api response: %w", err)
		}

		if parsed.Error != nil {
			return ModelResponse{}, fmt.Errorf("model error: %s", parsed.Error.Message)
		}

		if len(parsed.Choices) == 0 {
			return ModelResponse{}, fmt.Errorf("model returned empty choices list")
		}

		choice := parsed.Choices[0]
		result := ModelResponse{
			Content:      choice.Message.Content,
			ModelID:      a.cfg.ModelID,
			Provider:     a.cfg.ProviderName,
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
			DurationMS:   time.Since(start).Milliseconds(),
			FinishReason: choice.FinishReason,
		}

		// A truncated answer is not a malformed answer: the provider ran out of output budget
		// halfway through. Reporting it as such stops the agent from trying to parse half a
		// JSON object, and names the real cause.
		if result.Truncated() {
			return result, fmt.Errorf("model output was truncated by the provider (finish_reason=%s, %d completion tokens): the answer is incomplete and cannot be parsed or validated. Use a model or endpoint with a larger output budget, or ask for a shorter answer",
				result.FinishReason, result.OutputTokens)
		}

		return result, nil
	}

	return ModelResponse{}, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// isRetryableStatus reports whether a failed request is worth repeating. Shared and free
// endpoints signal a rate limit in several ways: 429, 5xx, and 402 with a limit-related body
// (Pollinations answers 402 FREE_LIMIT for its anonymous per-IP quota). Without the 402 case a
// single rate-limited call failed the whole audit.
//
// A 400 with code "output_token_limit_exceeded" is retryable too: the same model name can be
// served by several upstreams behind a free endpoint, and one of them can run a chatty
// reasoning variant that spends the whole budget without answering. Another attempt often
// lands on a different upstream.
func isRetryableStatus(status int, body []byte) bool {
	switch {
	case status == http.StatusTooManyRequests:
		return true
	case status >= 500 && status <= 599:
		return true
	case status == http.StatusPaymentRequired:
		lower := strings.ToLower(string(body))
		for _, marker := range []string{"free_limit", "free limit", "rate limit", "ratelimit", "too many requests", "retry after", "quota"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	case status == http.StatusBadRequest:
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "output_token_limit_exceeded") {
			return true
		}
	}
	return false
}

// nextRetryDelay doubles the wait between attempts and never waits less than the server asked
// for. It is capped so a single job cannot stall forever.
func (a *OpenAICompatibleAdapter) nextRetryDelay(current time.Duration, retryAfter string) time.Duration {
	next := current * 2
	if ra := parseRetryAfter(retryAfter); ra > next {
		next = ra
	}
	if next > a.cfg.RetryMaxDelay {
		next = a.cfg.RetryMaxDelay
	}
	return next
}

// parseRetryAfter reads a Retry-After header expressed in seconds.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

func (a *OpenAICompatibleAdapter) Health(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1/models", a.cfg.BaseURL)
	if strings.HasSuffix(a.cfg.BaseURL, "/v1") {
		endpoint = fmt.Sprintf("%s/models", a.cfg.BaseURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.cfg.APIKey))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check non-200 code: %d", resp.StatusCode)
	}
	return nil
}
