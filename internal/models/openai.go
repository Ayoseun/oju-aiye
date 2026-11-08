package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
}

type chatCompletionChoice struct {
	Message chatMessage `json:"message"`
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
		Model:       a.cfg.ModelID,
		Messages:    messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxOutputTokens,
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
	backoff := 500 * time.Millisecond

	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ModelResponse{}, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
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
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		// Handle transient server errors with retries
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
			lastErr = fmt.Errorf("transient http error code %d: %s", resp.StatusCode, string(respBytes))
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

		return ModelResponse{
			Content:      parsed.Choices[0].Message.Content,
			ModelID:      a.cfg.ModelID,
			Provider:     a.cfg.ProviderName,
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
			DurationMS:   time.Since(start).Milliseconds(),
		}, nil
	}

	return ModelResponse{}, fmt.Errorf("max retries exceeded: %w", lastErr)
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
