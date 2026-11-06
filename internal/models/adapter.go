package models

import (
	"context"
	"fmt"
	"time"
)

// ModelRequest encapsulates a prompt request to a model.
type ModelRequest struct {
	Role            string
	SystemPrompt    string
	Input           string
	MaxOutputTokens int
	Temperature     float64
	ResponseSchema  string
}

// ModelResponse captures the raw generation output along with provenance and usage metadata.
type ModelResponse struct {
	Content      string
	ModelID      string
	Provider     string
	InputTokens  int
	OutputTokens int
	DurationMS   int64
}

// ModelAdapter decouples the agent orchestration logic from any specific inference provider.
type ModelAdapter interface {
	Generate(ctx context.Context, req ModelRequest) (ModelResponse, error)
	Health(ctx context.Context) error
}

// FakeAdapter provides deterministic responses for CI and hermetic unit/integration tests.
type FakeAdapter struct {
	ModelID          string
	ProviderName     string
	ResponseQueue    []ModelResponse
	ResponseFn       func(req ModelRequest) (ModelResponse, error)
	HealthErr        error
	ReceivedRequests []ModelRequest
}

func NewFakeAdapter(modelID string) *FakeAdapter {
	return &FakeAdapter{
		ModelID:      modelID,
		ProviderName: "fake-provider",
	}
}

func (f *FakeAdapter) Generate(ctx context.Context, req ModelRequest) (ModelResponse, error) {
	f.ReceivedRequests = append(f.ReceivedRequests, req)

	if f.ResponseFn != nil {
		return f.ResponseFn(req)
	}

	if len(f.ResponseQueue) > 0 {
		resp := f.ResponseQueue[0]
		f.ResponseQueue = f.ResponseQueue[1:]
		if resp.ModelID == "" {
			resp.ModelID = f.ModelID
		}
		if resp.Provider == "" {
			resp.Provider = f.ProviderName
		}
		return resp, nil
	}

	// Default dummy response
	return ModelResponse{
		Content:      `{"status":"ok"}`,
		ModelID:      f.ModelID,
		Provider:     f.ProviderName,
		InputTokens:  10,
		OutputTokens: 10,
		DurationMS:   1,
	}, nil
}

func (f *FakeAdapter) Health(ctx context.Context) error {
	return f.HealthErr
}

func (f *FakeAdapter) EnqueueResponse(content string, inputTokens, outputTokens int) {
	f.ResponseQueue = append(f.ResponseQueue, ModelResponse{
		Content:      content,
		ModelID:      f.ModelID,
		Provider:     f.ProviderName,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		DurationMS:   time.Now().UnixMilli(),
	})
}

// Registry manages and provides role-configured model adapters.
type Registry struct {
	adapters map[string]ModelAdapter
}

func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]ModelAdapter),
	}
}

func (r *Registry) Register(role string, adapter ModelAdapter) {
	r.adapters[role] = adapter
}

func (r *Registry) ForRole(role string) (ModelAdapter, error) {
	adapter, exists := r.adapters[role]
	if !exists {
		return nil, fmt.Errorf("no model adapter registered for role: %s", role)
	}
	return adapter, nil
}
