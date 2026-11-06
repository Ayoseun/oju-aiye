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

	"vuln-research/internal/telemetry"
)

// ModelProvisioner manages automatic model downloading and presence verification.
type ModelProvisioner struct {
	BaseURL string
	client  *http.Client
}

func NewModelProvisioner(baseURL string) *ModelProvisioner {
	cleanURL := strings.TrimRight(baseURL, "/")
	cleanURL = strings.TrimSuffix(cleanURL, "/v1")

	return &ModelProvisioner{
		BaseURL: cleanURL,
		client: &http.Client{
			Timeout: 30 * time.Minute, // Large timeout for model downloads
		},
	}
}

type pullRequest struct {
	Name   string `json:"name"`
	Stream bool   `json:"stream"`
}

type pullResponse struct {
	Status    string `json:"status"`
	Digest    string `json:"digest,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Completed int64  `json:"completed,omitempty"`
	Error     string `json:"error,omitempty"`
}

type tagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// IsModelAvailable checks if the model is already cached in the local inference engine.
func (p *ModelProvisioner) IsModelAvailable(ctx context.Context, modelName string) (bool, error) {
	endpoint := fmt.Sprintf("%s/api/tags", p.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to query available models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code querying models: %d", resp.StatusCode)
	}

	var tags tagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return false, err
	}

	for _, m := range tags.Models {
		if strings.EqualFold(m.Name, modelName) || strings.EqualFold(m.Name, modelName+":latest") {
			return true, nil
		}
	}

	return false, nil
}

// EnsureModelAvailable checks if the model is cached; if not, automatically downloads it into the engine.
func (p *ModelProvisioner) EnsureModelAvailable(ctx context.Context, modelName string) error {
	telemetry.Info(fmt.Sprintf("Checking local cache for model: %s", modelName), nil)

	available, err := p.IsModelAvailable(ctx, modelName)
	if err == nil && available {
		telemetry.Info(fmt.Sprintf("Model %s is already cached and ready.", modelName), nil)
		return nil
	}

	telemetry.Info(fmt.Sprintf("Model %s not found locally. Initiating automated download...", modelName), nil)

	endpoint := fmt.Sprintf("%s/api/pull", p.BaseURL)
	payload, _ := json.Marshal(pullRequest{Name: modelName, Stream: false})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("automated download failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var res pullResponse
	_ = json.Unmarshal(bodyBytes, &res)
	if res.Error != "" {
		return fmt.Errorf("model pull reported error: %s", res.Error)
	}

	telemetry.Info(fmt.Sprintf("Successfully downloaded and cached model: %s", modelName), nil)
	return nil
}
