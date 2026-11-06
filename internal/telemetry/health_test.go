package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockChecker struct {
	err error
}

func (m *mockChecker) Health(ctx context.Context) error {
	return m.err
}

func TestHealthEndpoints(t *testing.T) {
	hs := NewHealthService()

	// 1. Live probe
	reqLive := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	wLive := httptest.NewRecorder()
	hs.LiveHandler()(wLive, reqLive)

	if wLive.Code != http.StatusOK {
		t.Errorf("expected 200 for live probe, got %d", wLive.Code)
	}

	// 2. Ready probe with healthy component
	hs.Register("db", &mockChecker{err: nil})
	reqReady := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	wReady := httptest.NewRecorder()
	hs.ReadyHandler()(wReady, reqReady)

	if wReady.Code != http.StatusOK {
		t.Errorf("expected 200 for ready probe, got %d", wReady.Code)
	}

	// 3. Ready probe with failing component
	hs.Register("llm-scout", &mockChecker{err: errors.New("timeout connecting to model")})
	wDegraded := httptest.NewRecorder()
	hs.ReadyHandler()(wDegraded, reqReady)

	if wDegraded.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for degraded ready probe, got %d", wDegraded.Code)
	}

	var res map[string]interface{}
	_ = json.Unmarshal(wDegraded.Body.Bytes(), &res)
	if res["status"] != "degraded" {
		t.Errorf("expected status 'degraded', got %v", res["status"])
	}
}

func TestStructuredLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(buf)

	logger.Log(StructuredLog{
		Level:     LevelInfo,
		Message:   "job created",
		JobID:     "j-123",
		AgentRole: "coordinator",
	})

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse structured log json: %v", err)
	}

	if parsed["message"] != "job created" || parsed["job_id"] != "j-123" {
		t.Errorf("unexpected log output: %+v", parsed)
	}
}
