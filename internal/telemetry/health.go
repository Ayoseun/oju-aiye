package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// HealthChecker checks readiness of a sub-component.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// HealthService manages liveness and readiness probes.
type HealthService struct {
	mu       sync.RWMutex
	checkers map[string]HealthChecker
}

func NewHealthService() *HealthService {
	return &HealthService{
		checkers: make(map[string]HealthChecker),
	}
}

func (h *HealthService) Register(name string, checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

// LiveHandler returns HTTP 200 indicating process liveness.
func (h *HealthService) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "alive",
		})
	}
}

// ReadyHandler evaluates registered component checkers and returns status.
func (h *HealthService) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		h.mu.RLock()
		checkers := make(map[string]HealthChecker, len(h.checkers))
		for k, v := range h.checkers {
			checkers[k] = v
		}
		h.mu.RUnlock()

		details := make(map[string]string)
		allHealthy := true

		for name, checker := range checkers {
			if err := checker.Health(ctx); err != nil {
				allHealthy = false
				details[name] = err.Error()
			} else {
				details[name] = "ok"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		status := "ready"
		code := http.StatusOK
		if !allHealthy {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     status,
			"components": details,
		})
	}
}
