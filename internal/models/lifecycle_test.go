package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModelProvisioner(t *testing.T) {
	ctx := context.Background()
	pulled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			// Initially model is absent
			resp := tagsResponse{}
			if pulled {
				resp.Models = []struct {
					Name string `json:"name"`
				}{
					{Name: "qwen2.5-coder:7b"},
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if r.URL.Path == "/api/pull" {
			pulled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pullResponse{Status: "success"})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	prov := NewModelProvisioner(server.URL)

	// Before pull -> not available
	avail, err := prov.IsModelAvailable(ctx, "qwen2.5-coder:7b")
	if err != nil || avail {
		t.Fatalf("expected model to not be available yet, got avail=%v, err=%v", avail, err)
	}

	// Trigger automated download
	if err := prov.EnsureModelAvailable(ctx, "qwen2.5-coder:7b"); err != nil {
		t.Fatalf("EnsureModelAvailable failed: %v", err)
	}

	// Verify model is now recognized
	avail, err = prov.IsModelAvailable(ctx, "qwen2.5-coder:7b")
	if err != nil || !avail {
		t.Fatalf("expected model to be available after pull, got avail=%v, err=%v", avail, err)
	}
}
