package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/config"
	"vuln-research/internal/coordinator"
	"vuln-research/internal/domain"
	"vuln-research/internal/models"
	"vuln-research/internal/reports"
	"vuln-research/internal/store"
	"vuln-research/internal/telemetry"
	"vuln-research/internal/tools"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "Path to YAML configuration file")
	autoPull := flag.Bool("auto-pull", false, "Automatically pull configured models if missing from local engine")
	flag.Parse()

	if os.Getenv("AUTO_PULL_MODELS") == "true" {
		*autoPull = true
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Configuration error: %v\n", err)
		os.Exit(1)
	}

	telemetry.Info("Starting Autonomous Vulnerability Research Platform", map[string]interface{}{
		"env":  cfg.App.Environment,
		"port": cfg.App.HTTPPort,
	})

	s := store.NewMemoryStore()

	health := telemetry.NewHealthService()
	reg := models.NewRegistry()
	for role, mCfg := range cfg.Models {
		switch mCfg.Adapter {
		case "openai-compatible", "ollama":
			adapter := models.NewOpenAICompatibleAdapter(models.OpenAICompatibleConfig{
				BaseURL:      mCfg.BaseURL,
				APIKey:       mCfg.GetAPIKey(),
				ModelID:      mCfg.ModelID,
				Timeout:      mCfg.Timeout(),
				ProviderName: mCfg.Adapter,
			})
			reg.Register(role, adapter)
			health.Register("model:"+role, adapter)
		case "fake":
			fake := models.NewFakeAdapter(mCfg.ModelID)
			reg.Register(role, fake)
			health.Register("model:"+role, fake)
		default:
			telemetry.Error("Unrecognized adapter type", "CONFIG_ERROR", map[string]interface{}{
				"role":    role,
				"adapter": mCfg.Adapter,
			})
		}
	}

	coord, err := coordinator.NewCoordinator(cfg, s, reg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Coordinator setup error: %v\n", err)
		os.Exit(1)
	}

	// Automatic model downloading if enabled
	if *autoPull {
		for role, mCfg := range cfg.Models {
			if mCfg.Adapter == "openai-compatible" || mCfg.Adapter == "ollama" {
				go func(rName, mID, bURL string) {
					prov := models.NewModelProvisioner(bURL)
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
					defer cancel()
					if err := prov.EnsureModelAvailable(ctx, mID); err != nil {
						telemetry.Error(fmt.Sprintf("Auto-pull failed for %s (%s)", rName, mID), "MODEL_PULL_ERROR", map[string]interface{}{"error": err.Error()})
					}
				}(role, mCfg.ModelID, mCfg.BaseURL)
			}
		}
	}

	mux := http.NewServeMux()

	// Serve retro 8-bit web console
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/ui" {
			http.NotFound(w, r)
			return
		}
		html, err := os.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "web UI asset not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(html)
	})

	mux.HandleFunc("/health/live", health.LiveHandler())
	mux.HandleFunc("/health/ready", health.ReadyHandler())

	// Job collections & sub-routes
	mux.HandleFunc("/api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			jobs, err := s.ListJobs(r.Context())
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(jobs)

		case http.MethodPost:
			var req struct {
				RepositoryRef      string                 `json:"repository_ref"`
				RepositoryRevision string                 `json:"repository_revision"`
				AuthorizationScope map[string]interface{} `json:"authorization_scope"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid request payload"}`))
				return
			}

			if req.RepositoryRef == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"repository_ref is required"}`))
				return
			}

			if authorized, _ := req.AuthorizationScope["authorized"].(bool); !authorized {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_scope.authorized must be true: confirm you are permitted to audit this repository"}`))
				return
			}

			jobID := uuid.New()
			job := &domain.ResearchJob{
				ID:                 jobID,
				RepositoryRef:      req.RepositoryRef,
				RepositoryRevision: req.RepositoryRevision,
				AuthorizationScope: req.AuthorizationScope,
				Status:             domain.JobStatusQueued,
				ConfigSnapshot:     map[string]interface{}{},
				IterationLimit:     cfg.Research.MaxHypothesesPerJob,
			}

			if err := s.CreateJob(r.Context(), job); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, err)))
				return
			}

			// Automatically dispatch coordinator in background
			go func(jID uuid.UUID, repoPath string) {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.Research.JobTimeout())
				defer cancel()

				// Build source context summary if local path exists
				sourceContext := fmt.Sprintf("Repository reference: %s", repoPath)
				if inv, err := tools.InventoryRepository(repoPath); err == nil {
					if summary, err := inv.BuildContextSummary(repoPath, 30000); err == nil {
						sourceContext = summary
					}
				}

				_ = coord.RunJob(ctx, jID, sourceContext)
			}(jobID, req.RepositoryRef)

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(job)

		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	// Job Detail, Cancel & Report Routes
	mux.HandleFunc("/api/v1/jobs/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}

		jobID, err := uuid.Parse(parts[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid job uuid"}`))
			return
		}

		job, err := s.GetJob(r.Context(), jobID)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// GET /api/v1/jobs/{id}
		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(job)
			return
		}

		action := parts[1]
		switch action {
		case "cancel":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			_ = s.UpdateJobStatus(r.Context(), jobID, "operator", domain.JobStatusCancelled, "User requested cancellation")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"cancelled"}`))

		case "report":
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}

			cands, _ := s.ListCandidates(r.Context(), jobID)
			hyps, _ := s.ListHypotheses(r.Context(), jobID)

			var confirmed, refuted, inconclusive []reports.FindingDetail
			for _, h := range hyps {
				revs, _ := s.ListReviews(r.Context(), h.HypothesisID)
				vals, _ := s.ListValidationRuns(r.Context(), h.HypothesisID)

				detail := reports.FindingDetail{
					HypothesisID:      h.HypothesisID.String(),
					Title:             h.Title,
					Status:            h.Status,
					Weakness:          h.Weakness,
					AffectedLocations: h.AffectedLocations,
					SecurityInvariant: h.SecurityInvariant,
					Impact:            h.Impact,
					Counterarguments:  h.Counterarguments,
					Reviews:           revs,
					Validations:       vals,
				}

				switch h.Status {
				case domain.HypothesisConfirmed:
					confirmed = append(confirmed, detail)
				case domain.HypothesisRefuted:
					refuted = append(refuted, detail)
				default:
					inconclusive = append(inconclusive, detail)
				}
			}

			rep := &reports.ResearchReport{
				JobID:              job.ID.String(),
				RepositoryRef:      job.RepositoryRef,
				RepositoryRevision: job.RepositoryRevision,
				JobStatus:          job.Status,
				GeneratedAt:        time.Now().UTC(),
				Summary: reports.ReportSummary{
					TotalCandidates: len(cands),
					TotalHypotheses: len(hyps),
					Confirmed:       len(confirmed),
					Refuted:         len(refuted),
					Inconclusive:    len(inconclusive),
				},
				ConfirmedFindings:    confirmed,
				RefutedFindings:      refuted,
				InconclusiveFindings: inconclusive,
			}

			if r.URL.Query().Get("format") == "markdown" {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				_, _ = w.Write([]byte(rep.GenerateMarkdownReport()))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rep)

		default:
			http.NotFound(w, r)
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.App.HTTPPort),
		Handler: mux,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		telemetry.Info(fmt.Sprintf("HTTP server listening on :%d", cfg.App.HTTPPort), nil)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			telemetry.Error("HTTP server listener terminated", "SERVER_ERROR", map[string]interface{}{"error": err.Error()})
		}
	}()

	<-stop
	telemetry.Info("Shutting down HTTP server...", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		telemetry.Error("Server shutdown failed", "SHUTDOWN_ERROR", map[string]interface{}{"error": err.Error()})
	}
	telemetry.Info("Server stopped cleanly.", nil)
}
