package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
	"vuln-research/internal/state"
)

// Store defines persistent storage operations for research workflows.
type Store interface {
	// Job operations
	CreateJob(ctx context.Context, job *domain.ResearchJob) error
	GetJob(ctx context.Context, id uuid.UUID) (*domain.ResearchJob, error)
	UpdateJobStatus(ctx context.Context, id uuid.UUID, actor string, status domain.JobStatus, reason string) error
	ListJobs(ctx context.Context) ([]*domain.ResearchJob, error)

	// Candidate operations
	CreateCandidate(ctx context.Context, jobID uuid.UUID, candidate *domain.Candidate) error
	ListCandidates(ctx context.Context, jobID uuid.UUID) ([]*domain.Candidate, error)

	// Hypothesis operations
	CreateHypothesis(ctx context.Context, jobID uuid.UUID, h *domain.Hypothesis) error
	GetHypothesis(ctx context.Context, id uuid.UUID) (*domain.Hypothesis, error)
	ListHypotheses(ctx context.Context, jobID uuid.UUID) ([]*domain.Hypothesis, error)
	UpdateHypothesisStatus(ctx context.Context, id uuid.UUID, status domain.HypothesisStatus) error
	UpdateHypothesis(ctx context.Context, h *domain.Hypothesis) error

	// Review operations
	CreateReview(ctx context.Context, review *domain.ReviewResult) error
	ListReviews(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.ReviewResult, error)

	// Evidence operations
	CreateEvidence(ctx context.Context, ev *domain.Evidence) error
	ListEvidence(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.Evidence, error)

	// Validation operations
	CreateValidationRun(ctx context.Context, run *domain.ValidationResult) error
	ListValidationRuns(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.ValidationResult, error)

	// Task operations
	CreateTask(ctx context.Context, task *domain.AgentTask) error
	GetTask(ctx context.Context, id uuid.UUID) (*domain.AgentTask, error)
	UpdateTask(ctx context.Context, task *domain.AgentTask) error
	ListTasks(ctx context.Context, jobID uuid.UUID) ([]*domain.AgentTask, error)

	// Audit trail
	ListTransitions(ctx context.Context, jobID uuid.UUID) ([]*state.TransitionRecord, error)
}

// MemoryStore provides a thread-safe in-memory store for hermetic testing.
type MemoryStore struct {
	mu           sync.RWMutex
	jobs         map[uuid.UUID]*domain.ResearchJob
	candidates   map[uuid.UUID][]*domain.Candidate
	hypotheses   map[uuid.UUID]*domain.Hypothesis
	hypByJob     map[uuid.UUID][]*domain.Hypothesis
	reviews      map[uuid.UUID][]*domain.ReviewResult
	evidence     map[uuid.UUID][]*domain.Evidence
	validations  map[uuid.UUID][]*domain.ValidationResult
	tasks        map[uuid.UUID]*domain.AgentTask
	taskOrder    []uuid.UUID
	auditRecords []*state.TransitionRecord
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs:        make(map[uuid.UUID]*domain.ResearchJob),
		candidates:  make(map[uuid.UUID][]*domain.Candidate),
		hypotheses:  make(map[uuid.UUID]*domain.Hypothesis),
		hypByJob:    make(map[uuid.UUID][]*domain.Hypothesis),
		reviews:     make(map[uuid.UUID][]*domain.ReviewResult),
		evidence:    make(map[uuid.UUID][]*domain.Evidence),
		validations: make(map[uuid.UUID][]*domain.ValidationResult),
		tasks:       make(map[uuid.UUID]*domain.AgentTask),
	}
}

func (m *MemoryStore) CreateJob(ctx context.Context, job *domain.ResearchJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.jobs[job.ID]; exists {
		return fmt.Errorf("job %s already exists", job.ID)
	}
	now := time.Now().UTC()
	job.CreatedAt = now
	job.UpdatedAt = now
	copyJob := *job
	m.jobs[job.ID] = &copyJob
	return nil
}

func (m *MemoryStore) GetJob(ctx context.Context, id uuid.UUID) (*domain.ResearchJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, fmt.Errorf("job %s not found", id)
	}
	copyJob := *job
	return &copyJob, nil
}

func (m *MemoryStore) UpdateJobStatus(ctx context.Context, id uuid.UUID, actor string, status domain.JobStatus, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return fmt.Errorf("job %s not found", id)
	}

	record, err := state.RecordTransition(id, actor, job.Status, status, reason)
	if err != nil {
		return err
	}

	job.Status = status
	job.UpdatedAt = time.Now().UTC()
	if status == domain.JobStatusFailed {
		job.ErrorSummary = reason
		finished := job.UpdatedAt
		job.FinishedAt = &finished
	}
	m.auditRecords = append(m.auditRecords, record)
	return nil
}

func (m *MemoryStore) ListJobs(ctx context.Context) ([]*domain.ResearchJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]*domain.ResearchJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		copyJob := *j
		res = append(res, &copyJob)
	}
	return res, nil
}

func (m *MemoryStore) CreateCandidate(ctx context.Context, jobID uuid.UUID, candidate *domain.Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyCand := *candidate
	m.candidates[jobID] = append(m.candidates[jobID], &copyCand)
	return nil
}

func (m *MemoryStore) ListCandidates(ctx context.Context, jobID uuid.UUID) ([]*domain.Candidate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.candidates[jobID]
	res := make([]*domain.Candidate, len(items))
	for i, c := range items {
		copyC := *c
		res[i] = &copyC
	}
	return res, nil
}

func (m *MemoryStore) CreateHypothesis(ctx context.Context, jobID uuid.UUID, h *domain.Hypothesis) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyH := *h
	m.hypotheses[h.HypothesisID] = &copyH
	m.hypByJob[jobID] = append(m.hypByJob[jobID], &copyH)
	return nil
}

func (m *MemoryStore) GetHypothesis(ctx context.Context, id uuid.UUID) (*domain.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	h, exists := m.hypotheses[id]
	if !exists {
		return nil, fmt.Errorf("hypothesis %s not found", id)
	}
	copyH := *h
	return &copyH, nil
}

func (m *MemoryStore) ListHypotheses(ctx context.Context, jobID uuid.UUID) ([]*domain.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.hypByJob[jobID]
	res := make([]*domain.Hypothesis, len(items))
	for i, h := range items {
		copyH := *h
		res[i] = &copyH
	}
	return res, nil
}

func (m *MemoryStore) UpdateHypothesisStatus(ctx context.Context, id uuid.UUID, status domain.HypothesisStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	h, exists := m.hypotheses[id]
	if !exists {
		return fmt.Errorf("hypothesis %s not found", id)
	}
	h.Status = status
	return nil
}

// UpdateHypothesis replaces a hypothesis in place, keeping its ID and its place in the job's list.
// Writing through the existing pointer keeps the by-ID and by-job views consistent.
func (m *MemoryStore) UpdateHypothesis(ctx context.Context, h *domain.Hypothesis) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.hypotheses[h.HypothesisID]
	if !exists {
		return fmt.Errorf("hypothesis %s not found", h.HypothesisID)
	}
	*existing = *h
	return nil
}

func (m *MemoryStore) CreateReview(ctx context.Context, review *domain.ReviewResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyR := *review
	m.reviews[review.HypothesisID] = append(m.reviews[review.HypothesisID], &copyR)
	return nil
}

func (m *MemoryStore) ListReviews(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.ReviewResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.reviews[hypothesisID]
	res := make([]*domain.ReviewResult, len(items))
	for i, r := range items {
		copyR := *r
		res[i] = &copyR
	}
	return res, nil
}

func (m *MemoryStore) CreateEvidence(ctx context.Context, ev *domain.Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyE := *ev
	if ev.HypothesisID != nil {
		m.evidence[*ev.HypothesisID] = append(m.evidence[*ev.HypothesisID], &copyE)
	}
	return nil
}

func (m *MemoryStore) ListEvidence(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.evidence[hypothesisID]
	res := make([]*domain.Evidence, len(items))
	for i, e := range items {
		copyE := *e
		res[i] = &copyE
	}
	return res, nil
}

func (m *MemoryStore) CreateValidationRun(ctx context.Context, run *domain.ValidationResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyRun := *run
	m.validations[run.HypothesisID] = append(m.validations[run.HypothesisID], &copyRun)
	return nil
}

func (m *MemoryStore) ListValidationRuns(ctx context.Context, hypothesisID uuid.UUID) ([]*domain.ValidationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.validations[hypothesisID]
	res := make([]*domain.ValidationResult, len(items))
	for i, v := range items {
		copyV := *v
		res[i] = &copyV
	}
	return res, nil
}

func (m *MemoryStore) CreateTask(ctx context.Context, task *domain.AgentTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stamp the caller's task too, so later UpdateTask calls keep the real start time.
	if task.StartedAt == nil {
		now := time.Now().UTC()
		task.StartedAt = &now
	}
	copyTask := *task
	m.tasks[task.ID] = &copyTask
	m.taskOrder = append(m.taskOrder, task.ID)
	return nil
}

// ListTasks returns a job's agent tasks in creation order.
func (m *MemoryStore) ListTasks(ctx context.Context, jobID uuid.UUID) ([]*domain.AgentTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*domain.AgentTask
	for _, id := range m.taskOrder {
		if t := m.tasks[id]; t != nil && t.JobID == jobID {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ListTransitions returns a job's status transitions in chronological order.
func (m *MemoryStore) ListTransitions(ctx context.Context, jobID uuid.UUID) ([]*state.TransitionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*state.TransitionRecord
	for _, r := range m.auditRecords {
		if r.JobID == jobID {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetTask(ctx context.Context, id uuid.UUID) (*domain.AgentTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	task, exists := m.tasks[id]
	if !exists {
		return nil, fmt.Errorf("task %s not found", id)
	}
	copyTask := *task
	return &copyTask, nil
}

func (m *MemoryStore) UpdateTask(ctx context.Context, task *domain.AgentTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tasks[task.ID]; !exists {
		return fmt.Errorf("task %s not found", task.ID)
	}
	copyTask := *task
	if copyTask.StartedAt == nil {
		copyTask.StartedAt = m.tasks[task.ID].StartedAt // never lose the start time
	}
	m.tasks[task.ID] = &copyTask
	return nil
}
