package domain

import (
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the state of a research job.
type JobStatus string

const (
	JobStatusQueued             JobStatus = "queued"
	JobStatusPreparingTarget    JobStatus = "preparing_target"
	JobStatusInventorying       JobStatus = "inventorying"
	JobStatusDiscovering        JobStatus = "discovering"
	JobStatusAnalyzing          JobStatus = "analyzing"
	JobStatusReviewing          JobStatus = "reviewing"
	JobStatusNeedsMoreEvidence  JobStatus = "needs_more_evidence"
	JobStatusReadyForValidation JobStatus = "ready_for_validation"
	JobStatusValidating         JobStatus = "validating"
	JobStatusConfirmed          JobStatus = "confirmed"
	JobStatusRefuted            JobStatus = "refuted"
	JobStatusInconclusive       JobStatus = "inconclusive"
	JobStatusFailed             JobStatus = "failed"
	JobStatusCancelled          JobStatus = "cancelled"
)

// HypothesisStatus represents the status of an individual vulnerability hypothesis.
type HypothesisStatus string

const (
	HypothesisProposed           HypothesisStatus = "proposed"
	HypothesisUnderReview        HypothesisStatus = "under_review"
	HypothesisNeedsMoreEvidence  HypothesisStatus = "needs_more_evidence"
	HypothesisReadyForValidation HypothesisStatus = "ready_for_validation"
	HypothesisValidating         HypothesisStatus = "validating"
	HypothesisConfirmed          HypothesisStatus = "confirmed"
	HypothesisRefuted            HypothesisStatus = "refuted"
	HypothesisInconclusive       HypothesisStatus = "inconclusive"
)

// ReviewDecision represents the outcome of the adversarial reviewer.
type ReviewDecision string

const (
	ReviewAcceptForValidation ReviewDecision = "accept_for_validation"
	ReviewRequestMoreEvidence ReviewDecision = "request_more_evidence"
	ReviewRejectHypothesis    ReviewDecision = "reject_hypothesis"
)

// ValidationOutcome represents the final execution outcome of a validation test.
type ValidationOutcome string

const (
	ValidationOutcomeReproduced   ValidationOutcome = "reproduced"
	ValidationOutcomeRefuted      ValidationOutcome = "refuted"
	ValidationOutcomeInconclusive ValidationOutcome = "inconclusive"
	ValidationOutcomeSetupFailed  ValidationOutcome = "setup_failed"
)

// EvidencePolarity represents how an evidence record relates to a hypothesis.
type EvidencePolarity string

const (
	PolaritySupporting    EvidencePolarity = "supporting"
	PolarityContradicting EvidencePolarity = "contradicting"
	PolarityNeutral       EvidencePolarity = "neutral"
)

// ResearchJob represents an authorized repository analysis job.
type ResearchJob struct {
	ID                 uuid.UUID              `json:"id"`
	RepositoryRef      string                 `json:"repository_ref"`
	RepositoryRevision string                 `json:"repository_revision"`
	AuthorizationScope map[string]interface{} `json:"authorization_scope"`
	Status             JobStatus              `json:"status"`
	ConfigSnapshot     map[string]interface{} `json:"config_snapshot"`
	IterationLimit     int                    `json:"iteration_limit"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	StartedAt          *time.Time             `json:"started_at,omitempty"`
	FinishedAt         *time.Time             `json:"finished_at,omitempty"`
	ErrorSummary       string                 `json:"error_summary,omitempty"`
}

// AgentTask represents a unit of work assigned to an agent role.
type AgentTask struct {
	ID               uuid.UUID              `json:"id"`
	JobID            uuid.UUID              `json:"job_id"`
	HypothesisID     *uuid.UUID             `json:"hypothesis_id,omitempty"`
	Role             string                 `json:"role"`
	Status           string                 `json:"status"`
	ModelID          string                 `json:"model_id"`
	InputArtifactID  *uuid.UUID             `json:"input_artifact_id,omitempty"`
	OutputArtifactID *uuid.UUID             `json:"output_artifact_id,omitempty"`
	AttemptCount     int                    `json:"attempt_count"`
	StartedAt        *time.Time             `json:"started_at,omitempty"`
	FinishedAt       *time.Time             `json:"finished_at,omitempty"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	ErrorSummary     string                 `json:"error_summary,omitempty"`
	UsageMetadata    map[string]interface{} `json:"usage_metadata,omitempty"`
}

// Candidate represents a candidate vulnerability location surfaced by Scout.
type Candidate struct {
	SchemaVersion      string    `json:"schema_version"`
	CandidateID        uuid.UUID `json:"candidate_id"`
	RepositoryPath     string    `json:"repository_path"`
	Symbol             string    `json:"symbol"`
	LineStart          int       `json:"line_start"`
	LineEnd            int       `json:"line_end"`
	SuspectedClass     string    `json:"suspected_class"`
	Rationale          string    `json:"rationale"`
	ObservedFacts      []string  `json:"observed_facts"`
	Assumptions        []string  `json:"assumptions"`
	SuggestedNextSteps []string  `json:"suggested_next_steps"`
	Confidence         float64   `json:"confidence"`
}

// Weakness defines the vulnerability classification.
type Weakness struct {
	CWE      string `json:"cwe"`
	Category string `json:"category"`
}

// AffectedLocation points to code locations relevant to a hypothesis.
type AffectedLocation struct {
	Path      string `json:"path"`
	Symbol    string `json:"symbol"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
}

// Hypothesis represents a falsifiable security hypothesis formulated by Investigator.
type Hypothesis struct {
	SchemaVersion            string             `json:"schema_version"`
	HypothesisID             uuid.UUID          `json:"hypothesis_id"`
	CandidateID              uuid.UUID          `json:"candidate_id"`
	Title                    string             `json:"title"`
	Weakness                 Weakness           `json:"weakness"`
	AffectedLocations        []AffectedLocation `json:"affected_locations"`
	SecurityInvariant        string             `json:"security_invariant"`
	Preconditions            []string           `json:"preconditions"`
	AttackerControlledInputs []string           `json:"attacker_controlled_inputs"`
	ExpectedFailure          string             `json:"expected_failure"`
	Impact                   string             `json:"impact"`
	SupportingEvidenceIDs    []string           `json:"supporting_evidence_ids"`
	Counterarguments         []string           `json:"counterarguments"`
	ValidationPlan           []string           `json:"validation_plan"`
	Status                   HypothesisStatus   `json:"status"`
}

// ReviewResult represents an independent critique formulated by Reviewer.
type ReviewResult struct {
	SchemaVersion      string         `json:"schema_version"`
	ReviewID           uuid.UUID      `json:"review_id"`
	HypothesisID       uuid.UUID      `json:"hypothesis_id"`
	Decision           ReviewDecision `json:"decision"`
	SupportingPoints   []string       `json:"supporting_points"`
	Counterarguments   []string       `json:"counterarguments"`
	MissingEvidence    []string       `json:"missing_evidence"`
	FalsificationTests []string       `json:"falsification_tests"`
	Rationale          string         `json:"rationale"`
	ReviewerModel      string         `json:"reviewer_model"`
}

// ValidationResult represents execution observations from the isolated sandbox.
type ValidationResult struct {
	SchemaVersion          string            `json:"schema_version"`
	ValidationID           uuid.UUID         `json:"validation_id"`
	HypothesisID           uuid.UUID         `json:"hypothesis_id"`
	EnvironmentID          uuid.UUID         `json:"environment_id"`
	TestCommandID          string            `json:"test_command_id"`
	ExitCode               int               `json:"exit_code"`
	Outcome                ValidationOutcome `json:"outcome"`
	StdoutArtifact         string            `json:"stdout_artifact"`
	StderrArtifact         string            `json:"stderr_artifact"`
	TestArtifact           string            `json:"test_artifact"`
	EnvironmentFingerprint string            `json:"environment_fingerprint"`
	Notes                  string            `json:"notes"`
}

// Evidence represents a factual, verifiable observation.
type Evidence struct {
	ID           uuid.UUID              `json:"id"`
	JobID        uuid.UUID              `json:"job_id"`
	HypothesisID *uuid.UUID             `json:"hypothesis_id,omitempty"`
	EvidenceType string                 `json:"evidence_type"`
	SourcePath   string                 `json:"source_path,omitempty"`
	ArtifactID   *uuid.UUID             `json:"artifact_id,omitempty"`
	ContentHash  string                 `json:"content_hash,omitempty"`
	Description  string                 `json:"description"`
	Polarity     EvidencePolarity       `json:"polarity"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}
