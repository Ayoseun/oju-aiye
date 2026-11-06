-- 001_initial_schema.sql
-- Autonomous Multi-Agent Vulnerability Research Platform

CREATE TABLE IF NOT EXISTS research_jobs (
    id UUID PRIMARY KEY,
    repository_ref TEXT NOT NULL,
    repository_revision TEXT NOT NULL,
    authorization_scope JSONB NOT NULL,
    status TEXT NOT NULL,
    config_snapshot JSONB NOT NULL,
    iteration_limit INT NOT NULL DEFAULT 4,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_research_jobs_status ON research_jobs(status);
CREATE INDEX IF NOT EXISTS idx_research_jobs_created_at ON research_jobs(created_at);

CREATE TABLE IF NOT EXISTS candidates (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES research_jobs(id) ON DELETE CASCADE,
    repository_path TEXT NOT NULL,
    symbol TEXT NOT NULL,
    line_start INT NOT NULL,
    line_end INT NOT NULL,
    suspected_class TEXT NOT NULL,
    rationale TEXT NOT NULL,
    structured_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_candidates_job_id ON candidates(job_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES research_jobs(id) ON DELETE CASCADE,
    candidate_id UUID NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    security_invariant TEXT NOT NULL,
    preconditions JSONB NOT NULL,
    impact TEXT NOT NULL,
    iteration_count INT NOT NULL DEFAULT 0,
    structured_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_job_id ON hypotheses(job_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);

CREATE TABLE IF NOT EXISTS reviews (
    id UUID PRIMARY KEY,
    hypothesis_id UUID NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    reviewer_model TEXT NOT NULL,
    decision TEXT NOT NULL,
    supporting_points JSONB NOT NULL,
    counterarguments JSONB NOT NULL,
    missing_evidence JSONB NOT NULL,
    rationale TEXT NOT NULL,
    structured_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reviews_hypothesis_id ON reviews(hypothesis_id);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES research_jobs(id) ON DELETE CASCADE,
    hypothesis_id UUID REFERENCES hypotheses(id) ON DELETE SET NULL,
    evidence_type TEXT NOT NULL,
    source_path TEXT,
    artifact_id UUID,
    content_hash TEXT,
    description TEXT NOT NULL,
    polarity TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_hypothesis_id ON evidence(hypothesis_id);

CREATE TABLE IF NOT EXISTS validation_runs (
    id UUID PRIMARY KEY,
    hypothesis_id UUID NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL,
    test_command_id TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INT,
    outcome TEXT NOT NULL,
    stdout_artifact TEXT,
    stderr_artifact TEXT,
    test_artifact TEXT,
    environment_fingerprint TEXT NOT NULL,
    notes TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_validation_runs_hypothesis_id ON validation_runs(hypothesis_id);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES research_jobs(id) ON DELETE CASCADE,
    hypothesis_id UUID REFERENCES hypotheses(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    model_id TEXT NOT NULL,
    input_artifact_id UUID,
    output_artifact_id UUID,
    attempt_count INT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_code TEXT,
    error_summary TEXT,
    usage_metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_job_id ON agent_tasks(job_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES research_jobs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    storage_uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retention_policy TEXT
);
