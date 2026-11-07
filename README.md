# Autonomous Multi-Agent Vulnerability Research Platform

A coordinator-led, multi-agent security research pipeline written in **Go**. Three model-backed roles (Scout, Investigator, Reviewer) turn a codebase you are **authorized to audit** into falsifiable hypotheses, and a validation runner tries to reproduce the accepted ones.

> **Status: early prototype.** The pipeline runs end to end against a model endpoint, but several pieces are intentionally minimal. Read [Current limitations](#9-current-limitations) before relying on any result.

---

## 1. Architecture

```
                         Operator / CLI / API
                                  │
                   ┌──────────────▼──────────────┐
                   │     Research Coordinator    │   one goroutine per job,
                   │   (sequential pipeline)     │   cancel + timeout aware
                   └──────────────┬──────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
        ┌─────▼─────┐      ┌──────▼──────┐      ┌─────▼─────┐
        │   Scout   │ ───▶ │ Investigator│ ───▶ │ Reviewer  │
        │  (leads)  │      │ (invariants)│      │(adversary)│
        └─────┬─────┘      └──────┬──────┘      └─────┬─────┘
              └──────────┬────────┴─────────┬─────────┘
                         │  Model adapters  │   (OpenAI-compatible API)
                         ▼                  ▼
                ┌──────────────────────────────────┐
                │  Local model server (Ollama)     │   default; base_url is configurable
                └──────────────────┬───────────────┘
                                   │ structured JSON, validated against schemas/
                                   ▼
                ┌──────────────────────────────────┐
                │ Validation runner (best-effort   │   copies source, scrubs env,
                │ sandbox, see §3)                 │   network namespace when available
                └──────────────────┬───────────────┘
                                   │ exit code + logs
                                   ▼
                ┌──────────────────────────────────┐
                │ In-memory job/audit state,       │   artifacts hashed (SHA-256)
                │ Markdown + JSON reports          │   and written to disk
                └──────────────────────────────────┘
```

### The three-agent workflow

1. **Scout** (`prompts/scout.md`): reads the repository inventory/context and emits candidate failure locations (`schemas/candidate.schema.json`).
2. **Investigator** (`prompts/investigator.md`): traces data flow, states the security invariant that should hold, and writes a falsifiable hypothesis with a validation plan (`schemas/hypothesis.schema.json`).
3. **Reviewer** (`prompts/reviewer.md`): argues against the hypothesis and decides `accept_for_validation`, `request_more_evidence` or `reject_hypothesis` (`schemas/review.schema.json`).
4. **Validation runner** (`internal/validation/runner.go`): runs the first command of an accepted hypothesis's validation plan (`sh -c <plan[0]>`) and classifies the result.

### How validation results are decided

| Result | When | Hypothesis status |
|:--|:--|:--|
| `reproduced` | command exits non-zero and it is not a setup problem | Confirmed |
| `refuted` | command exits `0` | Refuted |
| `setup_failed` | exit `126`/`127`, or output matches a known compile/setup error | Inconclusive (never marked refuted) |
| timeout | exceeds `max_runtime_seconds` | Inconclusive |

"Non-zero exit means reproduced" is a deliberately simple contract: the validation plan must be written so that it **fails only when the vulnerability is demonstrated**. A plan that fails for any other reason will be reported as reproduced, so treat Confirmed findings as leads to verify by hand.

---

## 2. Local models

By default every role talks to a local [Ollama](https://ollama.com) server, so code and prompts stay on your machine. Roles use the `openai-compatible` adapter, so `base_url` can point anywhere (including a hosted API); the shipped configs only point at localhost or the bundled Ollama container.

The default model is `huihui_ai/qwen2.5-coder-7b-instruct-abliterated`, an uncensored community variant chosen to reduce refusals on security wording. Any OpenAI-compatible model works. Note that all three roles use the same small model by default, which weakens the Reviewer's independence; point `reviewer` at a different, stronger model for better critique.

Models are pulled automatically only when the API runs with `-auto-pull` (or `AUTO_PULL_MODELS=true`, which the Docker stack sets).

---

## 3. Validation sandbox: what it does and does not do

For each validation run the runner:

- stages a **copy** of the target source into a throwaway temp directory (`.git` and symlinks skipped; capped by `validation.max_artifact_mb`, default 256 MB) so tests never modify your repository. Source is only staged when the job's `repository_ref` is a local directory;
- runs the command with a **scrubbed environment** (only `PATH`, locale and toolchain variables such as `GOPATH`/`CARGO_HOME`; `HOME` and `TMPDIR` point at the sandbox), so host secrets are not inherited;
- when `network_access: disabled`, runs inside a **network namespace** (`unshare -rn`) if the kernel allows it, and always sets offline variables (`GOPROXY=off`, `CARGO_NET_OFFLINE=true`, `npm_config_offline=true`);
- kills the **whole process group** on timeout.

Each result records the isolation level it actually got in its `notes`. If no namespace is available it says `ADVISORY ONLY`.

It does **not** yet enforce memory, CPU or process limits, filesystem confinement beyond the temp copy, or seccomp. It is not a security boundary against hostile code. The Docker stack runs the API as a non-root user inside a container, which is the intended outer boundary; Docker's default seccomp profile usually blocks `unshare`, so inside the stack network isolation is typically advisory. Run untrusted targets on a disposable machine or VM.

---

## 4. Requirements and quickstart

- **Docker route:** Docker with Compose.
- **Native route:** Go (version pinned in `go.mod`) and a running Ollama (or other OpenAI-compatible server) at `http://localhost:11434/v1`.

### Option A: Docker stack

```bash
# 1. Put the repositories you are authorized to audit under ./targets
mkdir -p targets && cp -r /path/to/my-repo targets/my-repo

# 2. Start Ollama + the API (models are pulled on first boot)
make docker-up
make docker-logs

# 3. Submit a job (paths are as seen inside the container)
make docker-cli ARGS="--authorized create /targets/my-repo HEAD"

# 4. Stop the stack
make docker-down
```

Use `TARGETS_DIR=/some/other/dir make docker-up` to mount a different directory.

### Option B: native

```bash
make build            # bin/api, bin/cli
make test
make run-api-autopull # API on :8080; pulls the configured models from Ollama
```

Override models and endpoints with `SCOUT_MODEL_ID`, `SCOUT_BASE_URL` (and the `INVESTIGATOR_*` / `REVIEWER_*` equivalents).

---

## 5. Makefile reference

| Command | Action |
|:--|:--|
| `make build` | Compiles `bin/api` and `bin/cli` |
| `make test` | Runs all tests |
| `make test-race` | Runs tests with the Go race detector |
| `make run-api` | API on `:8080` using `configs/config.example.yaml` |
| `make run-api-autopull` | Same, with automatic model download |
| `make docker-up` / `docker-down` / `docker-logs` | Manage the Docker Compose stack |
| `make docker-cli ARGS="..."` | Run the CLI inside the API container |
| `make fmt` | `gofmt` all Go files |
| `make clean` | Remove binaries and temp artifacts |

---

## 6. CLI

`bin/cli` talks to the API (`--server`, default `http://localhost:8080`).

```bash
./bin/cli health
./bin/cli --authorized create /path/to/target-repo HEAD   # --authorized is required
./bin/cli list
./bin/cli inspect <job-id>                                # includes error_summary on failure
./bin/cli report <job-id> --format markdown               # or json (default)
./bin/cli cancel <job-id>                                 # interrupts the running job
```

`--authorized` is an explicit confirmation that you are permitted to audit the target; the API rejects jobs without `authorization_scope.authorized: true`. This is a deliberate speed bump, not access control: the API has no authentication, so do not expose it beyond localhost.

The `HEAD` revision argument is recorded on the job and shown in reports, but the platform audits the directory as it is on disk; it does not check out that revision.

`GET /health/ready` returns `503 degraded` with per-model errors when a model endpoint is unreachable.

---

## 7. Web console

`web/index.html` (served at `http://localhost:8080/`) is a retro 8-bit console. **It is currently a scripted demo animation and is not wired to the API**: it does not show real jobs, logs or findings. Use the CLI or the HTTP API (`/api/v1/jobs`, `/api/v1/jobs/<id>`, `/api/v1/jobs/<id>/report`, `/api/v1/jobs/<id>/cancel`) for real results.

---

## 8. Configuration

Files live in `configs/` (`config.example.yaml` for native runs, `config.docker.yaml` for the Compose stack, `config.local.yaml` as a small local-test profile). Values support `${VAR}` and `${VAR:-default}`; startup fails with a clear error if a variable is unset and has no default.

```yaml
app:
  environment: production
  http_port: 8080

research:
  job_timeout_seconds: 1800
  max_agent_retries: 2          # values <= 0 fall back to 3

validation:
  network_access: disabled
  max_runtime_seconds: 120
  max_artifact_mb: 256          # cap on source staged into the sandbox

models:
  scout:
    adapter: openai-compatible
    model_id: ${SCOUT_MODEL_ID:-huihui_ai/qwen2.5-coder-7b-instruct-abliterated}
    base_url: ${SCOUT_BASE_URL:-http://localhost:11434/v1}
    timeout_seconds: 180
  # investigator and reviewer have the same shape

storage:
  artifact_directory: ./var/artifacts
```

Some keys are accepted by the config loader but **not enforced yet**: `app.log_level`, `research.max_concurrent_jobs`, `research.max_hypotheses_per_job` (recorded as the job's iteration limit only), `research.max_iterations_per_hypothesis`, `research.require_reviewer_before_validation` (the Reviewer always runs), `validation.enabled`, `validation.max_memory_mb`, `validation.max_cpu_seconds`, `validation.max_processes`, `storage.postgres_dsn_env`, `storage.artifact_backend`.

---

## 9. Current limitations

- **State is in memory.** Jobs, hypotheses and the audit trail are lost on restart. `migrations/001_initial_schema.sql` is the planned PostgreSQL schema; no Postgres store is implemented or wired.
- **Jobs run unbounded in parallel** (no `max_concurrent_jobs` enforcement), and there is no authentication on the API.
- **The Reviewer's `request_more_evidence` decision does not loop back** to the Investigator yet, and a job whose hypotheses all end up in that state is reported as `refuted`.
- **Validation is best-effort** (see §3) and its pass/fail contract is simple (see §1).
- **The web console is not connected** to the API (see §7).

---

## 10. Repository layout

```
oju-aiye/                      # Go module name: vuln-research
├── cmd/
│   ├── api/main.go            # API daemon + job dispatch
│   └── cli/main.go            # Operator CLI
├── configs/                   # example / docker / local-test YAML configs
├── deploy/
│   ├── Dockerfile.api         # multi-stage build, non-root runtime
│   └── compose.yaml           # ollama + api (mounts ./targets read-only)
├── internal/
│   ├── agents/                # Scout, Investigator, Reviewer
│   ├── config/                # YAML loader, env expansion, validation
│   ├── coordinator/           # sequential pipeline + state transitions
│   ├── domain/                # domain models
│   ├── models/                # adapters, registry, model auto-pull
│   ├── reports/               # Markdown / JSON reports
│   ├── schema/                # JSON Schema validation of agent output
│   ├── state/                 # job state machine + audit records
│   ├── store/                 # in-memory store (Postgres planned)
│   ├── telemetry/             # JSON logging + health probes
│   ├── tools/                 # repo inventory, path confinement, artifact hashing
│   └── validation/            # validation runner (best-effort sandbox)
├── migrations/                # planned Postgres schema (not wired)
├── prompts/                   # agent prompts
├── schemas/                   # JSON Schemas for agent I/O
├── testdata/                  # vulnerable / patched vault.sol fixtures
├── web/index.html             # demo console (not wired to the API)
└── Makefile
```
