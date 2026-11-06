# Autonomous Multi-Agent Vulnerability Research Platform

An extensible, coordinator-led multi-agent security platform built in **Go** that conducts automated vulnerability discovery, contextual invariant formulation, independent adversarial critique, and isolated sandbox reproduction against authorized codebases.

---

## 1. Architectural Overview

```text
                                  Operator / CLI
                                        │
                         ┌──────────────▼──────────────┐
                         │    Research Coordinator     │
                         │   (Authoritative State)     │
                         └──────────────┬──────────────┘
                                        │
                      ┌─────────────────┴─────────────────┐
                      │      Task & Agent Scheduler       │
                      └───────┬───────────┬───────────┬───┘
                              │           │           │
                     ┌────────▼──┐  ┌─────▼─────┐  ┌──▼────────┐
                     │   Scout   │  │Investigat.│  │ Reviewer  │
                     │  (Leads)  │  │(Invariant)│  │(Adversary)│
                     └────────┬──┘  └─────┬─────┘  └──┬────────┘
                              │           │           │
                              └─────┬─────┴─────┬─────┘
                                    │ Model     │
                                    │ Adapters  │
                                    ▼           ▼
                      ┌──────────────────────────────────┐
                      │    Local / Open-Weight Models    │
                      │ (Qwen2.5-Coder, Llama, DeepSeek) │
                      └──────────────────┬───────────────┘
                                         │ Structured JSON
                                         ▼
                      ┌──────────────────────────────────┐
                      │    Deterministic Tool Runner     │
                      │  (Language Inventory, Traversal) │
                      └──────────────────┬───────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────┐
                      │    Isolated Validation Runner    │
                      │  (Disposable Sandbox, No Network)│
                      └──────────────────┬───────────────┘
                                         │ Exit Codes & Logs
                                         ▼
                      ┌──────────────────────────────────┐
                      │  Durable Audit Trail & Reports   │
                      │ (Markdown, JSON, Artifact Hashes)│
                      └──────────────────────────────────┘
```

### The Three-Agent Specialist Workflow

1. **Scout (`prompts/scout.md`)**:
   - Analyzes project tree, language inventory, and entry points.
   - Emits candidate failure locations conforming to [`schemas/candidate.schema.json`](schemas/candidate.schema.json).
2. **Investigator (`prompts/investigator.md`)**:
   - Traces data flow and state transitions.
   - Defines explicit security invariants that should hold and formulates a falsifiable hypothesis conforming to [`schemas/hypothesis.schema.json`](schemas/hypothesis.schema.json).
3. **Reviewer (`prompts/reviewer.md`)**:
   - Acts as devil's advocate. Looks for compiler mitigations, unreachable paths, and missing preconditions.
   - Decides: `accept_for_validation`, `request_more_evidence`, or `reject_hypothesis` conforming to [`schemas/review.schema.json`](schemas/review.schema.json).
4. **Deterministic Validation Runner (`internal/validation/runner.go`)**:
   - Executes reproduction tests inside a disposable, temporary workspace.
   - Enforces execution deadlines, terminates process trees on timeout, and runs with network disabled (`GOPROXY=off`, `CARGO_NET_OFFLINE=true`).
   - Categorizes outcomes into:
     - `reproduced` $\rightarrow$ Hypothesis marked **Confirmed**.
     - `refuted` $\rightarrow$ Invariant held; Hypothesis marked **Refuted**.
     - `setup_failed` $\rightarrow$ Compilation or missing mock error; marked **Inconclusive** (never falsely refuted).

---

## 2. Zero-Censorship & Local Models

When auditing security-sensitive code, hosted cloud models (Claude, ChatGPT, Gemini) often trigger false-positive content-filter refusals when encountering words like `exploit`, `drain`, or `vulnerability`.

This platform is **100% self-hosted and private**:
- **Zero Cloud Calls:** Code and prompts never leave your local environment.
- **Support for Abliterated Weights:** Compatible with models that have internal refusal vectors mathematically removed (e.g., `huihui_ai/qwen2.5-coder-7b-instruct-abliterated` or `huihui_ai/qwen2.5-coder-32b-instruct-abliterated`). These models will never refuse to analyze invariant bugs or simulate attack payloads.
- **Automated Provisioning:** The built-in provisioner automatically pulls and caches the configured model into your Docker volume on boot.

---

## 3. Quickstart

### Option A: Turnkey Docker Stack (Recommended)

Requires only Docker. Ollama, model weights, and the coordinator API are bundled together in a private container bridge:

```bash
# 1. Start the platform and inference engine
make docker-up

# 2. Tail the auto-pull and boot logs
make docker-logs

# 3. View the Retro 8-bit Console in your browser:
#    http://localhost:8080/

# 4. Submit an audit job via the container CLI:
make docker-cli ARGS="create audit://my-target-repo HEAD"

# 5. Stop the stack when done:
make docker-down
```

### Option B: Native Go Run

If you wish to run the binaries directly on your host machine:

```bash
# 1. Build local binaries (bin/api, bin/cli)
make build

# 2. Run the test suite
make test

# 3. Start the API daemon with auto-pull enabled
make run-api-autopull
```

---

## 4. Makefile Command Reference

| Command | Action |
| :--- | :--- |
| `make build` | Compiles `bin/api` and `bin/cli` binaries |
| `make test` | Runs the complete unit and integration test suite |
| `make test-race` | Runs tests with Go data race detector enabled |
| `make run-api` | Starts the local API server on `:8080` with standard config |
| `make run-api-autopull`| Starts the local API server with automated model downloading |
| `make docker-up` | Launches the turnkey Docker Compose stack (`ollama` + `api`) |
| `make docker-down` | Stops the Docker Compose stack (preserves model cache) |
| `make docker-logs` | Streams live logs from all containers in the stack |
| `make docker-cli ARGS="..."` | Executes CLI commands directly inside the running container |
| `make fmt` | Formats all Go source files according to Go standards |
| `make clean` | Removes compiled binaries and temporary test artifacts |

---

## 5. CLI Usage Guide

The CLI client (`bin/cli`) communicates with the API daemon:

```bash
# Query health and readiness probes
./bin/cli health

# Submit a repository for an automated research run
./bin/cli create /path/to/target-repo HEAD

# List active and completed jobs
./bin/cli list

# View detailed job status and state machine progress
./bin/cli inspect <job-id>

# Export the audit report in Markdown format
./bin/cli report <job-id> --format markdown

# Cancel an active job
./bin/cli cancel <job-id>
```

---

## 6. Interactive Retro 8-Bit Web Console

The platform includes a built-in retro arcade-style cyber terminal served at `http://localhost:8080/` (or `web/index.html`):

- **Live Squad Party Status:** Monitors Scout, Investigator, and Reviewer task execution.
- **Real-Time CRT Terminal:** Live log stream of coordinator state transitions.
- **Confirmed Loot Dossier:** Visualizes reproduced vulnerabilities alongside exact source locations and SHA-256 evidence hashes.

---

## 7. Configuration Reference

Configuration files are located in `configs/`:
- `configs/config.example.yaml`: For local host development.
- `configs/config.docker.yaml`: For containerized Docker Compose deployments.

```yaml
app:
  environment: production
  http_port: 8080

research:
  max_concurrent_jobs: 2
  max_hypotheses_per_job: 20
  max_iterations_per_hypothesis: 4
  job_timeout_seconds: 1800

validation:
  enabled: true
  network_access: disabled     # Blocks all outbound network in sandboxes
  max_runtime_seconds: 120

models:
  scout:
    adapter: openai-compatible
    model_id: huihui_ai/qwen2.5-coder-7b-instruct-abliterated
    base_url: http://ollama:11434/v1
    timeout_seconds: 180

  investigator:
    adapter: openai-compatible
    model_id: huihui_ai/qwen2.5-coder-7b-instruct-abliterated
    base_url: http://ollama:11434/v1
    timeout_seconds: 240

  reviewer:
    adapter: openai-compatible
    model_id: huihui_ai/qwen2.5-coder-7b-instruct-abliterated
    base_url: http://ollama:11434/v1
    timeout_seconds: 240
```

---

## 8. Repository Layout

```text
vuln-research/
├── cmd/
│   ├── api/main.go            # Orchestration server daemon
│   └── cli/main.go            # Operator CLI
├── configs/
│   ├── config.example.yaml    # Local host config
│   └── config.docker.yaml     # Containerized config
├── deploy/
│   ├── Dockerfile.api         # Multi-stage production container build
│   └── compose.yaml           # Turnkey Docker Compose configuration
├── internal/
│   ├── agents/                # Scout, Investigator, and Reviewer agent implementations
│   ├── config/                # YAML configuration loader & validator
│   ├── coordinator/           # State machine loop & task orchestrator
│   ├── domain/                # Canonical domain models
│   ├── models/                # Adapters & automated model provisioner
│   ├── reports/               # Markdown and JSON report generator
│   ├── schema/                # Draft 2020-12 JSON Schema validator
│   ├── state/                 # State transitions & immutable audit logger
│   ├── store/                 # MemoryStore & PostgreSQL store interfaces
│   ├── telemetry/             # Structured JSON logger & health probes
│   ├── tools/                 # Path confinement, repository inventory, artifact hashes
│   └── validation/            # Isolated sandbox runner (network disabled)
├── migrations/
│   └── 001_initial_schema.sql # PostgreSQL schema migrations
├── prompts/
│   ├── scout.md
│   ├── investigator.md
│   └── reviewer.md
├── schemas/
│   ├── candidate.schema.json
│   ├── hypothesis.schema.json
│   ├── review.schema.json
│   └── validation-result.schema.json
├── testdata/
│   ├── vulnerable/vault.sol   # Benchmark vulnerable fixture
│   └── patched/vault.sol      # Benchmark patched fixture
├── web/
│   └── index.html             # Retro 8-bit web console
├── Makefile                   # Build, test, and run automation
├── go.mod
└── go.sum
```
