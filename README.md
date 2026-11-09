# Autonomous Multi-Agent Vulnerability Research Platform

A coordinator-led, multi-agent security research pipeline written in **Go**. Three model-backed roles (Scout, Investigator, Reviewer) turn a codebase you are **authorized to audit** into falsifiable hypotheses, and a validation runner tries to reproduce the accepted ones.

> **Status: early prototype.** The pipeline runs end to end against a model endpoint, but several pieces are intentionally minimal. Read [Current limitations](#10-current-limitations) before relying on any result.

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
2. **Investigator** (`prompts/investigator.md`): traces data flow, states the security invariant that should hold, and writes a falsifiable hypothesis with a validation plan and a `failure_signature` (`schemas/hypothesis.schema.json`).
3. **Reviewer** (`prompts/reviewer.md`): argues against the hypothesis and decides `accept_for_validation`, `request_more_evidence` or `reject_hypothesis` (`schemas/review.schema.json`). On `request_more_evidence` the Reviewer's feedback (counterarguments, missing evidence, falsification tests) goes back to the Investigator, which **revises the same hypothesis**, and the Reviewer looks again. `research.max_iterations_per_hypothesis` caps the review rounds (default 4; 1 means never revise).
4. **Validation runner** (`internal/validation/runner.go`): runs the first command of an accepted hypothesis's validation plan (`sh -c <plan[0]>`) and classifies the result.

### How a job ends

| Job status | Meaning |
|:--|:--|
| `confirmed` | at least one hypothesis was validated (see below) |
| `refuted` | every hypothesis was either rejected by the Reviewer (**none were tested**, and the reason says so) or tested and not reproduced |
| `inconclusive` | not an all-clear. The Scout found nothing, a hypothesis never satisfied the Reviewer within the round limit, an agent call failed on some hypothesis, or a validation run was inconclusive. The reason lists what is unresolved |
| `failed` | the run could not be carried out, for example the Scout or the Investigator failed on every candidate |
| `cancelled` | stopped by the operator |

A broken or flaky model never produces `refuted`: unreviewed, unrevisable or unanalyzed work is `inconclusive` or `failed`.

### How validation results are decided

The Investigator must declare a `failure_signature` up front: text its test prints **only** when the vulnerability is demonstrated (for example `path traversal: read`). The runner then classifies the first command of the validation plan like this:

| Result | When | Hypothesis status |
|:--|:--|:--|
| `reproduced` | exits non-zero **and** the output contains the declared signature | Confirmed |
| `refuted` | exits `0` | Refuted |
| `inconclusive` | exits non-zero but no usable signature was declared, or the output does not contain it (a typo, crash or missing dependency in the test itself looks exactly like this) | Inconclusive |
| `setup_failed` | exit `126`/`127`, or output matches a known compile/setup error | Inconclusive (never marked refuted) |
| timeout | exceeds `max_runtime_seconds` | Inconclusive |

A signature shorter than 8 characters (`FAIL`, `error`) is treated as missing. This closes the biggest false-positive path, where any broken test used to count as a confirmed bug, but it is still only as honest as the test the model wrote: a model can print its own signature from a bogus test. Treat Confirmed findings as strong leads and read the captured output.

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

### Option C: choose where the models run

Two ready-made profiles, switchable with one command. The console always shows which one is active (a pill in the header, plus a warning in the new-audit dialog when your code would leave this machine).

| | `make run-api-mac` | `make run-api-gpu` |
|:--|:--|:--|
| Config | `configs/config.mac.yaml` | `configs/config.gpu.yaml` |
| Where models run | Ollama on this machine | a GPU server you control |
| Does your code leave the machine? | No | **Yes, in every prompt** |
| Tuned for | small CPU-only laptops (one shared model, 1 revision round, long timeouts) | speed and quality (bigger models, full revision loop) |
| Needs | `ollama pull <model>` | the `GPU_*` variables in `configs/gpu.env.example`, no defaults, so it can't start half-configured |

**On a small Mac.** Ollama must be installed and `ollama serve` running. The profile defaults all four roles to `hermes3:8b` (check the tag with `ollama list`; override with `LEAD_MODEL_ID`, `SCOUT_MODEL_ID`, and so on). One shared model avoids reloading several GB between roles on 16 GB. Expect roughly 2 to 4 tokens per second on an older Intel laptop (an estimate, not a measurement), so an audit can take an hour or more; it is meant for development and small targets. Old Macs may be unable to run the current Ollama app; building llama.cpp is the fallback, since it serves the same OpenAI-compatible API.

**On a GPU server.**

```bash
cp configs/gpu.env.example configs/gpu.env      # git-ignored; fill in the model tags and URL
source configs/gpu.env && make run-api-gpu
```

Reach the server in one of these ways, best first:

1. **SSH tunnel:** `ssh -N -L 11434:localhost:11434 you@your-gpu-host`, then `GPU_BASE_URL=http://localhost:11434/v1`. Encrypted and needs no open port. The profile marks every role `remote: true`, so the console still reports that your code leaves the machine even though the URL says localhost.
2. **https reverse proxy** that checks an API key (set `GPU_API_KEY`).
3. **WireGuard or Tailscale address** over plain http. Add `allow_insecure_http: true` to each model in `config.gpu.yaml`.

**Ollama has no authentication, so never expose its port to the internet.** The config loader refuses to start when a model's `base_url` is plain `http://` to another machine, unless that model sets `allow_insecure_http: true`, because it would send your source code (and any API key) unencrypted. To mix the two (for example a local lead and a remote analysis model), set `base_url` per role. `GET /api/v1/system` reports the profile, each role's model and host, and whether any code leaves the machine (never keys).

---

## 5. Testing without a GPU (scripted stand-in model)

You can exercise the whole pipeline (real API, real CLI, real HTTP model adapter, schema validation, the validation sandbox, reports) without Ollama or a GPU. `replayllm` is a tiny OpenAI-compatible server that answers each role with a canned JSON file from `testdata/scenarios/<name>/`:

```bash
make test   # includes TestEndToEndReplay (needs `go` on PATH; use `go test -short` to skip)
make e2e    # builds everything, starts replayllm + the API, drives them with the CLI
```

The bundled scenario claims a path-traversal bug in `fileserve.Read`, and `testdata/targets/` holds two Go modules with the same function: `traversal-vulnerable` and `traversal-patched`. The scripted model makes the **same** claim for both, and only the validation step (a real `go test` run in the sandbox) tells them apart: the vulnerable copy ends `confirmed`, the patched copy ends `refuted`. A third scenario, `traversal-wrong-signature`, has a test that fails on the vulnerable code but declares a signature it never prints; it ends `inconclusive`, which is the case the old "any non-zero exit" rule got wrong. That checks the plumbing and the pass/fail contract, **not model quality**: the replay model cannot analyze code it has not been scripted for. To audit an arbitrary codebase you need a real model (see §2 and §4).

To add a scenario, create a directory with `scout.json`, `investigator.json` and `reviewer.json` (valid against `schemas/`; `{{uuid}}` becomes a fresh UUID per reply) and run `replayllm -scenario <dir>`. To script different answers over time, add `<role>.<n>.json`: the nth call for that role gets that file and every other call falls back to `<role>.json`. The bundled scenarios cover the review loop and the failure paths: `traversal-evidence-once` (Reviewer asks once, then accepts), `-never-converges`, `-no-candidates`, `-rejected`, `-investigator-garbage` and `-reviewer-garbage`.

---

## 6. Makefile reference

| Command | Action |
|:--|:--|
| `make build` | Compiles `bin/api` and `bin/cli` |
| `make test` | Runs all tests |
| `make e2e` | End-to-end smoke test with the scripted stand-in model (no GPU) |
| `make test-race` | Runs tests with the Go race detector |
| `make run-api` | API on `:8080` using `configs/config.example.yaml` |
| `make run-api-autopull` | Same, with automatic model download |
| `make docker-up` / `docker-down` / `docker-logs` | Manage the Docker Compose stack |
| `make docker-cli ARGS="..."` | Run the CLI inside the API container |
| `make fmt` | `gofmt` all Go files |
| `make clean` | Remove binaries and temp artifacts |

---

## 7. CLI

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

## 8. Web console

`web/index.html` (served at `http://localhost:8080/`) is a single self-contained page wired to the real API. It makes no external requests (no CDN, no web fonts) and the server sends a strict Content-Security-Policy that blocks everything except same-origin calls.

- **Audits list and detail**, with deep links (`#/jobs/<id>`) and a "Models ready / unreachable" indicator fed by `/health/ready`, so a dead model server is visible before you start a run.
- **Live pipeline** (Prepare, Scout, Investigate, Review, Validate) with per-stage timing. The page polls every ~1.5 s while a job is running and stops polling a finished job.
- **Findings with evidence**: weakness, invariant, impact, the Reviewer's decision and counterarguments, the validation outcome and exit code, the isolation level actually achieved (a warning if it was only advisory), the exact command that was run, and the captured test output.
- **Activity log** of status transitions and agent calls; it opens automatically when a job fails, together with the error and a hint.
- **New audit** dialog (press `N`) that requires the same authorization confirmation as `--authorized`, plus **Cancel** (two clicks) and **Export report** (Markdown).

Everything shown comes from the API; model output, repository paths and test logs are rendered as plain text only, never as HTML. The API endpoints it uses:

| Endpoint | Purpose |
|:--|:--|
| `GET /api/v1/jobs`, `POST /api/v1/jobs` | list and create audits |
| `GET /api/v1/jobs/<id>` | one job, including `error_summary` |
| `GET /api/v1/jobs/<id>/events` | status transitions and agent tasks |
| `GET /api/v1/jobs/<id>/report[?format=markdown]` | findings with reviews, validations and the validation plan |
| `POST /api/v1/jobs/<id>/cancel` | stop a running job |
| `GET /api/v1/system` | active profile, where each model role runs, and whether code leaves this machine |
| `GET /api/v1/artifacts/<sha256>` | captured stdout/stderr of a validation run (hash-validated, capped at 64 KB) |

Like the rest of the API it has no authentication, so keep it on localhost. The console is exercised over HTTP by `make e2e` (security headers, no external resources, endpoint shapes); its rendering is not covered by automated browser tests.

---

## 9. Configuration

Files live in `configs/`: `config.example.yaml` (native), `config.mac.yaml` and `config.gpu.yaml` (the two profiles in §4), `config.docker.yaml` (Compose stack), `config.e2e.yaml` (tests) and `config.local.yaml` (a small local-test profile). Model roles accept `remote: true` (report the endpoint as another machine, e.g. an SSH tunnel) and `allow_insecure_http: true` (permit plain http to a private network); `app.profile` is the label the console shows. Values support `${VAR}` and `${VAR:-default}`; startup fails with a clear error if a variable is unset and has no default.

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

Some keys are accepted by the config loader but **not enforced yet**: `app.log_level`, `research.max_concurrent_jobs`, `research.max_hypotheses_per_job` (recorded as the job's iteration limit only), `research.require_reviewer_before_validation` (the Reviewer always runs), `validation.enabled`, `validation.max_memory_mb`, `validation.max_cpu_seconds`, `validation.max_processes`, `storage.postgres_dsn_env`, `storage.artifact_backend`.

---

## 10. Current limitations

- **State is in memory.** Jobs, hypotheses and the audit trail are lost on restart. `migrations/001_initial_schema.sql` is the planned PostgreSQL schema; no Postgres store is implemented or wired.
- **Jobs run unbounded in parallel** (no `max_concurrent_jobs` enforcement), and there is no authentication on the API.
- **Revision quality depends on the model.** By default all three roles use the same small model, so the Reviewer and Investigator share blind spots; a stronger, different Reviewer helps.
- **Validation is best-effort** (see §3). A Confirmed finding means "the declared signature appeared in a failing test", which is evidence, not proof (see §1).
- **Real-model behavior is untested here.** The automated tests use a scripted stand-in model; how well a 7B model finds and reasons about real bugs has not been evaluated.

---

## 11. Repository layout

```
oju-aiye/                      # Go module name: vuln-research
├── cmd/
│   ├── api/main.go            # API daemon + job dispatch
│   ├── cli/main.go            # Operator CLI
│   └── replayllm/main.go      # scripted stand-in model server (testing)
├── configs/                   # example / docker / local-test YAML configs
├── deploy/
│   ├── Dockerfile.api         # multi-stage build, non-root runtime
│   └── compose.yaml           # ollama + api (mounts ./targets read-only)
├── internal/
│   ├── agents/                # Scout, Investigator, Reviewer
│   ├── replay/                # scripted OpenAI-compatible stand-in model
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
├── scripts/e2e.sh             # end-to-end smoke test (make e2e)
├── testdata/
│   ├── targets/               # vulnerable / patched Go targets for the e2e test
│   ├── scenarios/             # scripted model replies
│   └── vulnerable, patched/   # vault.sol fixtures
├── web/index.html             # web console (single file, wired to the API)
└── Makefile
```
