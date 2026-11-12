# ==============================================================================
# Autonomous Multi-Agent Vulnerability Research Platform Makefile
# ==============================================================================

SHELL := /bin/bash
BINARY_DIR := bin
API_BIN := $(BINARY_DIR)/api
CLI_BIN := $(BINARY_DIR)/cli
COMPOSE_FILE := deploy/compose.yaml

# Colors for terminal output
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

.PHONY: all help build test e2e run-api-mac run-api-gpu run-api-free audit test-race run-api run-api-autopull clean docker-up docker-down docker-logs docker-cli fmt

all: help

## help: Display this help screen
help:
	@echo -e "$(CYAN)Autonomous Multi-Agent Vulnerability Research Platform$(RESET)"
	@echo -e "Usage: make [target]\n"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: Compile both the API daemon and CLI binaries locally
build:
	@echo -e "$(CYAN)==> Building binaries...$(RESET)"
	@mkdir -p $(BINARY_DIR)
	go build -o $(API_BIN) ./cmd/api
	go build -o $(CLI_BIN) ./cmd/cli
	@echo -e "$(GREEN)✓ Binaries compiled to $(API_BIN) and $(CLI_BIN)$(RESET)"

## test: Run all unit and integration tests
test:
	@echo -e "$(CYAN)==> Running test suite...$(RESET)"
	go test -v ./...

## e2e: End-to-end smoke test with a scripted stand-in model (no GPU needed)
e2e:
	@./scripts/e2e.sh

## test-race: Run test suite with Go data race detector
test-race:
	@echo -e "$(CYAN)==> Running tests with race detector...$(RESET)"
	go test -race -v ./...

## run-api: Run the API daemon locally using configs/config.example.yaml
run-api: build
	@echo -e "$(CYAN)==> Launching API server on :8080...$(RESET)"
	@echo -e "$(YELLOW)Console available at: http://localhost:8080/$(RESET)"
	./$(API_BIN) -config configs/config.example.yaml

## run-api-mac: Run with every model on this machine (Ollama on localhost), tuned for a small CPU-only laptop
run-api-mac: build
	@echo -e "$(CYAN)==> Launching API with the mac-local profile (nothing leaves this machine)...$(RESET)"
	./$(API_BIN) -config configs/config.mac.yaml -auto-pull

## run-api-gpu: Run with models on a GPU server you control (set the GPU_* variables first; see configs/gpu.env.example)
run-api-gpu: build
	@echo -e "$(CYAN)==> Launching API with the remote-gpu profile (your code is sent to GPU_BASE_URL)...$(RESET)"
	./$(API_BIN) -config configs/config.gpu.yaml

## run-api-free: Run the API against a free online model endpoint (see configs/free.env.example)
run-api-free: build
	@echo -e "$(CYAN)==> Launching API with the free-online profile (your code leaves this machine)...$(RESET)"
	@echo -e "$(YELLOW)Source configs/free.env first to pick a provider. Console: http://localhost:8080/$(RESET)"
	./$(API_BIN) -config configs/config.free.yaml

## run-api-competition: Run the API with the competition profile (large targets, bounded runs)
run-api-competition: build
	@echo -e "$(CYAN)==> Launching API with the competition profile (your code leaves this machine)...$(RESET)"
	./$(API_BIN) -config configs/config.competition.yaml

## audit: Run one real audit against a running API and print the report (TARGET=<dir> to override)
audit: build
	@./scripts/audit.sh $(TARGET)

## run-api-autopull: Run the API daemon with automated model downloading enabled
run-api-autopull: build
	@echo -e "$(CYAN)==> Launching API server with auto-pull enabled...$(RESET)"
	./$(API_BIN) -config configs/config.example.yaml -auto-pull

## docker-up: Start the entire self-contained stack (Ollama + Coordinator + Auto-Pull) in Docker
docker-up:
	@echo -e "$(CYAN)==> Starting Docker Compose stack...$(RESET)"
	docker compose -f $(COMPOSE_FILE) up -d --build
	@echo -e "$(GREEN)✓ Platform started!$(RESET)"
	@echo -e "$(YELLOW)Retro Web UI: http://localhost:8080/$(RESET)"
	@echo -e "$(YELLOW)Inference API: http://localhost:11434/$(RESET)"

## docker-down: Stop the Docker Compose stack and keep volumes
docker-down:
	@echo -e "$(CYAN)==> Stopping Docker Compose stack...$(RESET)"
	docker compose -f $(COMPOSE_FILE) down

## docker-logs: Follow logs from all containers in the Compose stack
docker-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

## docker-cli: Execute CLI inside the running Docker container (e.g., make docker-cli ARGS="list")
docker-cli:
	docker exec -it vuln-research-api cli $(ARGS)

## fmt: Format all Go source files
fmt:
	@echo -e "$(CYAN)==> Formatting source code...$(RESET)"
	go fmt ./...

## clean: Remove compiled binaries and temporary test artifacts
clean:
	@echo -e "$(CYAN)==> Cleaning build artifacts...$(RESET)"
	rm -rf $(BINARY_DIR)
	rm -rf var/artifacts/*
	@echo -e "$(GREEN)✓ Clean complete.$(RESET)"
