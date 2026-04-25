.PHONY: all build test test-race test-short fuzz lint vet fmt clean deps deps-update \
        deps-check coverage bench run test-e2e release help

MODULE        := github.com/rsturla/warden
WARDEN_BIN    := bin/warden
BRIDGE_BIN    := bin/warden-bridge
CONFIG        ?= config.example.yaml
FUZZ_TIME     ?= 30s
FUZZ_PARALLEL ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
COVER_PROFILE := coverage.out

VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE          := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w \
                 -X $(MODULE)/internal/version.Version=$(VERSION) \
                 -X $(MODULE)/internal/version.Commit=$(COMMIT) \
                 -X $(MODULE)/internal/version.Date=$(DATE)

all: deps lint test build ## Full pipeline: deps → lint → test → build

## --- Build ---

build: ## Build all binaries (dev)
	go build -ldflags "$(LDFLAGS)" -o $(WARDEN_BIN) ./cmd/warden
	go build -ldflags "$(LDFLAGS)" -o $(BRIDGE_BIN) ./cmd/warden-bridge

release: ## Build release binaries (stripped, static, CGO disabled)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(WARDEN_BIN) ./cmd/warden
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BRIDGE_BIN) ./cmd/warden-bridge

## --- Dependencies ---

deps: ## Download and verify dependencies
	go mod download
	go mod verify

deps-update: ## Update all dependencies to latest, tidy
	go get -u ./...
	go mod tidy

deps-check: ## List outdated dependencies
	go list -u -m all

## --- Test ---

test: ## Run all tests
	go test ./...

test-race: ## Run all tests with race detector
	go test -race ./...

test-short: ## Run tests, skip network-dependent
	go test -short ./...

test-e2e: build ## Run end-to-end tests
	go test -tags=e2e ./e2e/...

## --- Fuzz ---

fuzz: ## Run all fuzz targets (FUZZ_TIME=30s), auto-discovered
	@grep -r '^func Fuzz' --include='*_test.go' -l . | while read file; do \
		pkg=$$(dirname "$$file"); \
		grep -o '^func Fuzz[A-Za-z0-9_]*' "$$file" | sed 's/^func //' | while read target; do \
			echo "=== FUZZ $$target ($$pkg) ==="; \
			go test -fuzz="$$target" -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) "./$$pkg/" || exit 1; \
		done || exit 1; \
	done

## --- Quality ---

lint: fmt vet ## Run all linters
	@which staticcheck > /dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

fmt: ## Check gofmt formatting
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

vet: ## Run go vet
	go vet ./...

coverage: ## Generate HTML coverage report
	go test -coverprofile=$(COVER_PROFILE) ./...
	go tool cover -html=$(COVER_PROFILE) -o coverage.html
	@echo "Coverage report: coverage.html"

bench: ## Run benchmarks
	go test -bench=. -benchmem ./internal/policy/ ./internal/ca/ ./internal/dns/ ./internal/secrets/

## --- Run ---

run: build ## Build and run warden (CONFIG=path)
	./$(WARDEN_BIN) --config $(CONFIG)

## --- Clean ---

clean: ## Remove build artifacts
	rm -rf bin/ $(COVER_PROFILE) coverage.html

## --- Help ---

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
