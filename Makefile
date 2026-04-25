.PHONY: all build test test-race test-short fuzz lint vet clean deps deps-update \
        deps-check coverage bench run test-e2e help

WARDEN_BIN    := bin/warden
BRIDGE_BIN    := bin/warden-bridge
CONFIG        ?= config.example.yaml
FUZZ_TIME     ?= 30s
FUZZ_PARALLEL ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
COVER_PROFILE := coverage.out

all: deps lint test build ## Full pipeline: deps → lint → test → build

## --- Build ---

build: ## Build all binaries
	go build -o $(WARDEN_BIN) ./cmd/warden
	go build -o $(BRIDGE_BIN) ./cmd/warden-bridge

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

fuzz: ## Run all fuzz targets (FUZZ_TIME=30s)
	go test -fuzz=FuzzCompilePathGlob -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/policy/
	go test -fuzz=FuzzPathMatch -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/policy/
	go test -fuzz=FuzzCompileHostGlob -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/policy/
	go test -fuzz=FuzzHostMatch -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/policy/
	go test -fuzz=FuzzConfigParse -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/config/
	go test -fuzz=FuzzResolveTemplate -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/secrets/
	go test -fuzz=FuzzGetOrCreateCert -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/ca/
	go test -fuzz=FuzzDenylistCheck -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/dns/
	go test -fuzz=FuzzInjectHeaders -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/inject/
	go test -fuzz=FuzzProxyRequest -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL) ./internal/proxy/

## --- Quality ---

lint: vet ## Run all linters
	@which staticcheck > /dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

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
