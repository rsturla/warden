BINARY     := warden-operator
BUILD_DIR  := bin
GOFLAGS    := -trimpath
LDFLAGS    := -s -w

ENVTEST_K8S_VERSION ?= 1.35.0
ENVTEST_BIN_DIR     ?= $(shell pwd)/bin/envtest

.PHONY: all build release test test-race fuzz lint vet clean deps \
        generate manifests controller-gen envtest fmt help

all: deps lint test build ## Full pipeline: deps → lint → test → build

build: fmt vet ## Build operator binary
	go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/operator

release: fmt vet ## Release build: stripped, static, CGO_ENABLED=0
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/operator

test: generate manifests envtest fmt vet ## Run tests (unit + envtest)
	KUBEBUILDER_ASSETS=$$($(ENVTEST_BIN_DIR)/setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_BIN_DIR) -p path) \
		go test ./... -count=1 -timeout=120s

test-race: generate manifests envtest fmt vet ## Run tests with race detector
	KUBEBUILDER_ASSETS=$$($(ENVTEST_BIN_DIR)/setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_BIN_DIR) -p path) \
		go test ./... -count=1 -race -timeout=120s

fuzz: ## Run fuzz tests (FUZZ_TIME=30s default)
	@echo "==> Discovering fuzz targets..."
	@TARGETS=$$(grep -r 'func Fuzz' --include='*_test.go' -l . 2>/dev/null); \
	if [ -z "$$TARGETS" ]; then echo "No fuzz targets found"; exit 0; fi; \
	for f in $$TARGETS; do \
		PKG=$$(dirname $$f); \
		FUNCS=$$(grep -oP 'func (Fuzz\w+)' $$f | awk '{print $$2}'); \
		for fn in $$FUNCS; do \
			echo "==> Fuzzing $$fn in $$PKG ($${FUZZ_TIME:-30s})"; \
			go test $$PKG -fuzz=$$fn -fuzztime=$${FUZZ_TIME:-30s} -timeout=0 || exit 1; \
		done; \
	done

lint: vet ## Lint (go vet + staticcheck)
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not found, skipping"; \
	fi

vet: ## Run go vet
	go vet ./...

fmt: ## Run gofmt
	gofmt -w .

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

deps: ## Download dependencies
	go mod download
	go mod tidy

generate: controller-gen ## Generate deepcopy code
	$(ENVTEST_BIN_DIR)/controller-gen object paths="./api/..."

manifests: controller-gen ## Generate CRD and RBAC manifests
	$(ENVTEST_BIN_DIR)/controller-gen crd rbac:roleName=warden-operator \
		paths="./..." output:crd:artifacts:config=config/crd/bases

controller-gen: ## Install controller-gen
	@mkdir -p $(ENVTEST_BIN_DIR)
	@test -f $(ENVTEST_BIN_DIR)/controller-gen || \
		GOBIN=$(ENVTEST_BIN_DIR) go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest

envtest: ## Install setup-envtest and download binaries
	@mkdir -p $(ENVTEST_BIN_DIR)
	@test -f $(ENVTEST_BIN_DIR)/setup-envtest || \
		GOBIN=$(ENVTEST_BIN_DIR) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	@$(ENVTEST_BIN_DIR)/setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_BIN_DIR) > /dev/null

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'
